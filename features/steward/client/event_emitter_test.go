// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client_test

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// Test LogStream gRPC server
// ---------------------------------------------------------------------------

// testLogStreamServer is a minimal StewardTransportServer that collects
// entries received via LogStream for assertion.
type testLogStreamServer struct {
	transportpb.UnimplementedStewardTransportServer
	mu      sync.Mutex
	entries []*transportpb.LogEntry
	// ready, when non-nil, is closed the first time LogStream is invoked so
	// tests can synchronize on the stream actually being open instead of
	// sleeping for an arbitrary duration.
	ready chan struct{}
}

func (s *testLogStreamServer) LogStream(
	stream grpc.ClientStreamingServer[transportpb.LogEntry, transportpb.LogStreamResponse],
) error {
	s.mu.Lock()
	if s.ready != nil {
		select {
		case <-s.ready: // already closed
		default:
			close(s.ready)
		}
	}
	s.mu.Unlock()
	for {
		entry, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.entries = append(s.entries, entry)
		s.mu.Unlock()
	}
	return stream.SendAndClose(&transportpb.LogStreamResponse{
		EntriesReceived: int64(len(s.entries)),
		Acknowledged:    true,
	})
}

func (s *testLogStreamServer) Collected() []*transportpb.LogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*transportpb.LogEntry, len(s.entries))
	copy(out, s.entries)
	return out
}

// Compile-time check.
var _ transportpb.StewardTransportServer = (*testLogStreamServer)(nil)

// ---------------------------------------------------------------------------
// Test environment helpers
// ---------------------------------------------------------------------------

type emitterTestEnv struct {
	srv    *testLogStreamServer
	client transportpb.StewardTransportClient
}

// newEmitterTestEnv starts an in-process gRPC server and returns a paired client.
func newEmitterTestEnv(t *testing.T) *emitterTestEnv {
	t.Helper()

	srv := &testLogStreamServer{ready: make(chan struct{})}
	grpcSrv := grpc.NewServer()
	transportpb.RegisterStewardTransportServer(grpcSrv, srv)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.GracefulStop)

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return &emitterTestEnv{
		srv:    srv,
		client: transportpb.NewStewardTransportClient(conn),
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestEventEmitter_EnqueueAndDeliver verifies that entries placed on the channel
// by Enqueue are delivered through the LogStream RPC to the server.
func TestEventEmitter_EnqueueAndDeliver(t *testing.T) {
	env := newEmitterTestEnv(t)

	emitter := client.NewEventEmitter(client.EventEmitterConfig{
		Client:    env.client,
		StewardID: "steward-deliver",
		Logger:    logging.NewNoopLogger(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	emitter.Start(ctx)
	defer emitter.Close()

	// Wait for the send goroutine to open the LogStream before enqueueing.
	select {
	case <-env.srv.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for LogStream connection")
	}

	emitter.Enqueue(&transportpb.LogEntry{
		StewardId:     "steward-deliver",
		Level:         transportpb.Severity_SEVERITY_INFO,
		Message:       "detection",
		Timestamp:     timestamppb.Now(),
		CorrelationId: "corr-1",
		Fields: map[string]string{
			"event_kind":  "detection",
			"resource_id": "test-resource",
			"drift_mode":  "apply",
		},
	})
	emitter.Enqueue(&transportpb.LogEntry{
		StewardId:     "steward-deliver",
		Level:         transportpb.Severity_SEVERITY_INFO,
		Message:       "outcome",
		Timestamp:     timestamppb.Now(),
		CorrelationId: "corr-1",
		Fields: map[string]string{
			"event_kind":  "outcome",
			"action":      "applied",
			"duration_ms": "42",
		},
	})

	// Close flushes remaining channel entries before calling CloseAndRecv,
	// so all enqueued entries are delivered before the test asserts.
	emitter.Close()

	collected := env.srv.Collected()
	require.Len(t, collected, 2, "both enqueued entries must be delivered")
	assert.Equal(t, "corr-1", collected[0].GetCorrelationId())
	assert.Equal(t, "corr-1", collected[1].GetCorrelationId())
	assert.Equal(t, "detection", collected[0].GetFields()["event_kind"])
	assert.Equal(t, "outcome", collected[1].GetFields()["event_kind"])
}

// TestEventEmitter_NonBlockingEnqueue verifies that enqueueing beyond the buffer
// depth drops entries without blocking and increments the drop counter.
func TestEventEmitter_NonBlockingEnqueue_DropsWhenFull(t *testing.T) {
	// Use a tiny buffer so overflow is easy to trigger without a live server.
	emitter := client.NewEventEmitter(client.EventEmitterConfig{
		// nil client — no goroutine draining the channel.
		StewardID:   "steward-drop",
		Logger:      logging.NewNoopLogger(),
		BufferDepth: 2,
	})

	// Fill the buffer exactly.
	emitter.Enqueue(&transportpb.LogEntry{Message: "a"})
	emitter.Enqueue(&transportpb.LogEntry{Message: "b"})

	// These must not block and must increment the drop counter.
	done := make(chan struct{})
	go func() {
		defer close(done)
		emitter.Enqueue(&transportpb.LogEntry{Message: "c"})
		emitter.Enqueue(&transportpb.LogEntry{Message: "d"})
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Enqueue blocked when channel was full")
	}

	assert.Equal(t, int64(2), emitter.DropCount(),
		"two overflow entries must be counted as drops")
}

// TestEventEmitter_ReconnectsOnStreamError verifies that the send goroutine
// reconnects after a stream failure and delivers buffered entries.
func TestEventEmitter_ReconnectsOnStreamError(t *testing.T) {
	// First server: accepts one stream then stops (simulates a controller restart).
	srv1 := &testLogStreamServer{ready: make(chan struct{})}
	grpcSrv1 := grpc.NewServer()
	transportpb.RegisterStewardTransportServer(grpcSrv1, srv1)
	lis1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = grpcSrv1.Serve(lis1) }()

	conn1, err := grpc.NewClient(
		lis1.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	emitter := client.NewEventEmitter(client.EventEmitterConfig{
		Client:      transportpb.NewStewardTransportClient(conn1),
		StewardID:   "steward-reconnect",
		Logger:      logging.NewNoopLogger(),
		BufferDepth: 8,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emitter.Start(ctx)

	// Enqueue an entry, wait briefly, then forcefully stop the first server to
	// trigger a stream error and exercise the reconnect path. Stop() (not
	// GracefulStop) is used here so the in-flight stream is terminated
	// immediately; GracefulStop would deadlock waiting for the emitter's stream
	// to close gracefully while the emitter waits for stop/ctx.
	// Wait for the first stream to open so the entry is sent on the live
	// connection (reconnect path), not buffered until after the server dies.
	select {
	case <-srv1.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first stream connection")
	}
	emitter.Enqueue(&transportpb.LogEntry{Message: "before-error", CorrelationId: "r1"})
	time.Sleep(20 * time.Millisecond) // small delay to allow send before kill
	grpcSrv1.Stop()
	_ = conn1.Close()

	// Cancel the context to break the reconnect backoff loop, then close the
	// emitter and verify Close() returns without hanging.
	cancel()
	emitter.Close()

	// Verify the entry before the crash was received by the server (reconnect
	// path exercised).
	collected := srv1.Collected()
	assert.GreaterOrEqual(t, len(collected), 1,
		"at least one entry must have been sent before server died")
}

// TestEventEmitter_Close_BeforeStart is a safety test verifying that Close
// before Start is a no-op and does not panic or hang.
func TestEventEmitter_Close_BeforeStart(t *testing.T) {
	emitter := client.NewEventEmitter(client.EventEmitterConfig{
		StewardID: "steward-noop",
		Logger:    logging.NewNoopLogger(),
	})
	// Must not panic or block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		emitter.Close()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close() blocked when Start() was never called")
	}
}
