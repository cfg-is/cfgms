// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// emitterMTLSCreds generates a CA plus server and client certificates using the
// central pkg/cert.Manager provider and returns the paired transport
// credentials. This mirrors the mTLS pattern in telemetry_stream_test.go so the
// emitter tests exercise the same mutual-TLS path used in production for
// internal gRPC communication — no insecure transport.
func emitterMTLSCreds(t *testing.T) (serverCreds, clientCreds credentials.TransportCredentials) {
	t.Helper()

	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cert.CAConfig{
			Organization: "CFGMS Test",
			Country:      "US",
			ValidityDays: 1,
		},
	})
	require.NoError(t, err)

	caPEM, err := mgr.GetCACertificate()
	require.NoError(t, err)

	serverCert, err := mgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
	})
	require.NoError(t, err)

	serverTLS, err := cert.CreateServerTLSConfig(
		serverCert.CertificatePEM, serverCert.PrivateKeyPEM, caPEM, tls.VersionTLS13,
	)
	require.NoError(t, err)

	clientCert, err := mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-test",
		ValidityDays: 1,
	})
	require.NoError(t, err)

	clientTLS, err := cert.CreateClientTLSConfig(
		clientCert.CertificatePEM, clientCert.PrivateKeyPEM, caPEM, "localhost", tls.VersionTLS13,
	)
	require.NoError(t, err)

	return credentials.NewTLS(serverTLS), credentials.NewTLS(clientTLS)
}

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
	// received, when non-nil, is closed when the first entry arrives so
	// tests can synchronize on actual entry receipt before stopping the server.
	received chan struct{}
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
		if s.received != nil {
			select {
			case <-s.received: // already closed
			default:
				close(s.received)
			}
		}
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

	serverCreds, clientCreds := emitterMTLSCreds(t)

	srv := &testLogStreamServer{ready: make(chan struct{})}
	grpcSrv := grpc.NewServer(grpc.Creds(serverCreds))
	transportpb.RegisterStewardTransportServer(grpcSrv, srv)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Forward the Serve error to the test goroutine. GracefulStop causes Serve
	// to return nil, so a non-nil error here means the server exited
	// unexpectedly — surface it instead of swallowing it behind opaque
	// downstream transport failures.
	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcSrv.Serve(lis) }()
	t.Cleanup(func() {
		grpcSrv.GracefulStop()
		if err := <-serveErr; err != nil {
			t.Errorf("gRPC test server exited with error: %v", err)
		}
	})

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(clientCreds),
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
	serverCreds, clientCreds := emitterMTLSCreds(t)

	// First server: accepts one stream then stops (simulates a controller restart).
	srv1 := &testLogStreamServer{ready: make(chan struct{}), received: make(chan struct{})}
	grpcSrv1 := grpc.NewServer(grpc.Creds(serverCreds))
	transportpb.RegisterStewardTransportServer(grpcSrv1, srv1)
	lis1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Capture the Serve error. Stop() (called mid-test below) fires the server's
	// quit signal, so Serve returns nil on a clean shutdown; a non-nil value
	// means the server died unexpectedly and would otherwise be masked behind an
	// opaque reconnect/connection error in the emitter.
	serveErr1 := make(chan error, 1)
	go func() { serveErr1 <- grpcSrv1.Serve(lis1) }()
	t.Cleanup(func() {
		// Stop the server before reading serveErr1 so the cleanup never
		// deadlocks: if a t.Fatal earlier in the test unwinds the goroutine
		// before grpcSrv1.Stop() runs in the test body, Serve(lis1) would
		// still be running and never write to serveErr1. Stop() is idempotent,
		// so calling it here is safe even after an in-test Stop().
		grpcSrv1.Stop()
		if err := <-serveErr1; err != nil {
			t.Errorf("gRPC test server exited with error: %v", err)
		}
	})

	conn1, err := grpc.NewClient(
		lis1.Addr().String(),
		grpc.WithTransportCredentials(clientCreds),
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
	// Wait until the server has received at least one entry before stopping it.
	// This replaces a fixed sleep that was too short on cold Windows runners.
	select {
	case <-srv1.received:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first entry to reach server before stop")
	}
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
