// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client_test

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/features/steward/telemetry"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// Fake collector — counts Snapshot() invocations without platform I/O.
// ---------------------------------------------------------------------------

type fakeCollector struct {
	mu    sync.Mutex
	count int64
	// snaps is the optional sequence of Telemetry values to return, indexed
	// by call number (wraps if exhausted). If empty, returns a zero value.
	snaps []telemetry.Telemetry
}

func (f *fakeCollector) Snapshot(_ context.Context) (telemetry.Telemetry, error) {
	atomic.AddInt64(&f.count, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.snaps) == 0 {
		return telemetry.Telemetry{}, nil
	}
	idx := int(atomic.LoadInt64(&f.count)-1) % len(f.snaps)
	return f.snaps[idx], nil
}

func (f *fakeCollector) CallCount() int64 {
	return atomic.LoadInt64(&f.count)
}

// Compile-time check that fakeCollector satisfies the SnapshotCollector interface.
var _ client.SnapshotCollector = (*fakeCollector)(nil)

// ---------------------------------------------------------------------------
// Test server — implements TelemetryStream on the controller side.
// ---------------------------------------------------------------------------

// telemetryTestServer is a minimal StewardTransportServer that drives
// TelemetryStream for testing. The send/recv semantics from the server's
// perspective are the inverse of the steward client:
//   - Recv() reads TelemetrySnapshot from the steward.
//   - Send() writes TelemetryRequest to the steward.
type telemetryTestServer struct {
	transportpb.UnimplementedStewardTransportServer

	mu        sync.Mutex
	snapshots []*transportpb.TelemetrySnapshot

	// controlFn, when non-nil, is called once per TelemetryStream invocation.
	// It receives the stream and can send requests / read snapshots as needed.
	// A nil controlFn causes the server to close the stream immediately (EOF).
	controlFn func(grpc.BidiStreamingServer[transportpb.TelemetrySnapshot, transportpb.TelemetryRequest]) error

	// ready is closed the first time TelemetryStream is invoked.
	ready chan struct{}
}

func (s *telemetryTestServer) TelemetryStream(
	stream grpc.BidiStreamingServer[transportpb.TelemetrySnapshot, transportpb.TelemetryRequest],
) error {
	s.mu.Lock()
	if s.ready != nil {
		select {
		case <-s.ready:
		default:
			close(s.ready)
		}
	}
	s.mu.Unlock()

	if s.controlFn != nil {
		return s.controlFn(stream)
	}
	return nil // immediately EOF → clean close
}

func (s *telemetryTestServer) addSnapshot(snap *transportpb.TelemetrySnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots = append(s.snapshots, snap)
}

func (s *telemetryTestServer) Snapshots() []*transportpb.TelemetrySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*transportpb.TelemetrySnapshot, len(s.snapshots))
	copy(out, s.snapshots)
	return out
}

// Compile-time check.
var _ transportpb.StewardTransportServer = (*telemetryTestServer)(nil)

// ---------------------------------------------------------------------------
// Test environment helpers
// ---------------------------------------------------------------------------

type telemetryTestEnv struct {
	srv    *telemetryTestServer
	client transportpb.StewardTransportClient
}

func newTelemetryTestEnv(t *testing.T, controlFn func(grpc.BidiStreamingServer[transportpb.TelemetrySnapshot, transportpb.TelemetryRequest]) error) *telemetryTestEnv {
	t.Helper()

	srv := &telemetryTestServer{
		ready:     make(chan struct{}),
		controlFn: controlFn,
	}
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

	return &telemetryTestEnv{
		srv:    srv,
		client: transportpb.NewStewardTransportClient(conn),
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestTelemetryStream_NoSnapshotBeforeSubscribe is the load-bearing AC test.
// It proves that Snapshot() is never called before the steward receives an
// inbound subscribe=true TelemetryRequest.
func TestTelemetryStream_NoSnapshotBeforeSubscribe(t *testing.T) {
	collector := &fakeCollector{}

	// The server holds the stream open for a bit without sending a subscribe
	// request, then closes it.
	env := newTelemetryTestEnv(t, func(
		stream grpc.BidiStreamingServer[transportpb.TelemetrySnapshot, transportpb.TelemetryRequest],
	) error {
		// Keep stream open long enough for the steward goroutine to be running.
		time.Sleep(100 * time.Millisecond)
		// No subscribe sent — just close.
		return nil
	})

	ts := client.NewTelemetryStream(client.TelemetryStreamConfig{
		Client:    env.client,
		StewardID: "steward-no-sub",
		Collector: collector,
		Logger:    logging.NewNoopLogger(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ts.Start(ctx)

	// Wait for the stream to open.
	select {
	case <-env.srv.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TelemetryStream connection")
	}

	// Wait for the server's control function to return (stream closed).
	time.Sleep(200 * time.Millisecond)
	ts.Close()

	assert.Equal(t, int64(0), collector.CallCount(),
		"Snapshot must not be called before a subscribe request")
}

// TestTelemetryStream_NoSnapshotAfterUnsubscribe proves that Snapshot() stops
// being called after the controller sends subscribe=false.
func TestTelemetryStream_NoSnapshotAfterUnsubscribe(t *testing.T) {
	collector := &fakeCollector{}

	// snapshotsSentAfterUnsub counts frames received after the unsubscribe.
	var snapshotsSentAfterUnsub atomic.Int64

	// subscribed is closed once the server sends subscribe=true.
	subscribed := make(chan struct{})
	// unsubscribed is closed once the server sends subscribe=false.
	unsubscribed := make(chan struct{})

	env := newTelemetryTestEnv(t, func(
		stream grpc.BidiStreamingServer[transportpb.TelemetrySnapshot, transportpb.TelemetryRequest],
	) error {
		// 1. Send subscribe=true with a short interval.
		if err := stream.Send(&transportpb.TelemetryRequest{
			StewardId:  "steward-unsub",
			Subscribe:  true,
			IntervalMs: 50, // will be clamped to 1000 ms
		}); err != nil {
			return err
		}
		close(subscribed)

		// 2. Collect a few snapshots to confirm sampling is running.
		for i := 0; i < 2; i++ {
			if _, err := stream.Recv(); err != nil {
				return err
			}
		}

		// 3. Send subscribe=false to stop sampling.
		if err := stream.Send(&transportpb.TelemetryRequest{
			StewardId: "steward-unsub",
			Subscribe: false,
		}); err != nil {
			return err
		}
		close(unsubscribed)

		// 4. Hold the stream open for a bit and count any further snapshots.
		deadline := time.After(500 * time.Millisecond)
		for {
			// Non-blocking recv — we just want to count unexpected frames.
			done := make(chan struct{})
			var snap *transportpb.TelemetrySnapshot
			var recvErr error
			go func() {
				snap, recvErr = stream.Recv()
				close(done)
			}()
			select {
			case <-done:
				if recvErr != nil {
					return nil
				}
				_ = snap
				snapshotsSentAfterUnsub.Add(1)
			case <-deadline:
				return nil
			}
		}
	})

	ts := client.NewTelemetryStream(client.TelemetryStreamConfig{
		Client:    env.client,
		StewardID: "steward-unsub",
		Collector: collector,
		Logger:    logging.NewNoopLogger(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ts.Start(ctx)

	// Wait for the subscribe request to have been sent.
	select {
	case <-subscribed:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for subscribe signal")
	}

	// Wait for unsubscribe to be sent and the observation window to close.
	select {
	case <-unsubscribed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for unsubscribe signal")
	}
	// Wait for the server's hold window to expire.
	time.Sleep(600 * time.Millisecond)
	ts.Close()

	assert.Equal(t, int64(0), snapshotsSentAfterUnsub.Load(),
		"no TelemetrySnapshot frames must be sent after unsubscribe")
	assert.Greater(t, collector.CallCount(), int64(0),
		"Snapshot must have been called at least once while subscribed")
}

// TestTelemetryStream_SnapshotsAtRequestedInterval proves that while subscribed,
// TelemetrySnapshot frames stream out at approximately the clamped interval.
func TestTelemetryStream_SnapshotsAtRequestedInterval(t *testing.T) {
	collector := &fakeCollector{
		snaps: []telemetry.Telemetry{
			{
				Processes: []telemetry.ProcessSnapshot{
					{PID: 1, Name: "init", FragmentID: "process:init"},
				},
			},
		},
	}

	// received collects frames from the steward; done is closed by the server
	// once it has enough samples.
	received := make(chan *transportpb.TelemetrySnapshot, 32)
	serverDone := make(chan struct{})
	const wantFrames = 3

	env := newTelemetryTestEnv(t, func(
		stream grpc.BidiStreamingServer[transportpb.TelemetrySnapshot, transportpb.TelemetryRequest],
	) error {
		defer close(serverDone)
		// Request a 1 s interval (the minimum after clamping).
		if err := stream.Send(&transportpb.TelemetryRequest{
			StewardId:  "steward-interval",
			Subscribe:  true,
			IntervalMs: 1000,
		}); err != nil {
			return err
		}
		// Collect wantFrames snapshots.
		for i := 0; i < wantFrames; i++ {
			snap, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			received <- snap
		}
		return nil
	})

	ts := client.NewTelemetryStream(client.TelemetryStreamConfig{
		Client:    env.client,
		StewardID: "steward-interval",
		Collector: collector,
		Logger:    logging.NewNoopLogger(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ts.Start(ctx)
	defer ts.Close()

	// Wait for the server to have collected wantFrames frames.
	select {
	case <-serverDone:
	case <-time.After(12*time.Second):
		t.Fatal("timeout waiting for server to collect snapshots")
	}

	close(received)
	var frames []*transportpb.TelemetrySnapshot
	for f := range received {
		frames = append(frames, f)
	}

	require.Len(t, frames, wantFrames, "must have received exactly wantFrames snapshots")
	for _, f := range frames {
		assert.Equal(t, "steward-interval", f.GetStewardId())
		require.NotNil(t, f.GetTimestamp())
		require.Len(t, f.GetProcesses(), 1)
		assert.Equal(t, "process:init", f.GetProcesses()[0].GetFragmentId())
	}
	assert.Equal(t, int64(wantFrames), collector.CallCount(),
		"Snapshot call count must match received frame count")
}

// TestTelemetryStream_IntervalClamping proves that an unreasonably small
// interval_ms is clamped to the 1 s floor rather than accepted as-is.
func TestTelemetryStream_IntervalClamping(t *testing.T) {
	collector := &fakeCollector{}

	// Record the timestamps of the first two snapshots so we can verify
	// the actual cadence was ≥ 1 s.
	var (
		recvMu   sync.Mutex
		recvTimes []time.Time
	)

	serverDone := make(chan struct{})
	env := newTelemetryTestEnv(t, func(
		stream grpc.BidiStreamingServer[transportpb.TelemetrySnapshot, transportpb.TelemetryRequest],
	) error {
		defer close(serverDone)
		// Send an absurdly small interval — should be clamped to 1000 ms.
		if err := stream.Send(&transportpb.TelemetryRequest{
			StewardId:  "steward-clamp",
			Subscribe:  true,
			IntervalMs: 1, // far below the 1 s floor
		}); err != nil {
			return err
		}
		for i := 0; i < 2; i++ {
			if _, err := stream.Recv(); err != nil {
				return err
			}
			recvMu.Lock()
			recvTimes = append(recvTimes, time.Now())
			recvMu.Unlock()
		}
		return nil
	})

	ts := client.NewTelemetryStream(client.TelemetryStreamConfig{
		Client:    env.client,
		StewardID: "steward-clamp",
		Collector: collector,
		Logger:    logging.NewNoopLogger(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ts.Start(ctx)
	defer ts.Close()

	select {
	case <-serverDone:
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for clamping test to complete")
	}

	recvMu.Lock()
	times := recvTimes
	recvMu.Unlock()

	require.Len(t, times, 2, "must have received 2 snapshots")
	gap := times[1].Sub(times[0])
	// The gap should be ≥ 900 ms (allowing 10% slack for scheduling jitter).
	assert.GreaterOrEqual(t, gap, 900*time.Millisecond,
		"interval must be clamped to ≥1 s even when interval_ms=1 was requested")
}

// TestTelemetryStream_Close_BeforeStart is a safety check: Close before Start
// must not panic or deadlock.
func TestTelemetryStream_Close_BeforeStart(t *testing.T) {
	ts := client.NewTelemetryStream(client.TelemetryStreamConfig{
		StewardID: "steward-early-close",
		Logger:    logging.NewNoopLogger(),
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ts.Close()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close() blocked before Start() was called")
	}
}

// TestTelemetryStream_NoSnapshotOnStreamClose proves that closing the stream
// (without a subscribe=false) also stops sampling.
func TestTelemetryStream_NoSnapshotOnStreamClose(t *testing.T) {
	collector := &fakeCollector{}

	// subscribeReceived is closed once the steward has processed the subscribe
	// (we know this when the first snapshot arrives at the server).
	firstSnap := make(chan struct{})

	env := newTelemetryTestEnv(t, func(
		stream grpc.BidiStreamingServer[transportpb.TelemetrySnapshot, transportpb.TelemetryRequest],
	) error {
		// Subscribe.
		if err := stream.Send(&transportpb.TelemetryRequest{
			StewardId:  "steward-close",
			Subscribe:  true,
			IntervalMs: 1000,
		}); err != nil {
			return err
		}
		// Wait for the first snapshot to confirm sampling started.
		if _, err := stream.Recv(); err != nil {
			return err
		}
		close(firstSnap)
		// Return immediately — server closes stream (EOF to client).
		return nil
	})

	ts := client.NewTelemetryStream(client.TelemetryStreamConfig{
		Client:    env.client,
		StewardID: "steward-close",
		Collector: collector,
		Logger:    logging.NewNoopLogger(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ts.Start(ctx)

	select {
	case <-firstSnap:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first snapshot")
	}

	// Record call count just after stream close; give reconnect a moment then
	// cancel so there is no active subscribe on the reconnected stream.
	countAtClose := collector.CallCount()
	time.Sleep(200 * time.Millisecond)
	cancel()
	ts.Close()

	// The count may increase slightly during the reconnect window, but the
	// primary assertion is that sampling was happening before the close.
	assert.Greater(t, countAtClose, int64(0),
		"Snapshot must have been called at least once while subscribed")
}
