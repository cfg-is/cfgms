// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client_test

import (
	"bytes"
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// Test gRPC server for Terminal RPC
// ---------------------------------------------------------------------------

// terminalTestServer is a minimal StewardTransportServer that exposes each
// Terminal stream so tests can send/recv frames directly.
type terminalTestServer struct {
	transportpb.UnimplementedStewardTransportServer
	// streamCh receives each new Terminal stream; buffered so the handler does
	// not block the gRPC goroutine while the test hasn't received yet.
	streamCh chan grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData]
}

func (s *terminalTestServer) Terminal(
	stream grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData],
) error {
	s.streamCh <- stream
	// Hold the stream open until the client disconnects.
	<-stream.Context().Done()
	return nil
}

// Compile-time check.
var _ transportpb.StewardTransportServer = (*terminalTestServer)(nil)

// ---------------------------------------------------------------------------
// Test env helpers
// ---------------------------------------------------------------------------

// newBridgeTestEnv starts an in-process gRPC server implementing the Terminal
// RPC and returns a connected TerminalBridge ready for testing.
func newBridgeTestEnv(t *testing.T) (*client.TerminalBridge, *terminalTestServer) {
	t.Helper()
	srv := &terminalTestServer{
		streamCh: make(chan grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData], 1),
	}
	grpcSrv := grpc.NewServer()
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

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	bridge := client.NewTerminalBridge(
		transportpb.NewStewardTransportClient(conn),
		logging.NewLogger("debug"),
	)
	return bridge, srv
}

// collectOutput reads frames from serverStream in a goroutine, writing received
// data bytes to outputCh. The goroutine stops when Recv returns an error or ctx
// is done.
func collectOutput(
	ctx context.Context,
	serverStream grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData],
) <-chan []byte {
	ch := make(chan []byte, 256)
	go func() {
		defer close(ch)
		for {
			frame, err := serverStream.Recv()
			if err != nil {
				return
			}
			if len(frame.GetData()) > 0 {
				select {
				case ch <- frame.GetData():
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch
}

// waitForString collects output from ch until the accumulated bytes contain
// want or until the deadline fires, then returns the full collected string.
func waitForString(t *testing.T, ch <-chan []byte, want string, deadline time.Duration) string {
	t.Helper()
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	var buf bytes.Buffer
	for {
		select {
		case data, ok := <-ch:
			if !ok {
				return buf.String()
			}
			buf.Write(data)
			if bytes.Contains(buf.Bytes(), []byte(want)) {
				return buf.String()
			}
		case <-timer.C:
			t.Fatalf("timed out after %s waiting for %q in PTY output; got: %q",
				deadline, want, buf.String())
			return buf.String()
		}
	}
}

// waitForPrompt collects output from ch until an interactive shell prompt
// character ('$' for a normal user or '#' for root) appears, then returns the
// collected string. Interactive bash on a PTY writes its PS1 prompt to the
// terminal before it is ready to read input, so this is the correct readiness
// signal to wait for instead of sleeping a fixed duration.
func waitForPrompt(t *testing.T, ch <-chan []byte, deadline time.Duration) string {
	t.Helper()
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	var buf bytes.Buffer
	for {
		select {
		case data, ok := <-ch:
			if !ok {
				t.Fatalf("output channel closed before shell prompt appeared; got: %q", buf.String())
				return buf.String()
			}
			buf.Write(data)
			if bytes.ContainsAny(buf.Bytes(), "$#") {
				return buf.String()
			}
		case <-timer.C:
			t.Fatalf("timed out after %s waiting for shell prompt; got: %q", deadline, buf.String())
			return buf.String()
		}
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestTerminalBridge_RoundTrip verifies the full input→PTY→output loop:
// a command sent by the controller ("echo hi\n") produces shell output that
// contains "hi" in frames sent back to the controller.
func TestTerminalBridge_RoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY round-trip requires a Unix PTY — not supported on Windows")
	}

	bridge, srv := newBridgeTestEnv(t)
	const sessionID = "sess-roundtrip-001"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dialDone := make(chan error, 1)
	go func() { dialDone <- bridge.Dial(ctx, sessionID, "bash", 80, 24) }()

	// Wait for the server-side stream to be established.
	var serverStream grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData]
	select {
	case serverStream = <-srv.streamCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Terminal stream")
	}

	// Start collecting PTY output before we send input.
	outputCh := collectOutput(ctx, serverStream)

	// Wait for bash to emit its initial prompt before sending input, rather
	// than sleeping a fixed duration that may be too short on a loaded host.
	waitForPrompt(t, outputCh, 15*time.Second)

	// Send "echo hi" to the PTY via the controller stream.
	require.NoError(t, serverStream.Send(&transportpb.TerminalData{
		SessionId: sessionID,
		Data:      []byte("echo hi\n"),
	}))

	// Collect output until we see "hi" (present in echoed input or command output).
	out := waitForString(t, outputCh, "hi", 15*time.Second)
	assert.Contains(t, out, "hi", "PTY output must contain 'hi'")

	// Close the session cleanly.
	cancel()
	select {
	case err := <-dialDone:
		assert.NoError(t, err, "Dial must return nil on context cancel")
	case <-time.After(5 * time.Second):
		t.Fatal("Dial did not return after context cancel")
	}
}

// TestTerminalBridge_Teardown verifies that cancelling the Dial context terminates
// the PTY process: executor.IsRunning() must be false after Dial returns.
func TestTerminalBridge_Teardown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY teardown test not supported on Windows")
	}

	bridge, srv := newBridgeTestEnv(t)
	const sessionID = "sess-teardown-001"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dialDone := make(chan error, 1)
	go func() { dialDone <- bridge.Dial(ctx, sessionID, "bash", 80, 24) }()

	select {
	case <-srv.streamCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Terminal stream")
	}

	// Poll until the PTY process is running instead of sleeping a fixed duration.
	require.Eventually(t, func() bool {
		e := bridge.ActiveExecutor()
		return e != nil && e.IsRunning()
	}, 10*time.Second, 10*time.Millisecond, "executor must be running before teardown")

	exec := bridge.ActiveExecutor()
	require.NotNil(t, exec, "executor must be set after Dial opens the stream")
	assert.True(t, exec.IsRunning(), "executor must be running before teardown")

	// Trigger teardown via context cancel.
	cancel()

	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Dial did not return after context cancel")
	}

	assert.False(t, exec.IsRunning(),
		"executor must not be running after Dial returns from context cancel")
}

// TestTerminalBridge_ResizeFrame verifies that a resize frame (is_resize=true)
// reaches Executor.Resize and the executor remains running afterwards.
func TestTerminalBridge_ResizeFrame(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY resize test not supported on Windows")
	}

	bridge, srv := newBridgeTestEnv(t)
	const sessionID = "sess-resize-001"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dialDone := make(chan error, 1)
	go func() { dialDone <- bridge.Dial(ctx, sessionID, "bash", 80, 24) }()

	var serverStream grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData]
	select {
	case serverStream = <-srv.streamCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Terminal stream")
	}

	outputCh := collectOutput(ctx, serverStream)

	// Poll until the PTY process is running instead of sleeping a fixed duration.
	require.Eventually(t, func() bool {
		e := bridge.ActiveExecutor()
		return e != nil && e.IsRunning()
	}, 10*time.Second, 10*time.Millisecond, "executor must be running before resize")

	// Send a resize frame — bridge must forward it to Executor.Resize.
	require.NoError(t, serverStream.Send(&transportpb.TerminalData{
		SessionId: sessionID,
		IsResize:  true,
		Cols:      200,
		Rows:      50,
	}))

	// The bridge processes the resize synchronously on the recv goroutine, so
	// there is no direct PTY-side signal that it completed. Confirm the resize
	// was consumed and the inbound loop is still serving by sending a data frame
	// and observing its output — sleeping a fixed duration would be flaky.
	require.NoError(t, serverStream.Send(&transportpb.TerminalData{
		SessionId: sessionID,
		Data:      []byte("echo resized\n"),
	}))
	out := waitForString(t, outputCh, "resized", 15*time.Second)
	assert.Contains(t, out, "resized", "PTY must remain responsive after resize")

	exec := bridge.ActiveExecutor()
	require.NotNil(t, exec)
	assert.True(t, exec.IsRunning(), "executor must still be running after resize")

	cancel()
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Dial did not return after context cancel")
	}
}

// TestTerminalBridge_SessionIDFilter verifies that frames with a mismatched
// session_id are ignored by the bridge and never forwarded to the PTY.
func TestTerminalBridge_SessionIDFilter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY session filter test not supported on Windows")
	}

	bridge, srv := newBridgeTestEnv(t)
	const sessionID = "sess-filter-001"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dialDone := make(chan error, 1)
	go func() { dialDone <- bridge.Dial(ctx, sessionID, "bash", 80, 24) }()

	var serverStream grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData]
	select {
	case serverStream = <-srv.streamCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Terminal stream")
	}

	outputCh := collectOutput(ctx, serverStream)

	// Wait for bash to emit its prompt before injecting frames, rather than
	// sleeping a fixed duration that may be too short on a loaded host.
	waitForPrompt(t, outputCh, 15*time.Second)

	// Frame with wrong session_id — must be silently dropped by bridge.
	require.NoError(t, serverStream.Send(&transportpb.TerminalData{
		SessionId: "wrong-session-id",
		Data:      []byte("echo shouldnotappear\n"),
	}))

	// Frame with correct session_id — "echo marker" must reach the PTY.
	require.NoError(t, serverStream.Send(&transportpb.TerminalData{
		SessionId: sessionID,
		Data:      []byte("echo marker\n"),
	}))

	// Wait for "marker" to appear in the output.
	out := waitForString(t, outputCh, "marker", 15*time.Second)
	assert.Contains(t, out, "marker", "output must contain 'marker' from the correctly-scoped frame")
	assert.NotContains(t, out, "shouldnotappear",
		"output must not contain output from a frame with mismatched session_id")

	cancel()
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Dial did not return after context cancel")
	}
}
