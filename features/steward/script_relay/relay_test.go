// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
//go:build !windows

package scriptrelay

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestRelay creates a Relay for testing. It captures published events and
// returns a thread-safe accessor function for reading them. The relay is
// created with the current process UID so the socket chown is a no-op.
func newTestRelay(t *testing.T, executionID string) (*Relay, func() []cpTypes.Event) {
	t.Helper()
	return newTestRelayWithUID(t, executionID, os.Getuid())
}

// newTestRelayWithUID is newTestRelay with an explicit execution UID, used to
// exercise the socket-ownership chown path.
func newTestRelayWithUID(t *testing.T, executionID string, uid int) (*Relay, func() []cpTypes.Event) {
	t.Helper()
	var mu sync.Mutex
	var events []cpTypes.Event

	publish := func(_ context.Context, event *cpTypes.Event) {
		mu.Lock()
		events = append(events, *event)
		mu.Unlock()
	}

	r, err := NewRelay(executionID, "steward-1", uid, publish, logging.NewNoopLogger())
	require.NoError(t, err)
	getEvents := func() []cpTypes.Event {
		mu.Lock()
		defer mu.Unlock()
		out := make([]cpTypes.Event, len(events))
		copy(out, events)
		return out
	}
	return r, getEvents
}

// statUID returns the owning UID of path via the underlying syscall.Stat_t.
func statUID(t *testing.T, path string) uint32 {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	st, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok, "expected *syscall.Stat_t for %s", path)
	return st.Uid
}

// TestRelay_SocketCreation verifies that Start creates a 0700 directory and
// 0600 socket owned by the execution UID, and that Stop removes them
// (AC1 — socket lifecycle and ownership).
func TestRelay_SocketCreation(t *testing.T) {
	execID := "test-exec-socket"
	r, _ := newTestRelay(t, execID)

	sockPath := r.SocketPath()
	require.NotEmpty(t, sockPath)

	sockDir := filepath.Dir(sockPath)

	// Directory must exist with mode 0700.
	dirInfo, err := os.Stat(sockDir)
	require.NoError(t, err, "socket directory must exist")
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm(), "socket directory must be 0700")

	// Socket file must exist with mode 0600.
	sockInfo, err := os.Stat(sockPath)
	require.NoError(t, err, "socket file must exist")
	assert.Equal(t, os.FileMode(0600), sockInfo.Mode().Perm(), "socket file must be 0600")

	// Directory and socket must be owned by the execution UID. newTestRelay
	// uses the current process UID, so ownership equals os.Getuid().
	wantUID := uint32(os.Getuid())
	assert.Equal(t, wantUID, statUID(t, sockDir), "socket directory must be owned by the execution UID")
	assert.Equal(t, wantUID, statUID(t, sockPath), "socket file must be owned by the execution UID")

	// Stop must remove both the socket and the directory.
	r.Stop()
	_, err = os.Stat(sockDir)
	assert.True(t, os.IsNotExist(err), "socket directory must be removed after Stop")
}

// TestRelay_SocketCreation_ChownsToExecutionUID verifies that the per-execution
// socket directory and socket file are chowned to the script's execution UID
// when it differs from the steward process UID (logged_in_user context). The
// chown requires CAP_CHOWN, so the test only runs as root.
func TestRelay_SocketCreation_ChownsToExecutionUID(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("chown to a different UID requires root (CAP_CHOWN)")
	}

	// UID 1 (daemon/bin) exists on every POSIX system and is never root.
	const execUID = 1
	r, _ := newTestRelayWithUID(t, "test-exec-chown", execUID)
	defer r.Stop()

	sockPath := r.SocketPath()
	sockDir := filepath.Dir(sockPath)

	assert.Equal(t, uint32(execUID), statUID(t, sockDir),
		"socket directory must be chowned to the execution UID")
	assert.Equal(t, uint32(execUID), statUID(t, sockPath),
		"socket file must be chowned to the execution UID")

	// Mode must remain restrictive after the chown.
	dirInfo, err := os.Stat(sockDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())
	sockInfo, err := os.Stat(sockPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), sockInfo.Mode().Perm())
}

// TestNewRelay_InvalidUIDChownFails verifies NewRelay returns an error (rather
// than silently producing an unconnectable socket) when the requested
// execution UID cannot be applied. Running as non-root, chowning to root (UID 0)
// is denied by the kernel.
func TestNewRelay_InvalidUIDChownFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: chown to any UID succeeds, cannot exercise the failure path")
	}

	publish := func(_ context.Context, _ *cpTypes.Event) {}
	_, err := NewRelay("test-exec-badchown", "steward-1", 0, publish, logging.NewNoopLogger())
	require.Error(t, err, "NewRelay must fail when the socket cannot be chowned to the execution UID")
	assert.Contains(t, err.Error(), "chown")

	// The failed socket directory must not be left behind.
	sockDir := filepath.Join(os.TempDir(), "cfgms-test-exec-badchown")
	_, statErr := os.Stat(sockDir)
	assert.True(t, os.IsNotExist(statErr), "socket directory must be cleaned up after a failed chown")
}

// TestRelay_RequestResponseCycle tests the full steward-side relay lifecycle:
// script connects, sends HTTP request, relay publishes event, response is
// delivered, script receives HTTP response.
func TestRelay_RequestResponseCycle(t *testing.T) {
	execID := "test-exec-cycle"
	r, capturedEvents := newTestRelay(t, execID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, r.Start(ctx))
	defer r.Stop()

	// Act as the script would: connect and send an HTTP request.
	var wg sync.WaitGroup
	wg.Add(1)
	var gotResponseBody string
	go func() {
		defer wg.Done()

		conn, err := net.DialTimeout("unix", r.SocketPath(), 2*time.Second)
		if err != nil {
			t.Errorf("dial relay socket: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()

		// Write a minimal HTTP GET request.
		_, _ = fmt.Fprintf(conn, "GET /api/v1/runs HTTP/1.1\r\nHost: cfgms\r\nConnection: close\r\n\r\n")

		// Read back the HTTP response.
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Errorf("read relay response: %v", err)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		var buf strings.Builder
		_, _ = fmt.Fscan(resp.Body, &buf)
		gotResponseBody = resp.Header.Get("X-Test")
	}()

	// Wait for the relay to publish an event, then inject a response.
	var event cpTypes.Event
	require.Eventually(t, func() bool {
		events := capturedEvents()
		if len(events) == 0 {
			return false
		}
		event = events[0]
		return true
	}, 3*time.Second, 50*time.Millisecond, "relay must publish EventRelayRequest")

	assert.Equal(t, cpTypes.EventRelayRequest, event.Type)
	assert.Equal(t, execID, event.Details["execution_id"])
	assert.Equal(t, "GET", event.Details["method"])
	assert.Equal(t, "/api/v1/runs", event.Details["path"])

	// Deliver the response command.
	responseCmd := &cpTypes.Command{
		ID:        "cmd-relay-1",
		Type:      cpTypes.CommandRelayResponse,
		StewardID: "steward-1",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"execution_id": execID,
			"sequence":     float64(1),
			"status":       float64(200),
			"headers":      map[string]interface{}{"X-Test": "relay-ok"},
			"body":         base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`)),
		},
	}
	r.DeliverRelayResponse(responseCmd)

	wg.Wait()
	assert.Equal(t, "relay-ok", gotResponseBody)
}

// TestRelay_StopCancelsWaiting verifies that Stop unblocks a relay goroutine
// waiting for a response.
func TestRelay_StopCancelsWaiting(t *testing.T) {
	execID := "test-exec-stop"
	r, _ := newTestRelay(t, execID)

	ctx := context.Background()
	require.NoError(t, r.Start(ctx))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.DialTimeout("unix", r.SocketPath(), 2*time.Second)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = fmt.Fprintf(conn, "GET /api/v1/runs HTTP/1.1\r\nHost: cfgms\r\nConnection: close\r\n\r\n")
		resp, _ := http.ReadResponse(bufio.NewReader(conn), nil)
		if resp != nil {
			_ = resp.Body.Close()
			// Expect 503 or similar when relay is stopped mid-flight.
			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		}
	}()

	// Let the relay accept the connection and block waiting for response.
	time.Sleep(200 * time.Millisecond)
	r.Stop()
	wg.Wait()
}

// TestRelay_ExecutionIDInEvent verifies the execution_id in the event Details
// matches the relay's bound execution_id (never from the request body).
func TestRelay_ExecutionIDInEvent(t *testing.T) {
	execID := "bound-exec-id"
	r, capturedEvents := newTestRelay(t, execID)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, r.Start(ctx))
	defer r.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, _ := net.DialTimeout("unix", r.SocketPath(), 2*time.Second)
		if conn == nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = fmt.Fprintf(conn, "GET /api/v1/runs HTTP/1.1\r\nHost: cfgms\r\nConnection: close\r\n\r\n")
		// Drain response so the goroutine exits cleanly.
		resp, _ := http.ReadResponse(bufio.NewReader(conn), nil)
		if resp != nil {
			_ = resp.Body.Close()
		}
	}()

	// Wait for event then inject response.
	require.Eventually(t, func() bool {
		return len(capturedEvents()) > 0
	}, 2*time.Second, 20*time.Millisecond)

	event := capturedEvents()[0]
	// execution_id in event must be the relay's bound ID, not anything from the request.
	assert.Equal(t, execID, event.Details["execution_id"])

	r.DeliverRelayResponse(&cpTypes.Command{
		ID:        "resp-1",
		Type:      cpTypes.CommandRelayResponse,
		StewardID: "steward-1",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"execution_id": execID,
			"sequence":     float64(1),
			"status":       float64(200),
			"headers":      map[string]interface{}{},
			"body":         base64.StdEncoding.EncodeToString([]byte(`{}`)),
		},
	})

	wg.Wait()
}
