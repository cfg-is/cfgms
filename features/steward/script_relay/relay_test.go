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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestRelay creates a Relay for testing. It captures published events and
// returns a thread-safe accessor function for reading them.
func newTestRelay(t *testing.T, executionID string) (*Relay, func() []cpTypes.Event) {
	t.Helper()
	var mu sync.Mutex
	var events []cpTypes.Event

	publish := func(_ context.Context, event *cpTypes.Event) {
		mu.Lock()
		events = append(events, *event)
		mu.Unlock()
	}

	r, err := NewRelay(executionID, "steward-1", publish, logging.NewNoopLogger())
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

// TestRelay_SocketCreation verifies that Start creates a 0700 directory and
// 0600 socket, and that Stop removes them (AC1 — socket lifecycle).
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

	// Stop must remove both the socket and the directory.
	r.Stop()
	_, err = os.Stat(sockDir)
	assert.True(t, os.IsNotExist(err), "socket directory must be removed after Stop")
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

	// Simulate the script connecting and sending an HTTP request.
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
