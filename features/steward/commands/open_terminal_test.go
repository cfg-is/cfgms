// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// ---------------------------------------------------------------------------
// recordingDialer — real in-process TerminalDialer for tests (no mocks).
// ---------------------------------------------------------------------------

// recordingDialer implements TerminalDialer and records every Dial call for
// assertion. It blocks until the test signals it via allow or until the context
// is cancelled, simulating a long-lived bridge session without a real PTY.
type recordingDialer struct {
	mu      sync.Mutex
	calls   []dialCall
	callCh  chan dialCall // non-nil allows callers to receive dial events
	allowCh chan struct{} // closed by allowReturn to unblock Dial
	dialErr error         // error Dial returns after unblocking
}

type dialCall struct {
	SessionID string
	Shell     string
	Cols      int
	Rows      int
}

// newRecordingDialer returns a recordingDialer whose Dial returns immediately
// with nil.
func newRecordingDialer() *recordingDialer {
	ch := make(chan struct{})
	close(ch) // Dial returns immediately unless blocked
	return &recordingDialer{allowCh: ch}
}

// newBlockingDialer returns a recordingDialer whose Dial blocks until
// allowReturn or ctx cancellation. Use for testing concurrent behaviour.
func newBlockingDialer() *recordingDialer {
	return &recordingDialer{
		callCh:  make(chan dialCall, 1),
		allowCh: make(chan struct{}),
	}
}

// allowReturn unblocks a Dial call that is currently blocking.
func (d *recordingDialer) allowReturn(err error) {
	d.mu.Lock()
	d.dialErr = err
	d.mu.Unlock()
	close(d.allowCh)
}

func (d *recordingDialer) Dial(_ context.Context, sessionID, shellStr string, cols, rows int) error {
	call := dialCall{SessionID: sessionID, Shell: shellStr, Cols: cols, Rows: rows}
	d.mu.Lock()
	d.calls = append(d.calls, call)
	d.mu.Unlock()
	if d.callCh != nil {
		d.callCh <- call
	}
	<-d.allowCh
	d.mu.Lock()
	err := d.dialErr
	d.mu.Unlock()
	return err
}

func (d *recordingDialer) dialCalls() []dialCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]dialCall, len(d.calls))
	copy(out, d.calls)
	return out
}

// Compile-time check: recordingDialer implements TerminalDialer.
var _ TerminalDialer = (*recordingDialer)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newOpenTerminalHandler(t *testing.T) *Handler {
	t.Helper()
	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  noopStatus,
		Logger:    newTestLogger(t),
	})
	require.NoError(t, err)
	return h
}

// allowedShell returns a shell name that is valid on the current platform.
func allowedShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "bash"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestOpenTerminal_InvalidShell_Rejected verifies that an unsupported shell in
// Command.params is rejected synchronously without ever calling TerminalDialer.Dial.
func TestOpenTerminal_InvalidShell_Rejected(t *testing.T) {
	dialer := newRecordingDialer()
	h := newOpenTerminalHandler(t)
	h.RegisterOpenTerminalHandler(dialer)

	sc := testSignedCommandWithParams("ot-bad-shell-001", cpTypes.CommandOpenTerminal, map[string]interface{}{
		"session_id": "sess-001",
		"shell":      "/bin/evil-shell",
		"cols":       float64(80),
		"rows":       float64(24),
	})

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	// The command must have failed (EventCommandFailed) because the handler returned an error.
	// The dialer must never have been called.
	assert.Empty(t, dialer.dialCalls(), "Dial must not be called for a non-allowlisted shell")
}

// TestOpenTerminal_ValidShell_DialerCalled verifies that a valid shell param causes
// TerminalDialer.Dial to be invoked with the correct session_id, shell, cols, and rows.
func TestOpenTerminal_ValidShell_DialerCalled(t *testing.T) {
	dialer := newBlockingDialer()
	h := newOpenTerminalHandler(t)
	h.RegisterOpenTerminalHandler(dialer)

	sc := testSignedCommandWithParams("ot-valid-001", cpTypes.CommandOpenTerminal, map[string]interface{}{
		"session_id": "sess-abc",
		"shell":      allowedShell(),
		"cols":       float64(120),
		"rows":       float64(40),
	})

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait() // waits for the executeCommand goroutine; bridge goroutine still blocking

	// Wait for Dial to be called (bridge goroutine runs concurrently).
	select {
	case call := <-dialer.callCh:
		assert.Equal(t, "sess-abc", call.SessionID)
		assert.Equal(t, allowedShell(), call.Shell)
		assert.Equal(t, 120, call.Cols)
		assert.Equal(t, 40, call.Rows)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TerminalDialer.Dial to be called")
	}

	// Unblock the bridge goroutine so the test exits cleanly.
	dialer.allowReturn(nil)
}

// TestOpenTerminal_DefaultShell_UsedWhenOmitted verifies that when no shell is
// provided in params the platform default shell is used and is allowlist-valid.
func TestOpenTerminal_DefaultShell_UsedWhenOmitted(t *testing.T) {
	dialer := newBlockingDialer()
	h := newOpenTerminalHandler(t)
	h.RegisterOpenTerminalHandler(dialer)

	sc := testSignedCommandWithParams("ot-default-shell-001", cpTypes.CommandOpenTerminal, map[string]interface{}{
		"session_id": "sess-def",
		// shell omitted intentionally
	})

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	select {
	case call := <-dialer.callCh:
		assert.NotEmpty(t, call.Shell, "shell must not be empty when default is used")
		assert.Equal(t, allowedShell(), call.Shell,
			"default shell must match platform default")
		assert.Equal(t, 80, call.Cols, "default cols must be 80 when omitted")
		assert.Equal(t, 24, call.Rows, "default rows must be 24 when omitted")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TerminalDialer.Dial with default shell")
	}

	dialer.allowReturn(nil)
}

// TestOpenTerminal_CommandCompletesBeforeBridgeDone verifies that handleOpenTerminal
// returns nil immediately (allowing EventCommandCompleted) while the bridge goroutine
// is still running. This decouples the command handler timeout from the PTY session.
func TestOpenTerminal_CommandCompletesBeforeBridgeDone(t *testing.T) {
	dialer := newBlockingDialer()
	h := newOpenTerminalHandler(t)
	h.RegisterOpenTerminalHandler(dialer)

	var commandCompletedAt atomic.Int64

	// Capture when EventCommandCompleted is emitted.
	cb := func(_ context.Context, evt *cpTypes.Event) {
		if evt.Type == cpTypes.EventCommandCompleted {
			commandCompletedAt.Store(time.Now().UnixNano())
		}
	}
	h2, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  cb,
		Logger:    newTestLogger(t),
	})
	require.NoError(t, err)
	h2.RegisterOpenTerminalHandler(dialer)

	sc := testSignedCommandWithParams("ot-timing-001", cpTypes.CommandOpenTerminal, map[string]interface{}{
		"session_id": "sess-timing",
		"shell":      allowedShell(),
		"cols":       float64(80),
		"rows":       float64(24),
	})

	require.NoError(t, h2.HandleCommand(context.Background(), sc))
	h2.Wait() // returns once executeCommand goroutine completes (bridge still blocked)

	// At this point EventCommandCompleted should have been emitted.
	assert.NotZero(t, commandCompletedAt.Load(),
		"EventCommandCompleted must be emitted before Dial returns")

	// Unblock the bridge goroutine.
	dialer.allowReturn(nil)
}
