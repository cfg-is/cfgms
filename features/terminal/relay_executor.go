// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package terminal

import (
	"context"
	"math"
	"sync/atomic"

	"github.com/cfgis/cfgms/features/terminal/shell"
)

// RelayExecutor implements shell.Executor for controller-side relay sessions.
// WriteData enqueues browser input for the controller→steward relay goroutine
// to forward over the gRPC Terminal stream. OutputChannel is never consumed in
// relay mode — the TerminalHandler feeds session.HandleOutput directly from
// the steward's inbound stream frames, bypassing the executor output path.
type RelayExecutor struct {
	inputCh  chan []byte
	resizeCh chan [2]int32 // [cols, rows]
	outputCh chan []byte   // always empty — TerminalHandler drives output directly
	errorCh  chan error
	closed   atomic.Bool
}

// NewRelayExecutor creates a RelayExecutor with buffered channels.
func NewRelayExecutor() *RelayExecutor {
	return &RelayExecutor{
		inputCh:  make(chan []byte, 64),
		resizeCh: make(chan [2]int32, 16),
		outputCh: make(chan []byte, 1), // effectively idle in relay mode
		errorCh:  make(chan error, 1),
	}
}

// Start is a no-op: relay sessions have no local shell process.
func (r *RelayExecutor) Start(_ context.Context, _ *shell.Config) error { return nil }

// WriteData enqueues data for forwarding to the steward. Non-blocking: if the
// channel is full (steward not consuming fast enough) the write is dropped
// rather than stalling the WebSocket read loop.
func (r *RelayExecutor) WriteData(_ context.Context, data []byte) error {
	if r.closed.Load() {
		return nil // silently drop after relay is torn down
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case r.inputCh <- cp:
	default:
		// steward input buffer full — drop to avoid blocking the WS goroutine
	}
	return nil
}

// Resize enqueues a terminal resize for forwarding to the steward.
func (r *RelayExecutor) Resize(_ context.Context, cols, rows int) error {
	if r.closed.Load() {
		return nil
	}
	var c, row int32
	if cols > 0 && cols <= math.MaxInt32 {
		c = int32(cols) //nolint:gosec // bounds-checked above
	} else {
		c = 80
	}
	if rows > 0 && rows <= math.MaxInt32 {
		row = int32(rows) //nolint:gosec // bounds-checked above
	} else {
		row = 24
	}
	select {
	case r.resizeCh <- [2]int32{c, row}:
	default:
	}
	return nil
}

// Close marks the executor as closed. Pending reads on InputChan and
// ResizeChan continue to drain; no new writes are accepted.
func (r *RelayExecutor) Close(_ context.Context) error {
	r.closed.Store(true)
	return nil
}

// OutputChannel returns the idle output channel (unused in relay mode).
func (r *RelayExecutor) OutputChannel() <-chan []byte { return r.outputCh }

// ErrorChannel returns the error channel (unused in relay mode).
func (r *RelayExecutor) ErrorChannel() <-chan error { return r.errorCh }

// IsRunning returns true while the relay is active.
func (r *RelayExecutor) IsRunning() bool { return !r.closed.Load() }

// InputChan returns the channel from which the relay goroutine reads browser input.
func (r *RelayExecutor) InputChan() <-chan []byte { return r.inputCh }

// ResizeChan returns the channel from which the relay goroutine reads resize events.
func (r *RelayExecutor) ResizeChan() <-chan [2]int32 { return r.resizeCh }

// SetExecutor replaces the shell executor on session s. Used by the controller
// relay to substitute a RelayExecutor for the platform shell executor that
// NewSession creates, enabling browser→steward data forwarding without
// modifying session.go (Issue #2761: controller Terminal relay).
func (s *Session) SetExecutor(executor shell.Executor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executor = executor
}
