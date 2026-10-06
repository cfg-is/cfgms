// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package pendingcmd holds the commands a steward-side control plane provider
// receives before a command handler is subscribed, and hands them to the handler
// when it subscribes (Issue #4678).
//
// A steward opens its control stream before it has built its command handler, and
// the controller sends commands as soon as the stream registers — the on-connect
// signing-cert refresh, queued deliveries. A provider that drops commands with no
// handler loses exactly those; the lost signing-cert push leaves a steward that
// missed a rotation unable to verify anything the controller sends it.
package pendingcmd

import (
	"context"
	"sync"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

// DefaultLimit bounds the commands held before subscription. The window is the
// time between a steward opening its control stream and subscribing — normally
// milliseconds — so the limit only matters for a misbehaving sender.
const DefaultLimit = 256

// Handler is the command handler signature (interfaces.CommandHandler), declared
// here so the controlplane interfaces package need not be imported.
type Handler = func(ctx context.Context, sc *types.SignedCommand) error

// Queue routes a provider's received commands: live to the subscribed handler,
// or held in arrival order while no handler is subscribed or a backlog is still
// draining. The zero value is not usable; call New.
type Queue struct {
	mu       sync.Mutex
	handler  Handler
	backlog  []*types.SignedCommand
	draining bool
	limit    int
}

// New returns a Queue holding at most limit commands (DefaultLimit if limit <= 0).
func New(limit int) *Queue {
	if limit <= 0 {
		limit = DefaultLimit
	}
	return &Queue{limit: limit}
}

// Admit takes a received command. It returns the handler when the command
// should be dispatched now. It returns nil when the command was held instead —
// no handler yet, or a backlog still draining ahead of it — with dropped set if
// the backlog was full and the command was discarded.
func (q *Queue) Admit(sc *types.SignedCommand) (h Handler, dropped bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.handler != nil && !q.draining {
		return q.handler, false
	}
	if len(q.backlog) >= q.limit {
		return nil, true
	}
	q.backlog = append(q.backlog, sc)
	return nil, false
}

// Subscribe sets the handler. It reports whether held commands are waiting; if
// so the caller must run Drain, and until Drain finishes every newly admitted
// command queues behind the backlog so arrival order is preserved.
func (q *Queue) Subscribe(h Handler) (mustDrain bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.handler = h
	if h == nil || len(q.backlog) == 0 || q.draining {
		return false
	}
	q.draining = true
	return true
}

// Drain hands each held command, oldest first, to dispatch together with the
// current handler, until the backlog is empty. dispatch runs on Drain's
// goroutine and must finish with a command before Drain takes the next one.
func (q *Queue) Drain(dispatch func(h Handler, sc *types.SignedCommand)) {
	for {
		q.mu.Lock()
		if len(q.backlog) == 0 || q.handler == nil {
			q.draining = false
			q.mu.Unlock()
			return
		}
		sc := q.backlog[0]
		q.backlog[0] = nil
		q.backlog = q.backlog[1:]
		h := q.handler
		q.mu.Unlock()

		dispatch(h, sc)
	}
}

// Reset clears the handler and discards held commands (provider Stop).
func (q *Queue) Reset() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.handler = nil
	q.backlog = nil
	q.draining = false
}
