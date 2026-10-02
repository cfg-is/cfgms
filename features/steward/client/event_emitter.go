// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/logging"
)

const defaultEmitterBufferDepth = 256

// EventEmitter owns a buffered channel of LogEntry values and a background
// goroutine that streams queued entries to the controller via the LogStream RPC.
// Enqueue never blocks the convergence goroutine; when the channel is full the
// entry is dropped and a drop counter is incremented (ADR-012 §2).
//
// EventEmitter satisfies the execution.EventEmitter interface.
type EventEmitter struct {
	ch        chan *transportpb.LogEntry
	dropCount atomic.Int64

	client    transportpb.StewardTransportClient
	stewardID string
	logger    logging.Logger

	// lifecycle — stop is closed by Close(); done is closed when the goroutine exits.
	// The stop channel is separate from the parent context so that Close() can drain
	// remaining channel entries before shutting down the gRPC stream.
	mu        sync.Mutex
	started   atomic.Bool
	closeOnce sync.Once
	stop      chan struct{} // closed by Close()
	done      chan struct{} // closed when goroutine exits
}

// EventEmitterConfig holds configuration for creating an EventEmitter.
type EventEmitterConfig struct {
	// Client is the gRPC client used to open the LogStream RPC.
	Client transportpb.StewardTransportClient

	// StewardID is stamped into every emitted LogEntry.
	StewardID string

	// Logger receives warnings about send failures and reconnects.
	Logger logging.Logger

	// BufferDepth is the size of the internal entry channel. Defaults to 256.
	BufferDepth int
}

// NewEventEmitter creates an EventEmitter. Call Start to begin the send goroutine.
func NewEventEmitter(cfg EventEmitterConfig) *EventEmitter {
	depth := cfg.BufferDepth
	if depth <= 0 {
		depth = defaultEmitterBufferDepth
	}
	logger := cfg.Logger
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &EventEmitter{
		ch:        make(chan *transportpb.LogEntry, depth),
		client:    cfg.Client,
		stewardID: cfg.StewardID,
		logger:    logger,
		done:      make(chan struct{}),
	}
}

// Start launches the background send goroutine. Subsequent calls are no-ops.
func (e *EventEmitter) Start(ctx context.Context) {
	if !e.started.CompareAndSwap(false, true) {
		return
	}
	stop := make(chan struct{})
	e.mu.Lock()
	e.stop = stop
	e.mu.Unlock()
	go func() {
		defer close(e.done)
		e.sendLoop(ctx, stop)
	}()
}

// Close drains any buffered entries, then signals the send goroutine to stop
// and waits for it to exit. Safe to call before Start or multiple times.
func (e *EventEmitter) Close() {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		stop := e.stop
		e.mu.Unlock()
		if stop == nil {
			return
		}
		close(stop)
		<-e.done
	})
}

// Enqueue adds entry to the send channel. If the channel is full the entry is
// silently dropped and the drop counter is incremented.
func (e *EventEmitter) Enqueue(entry *transportpb.LogEntry) {
	select {
	case e.ch <- entry:
	default:
		e.dropCount.Add(1)
	}
}

// DropCount returns the total number of entries dropped since creation.
func (e *EventEmitter) DropCount() int64 {
	return e.dropCount.Load()
}

// sendLoop opens LogStream RPCs and drains queued entries, reconnecting with
// exponential backoff after any stream error. stop is closed by Close().
func (e *EventEmitter) sendLoop(ctx context.Context, stop <-chan struct{}) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		default:
		}
		if err := e.sendStream(ctx, stop); err != nil {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			default:
			}
			e.logger.Warn("EventEmitter: LogStream send failed, reconnecting",
				"error", err, "attempt", attempt)
			delay := emitterBackoff(attempt)
			attempt++
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-time.After(delay):
			}
			continue
		}
		// sendStream returned nil — stop was signalled; exit cleanly.
		return
	}
}

// sendStream opens one LogStream RPC and drains queued entries until the stop
// channel is closed or a send error occurs. When stop is closed the channel is
// drained fully before CloseAndRecv so no queued entries are silently lost.
// The gRPC stream uses ctx (not stop) so cancellation of the parent context
// still terminates the stream immediately when needed.
func (e *EventEmitter) sendStream(ctx context.Context, stop <-chan struct{}) error {
	stream, err := e.client.LogStream(ctx)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			_, _ = stream.CloseAndRecv()
			return nil
		case <-stop:
			// Drain any remaining buffered entries before closing so entries
			// enqueued just before Close() are not silently dropped.
		drain:
			for {
				select {
				case entry, ok := <-e.ch:
					if !ok {
						break drain
					}
					if sendErr := stream.Send(entry); sendErr != nil {
						// Stream broken; give up on remaining entries.
						break drain
					}
				default:
					break drain
				}
			}
			_, _ = stream.CloseAndRecv()
			return nil
		case entry, ok := <-e.ch:
			if !ok {
				_, _ = stream.CloseAndRecv()
				return nil
			}
			if sendErr := stream.Send(entry); sendErr != nil {
				return sendErr
			}
		}
	}
}

// emitterBackoff returns the exponential backoff delay for the given attempt.
// Capped at 60 s with an overflow guard for large attempt counts.
func emitterBackoff(attempt int) time.Duration {
	const (
		initial = 1 * time.Second
		max     = 60 * time.Second
	)
	d := initial << attempt
	if d > max || d <= 0 { // <= 0 guards against int overflow on large attempts
		return max
	}
	return d
}
