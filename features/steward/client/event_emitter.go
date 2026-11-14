// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/logging"
)

const defaultEmitterBufferDepth = 256

// errNoClient is returned by sendStream when the client source has no client yet.
var errNoClient = errors.New("no transport client available")

// errStreamFlushed is returned by sendStream after it answered a Flush: the
// stream was closed on purpose, so sendLoop opens the next one without back-off.
var errStreamFlushed = errors.New("log stream closed by flush")

// ErrEmitterNotRunning is returned by Flush when the send goroutine is not
// running, so nothing queued can be delivered.
var ErrEmitterNotRunning = errors.New("event emitter is not running")

// flushRequest asks the send goroutine to deliver everything queued and have the
// controller acknowledge it. The goroutine answers on reply.
type flushRequest struct {
	reply chan error
}

// settle answers the request, if there is one.
func (r *flushRequest) settle(err error) {
	if r != nil {
		r.reply <- err
	}
}

// EventEmitter owns a buffered channel of LogEntry values and a background
// goroutine that streams queued entries to the controller via the LogStream RPC.
// Enqueue never blocks the convergence goroutine; when the channel is full the
// entry is dropped and a drop counter is incremented (ADR-012 §2).
//
// EventEmitter satisfies the execution.EventEmitter interface.
type EventEmitter struct {
	ch        chan *transportpb.LogEntry
	dropCount atomic.Int64
	// lostCount counts entries taken off the channel whose delivery the
	// controller did not confirm: a failed send, or a stream that ended with an
	// error after carrying them.
	lostCount atomic.Int64
	flushCh   chan flushRequest

	clientSrc func() transportpb.StewardTransportClient
	stewardID string
	logger    logging.Logger
	onPanic   func(component string)

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
	// ClientSource returns the gRPC client used to open the LogStream RPC. It is
	// called on every stream attempt so the emitter follows the control-plane
	// provider across reconnects. A nil result means no connection is available
	// yet; the emitter backs off without logging a warning.
	ClientSource func() transportpb.StewardTransportClient

	// StewardID is stamped into every emitted LogEntry.
	StewardID string

	// Logger receives warnings about send failures and reconnects.
	Logger logging.Logger

	// BufferDepth is the size of the internal entry channel. Defaults to 256.
	BufferDepth int

	// OnPanic, when non-nil, is called with the component name after the send
	// loop recovered from a panic. The loop then reconnects with back-off.
	OnPanic func(component string)
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
		flushCh:   make(chan flushRequest),
		clientSrc: cfg.ClientSource,
		stewardID: cfg.StewardID,
		logger:    logger,
		onPanic:   cfg.OnPanic,
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

// Lost returns the number of entries that did not reach the controller, counting
// entries dropped on a full buffer and entries whose delivery a failed stream
// left unconfirmed. A caller that must know its entries arrived reads it before
// it enqueues and again after Flush: an increase means some may be missing.
func (e *EventEmitter) Lost() int64 {
	return e.dropCount.Load() + e.lostCount.Load()
}

// Flush delivers every queued entry over a LogStream and returns once the
// controller acknowledged the stream. Unlike Close it does not stop the emitter,
// and it fails instead of dropping entries silently: it returns an error when no
// stream can be opened (no client yet, or the open fails), when a send fails, or
// when ctx ends first. A nil return means the controller received the entries
// queued before the call.
func (e *EventEmitter) Flush(ctx context.Context) error {
	if !e.started.Load() {
		return ErrEmitterNotRunning
	}
	req := flushRequest{reply: make(chan error, 1)}
	select {
	case e.flushCh <- req:
	case <-e.done:
		return ErrEmitterNotRunning
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-req.reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stopped reports whether the emitter's context ended or Close() was called.
func stopped(ctx context.Context, stop <-chan struct{}) bool {
	select {
	case <-ctx.Done():
		return true
	case <-stop:
		return true
	default:
		return false
	}
}

// sendLoop opens LogStream RPCs and drains queued entries, reconnecting with
// exponential backoff after any stream error. stop is closed by Close().
func (e *EventEmitter) sendLoop(ctx context.Context, stop <-chan struct{}) {
	attempt := 0
	// pending is a Flush that arrived while no stream was open. The next stream
	// attempt answers it, so a Flush does not wait out the back-off.
	var pending *flushRequest
	defer func() { pending.settle(ErrEmitterNotRunning) }()
	for {
		if stopped(ctx, stop) {
			return
		}
		req := pending
		pending = nil
		err := recoverToError(e.logger, componentEventEmitter, e.onPanic, func() error {
			return e.sendStream(ctx, stop, req)
		})
		if errors.Is(err, errStreamFlushed) {
			attempt = 0
			continue
		}
		if err == nil {
			// sendStream returned nil — stop was signalled; exit cleanly.
			return
		}
		if stopped(ctx, stop) {
			return
		}
		e.logSendFailure(err, attempt)
		delay := emitterBackoff(attempt)
		attempt++
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case r := <-e.flushCh:
			pending = &r
		case <-time.After(delay):
		}
	}
}

// logSendFailure warns about a failed stream; a missing client is expected
// while the link comes up and is not logged.
func (e *EventEmitter) logSendFailure(err error, attempt int) {
	if errors.Is(err, errNoClient) {
		return
	}
	e.logger.Warn("EventEmitter: LogStream send failed, reconnecting",
		"error", logging.SanitizeLogValue(err.Error()), "attempt", attempt)
}

// emitterStream is one open LogStream RPC. sent counts the entries it carried:
// until CloseAndRecv succeeds the controller has not confirmed them.
type emitterStream struct {
	e      *EventEmitter
	stream transportpb.StewardTransport_LogStreamClient
	sent   int64
}

// send writes one entry, counting the stream's unconfirmed entries as lost on failure.
func (s *emitterStream) send(entry *transportpb.LogEntry) error {
	if err := s.stream.Send(entry); err != nil {
		s.e.lostCount.Add(s.sent + 1)
		return err
	}
	s.sent++
	return nil
}

// drain sends what is queued now.
func (s *emitterStream) drain() error {
	for {
		select {
		case entry, ok := <-s.e.ch:
			if !ok {
				return nil
			}
			if err := s.send(entry); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// finish ends the stream and reports whether the controller acknowledged it.
func (s *emitterStream) finish() error {
	if _, err := s.stream.CloseAndRecv(); err != nil {
		s.e.lostCount.Add(s.sent)
		return err
	}
	return nil
}

// flush answers req: it drains the channel and waits for the controller's
// acknowledgement. It returns errStreamFlushed on success so sendLoop opens the
// next stream without back-off.
func (s *emitterStream) flush(req *flushRequest) error {
	err := s.drain()
	if err != nil {
		// The stream is broken; give up on this stream. Entries still queued
		// stay queued for the next stream.
		_, _ = s.stream.CloseAndRecv()
	} else {
		err = s.finish()
	}
	req.settle(err)
	if err != nil {
		return err
	}
	return errStreamFlushed
}

// sendStream opens one LogStream RPC and drains queued entries until the stop
// channel is closed or a send error occurs. When stop is closed the channel is
// drained fully before CloseAndRecv so no queued entries are silently lost.
// The gRPC stream uses ctx (not stop) so cancellation of the parent context
// still terminates the stream immediately when needed.
//
// pending, when non-nil, is a Flush waiting for a stream: it is answered here
// whether or not a stream opens. A Flush arriving on an open stream drains the
// channel, waits for the controller's acknowledgement and ends the stream with
// errStreamFlushed.
func (e *EventEmitter) sendStream(ctx context.Context, stop <-chan struct{}, pending *flushRequest) error {
	var client transportpb.StewardTransportClient
	if e.clientSrc != nil {
		client = e.clientSrc()
	}
	if client == nil {
		pending.settle(errNoClient)
		return errNoClient
	}
	stream, err := client.LogStream(ctx)
	if err != nil {
		pending.settle(err)
		return err
	}
	s := &emitterStream{e: e, stream: stream}
	if pending != nil {
		return s.flush(pending)
	}
	for {
		select {
		case <-ctx.Done():
			_, _ = stream.CloseAndRecv()
			return nil
		case req := <-e.flushCh:
			return s.flush(&req)
		case <-stop:
			// Drain any remaining buffered entries before closing so entries
			// enqueued just before Close() are not silently dropped. A stream
			// broken while draining gives up on the remaining entries.
			_ = s.drain()
			_ = s.finish()
			return nil
		case entry, ok := <-e.ch:
			if !ok {
				_, _ = stream.CloseAndRecv()
				return nil
			}
			if sendErr := s.send(entry); sendErr != nil {
				return sendErr
			}
		}
	}
}

// LogLoss returns how many entries the client's event emitter has lost (see
// EventEmitter.Lost); 0 when the link has no emitter.
func (c *TransportClient) LogLoss() int64 {
	c.mu.RLock()
	e := c.eventEmitter
	c.mu.RUnlock()
	if e == nil {
		return 0
	}
	return e.Lost()
}

// FlushLogs delivers every log entry queued by EnqueueLog and returns once the
// controller acknowledged them, or an error when it cannot be confirmed (the
// link has no emitter, no stream could be opened, a send failed, or ctx ended).
// A caller that must not proceed until its entries left the host checks it.
func (c *TransportClient) FlushLogs(ctx context.Context) error {
	c.mu.RLock()
	e := c.eventEmitter
	c.mu.RUnlock()
	if e == nil {
		return ErrEmitterNotRunning
	}
	return e.Flush(ctx)
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
