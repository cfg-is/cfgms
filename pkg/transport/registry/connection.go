// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package registry

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultSendStallTimeout is how long a Send may take, or wait behind another
// Send, before the connection is judged stalled and evicted. It is far above the
// time a healthy stream needs to accept one control message, and far below the
// transport's idle timeout, which is how long a dead peer would otherwise be
// kept registered.
const DefaultSendStallTimeout = 30 * time.Second

// ErrSendStalled is returned by Send when the stream did not accept a message
// within the stall timeout, and is the error the connection is evicted with.
var ErrSendStalled = errors.New("registry: send to steward stalled")

// MessageSender is the minimal interface a connection must satisfy.
//
// This keeps the registry transport-agnostic — gRPC streams, WebSocket
// connections, or any bidirectional channel can implement this.
// The registry serializes concurrent writes via StewardConnection.Send().
type MessageSender interface {
	// SendMsg writes a message to the peer.
	// Implementations must be thread-safe or the caller must serialize.
	// The registry serializes via StewardConnection.Send().
	SendMsg(msg interface{}) error
}

// StewardConnection represents an active steward connection in the registry.
//
// StewardConnection wraps a MessageSender with metadata about the connection
// and serializes concurrent writes to the underlying sender.
type StewardConnection struct {
	// StewardID is the unique identifier for this steward.
	StewardID string

	// Sender is the underlying transport stream.
	Sender MessageSender

	// ConnectedAt records when this connection was registered.
	ConnectedAt time.Time

	// lastActivity records the most recent send or received activity as Unix
	// nanoseconds. It is atomic, not guarded by the send slot, so that recording
	// a received message never waits on a Send. Access via GetLastActivity().
	lastActivity atomic.Int64

	// RemoteAddr is the network address of the connected steward.
	RemoteAddr string

	// PeerSerial is the serial number of the client certificate the steward
	// presented on this connection. Empty when it could not be read. It lets a
	// later connection for the same steward ID be compared against this one.
	PeerSerial string

	// Evict ends this connection's stream with the given error. It is set by the
	// stream handler that owns the connection, and is how a newer connection
	// for the same steward ID displaces it (ADR-034 §2). Nil when the
	// connection cannot be evicted. Safe to call more than once.
	Evict func(error)

	// SendStallTimeout bounds a Send and the wait to start one. A Send that
	// exceeds it evicts the connection (see Send). Zero means
	// DefaultSendStallTimeout.
	SendStallTimeout time.Duration

	// slot serializes writes to Sender: a Send holds it while the stream
	// accepts the message. It is created on first use so the zero value works.
	slotOnce sync.Once
	slot     chan struct{}
}

func (c *StewardConnection) sendSlot() chan struct{} {
	c.slotOnce.Do(func() { c.slot = make(chan struct{}, 1) })
	return c.slot
}

func (c *StewardConnection) stallTimeout() time.Duration {
	if c.SendStallTimeout > 0 {
		return c.SendStallTimeout
	}
	return DefaultSendStallTimeout
}

// Send writes a message to this steward's connection.
//
// Send is thread-safe — concurrent callers are serialized. lastActivity is
// updated on every send attempt.
//
// A stream whose peer has stopped reading blocks SendMsg indefinitely, and every
// later Send would queue behind it. So Send is bounded by SendStallTimeout: a
// Send that cannot start in that time returns ErrSendStalled, and a SendMsg that
// does not return in that time evicts the connection with ErrSendStalled, which
// makes the stream handler end the stream and unblock it.
func (c *StewardConnection) Send(msg interface{}) error {
	slot := c.sendSlot()
	timeout := c.stallTimeout()

	wait := time.NewTimer(timeout)
	select {
	case slot <- struct{}{}:
		wait.Stop()
	case <-wait.C:
		c.evictStalled()
		return ErrSendStalled
	}
	defer func() { <-slot }()

	watchdog := time.AfterFunc(timeout, c.evictStalled)
	defer watchdog.Stop()

	c.touch()
	return c.Sender.SendMsg(msg)
}

// evictStalled ends the connection's stream; a no-op when it cannot be evicted.
func (c *StewardConnection) evictStalled() {
	if c.Evict != nil {
		c.Evict(ErrSendStalled)
	}
}

func (c *StewardConnection) touch() {
	c.lastActivity.Store(time.Now().UnixNano())
}

// UpdateActivity records the current time as the most recent activity.
//
// Call this when a message is received from the steward to keep the
// activity timestamp current for health monitoring purposes. It never waits on
// a Send.
func (c *StewardConnection) UpdateActivity() {
	c.touch()
}

// GetLastActivity returns the most recent activity timestamp, or the zero time
// when there has been none.
//
// Thread-safe. This is a monitoring hook for future use (e.g. idle-connection
// reaping); it is not called in production today.
func (c *StewardConnection) GetLastActivity() time.Time {
	ns := c.lastActivity.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}
