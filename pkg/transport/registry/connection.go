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

	// ConnectionID identifies this one connection (stream), as opposed to the
	// steward: a reconnect gets a new ID. Durable capability writes are keyed to
	// it so a late write from an old stream cannot overwrite a newer connection's
	// record. Set by the stream handler before the connection is registered.
	ConnectionID string

	// SendStallTimeout bounds a Send and the wait to start one. A Send that
	// exceeds it evicts the connection (see Send). Zero means
	// DefaultSendStallTimeout.
	SendStallTimeout time.Duration

	// slot serializes writes to Sender: a Send holds it while the stream
	// accepts the message. It is created on first use so the zero value works.
	slotOnce sync.Once
	slot     chan struct{}

	// capMu guards the capability state below. The zero value is the pending
	// state with an open settled signal.
	capMu           sync.Mutex
	capState        string
	capCommandTypes []int32
	capVersions     []uint32
	capSettled      chan struct{}
	capDurableLost  bool
}

// Capability states of a connection. They match the values of the control-plane
// types and of the durable record; the registry holds plain strings so it stays
// free of other CFGMS packages.
const (
	CapabilityPending  = "pending"
	CapabilityDeclared = "declared"
	CapabilityFloor    = "floor"
)

// CapabilitySnapshot is a copy of a connection's capability state.
type CapabilitySnapshot struct {
	// State is CapabilityPending, CapabilityDeclared or CapabilityFloor.
	State string
	// CommandTypes and SigningPayloadVersions are set for declared and floor.
	CommandTypes           []int32
	SigningPayloadVersions []uint32
}

// settledLocked returns the settled channel, creating it on first use.
// Caller holds capMu.
func (c *StewardConnection) settledLocked() chan struct{} {
	if c.capSettled == nil {
		c.capSettled = make(chan struct{})
	}
	return c.capSettled
}

// CapabilitiesSettled returns a channel that is closed once the connection's
// capability state leaves pending: on the steward's first declaration, or when
// the grace period ends without one. It is closed at most once and stays closed.
func (c *StewardConnection) CapabilitiesSettled() <-chan struct{} {
	c.capMu.Lock()
	defer c.capMu.Unlock()
	return c.settledLocked()
}

// CapabilitySnapshot returns the connection's current capability state. A
// connection that has not settled reports CapabilityPending.
func (c *StewardConnection) CapabilitySnapshot() CapabilitySnapshot {
	c.capMu.Lock()
	defer c.capMu.Unlock()
	state := c.capState
	if state == "" {
		state = CapabilityPending
	}
	return CapabilitySnapshot{
		State:                  state,
		CommandTypes:           append([]int32(nil), c.capCommandTypes...),
		SigningPayloadVersions: append([]uint32(nil), c.capVersions...),
	}
}

// SettleCapabilities moves the connection to state with the given sets and
// releases the settled signal. Allowed moves are pending to declared, pending to
// floor, and floor to declared (a declaration that arrives after the grace
// period); any other request leaves the state unchanged, so a connection's first
// declaration is final. changed reports whether the state moved, and late
// whether it moved from floor.
func (c *StewardConnection) SettleCapabilities(state string, commandTypes []int32, versions []uint32) (changed, late bool) {
	c.capMu.Lock()
	defer c.capMu.Unlock()

	cur := c.capState
	if cur == "" {
		cur = CapabilityPending
	}
	switch {
	case state == CapabilityDeclared && (cur == CapabilityPending || cur == CapabilityFloor):
	case state == CapabilityFloor && cur == CapabilityPending:
	default:
		return false, false
	}

	c.capState = state
	c.capCommandTypes = append([]int32(nil), commandTypes...)
	c.capVersions = append([]uint32(nil), versions...)
	if cur == CapabilityPending {
		close(c.settledLocked())
	}
	return true, cur == CapabilityFloor
}

// MarkCapabilityDurableLost records that the durable reset for this connection
// failed, so the stored record does not belong to it and must never be read as
// this connection's profile.
func (c *StewardConnection) MarkCapabilityDurableLost() {
	c.capMu.Lock()
	c.capDurableLost = true
	c.capMu.Unlock()
}

// CapabilityDurableLost reports whether the durable reset for this connection
// failed.
func (c *StewardConnection) CapabilityDurableLost() bool {
	c.capMu.Lock()
	defer c.capMu.Unlock()
	return c.capDurableLost
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
