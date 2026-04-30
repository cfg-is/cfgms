// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package registry

import (
	"sync"
	"time"
)

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

	// lastActivity records the most recent send or received activity.
	// Access via GetLastActivity() for thread-safe reads.
	lastActivity time.Time

	// RemoteAddr is the network address of the connected steward.
	RemoteAddr string

	// mu serializes writes to Sender and lastActivity.
	mu sync.Mutex
}

// Send writes a message to this steward's connection.
//
// Send is thread-safe — concurrent callers are serialized via an internal
// mutex. lastActivity is updated on every successful or failed send attempt.
func (c *StewardConnection) Send(msg interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastActivity = time.Now()
	return c.Sender.SendMsg(msg)
}

// UpdateActivity records the current time as the most recent activity.
//
// Call this when a message is received from the steward to keep the
// activity timestamp current for health monitoring purposes.
func (c *StewardConnection) UpdateActivity() {
	c.mu.Lock()
	c.lastActivity = time.Now()
	c.mu.Unlock()
}

// GetLastActivity returns the most recent activity timestamp.
//
// Thread-safe — acquires the internal mutex to read the timestamp
// that is written by Send() and UpdateActivity().
// This is a monitoring hook for future use (e.g. idle-connection reaping);
// it is not called in production today.
func (c *StewardConnection) GetLastActivity() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastActivity
}
