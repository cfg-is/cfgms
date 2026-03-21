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

	// TenantPath is the tenant path for this steward (e.g. "root/msp-a/client-1").
	// Informational only — the registry does not use this for routing.
	TenantPath string

	// Sender is the underlying transport stream.
	Sender MessageSender

	// ConnectedAt records when this connection was registered.
	ConnectedAt time.Time

	// LastActivity records the most recent send or received activity.
	LastActivity time.Time

	// RemoteAddr is the network address of the connected steward.
	RemoteAddr string

	// mu serializes writes to Sender.
	mu sync.Mutex
}

// Send writes a message to this steward's connection.
//
// Send is thread-safe — concurrent callers are serialized via an internal
// mutex. LastActivity is updated on every successful or failed send attempt.
func (c *StewardConnection) Send(msg interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastActivity = time.Now()
	return c.Sender.SendMsg(msg)
}

// UpdateActivity records the current time as the most recent activity.
//
// Call this when a message is received from the steward to keep the
// LastActivity timestamp current for health monitoring purposes.
func (c *StewardConnection) UpdateActivity() {
	c.mu.Lock()
	c.LastActivity = time.Now()
	c.mu.Unlock()
}
