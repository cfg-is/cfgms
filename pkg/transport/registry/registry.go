// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package registry

import (
	"errors"
	"sync"
)

// Registry manages active steward connections.
//
// All methods are safe for concurrent use from multiple goroutines.
type Registry interface {
	// Register adds or replaces a steward connection.
	//
	// If a connection for this stewardID already exists, it is replaced.
	// The old connection is NOT closed — the caller is responsible for cleanup.
	// Returns an error if conn is nil or conn.StewardID is empty, or if
	// conn.Sender is nil.
	Register(conn *StewardConnection) error

	// Unregister removes a steward connection.
	//
	// No-op if stewardID is not registered. Removes whatever connection is
	// currently registered for stewardID — use UnregisterConn from a stream
	// handler's cleanup path to avoid evicting a newer reconnected connection.
	Unregister(stewardID string)

	// UnregisterConn removes a steward connection only if it is still the
	// connection currently registered for its stewardID.
	//
	// This is the reconnect-safe cleanup path: when a steward restarts, the
	// stale stream handler's deferred cleanup must not evict the live
	// connection that the reconnected steward just registered. No-op if conn
	// is nil or has been superseded by a newer Register call.
	UnregisterConn(conn *StewardConnection)

	// Get returns a single steward's connection.
	//
	// Returns the connection and true if found, nil and false if not registered.
	Get(stewardID string) (*StewardConnection, bool)

	// GetMany returns connections for a list of steward IDs.
	//
	// Only connected stewards are included in the result map.
	// Missing or disconnected stewards are silently absent.
	GetMany(stewardIDs []string) map[string]*StewardConnection

	// GetAll returns a snapshot of all registered connections.
	//
	// The returned map is a copy — safe to iterate without holding locks.
	// Modifications to the returned map do not affect the registry.
	GetAll() map[string]*StewardConnection

	// Count returns the number of registered connections.
	Count() int

	// OnConnect registers a callback fired when a steward connects.
	//
	// The callback receives the steward ID. Multiple callbacks may be
	// registered and all are fired. Callbacks fire in goroutines to
	// prevent slow callbacks from blocking registry operations.
	OnConnect(fn func(stewardID string))

	// OnDisconnect registers a callback fired when a steward is unregistered.
	//
	// The callback receives the steward ID. Multiple callbacks may be
	// registered and all are fired. Callbacks fire in goroutines to
	// prevent slow callbacks from blocking registry operations.
	OnDisconnect(fn func(stewardID string))
}

// InMemoryRegistry is the default Registry implementation.
//
// It uses a sync.RWMutex to allow concurrent reads with exclusive writes.
// All public methods are safe for concurrent use.
type InMemoryRegistry struct {
	mu                sync.RWMutex
	connections       map[string]*StewardConnection
	onConnectHooks    []func(string)
	onDisconnectHooks []func(string)
}

// NewRegistry creates a new InMemoryRegistry ready for use.
func NewRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{
		connections:       make(map[string]*StewardConnection),
		onConnectHooks:    nil,
		onDisconnectHooks: nil,
	}
}

// Register adds or replaces a steward connection.
//
// Returns an error if conn is nil, conn.StewardID is empty, or conn.Sender is nil.
// On success, fires all registered OnConnect hooks in separate goroutines.
func (r *InMemoryRegistry) Register(conn *StewardConnection) error {
	if conn == nil {
		return errors.New("registry: connection must not be nil")
	}
	if conn.StewardID == "" {
		return errors.New("registry: connection StewardID must not be empty")
	}
	if conn.Sender == nil {
		return errors.New("registry: connection Sender must not be nil")
	}

	r.mu.Lock()
	r.connections[conn.StewardID] = conn
	hooks := r.onConnectHooks
	r.mu.Unlock()

	stewardID := conn.StewardID
	for _, fn := range hooks {
		fn := fn
		go func() {
			defer func() { recover() }() //nolint:errcheck // panic value intentionally discarded; no logger available in InMemoryRegistry yet
			fn(stewardID)
		}()
	}

	return nil
}

// Unregister removes a steward connection.
//
// No-op if stewardID is not registered. On removal, fires all registered
// OnDisconnect hooks in separate goroutines.
func (r *InMemoryRegistry) Unregister(stewardID string) {
	r.mu.Lock()
	_, exists := r.connections[stewardID]
	if exists {
		delete(r.connections, stewardID)
	}
	hooks := r.onDisconnectHooks
	r.mu.Unlock()

	r.fireDisconnectHooks(exists, stewardID, hooks)
}

// UnregisterConn removes conn only if it is still the connection currently
// registered for conn.StewardID.
//
// A steward restart races a stale stream handler against the reconnected
// steward: the new connection registers first, then the old handler's
// deferred cleanup runs. An ID-keyed Unregister would delete the live new
// connection. UnregisterConn compares pointer identity so the stale cleanup
// becomes a no-op once the connection has been superseded. On removal, fires
// all registered OnDisconnect hooks in separate goroutines.
func (r *InMemoryRegistry) UnregisterConn(conn *StewardConnection) {
	if conn == nil {
		return
	}

	r.mu.Lock()
	current, exists := r.connections[conn.StewardID]
	removed := exists && current == conn
	if removed {
		delete(r.connections, conn.StewardID)
	}
	hooks := r.onDisconnectHooks
	r.mu.Unlock()

	r.fireDisconnectHooks(removed, conn.StewardID, hooks)
}

// fireDisconnectHooks runs each OnDisconnect hook in its own goroutine when a
// connection was actually removed.
func (r *InMemoryRegistry) fireDisconnectHooks(removed bool, stewardID string, hooks []func(string)) {
	if !removed {
		return
	}
	for _, fn := range hooks {
		fn := fn
		go func() {
			defer func() { recover() }() //nolint:errcheck // panic value intentionally discarded; no logger available in InMemoryRegistry yet
			fn(stewardID)
		}()
	}
}

// Get returns a single steward's connection.
//
// Returns the connection and true if found, nil and false otherwise.
func (r *InMemoryRegistry) Get(stewardID string) (*StewardConnection, bool) {
	r.mu.RLock()
	conn, ok := r.connections[stewardID]
	r.mu.RUnlock()
	return conn, ok
}

// GetMany returns connections for a list of steward IDs.
//
// Only stewards that are currently registered appear in the result map.
// Takes a single read lock for the entire operation — O(n) in requested list size.
func (r *InMemoryRegistry) GetMany(stewardIDs []string) map[string]*StewardConnection {
	result := make(map[string]*StewardConnection, len(stewardIDs))

	r.mu.RLock()
	for _, id := range stewardIDs {
		if conn, ok := r.connections[id]; ok {
			result[id] = conn
		}
	}
	r.mu.RUnlock()

	return result
}

// GetAll returns a snapshot copy of all registered connections.
//
// The returned map is safe to iterate and modify without affecting the registry.
func (r *InMemoryRegistry) GetAll() map[string]*StewardConnection {
	r.mu.RLock()
	result := make(map[string]*StewardConnection, len(r.connections))
	for k, v := range r.connections {
		result[k] = v
	}
	r.mu.RUnlock()
	return result
}

// Count returns the number of registered connections.
func (r *InMemoryRegistry) Count() int {
	r.mu.RLock()
	n := len(r.connections)
	r.mu.RUnlock()
	return n
}

// OnConnect registers a callback fired when a steward connects.
//
// Callbacks are called in separate goroutines so slow callbacks do not
// block registry operations. Multiple callbacks may be registered.
func (r *InMemoryRegistry) OnConnect(fn func(stewardID string)) {
	r.mu.Lock()
	r.onConnectHooks = append(r.onConnectHooks, fn)
	r.mu.Unlock()
}

// OnDisconnect registers a callback fired when a steward is unregistered.
//
// Callbacks are called in separate goroutines so slow callbacks do not
// block registry operations. Multiple callbacks may be registered.
func (r *InMemoryRegistry) OnDisconnect(fn func(stewardID string)) {
	r.mu.Lock()
	r.onDisconnectHooks = append(r.onDisconnectHooks, fn)
	r.mu.Unlock()
}
