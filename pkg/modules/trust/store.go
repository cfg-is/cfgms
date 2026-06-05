// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust

import (
	"bytes"
	"sync"
)

// algorithmEd25519 is the only signing algorithm supported by v1 bundles.
const algorithmEd25519 = "ed25519"

// PublisherIdentity represents a trusted module publisher identified by name and
// their raw Ed25519 public key.
type PublisherIdentity struct {
	// Name is the human-readable publisher identifier (e.g. "cfgms").
	Name string
	// PublicKey is the raw 32-byte Ed25519 public key.
	PublicKey []byte
	// Algorithm is always "ed25519" for v1 bundles.
	Algorithm string
}

// TrustStore is the interface for managing trusted publisher identities.
// The default implementation is InMemoryTrustStore; durable persistence is a
// controller (S5) and steward (S7) concern handled in later stories.
type TrustStore interface {
	// AddPublisher registers a publisher identity as trusted.
	AddPublisher(PublisherIdentity) error
	// GetPublisher returns the identity for the named publisher, if known.
	GetPublisher(name string) (PublisherIdentity, bool)
	// ListPublishers returns all registered publisher identities.
	ListPublishers() []PublisherIdentity
	// IsTrusted reports whether the named publisher with the given public key is trusted.
	IsTrusted(name string, pubKey []byte) bool
}

// InMemoryTrustStore is a thread-safe, non-persistent TrustStore implementation
// suitable for use in tests and at startup before durable state is loaded.
type InMemoryTrustStore struct {
	mu         sync.RWMutex
	publishers map[string]PublisherIdentity
}

// NewInMemoryTrustStore creates an empty InMemoryTrustStore.
func NewInMemoryTrustStore() *InMemoryTrustStore {
	return &InMemoryTrustStore{
		publishers: make(map[string]PublisherIdentity),
	}
}

// AddPublisher registers the identity as trusted. Overwrites any existing
// entry for the same publisher name.
func (s *InMemoryTrustStore) AddPublisher(id PublisherIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publishers[id.Name] = id
	return nil
}

// GetPublisher returns the identity registered under name, if any.
func (s *InMemoryTrustStore) GetPublisher(name string) (PublisherIdentity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.publishers[name]
	return id, ok
}

// ListPublishers returns a snapshot of all registered identities.
func (s *InMemoryTrustStore) ListPublishers() []PublisherIdentity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PublisherIdentity, 0, len(s.publishers))
	for _, id := range s.publishers {
		out = append(out, id)
	}
	return out
}

// IsTrusted reports whether the publisher is registered and the stored public key
// matches pubKey exactly.
func (s *InMemoryTrustStore) IsTrusted(name string, pubKey []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.publishers[name]
	if !ok {
		return false
	}
	return bytes.Equal(id.PublicKey, pubKey)
}
