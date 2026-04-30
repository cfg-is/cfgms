// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package saas multitenant_store defines the ConsentStore interface for persisting
// and retrieving admin-consent state, and provides InMemoryConsentStore as the
// pre-production implementation used until a durable store is wired up.
package saas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
)

// ConsentStore persists and retrieves admin-consent state for a provider.
// Implementations must preserve all fields of ConsentStatus, including the
// AccessibleTenants slice and the nested ConsentFlow pointer.
type ConsentStore interface {
	// StoreConsent persists the consent status for the given provider, replacing
	// any previously stored value.
	StoreConsent(provider string, status *ConsentStatus) error

	// GetConsent retrieves the consent status for the given provider.
	// Returns (nil, nil) when no entry exists — callers must handle the nil case.
	GetConsent(provider string) (*ConsentStatus, error)

	// DeleteConsent removes the consent status for the given provider.
	// It is idempotent: deleting a non-existent entry returns nil.
	DeleteConsent(provider string) error
}

// InMemoryConsentStore is the pre-production ConsentStore implementation.
// It serialises each ConsentStatus to JSON before storing, which enforces the
// same round-trip fidelity that a durable store would require and allows the
// contract test to catch field loss early.
//
// The zero value is ready to use; NewInMemoryConsentStore is provided for
// explicit initialisation.
type InMemoryConsentStore struct {
	mu   sync.RWMutex
	data map[string][]byte // JSON-encoded ConsentStatus per provider
}

// NewInMemoryConsentStore returns an initialised InMemoryConsentStore.
func NewInMemoryConsentStore() *InMemoryConsentStore {
	return &InMemoryConsentStore{
		data: make(map[string][]byte),
	}
}

// StoreConsent serialises status to JSON and stores it under provider.
func (s *InMemoryConsentStore) StoreConsent(provider string, status *ConsentStatus) error {
	encoded, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("consent store: failed to serialise status for %q: %w", provider, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		s.data = make(map[string][]byte)
	}
	s.data[provider] = encoded
	return nil
}

// GetConsent deserialises and returns the stored ConsentStatus for provider.
// Returns (nil, nil) when no entry exists.
// Returns an error — with message "re-grant admin consent" — when the stored
// bytes are in the pre-#954 flat-string format or are otherwise unparseable.
// No attempt is made to parse old-format data; callers must trigger a fresh
// consent flow.
func (s *InMemoryConsentStore) GetConsent(provider string) (*ConsentStatus, error) {
	s.mu.RLock()
	encoded, ok := s.data[provider]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}

	// Reject the pre-#954 flat-string format (e.g. "consent_granted:true;tenants:1").
	// These bytes will never be written by StoreConsent, but can appear when tests
	// or future migration code inject raw data directly.
	if bytes.Contains(encoded, []byte("consent_granted:")) {
		return nil, fmt.Errorf("consent store: unrecognised format — re-grant admin consent")
	}

	var status ConsentStatus
	if err := json.Unmarshal(encoded, &status); err != nil {
		return nil, fmt.Errorf("consent store: unrecognised format — re-grant admin consent")
	}
	return &status, nil
}

// DeleteConsent removes the stored consent status for provider.
// It is idempotent.
func (s *InMemoryConsentStore) DeleteConsent(provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, provider)
	return nil
}
