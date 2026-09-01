// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.NonceStore = (*FlatFileNonceStore)(nil)

// FlatFileNonceStore implements business.NonceStore backed by a single JSON file.
//
// File layout: <root>/nonces/refresh_nonces.json
//
// Writes are atomic (temp-file + rename). sync.Mutex serialises PutNonce and
// GetAndConsumeNonce within one process, which is sufficient here because the
// flatfile provider only ever backs a single-node deployment (ADR-003) — there
// is no cross-process concurrency to arbitrate.
type FlatFileNonceStore struct {
	root string
	mu   sync.Mutex
}

// nonceEntryJSON is the on-disk representation of one nonce entry.
type nonceEntryJSON struct {
	Key       string    `json:"key"`
	Entry     []byte    `json:"entry"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewFlatFileNonceStore creates a FlatFileNonceStore rooted at <root>/nonces.
// The directory is created if it does not exist.
func NewFlatFileNonceStore(root string) (*FlatFileNonceStore, error) {
	dir := filepath.Join(root, "nonces")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create nonces directory: %w", err)
	}
	return &FlatFileNonceStore{root: root}, nil
}

func (s *FlatFileNonceStore) dataFilePath() string {
	return filepath.Join(s.root, "nonces", "refresh_nonces.json")
}

// load reads and parses the refresh_nonces.json file.
// Returns nil slice when the file does not exist.
// Must be called with s.mu held.
func (s *FlatFileNonceStore) load() ([]nonceEntryJSON, error) {
	raw, err := readFile(s.dataFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read nonce file: %w", err)
	}
	var entries []nonceEntryJSON
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("flatfile: failed to parse nonce file: %w", err)
	}
	return entries, nil
}

// save atomically writes entries to refresh_nonces.json.
// Must be called with s.mu held.
func (s *FlatFileNonceStore) save(entries []nonceEntryJSON) error {
	if entries == nil {
		entries = []nonceEntryJSON{}
	}
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal nonce entries: %w", err)
	}
	return writeAtomic(s.dataFilePath(), raw)
}

// PutNonce implements business.NonceStore.PutNonce.
func (s *FlatFileNonceStore) PutNonce(_ context.Context, key string, entry []byte, ttl time.Duration) error {
	if key == "" {
		return fmt.Errorf("flatfile: nonce key cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return err
	}

	expiresAt := time.Now().UTC().Add(ttl)
	for i, e := range entries {
		if e.Key == key {
			entries[i].Entry = entry
			entries[i].ExpiresAt = expiresAt
			return s.save(entries)
		}
	}
	entries = append(entries, nonceEntryJSON{Key: key, Entry: entry, ExpiresAt: expiresAt})
	return s.save(entries)
}

// GetAndConsumeNonce implements business.NonceStore.GetAndConsumeNonce.
// The load-mutate-save cycle runs under s.mu, making the read-then-delete
// atomic against other goroutines in this process.
func (s *FlatFileNonceStore) GetAndConsumeNonce(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return nil, false, err
	}

	now := time.Now().UTC()
	for i, e := range entries {
		if e.Key != key {
			continue
		}
		remaining := append(append([]nonceEntryJSON{}, entries[:i]...), entries[i+1:]...)
		if err := s.save(remaining); err != nil {
			return nil, false, err
		}
		if now.After(e.ExpiresAt) {
			return nil, false, nil
		}
		return e.Entry, true, nil
	}
	return nil, false, nil
}
