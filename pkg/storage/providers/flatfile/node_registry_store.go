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
var _ business.NodeRegistryStore = (*FlatFileNodeRegistryStore)(nil)

// FlatFileNodeRegistryStore implements business.NodeRegistryStore backed by
// a single JSON file — a single-node mirror of the shared controller-node
// registry (Issue #3763, ADR-031 Decision 5's post-Raft membership
// mechanism) for non-clustered deployment shapes and tests.
//
// File layout: <root>/node_registry/node_registry.json, a JSON object keyed
// by node ID. Writes are atomic (temp-file + rename). sync.RWMutex
// serializes goroutine access within one process.
type FlatFileNodeRegistryStore struct {
	root string
	mu   sync.RWMutex
}

// nodeRegistryEntryJSON is the on-disk representation of a node registry row.
type nodeRegistryEntryJSON struct {
	Address   string    `json:"address"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewFlatFileNodeRegistryStore creates a FlatFileNodeRegistryStore rooted at
// <root>/node_registry. The directory is created if it does not exist.
func NewFlatFileNodeRegistryStore(root string) (*FlatFileNodeRegistryStore, error) {
	dir := filepath.Join(root, "node_registry")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create node registry directory: %w", err)
	}
	return &FlatFileNodeRegistryStore{root: root}, nil
}

// Close is a no-op; the store holds no persistent handles.
func (s *FlatFileNodeRegistryStore) Close() error { return nil }

func (s *FlatFileNodeRegistryStore) dataFilePath() string {
	return filepath.Join(s.root, "node_registry", "node_registry.json")
}

// load reads and parses node_registry.json. Returns an empty (non-nil) map
// when the file does not exist. Must be called with at least a read lock
// held.
func (s *FlatFileNodeRegistryStore) load() (map[string]nodeRegistryEntryJSON, error) {
	raw, err := readFile(s.dataFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]nodeRegistryEntryJSON{}, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read node registry file: %w", err)
	}
	entries := map[string]nodeRegistryEntryJSON{}
	if len(raw) == 0 {
		return entries, nil
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("flatfile: failed to parse node registry file: %w", err)
	}
	return entries, nil
}

// save atomically writes entries to node_registry.json. Must be called with
// the write lock held.
func (s *FlatFileNodeRegistryStore) save(entries map[string]nodeRegistryEntryJSON) error {
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal node registry entries: %w", err)
	}
	return writeAtomic(s.dataFilePath(), raw)
}

// RegisterNode implements business.NodeRegistryStore.RegisterNode.
func (s *FlatFileNodeRegistryStore) RegisterNode(_ context.Context, self business.NodeRecord) error {
	if self.ID == "" {
		return fmt.Errorf("flatfile: node id cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return err
	}
	entries[self.ID] = nodeRegistryEntryJSON{Address: self.Address, UpdatedAt: time.Now()}
	return s.save(entries)
}

// ListNodes implements business.NodeRegistryStore.ListNodes. Staleness is
// evaluated against this process's own clock — the same clock that wrote
// UpdatedAt — so no cross-host offset can enter the decision.
func (s *FlatFileNodeRegistryStore) ListNodes(_ context.Context) ([]business.NodeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := s.load()
	if err != nil {
		return nil, err
	}

	var records []business.NodeRecord
	for id, entry := range entries {
		if time.Since(entry.UpdatedAt) > business.NodeRegistryStaleAfter {
			continue
		}
		records = append(records, business.NodeRecord{ID: id, Address: entry.Address})
	}
	return records, nil
}
