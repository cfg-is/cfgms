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
var _ business.RoutingStore = (*FlatFileRoutingStore)(nil)

// FlatFileRoutingStore implements business.RoutingStore backed by a single
// JSON file — a single-node mirror of the shared steward-routing table
// (ADR-031 Decision 3, Issue #3764) for non-clustered deployment shapes.
//
// File layout: <root>/routing/routing.json, a JSON object keyed by steward ID.
// Writes are atomic (temp-file + rename). sync.RWMutex serializes goroutine
// access within one process.
//
// A single-node deployment has only one controller node, so LookupNode here
// only ever finds records this same process wrote — a peer lookup for a
// steward connected elsewhere is structurally impossible on this substrate,
// mirroring FlatFileLeaseStore's non-shared nature.
type FlatFileRoutingStore struct {
	root string
	mu   sync.RWMutex
}

// routingEntryJSON is the on-disk representation of a routing row.
type routingEntryJSON struct {
	NodeID    string    `json:"node_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewFlatFileRoutingStore creates a FlatFileRoutingStore rooted at
// <root>/routing. The directory is created if it does not exist.
func NewFlatFileRoutingStore(root string) (*FlatFileRoutingStore, error) {
	dir := filepath.Join(root, "routing")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create routing directory: %w", err)
	}
	return &FlatFileRoutingStore{root: root}, nil
}

// Close is a no-op; the store holds no persistent handles.
func (s *FlatFileRoutingStore) Close() error { return nil }

func (s *FlatFileRoutingStore) dataFilePath() string {
	return filepath.Join(s.root, "routing", "routing.json")
}

// load reads and parses routing.json. Returns an empty (non-nil) map when the
// file does not exist. Must be called with at least a read lock held.
func (s *FlatFileRoutingStore) load() (map[string]routingEntryJSON, error) {
	raw, err := readFile(s.dataFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]routingEntryJSON{}, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read routing file: %w", err)
	}
	entries := map[string]routingEntryJSON{}
	if len(raw) == 0 {
		return entries, nil
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("flatfile: failed to parse routing file: %w", err)
	}
	return entries, nil
}

// save atomically writes entries to routing.json. Must be called with the
// write lock held.
func (s *FlatFileRoutingStore) save(entries map[string]routingEntryJSON) error {
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal routing entries: %w", err)
	}
	return writeAtomic(s.dataFilePath(), raw)
}

// RecordConnection implements business.RoutingStore.RecordConnection.
func (s *FlatFileRoutingStore) RecordConnection(_ context.Context, stewardID, nodeID string) error {
	if stewardID == "" {
		return fmt.Errorf("flatfile: steward id cannot be empty")
	}
	if nodeID == "" {
		return fmt.Errorf("flatfile: node id cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return err
	}
	entries[stewardID] = routingEntryJSON{NodeID: nodeID, UpdatedAt: time.Now()}
	return s.save(entries)
}

// LookupNode implements business.RoutingStore.LookupNode. Staleness is
// evaluated against this process's own clock — the same clock that wrote
// UpdatedAt — so no cross-host offset can enter the decision.
func (s *FlatFileRoutingStore) LookupNode(_ context.Context, stewardID string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := s.load()
	if err != nil {
		return "", false, err
	}
	entry, exists := entries[stewardID]
	if !exists {
		return "", false, nil
	}
	if time.Since(entry.UpdatedAt) > business.RoutingStaleAfter {
		return "", false, nil
	}
	return entry.NodeID, true, nil
}

// RemoveConnection implements business.RoutingStore.RemoveConnection. The
// nodeID predicate makes this safe against a late-arriving disconnect from a
// node that lost a reconnect race: only a record still attributed to nodeID
// is removed.
func (s *FlatFileRoutingStore) RemoveConnection(_ context.Context, stewardID, nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return err
	}
	if existing, exists := entries[stewardID]; !exists || existing.NodeID != nodeID {
		return nil
	}
	delete(entries, stewardID)
	return s.save(entries)
}
