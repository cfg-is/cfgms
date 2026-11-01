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

// Compile-time assertions.
var (
	_ business.LeaseStore           = (*FlatFileLeaseStore)(nil)
	_ business.NodeSharedLeaseStore = (*FlatFileLeaseStore)(nil)
)

// FlatFileLeaseStore implements business.LeaseStore backed by a single JSON
// file — the fenced, quorum-equivalent singleton-claim primitive (ADR-031
// Decision 5, Issue #3756) for non-clustered deployment shapes.
//
// File layout: <root>/leases/leases.json, a JSON object keyed by lease name.
// Writes are atomic (temp-file + rename). sync.RWMutex serializes goroutine
// access within one process.
//
// Single-writer only: in SingleServerMode a given lease name is never
// contended across processes, so a straightforward load-check-save under an
// in-process lock is sufficient — this store makes no attempt at cross-process
// atomicity, unlike the database and sqlite providers' single UPSERT
// statement.
type FlatFileLeaseStore struct {
	root string
	mu   sync.RWMutex
}

// leaseEntryJSON is the on-disk representation of a lease row.
type leaseEntryJSON struct {
	HolderID  string    `json:"holder_id"`
	Token     uint64    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewFlatFileLeaseStore creates a FlatFileLeaseStore rooted at <root>/leases.
// The directory is created if it does not exist.
func NewFlatFileLeaseStore(root string) (*FlatFileLeaseStore, error) {
	dir := filepath.Join(root, "leases")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create leases directory: %w", err)
	}
	return &FlatFileLeaseStore{root: root}, nil
}

// SharedAcrossNodes implements business.NodeSharedLeaseStore: false. The backing
// JSON file lives on the node's own disk and exclusion is an in-process mutex, so
// a second controller node contends with nothing here. Usable as a single-node
// claim, never as cluster-wide leadership authority (ADR-031 Decision 5).
func (s *FlatFileLeaseStore) SharedAcrossNodes() bool { return false }

// Close is a no-op; the store holds no persistent handles.
func (s *FlatFileLeaseStore) Close() error { return nil }

func (s *FlatFileLeaseStore) dataFilePath() string {
	return filepath.Join(s.root, "leases", "leases.json")
}

// load reads and parses leases.json. Returns an empty (non-nil) map when the
// file does not exist. Must be called with at least a read lock held.
func (s *FlatFileLeaseStore) load() (map[string]leaseEntryJSON, error) {
	raw, err := readFile(s.dataFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]leaseEntryJSON{}, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read leases file: %w", err)
	}
	entries := map[string]leaseEntryJSON{}
	if len(raw) == 0 {
		return entries, nil
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("flatfile: failed to parse leases file: %w", err)
	}
	return entries, nil
}

// save atomically writes entries to leases.json. Must be called with the
// write lock held.
func (s *FlatFileLeaseStore) save(entries map[string]leaseEntryJSON) error {
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal lease entries: %w", err)
	}
	return writeAtomic(s.dataFilePath(), raw)
}

// AcquireOrRenew implements business.LeaseStore.AcquireOrRenew. See the
// database provider's AcquireOrRenew for the full branch semantics; this is
// the same logic expressed as an explicit load-check-save sequence under a
// process-local lock rather than a single atomic SQL statement.
func (s *FlatFileLeaseStore) AcquireOrRenew(_ context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	if name == "" {
		return nil, fmt.Errorf("flatfile: lease name cannot be empty")
	}
	if holderID == "" {
		return nil, fmt.Errorf("flatfile: holder id cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	existing, exists := entries[name]

	if exists {
		expired := existing.ExpiresAt.Before(now)
		sameHolder := existing.HolderID == holderID
		if !expired && !sameHolder {
			// Held by a different holder and not yet expired: contended, no
			// state change.
			return &business.LeaseState{
				Name:      name,
				HolderID:  existing.HolderID,
				Token:     existing.Token,
				ExpiresAt: existing.ExpiresAt,
				Valid:     true, // unexpired by the check immediately above
				Acquired:  false,
			}, nil
		}
	}

	// Genuine acquisition (first creation, or the existing row is expired)
	// gets a strictly higher token. A renewal by the current, unexpired
	// holder keeps its token unchanged.
	newToken := uint64(1)
	if exists {
		newToken = existing.Token
		if existing.ExpiresAt.Before(now) || existing.HolderID != holderID {
			newToken++
		}
	}

	entries[name] = leaseEntryJSON{
		HolderID:  holderID,
		Token:     newToken,
		ExpiresAt: now.Add(ttl),
	}
	if err := s.save(entries); err != nil {
		return nil, err
	}

	return &business.LeaseState{
		Name:      name,
		HolderID:  holderID,
		Token:     newToken,
		ExpiresAt: entries[name].ExpiresAt,
		Valid:     entries[name].ExpiresAt.After(now),
		Acquired:  true,
	}, nil
}

// Release implements business.LeaseStore.Release. The row is force-expired
// (ExpiresAt set to the Unix epoch) rather than removed, preserving the token
// as the lease's high-water mark for the next acquisition. Idempotent: a
// holder/token mismatch is a silent no-op.
func (s *FlatFileLeaseStore) Release(_ context.Context, name, holderID string, token uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return err
	}

	existing, exists := entries[name]
	if !exists || existing.HolderID != holderID || existing.Token != token {
		return nil
	}

	existing.ExpiresAt = time.Unix(0, 0)
	entries[name] = existing
	return s.save(entries)
}

// GetLease implements business.LeaseStore.GetLease. Validity is evaluated
// here, against the same process clock that wrote ExpiresAt — this store's
// "server" clock is its own process, so no cross-host offset can enter the
// decision (business.LeaseStore's "one clock only" contract).
func (s *FlatFileLeaseStore) GetLease(_ context.Context, name string) (*business.LeaseState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := s.load()
	if err != nil {
		return nil, err
	}

	entry, exists := entries[name]
	if !exists {
		return nil, business.ErrLeaseNotFound
	}

	return &business.LeaseState{
		Name:      name,
		HolderID:  entry.HolderID,
		Token:     entry.Token,
		ExpiresAt: entry.ExpiresAt,
		Valid:     entry.ExpiresAt.After(time.Now()),
	}, nil
}
