// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Revocation primitive for cert.Manager.
//
// Access pattern: IsRevoked is called on every mTLS admin cert authentication
// request (frequent reads, called from auth middleware). Revoke is called rarely
// (admin action, CLI invocation). A sync.RWMutex allows many concurrent readers
// while Revoke acquires exclusive access for the write+persist operation.
package cert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const revocationFileName = "revocation.json"

// RevocationEntry records a revoked certificate serial with metadata.
type RevocationEntry struct {
	Serial    string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason,omitempty"`
}

// revocationList is the on-disk JSON format.
type revocationList struct {
	Entries []RevocationEntry `json:"entries"`
}

// revocationStore persists the revocation list as a JSON file in the certificate
// store's base path and re-reads it on every IsRevoked call. This ensures that
// revocations issued by a separate process (e.g. `cfgms-controller bootstrap-admin
// --revoke`) take effect immediately in the running controller without a restart.
// The write lock is held for both reads and writes; the list is expected to be small
// (admin certs only), so lock contention is not a bottleneck in practice.
type revocationStore struct {
	mu       sync.RWMutex
	filePath string
	bySerial map[string]RevocationEntry
}

// newRevocationStore loads or creates an empty revocation store backed by
// basePath/revocation.json. A missing file is treated as an empty list (not an error).
func newRevocationStore(basePath string) (*revocationStore, error) {
	rs := &revocationStore{
		filePath: filepath.Join(basePath, revocationFileName),
		bySerial: make(map[string]RevocationEntry),
	}
	if err := rs.reload(); err != nil {
		return nil, err
	}
	return rs, nil
}

// reload re-reads the revocation file and rebuilds the in-memory map.
// Called during initialization and after each addAndPersist to keep cache consistent.
func (rs *revocationStore) reload() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.loadLocked()
}

// loadLocked reads the file and rebuilds bySerial. Must be called with the write lock held.
func (rs *revocationStore) loadLocked() error {
	// #nosec G304 -- path is controlled: constructed from the cert manager's storage path
	data, err := os.ReadFile(rs.filePath)
	if os.IsNotExist(err) {
		rs.bySerial = make(map[string]RevocationEntry)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read revocation list: %w", err)
	}

	var list revocationList
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("failed to parse revocation list: %w", err)
	}

	m := make(map[string]RevocationEntry, len(list.Entries))
	for _, e := range list.Entries {
		m[e.Serial] = e
	}
	rs.bySerial = m
	return nil
}

// addAndPersist adds the entry to the in-memory map and atomically saves to disk.
// If the serial is already revoked the call is a no-op (original timestamp preserved).
// The write lock is held for the duration of the update.
func (rs *revocationStore) addAndPersist(entry RevocationEntry) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if _, exists := rs.bySerial[entry.Serial]; exists {
		return nil
	}
	rs.bySerial[entry.Serial] = entry
	return rs.saveLocked()
}

// saveLocked serializes bySerial to disk atomically. Must be called with the write lock held.
func (rs *revocationStore) saveLocked() error {
	entries := make([]RevocationEntry, 0, len(rs.bySerial))
	for _, e := range rs.bySerial {
		entries = append(entries, e)
	}

	list := revocationList{Entries: entries}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal revocation list: %w", err)
	}

	tmpPath := rs.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write revocation list: %w", err)
	}

	if err := os.Rename(tmpPath, rs.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize revocation list: %w", err)
	}
	return nil
}

// isRevoked reports whether serial is in the revocation list.
// Re-reads from disk on every call to detect cross-process revocations.
func (rs *revocationStore) isRevoked(serial string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	_ = rs.loadLocked() // best-effort reload; stale cache preferred over crashing
	_, ok := rs.bySerial[serial]
	return ok
}

// allEntries returns a snapshot of all revocation entries.
func (rs *revocationStore) allEntries() []RevocationEntry {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]RevocationEntry, 0, len(rs.bySerial))
	for _, e := range rs.bySerial {
		out = append(out, e)
	}
	return out
}
