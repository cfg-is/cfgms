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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

const (
	revocationFileName     = "revocation.json"
	revocationLockFileName = revocationFileName + ".lock"
)

// RevocationEntry records a revoked certificate serial with metadata.
type RevocationEntry = certinterfaces.RevocationEntry

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

// addAndPersist merges the entry into the on-disk list under an exclusive
// cross-process lock. The file is re-read under the lock so a revocation written
// by another process since this store last loaded is never overwritten. If the
// serial is already present the call is a no-op (original timestamp preserved).
// If the lock cannot be taken or the re-read fails, nothing is written (fail
// closed). Lock order: rs.mu first, then the file lock.
func (rs *revocationStore) addAndPersist(entry RevocationEntry) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	unlock, err := lockRevocationFile(filepath.Join(filepath.Dir(rs.filePath), revocationLockFileName))
	if err != nil {
		return err
	}
	defer unlock()

	if err := rs.loadLocked(); err != nil {
		return err
	}
	if _, exists := rs.bySerial[entry.Serial]; exists {
		return nil
	}
	rs.bySerial[entry.Serial] = entry
	if err := rs.saveLocked(); err != nil {
		delete(rs.bySerial, entry.Serial)
		return err
	}
	return nil
}

// saveLocked serializes bySerial to disk atomically via a uniquely named temp
// file in the same directory. Must be called with the write lock and file lock held.
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

	tmp, err := os.CreateTemp(filepath.Dir(rs.filePath), revocationFileName+".*.tmp")
	if err != nil {
		return fmt.Errorf("failed to write revocation list: %w", err)
	}
	tmpPath := tmp.Name()
	fail := func(msg string, err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("%s: %w", msg, err)
	}
	if err := tmp.Chmod(0600); err != nil && runtime.GOOS != "windows" {
		return fail("failed to write revocation list", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail("failed to write revocation list", err)
	}
	if err := tmp.Sync(); err != nil {
		return fail("failed to sync revocation list", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write revocation list: %w", err)
	}
	if err := os.Rename(tmpPath, rs.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize revocation list: %w", err)
	}
	return nil
}

// isRevoked reports whether serial is in the revocation list.
// Re-reads from disk on every call to detect cross-process revocations. If the
// reload fails the status cannot be determined, so an error is returned and the
// stale in-memory map is never consulted (fail closed).
func (rs *revocationStore) isRevoked(serial string) (bool, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if err := rs.loadLocked(); err != nil {
		return false, fmt.Errorf("cannot determine revocation status: %w", err)
	}
	_, ok := rs.bySerial[serial]
	return ok, nil
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

// Revoke implements certinterfaces.RevocationStore.Revoke. ctx is unused: all
// I/O here is local-file, matching the rest of pkg/cert's Manager API, which
// predates context propagation.
func (rs *revocationStore) Revoke(_ context.Context, entry RevocationEntry) error {
	return rs.addAndPersist(entry)
}

// IsRevoked implements certinterfaces.RevocationStore.IsRevoked.
func (rs *revocationStore) IsRevoked(_ context.Context, serial string) (bool, error) {
	return rs.isRevoked(serial)
}

// ListRevoked implements certinterfaces.RevocationStore.ListRevoked.
func (rs *revocationStore) ListRevoked(_ context.Context) ([]RevocationEntry, error) {
	return rs.allEntries(), nil
}

// NewFileRevocationStore returns the node-local, file-backed RevocationStore
// implementation: a JSON file at basePath/revocation.json, preserving the
// exact on-disk layout and "missing file means empty list" semantics this
// package has always used. This is pkg/cert's default for single-node
// deployments (Issue #3852 AC2); a clustered controller overrides it via
// ManagerConfig.RevocationStore.
func NewFileRevocationStore(basePath string) (certinterfaces.RevocationStore, error) {
	return newRevocationStore(basePath)
}
