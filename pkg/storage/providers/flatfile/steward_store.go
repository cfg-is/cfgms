// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// FlatFileStewardStore implements business.StewardStore using one JSON file per steward.
//
// File layout: <root>/stewards/<stewardID>.json
//
// Each file contains the full StewardRecord marshalled as JSON.
// Writes are atomic (temp-file + rename). ListStewards reads every file in the directory,
// which is a known O(n) limitation for large fleets; use SQLite for fleets where query
// performance matters.
//
// Single-writer only: this store is not safe for concurrent writers sharing the same root.
type FlatFileStewardStore struct {
	root  string
	mutex sync.RWMutex
}

// NewFlatFileStewardStore creates a FlatFileStewardStore rooted at <root>/stewards.
// The directory is created if it does not exist.
func NewFlatFileStewardStore(root string) (*FlatFileStewardStore, error) {
	stewardDir := filepath.Join(root, "stewards")
	if err := os.MkdirAll(stewardDir, 0750); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create steward directory: %w", err)
	}
	return &FlatFileStewardStore{root: root}, nil
}

// stewardDir returns the directory that holds all steward JSON files.
func (s *FlatFileStewardStore) stewardDir() string {
	return filepath.Join(s.root, "stewards")
}

// stewardPath returns the path for a given steward ID, validated against traversal.
func (s *FlatFileStewardStore) stewardPath(stewardID string) (string, error) {
	if stewardID == "" {
		return "", fmt.Errorf("flatfile: steward ID cannot be empty")
	}
	return safeJoin(s.stewardDir(), stewardID+".json")
}

// readSteward reads and unmarshals a steward record file. Must be called with at least a read lock.
func (s *FlatFileStewardStore) readSteward(stewardID string) (*business.StewardRecord, error) {
	path, err := s.stewardPath(stewardID)
	if err != nil {
		return nil, err
	}
	// #nosec G304 — path is validated by safeJoin
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, business.ErrStewardNotFound
		}
		return nil, fmt.Errorf("flatfile: failed to read steward file: %w", err)
	}
	var record business.StewardRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("flatfile: failed to unmarshal steward record: %w", err)
	}
	return &record, nil
}

// writeSteward marshals and atomically writes a steward record. Must be called with a write lock.
func (s *FlatFileStewardStore) writeSteward(record *business.StewardRecord) error {
	path, err := s.stewardPath(record.ID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal steward record: %w", err)
	}
	return writeAtomic(path, raw)
}

// RegisterSteward creates a new steward record. Returns ErrStewardAlreadyExists if a record
// with the same ID already exists.
func (s *FlatFileStewardStore) RegisterSteward(_ context.Context, record *business.StewardRecord) error {
	if record == nil {
		return fmt.Errorf("flatfile: record cannot be nil")
	}
	if record.ID == "" {
		return fmt.Errorf("flatfile: steward ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, err := s.readSteward(record.ID); err == nil {
		return business.ErrStewardAlreadyExists
	}

	now := time.Now().UTC()
	r := *record
	r.RegisteredAt = now
	r.LastSeen = now
	if r.Status == "" {
		r.Status = business.StewardStatusRegistered
	}
	return s.writeSteward(&r)
}

// UpdateHeartbeat records a heartbeat for the steward, updating last_heartbeat_at and last_seen.
func (s *FlatFileStewardStore) UpdateHeartbeat(_ context.Context, stewardID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	record, err := s.readSteward(stewardID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	record.LastHeartbeatAt = now
	record.LastSeen = now
	return s.writeSteward(record)
}

// GetSteward retrieves the record for the given steward ID.
func (s *FlatFileStewardStore) GetSteward(_ context.Context, stewardID string) (*business.StewardRecord, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.readSteward(stewardID)
}

// ListStewards returns all steward records. Reads every file in the stewards directory.
// For large fleets this is O(n); prefer the SQLite provider if query latency matters.
func (s *FlatFileStewardStore) ListStewards(_ context.Context) ([]*business.StewardRecord, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.readAllStewards()
}

// readAllStewards reads all steward JSON files. Must be called with at least a read lock.
func (s *FlatFileStewardStore) readAllStewards() ([]*business.StewardRecord, error) {
	dir := s.stewardDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read steward directory: %w", err)
	}

	var records []*business.StewardRecord
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		// #nosec G304 — path is rooted at s.stewardDir()
		raw, err := os.ReadFile(path)
		if err != nil {
			continue // skip unreadable files
		}
		var record business.StewardRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			continue // skip malformed files
		}
		records = append(records, &record)
	}
	return records, nil
}

// ListStewardsByStatus returns records with the given status.
func (s *FlatFileStewardStore) ListStewardsByStatus(_ context.Context, status business.StewardStatus) ([]*business.StewardRecord, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	all, err := s.readAllStewards()
	if err != nil {
		return nil, err
	}
	var filtered []*business.StewardRecord
	for _, r := range all {
		if r.Status == status {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

// UpdateStewardStatus updates the lifecycle status of the given steward.
func (s *FlatFileStewardStore) UpdateStewardStatus(_ context.Context, stewardID string, status business.StewardStatus) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	record, err := s.readSteward(stewardID)
	if err != nil {
		return err
	}
	record.Status = status
	record.LastSeen = time.Now().UTC()
	return s.writeSteward(record)
}

// DeregisterSteward marks the steward as deregistered. Records are retained for audit.
func (s *FlatFileStewardStore) DeregisterSteward(ctx context.Context, stewardID string) error {
	return s.UpdateStewardStatus(ctx, stewardID, business.StewardStatusDeregistered)
}

// GetStewardsSeen returns all stewards whose last_seen time is after the given time.
func (s *FlatFileStewardStore) GetStewardsSeen(_ context.Context, since time.Time) ([]*business.StewardRecord, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	all, err := s.readAllStewards()
	if err != nil {
		return nil, err
	}
	var result []*business.StewardRecord
	for _, r := range all {
		if r.LastSeen.After(since) {
			result = append(result, r)
		}
	}
	return result, nil
}

// HealthCheck verifies the steward directory is accessible.
func (s *FlatFileStewardStore) HealthCheck(_ context.Context) error {
	dir := s.stewardDir()
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("flatfile: steward directory not accessible: %w", err)
	}
	return nil
}

// Initialize ensures the steward directory exists.
func (s *FlatFileStewardStore) Initialize(_ context.Context) error {
	return os.MkdirAll(s.stewardDir(), 0750)
}

// Close is a no-op for the flat-file provider (no persistent connections to release).
func (s *FlatFileStewardStore) Close() error { return nil }

// Compile-time assertion
var _ business.StewardStore = (*FlatFileStewardStore)(nil)
