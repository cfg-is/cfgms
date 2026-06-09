// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package memory provides in-memory storage implementations for development and testing.
package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// UpgradeStore is a thread-safe in-memory implementation of business.UpgradeStore.
// Used by the fleet controller in development and test deployments where durable
// upgrade-state persistence is not required.
type UpgradeStore struct {
	mu      sync.RWMutex
	records map[string]*business.UpgradeRecord
}

// NewUpgradeStore returns an initialised in-memory UpgradeStore.
func NewUpgradeStore() *UpgradeStore {
	return &UpgradeStore{records: make(map[string]*business.UpgradeRecord)}
}

// CreateUpgrade inserts a new upgrade record. Returns an error when
// record.BundleSignature is nil (required for audit completeness).
func (s *UpgradeStore) CreateUpgrade(_ context.Context, record *business.UpgradeRecord) error {
	if len(record.BundleSignature) == 0 {
		return fmt.Errorf("bundle signature is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *record
	s.records[record.ID] = &cp
	return nil
}

// UpdateUpgradeStatus sets the status of an existing upgrade record.
func (s *UpgradeStore) UpdateUpgradeStatus(_ context.Context, id string, status business.UpgradeStatus, errorMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return business.ErrUpgradeNotFound
	}
	r.Status = status
	r.ErrorMessage = errorMsg
	if status == business.UpgradeStatusCommitted ||
		status == business.UpgradeStatusRolledBack ||
		status == business.UpgradeStatusFailed {
		now := time.Now().UTC()
		r.CompletedAt = &now
	}
	return nil
}

// GetUpgrade retrieves an upgrade record by ID.
func (s *UpgradeStore) GetUpgrade(_ context.Context, id string) (*business.UpgradeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return nil, business.ErrUpgradeNotFound
	}
	cp := *r
	return &cp, nil
}

// ListUpgradesBySteward returns all upgrade records for the given steward ID,
// ordered by CreatedAt descending.
func (s *UpgradeStore) ListUpgradesBySteward(_ context.Context, stewardID string) ([]*business.UpgradeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.UpgradeRecord
	for _, r := range s.records {
		if r.StewardID == stewardID {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// ListUpgradesByTenant returns all upgrade records for the given tenant ID,
// ordered by CreatedAt descending.
func (s *UpgradeStore) ListUpgradesByTenant(_ context.Context, tenantID string) ([]*business.UpgradeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.UpgradeRecord
	for _, r := range s.records {
		if r.TenantID == tenantID {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *UpgradeStore) HealthCheck(_ context.Context) error { return nil }
func (s *UpgradeStore) Initialize(_ context.Context) error  { return nil }
func (s *UpgradeStore) Close() error                        { return nil }

var _ business.UpgradeStore = (*UpgradeStore)(nil)
