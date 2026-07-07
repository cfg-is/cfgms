// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package memory provides in-memory storage implementations for development and testing.
package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// RolloutStore is a thread-safe in-memory implementation of business.RolloutStore.
// Used in tests and development environments where durable rollout-state persistence
// is not required. All mutations deep-copy the stored record to prevent aliasing.
type RolloutStore struct {
	mu      sync.RWMutex
	records map[string]*business.RolloutRecord
}

// NewRolloutStore returns an initialised in-memory RolloutStore.
func NewRolloutStore() *RolloutStore {
	return &RolloutStore{records: make(map[string]*business.RolloutRecord)}
}

// CreateRollout inserts a new rollout record.
// Returns an error if a record with the same ID already exists.
func (s *RolloutStore) CreateRollout(_ context.Context, record *business.RolloutRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.ID]; exists {
		return fmt.Errorf("rollout %q already exists", record.ID)
	}
	s.records[record.ID] = copyRollout(record)
	return nil
}

// GetRollout retrieves a deep copy of the rollout record identified by id.
func (s *RolloutStore) GetRollout(_ context.Context, id string) (*business.RolloutRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return nil, business.ErrRolloutNotFound
	}
	return copyRollout(r), nil
}

// UpdateRolloutProgress sets the status, current ring, completed ring count, and
// optional halt metadata.
func (s *RolloutStore) UpdateRolloutProgress(_ context.Context, id string, status business.RolloutStatus, currentRing string, ringsCompleted int, haltedAt *time.Time, errorMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return business.ErrRolloutNotFound
	}
	r.Status = status
	r.CurrentRing = currentRing
	r.RingsCompleted = ringsCompleted
	if haltedAt != nil {
		t := *haltedAt
		r.HaltedAt = &t
	}
	r.Error = errorMsg
	return nil
}

// AppendDeferredStewards adds steward IDs to the deferred-retry list for a rollout.
func (s *RolloutStore) AppendDeferredStewards(_ context.Context, rolloutID string, stewardIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[rolloutID]
	if !ok {
		return business.ErrRolloutNotFound
	}
	r.DeferredStewards = append(r.DeferredStewards, stewardIDs...)
	return nil
}

// ListRolloutsByTenant returns deep copies of all rollouts belonging to tenantID.
func (s *RolloutStore) ListRolloutsByTenant(_ context.Context, tenantID string) ([]*business.RolloutRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.RolloutRecord
	for _, r := range s.records {
		if r.TenantID == tenantID {
			out = append(out, copyRollout(r))
		}
	}
	return out, nil
}

func (s *RolloutStore) HealthCheck(_ context.Context) error { return nil }
func (s *RolloutStore) Initialize(_ context.Context) error  { return nil }
func (s *RolloutStore) Close() error                        { return nil }

var _ business.RolloutStore = (*RolloutStore)(nil)

// copyRollout returns a fully independent copy of a RolloutRecord, preventing aliasing
// between the store's internal state and caller-held pointers.
func copyRollout(r *business.RolloutRecord) *business.RolloutRecord {
	cp := *r
	cp.DeferredStewards = append([]string(nil), r.DeferredStewards...)
	if r.HaltedAt != nil {
		t := *r.HaltedAt
		cp.HaltedAt = &t
	}
	return &cp
}
