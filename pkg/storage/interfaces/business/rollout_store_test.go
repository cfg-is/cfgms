// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// inMemRolloutStore is a minimal in-memory RolloutStore used to validate the
// shared contract harness. It is not a substitute for production implementations —
// the real memory provider runs the same operations in its own test package.
type inMemRolloutStore struct {
	mu      sync.RWMutex
	records map[string]*business.RolloutRecord
}

func newInMemRolloutStore() business.RolloutStore {
	return &inMemRolloutStore{records: make(map[string]*business.RolloutRecord)}
}

func (s *inMemRolloutStore) CreateRollout(_ context.Context, record *business.RolloutRecord) error {
	if record == nil {
		return errRolloutTestNilRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.ID]; exists {
		return errRolloutTestDuplicateID
	}
	cp := copyRolloutRecord(record)
	s.records[record.ID] = cp
	return nil
}

func (s *inMemRolloutStore) GetRollout(_ context.Context, id string) (*business.RolloutRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return nil, business.ErrRolloutNotFound
	}
	return copyRolloutRecord(r), nil
}

func (s *inMemRolloutStore) UpdateRolloutProgress(_ context.Context, id string, status business.RolloutStatus, currentRing string, ringsCompleted int, haltedAt *time.Time, errorMsg string) error {
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

func (s *inMemRolloutStore) AppendDeferredStewards(_ context.Context, rolloutID string, stewardIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[rolloutID]
	if !ok {
		return business.ErrRolloutNotFound
	}
	r.DeferredStewards = append(r.DeferredStewards, stewardIDs...)
	return nil
}

func (s *inMemRolloutStore) ListRolloutsByTenant(_ context.Context, tenantID string) ([]*business.RolloutRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.RolloutRecord
	for _, r := range s.records {
		if r.TenantID == tenantID {
			out = append(out, copyRolloutRecord(r))
		}
	}
	return out, nil
}

func (s *inMemRolloutStore) ListInProgressRollouts(_ context.Context) ([]*business.RolloutRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.RolloutRecord
	for _, r := range s.records {
		if r.Status == business.RolloutStatusInProgress {
			out = append(out, copyRolloutRecord(r))
		}
	}
	return out, nil
}

func (s *inMemRolloutStore) HealthCheck(_ context.Context) error { return nil }
func (s *inMemRolloutStore) Initialize(_ context.Context) error  { return nil }
func (s *inMemRolloutStore) Close() error                        { return nil }

var _ business.RolloutStore = (*inMemRolloutStore)(nil)

func copyRolloutRecord(r *business.RolloutRecord) *business.RolloutRecord {
	cp := *r
	cp.DeferredStewards = append([]string(nil), r.DeferredStewards...)
	if r.HaltedAt != nil {
		t := *r.HaltedAt
		cp.HaltedAt = &t
	}
	return &cp
}

var (
	errRolloutTestNilRecord   = errRolloutTestStr("nil rollout record")
	errRolloutTestDuplicateID = errRolloutTestStr("duplicate rollout ID")
)

type errRolloutTestStr string

func (e errRolloutTestStr) Error() string { return string(e) }

func TestRolloutStore_Contract(t *testing.T) {
	business.RolloutStoreContract(t, newInMemRolloutStore())
}

func TestRolloutStore_StatusConstants(t *testing.T) {
	assert.Equal(t, business.RolloutStatus("in-progress"), business.RolloutStatusInProgress)
	assert.Equal(t, business.RolloutStatus("halted"), business.RolloutStatusHalted)
	assert.Equal(t, business.RolloutStatus("completed"), business.RolloutStatusCompleted)
}

func TestErrRolloutNotFound(t *testing.T) {
	assert.NotNil(t, business.ErrRolloutNotFound)
	assert.Equal(t, "rollout record not found", business.ErrRolloutNotFound.Error())
}
