// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func newTestRolloutRecord(id, tenantID string) *business.RolloutRecord {
	return &business.RolloutRecord{
		ID:               id,
		TenantID:         tenantID,
		TargetVersion:    "v2.0.0",
		CurrentRing:      "canary",
		RingsCompleted:   0,
		RingsTotal:       4,
		Status:           business.RolloutStatusInProgress,
		StartedAt:        time.Now().UTC(),
		DeferredStewards: []string{},
	}
}

func TestRolloutStore_Contract(t *testing.T) {
	store := newInMemRolloutStore()
	ctx := context.Background()

	require.NoError(t, store.Initialize(ctx))
	require.NoError(t, store.HealthCheck(ctx))

	t.Run("create and get round-trip", func(t *testing.T) {
		rec := newTestRolloutRecord("rollout-1", "tenant-1")
		require.NoError(t, store.CreateRollout(ctx, rec))

		got, err := store.GetRollout(ctx, "rollout-1")
		require.NoError(t, err)
		assert.Equal(t, "rollout-1", got.ID)
		assert.Equal(t, "tenant-1", got.TenantID)
		assert.Equal(t, "v2.0.0", got.TargetVersion)
		assert.Equal(t, "canary", got.CurrentRing)
		assert.Equal(t, 0, got.RingsCompleted)
		assert.Equal(t, 4, got.RingsTotal)
		assert.Equal(t, business.RolloutStatusInProgress, got.Status)
		assert.Nil(t, got.HaltedAt)
		assert.Empty(t, got.Error)
		assert.Empty(t, got.DeferredStewards)
	})

	t.Run("duplicate ID returns error", func(t *testing.T) {
		rec := newTestRolloutRecord("rollout-dup", "tenant-1")
		require.NoError(t, store.CreateRollout(ctx, rec))
		err := store.CreateRollout(ctx, rec)
		require.Error(t, err)
	})

	t.Run("get not found returns ErrRolloutNotFound", func(t *testing.T) {
		_, err := store.GetRollout(ctx, "no-such-id")
		assert.ErrorIs(t, err, business.ErrRolloutNotFound)
	})

	t.Run("UpdateRolloutProgress reflects in Get", func(t *testing.T) {
		rec := newTestRolloutRecord("rollout-progress", "tenant-1")
		require.NoError(t, store.CreateRollout(ctx, rec))

		require.NoError(t, store.UpdateRolloutProgress(ctx, "rollout-progress", business.RolloutStatusInProgress, "early", 1, nil, ""))
		got, err := store.GetRollout(ctx, "rollout-progress")
		require.NoError(t, err)
		assert.Equal(t, business.RolloutStatusInProgress, got.Status)
		assert.Equal(t, "early", got.CurrentRing)
		assert.Equal(t, 1, got.RingsCompleted)
		assert.Nil(t, got.HaltedAt)

		require.NoError(t, store.UpdateRolloutProgress(ctx, "rollout-progress", business.RolloutStatusCompleted, "", 4, nil, ""))
		got, err = store.GetRollout(ctx, "rollout-progress")
		require.NoError(t, err)
		assert.Equal(t, business.RolloutStatusCompleted, got.Status)
		assert.Equal(t, 4, got.RingsCompleted)
	})

	t.Run("UpdateRolloutProgress halted sets HaltedAt and error", func(t *testing.T) {
		rec := newTestRolloutRecord("rollout-halt", "tenant-1")
		require.NoError(t, store.CreateRollout(ctx, rec))

		haltTime := time.Now().UTC()
		require.NoError(t, store.UpdateRolloutProgress(ctx, "rollout-halt", business.RolloutStatusHalted, "canary", 0, &haltTime, "error rate exceeded threshold"))

		got, err := store.GetRollout(ctx, "rollout-halt")
		require.NoError(t, err)
		assert.Equal(t, business.RolloutStatusHalted, got.Status)
		assert.Equal(t, "error rate exceeded threshold", got.Error)
		require.NotNil(t, got.HaltedAt)
	})

	t.Run("UpdateRolloutProgress not found", func(t *testing.T) {
		err := store.UpdateRolloutProgress(ctx, "ghost", business.RolloutStatusHalted, "", 0, nil, "")
		assert.ErrorIs(t, err, business.ErrRolloutNotFound)
	})

	t.Run("deferred-retry list persists across appends", func(t *testing.T) {
		rec := newTestRolloutRecord("rollout-deferred", "tenant-1")
		require.NoError(t, store.CreateRollout(ctx, rec))

		require.NoError(t, store.AppendDeferredStewards(ctx, "rollout-deferred", []string{"s-1", "s-2"}))
		require.NoError(t, store.AppendDeferredStewards(ctx, "rollout-deferred", []string{"s-3"}))

		got, err := store.GetRollout(ctx, "rollout-deferred")
		require.NoError(t, err)
		assert.Equal(t, []string{"s-1", "s-2", "s-3"}, got.DeferredStewards)
	})

	t.Run("AppendDeferredStewards not found", func(t *testing.T) {
		err := store.AppendDeferredStewards(ctx, "ghost-rollout", []string{"s-x"})
		assert.ErrorIs(t, err, business.ErrRolloutNotFound)
	})

	t.Run("ListRolloutsByTenant scopes by tenant", func(t *testing.T) {
		require.NoError(t, store.CreateRollout(ctx, newTestRolloutRecord("rollout-ta-1", "tenant-A")))
		require.NoError(t, store.CreateRollout(ctx, newTestRolloutRecord("rollout-ta-2", "tenant-A")))
		require.NoError(t, store.CreateRollout(ctx, newTestRolloutRecord("rollout-tb-1", "tenant-B")))

		listA, err := store.ListRolloutsByTenant(ctx, "tenant-A")
		require.NoError(t, err)
		assert.Len(t, listA, 2)

		listB, err := store.ListRolloutsByTenant(ctx, "tenant-B")
		require.NoError(t, err)
		assert.Len(t, listB, 1)
		assert.Equal(t, "rollout-tb-1", listB[0].ID)

		listNone, err := store.ListRolloutsByTenant(ctx, "tenant-unknown")
		require.NoError(t, err)
		assert.Empty(t, listNone)
	})

	require.NoError(t, store.Close())
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
