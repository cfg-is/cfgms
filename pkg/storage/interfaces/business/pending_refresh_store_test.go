// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// inMemPendingRefreshStore is a minimal in-memory PendingRefreshStore for contract tests.
type inMemPendingRefreshStore struct {
	mu      sync.RWMutex
	entries map[string]*business.PendingRefreshEntry
}

func newInMemPendingRefreshStore() business.PendingRefreshStore {
	return &inMemPendingRefreshStore{entries: make(map[string]*business.PendingRefreshEntry)}
}

func (s *inMemPendingRefreshStore) AddPendingRefresh(_ context.Context, entry *business.PendingRefreshEntry) error {
	if entry == nil {
		return fmt.Errorf("nil entry")
	}
	if entry.PendingID == "" {
		return fmt.Errorf("pending_id cannot be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[entry.PendingID]; exists {
		return fmt.Errorf("duplicate pending_id: %s", entry.PendingID)
	}
	cp := *entry
	if cp.Status == "" {
		cp.Status = business.PendingRefreshStatusPending
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	s.entries[entry.PendingID] = &cp
	return nil
}

func (s *inMemPendingRefreshStore) GetPendingRefreshByID(_ context.Context, pendingID string) (*business.PendingRefreshEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[pendingID]
	if !ok {
		return nil, business.ErrPendingRefreshNotFound
	}
	cp := *e
	return &cp, nil
}

func (s *inMemPendingRefreshStore) UpdateRefreshStatus(_ context.Context, pendingID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[pendingID]
	if !ok {
		return business.ErrPendingRefreshNotFound
	}
	e.Status = status
	isTerminal := status == business.PendingRefreshStatusApproved || status == business.PendingRefreshStatusRejected
	if isTerminal {
		now := time.Now().UTC()
		e.ResolvedAt = &now
	}
	return nil
}

func (s *inMemPendingRefreshStore) ListPendingRefresh(_ context.Context, tenantID string) ([]*business.PendingRefreshEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.PendingRefreshEntry
	for _, e := range s.entries {
		if tenantID == "" || e.TenantID == tenantID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *inMemPendingRefreshStore) ExpireStaleRefresh(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, e := range s.entries {
		if e.Status == business.PendingRefreshStatusPending && !e.ExpiresAt.After(cutoff) {
			e.Status = business.PendingRefreshStatusExpired
			now := time.Now().UTC()
			e.ResolvedAt = &now
			count++
		}
	}
	return count, nil
}

func (s *inMemPendingRefreshStore) StoreClaimBundle(_ context.Context, pendingID string, bundle []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[pendingID]
	if !ok {
		return business.ErrPendingRefreshNotFound
	}
	e.ClaimBundle = bundle
	return nil
}

// Compile-time assertion.
var _ business.PendingRefreshStore = (*inMemPendingRefreshStore)(nil)

// --- Contract tests ---

func newTestRefreshEntry(id, deviceID, tenant string) *business.PendingRefreshEntry {
	now := time.Now().UTC()
	return &business.PendingRefreshEntry{
		PendingID:               id,
		DeviceID:                deviceID,
		TenantID:                tenant,
		SourceIP:                "10.0.0.1",
		ProvenanceMatchedFields: 3,
		ProvenanceTotalFields:   5,
		Status:                  business.PendingRefreshStatusPending,
		CreatedAt:               now,
		ExpiresAt:               now.Add(65 * time.Second),
	}
}

func TestPendingRefreshStore_AddAndGetByID(t *testing.T) {
	store := newInMemPendingRefreshStore()
	ctx := context.Background()

	entry := newTestRefreshEntry("pr-1", "devid-1", "tenant-1")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	got, err := store.GetPendingRefreshByID(ctx, "pr-1")
	require.NoError(t, err)
	assert.Equal(t, "pr-1", got.PendingID)
	assert.Equal(t, "devid-1", got.DeviceID)
	assert.Equal(t, "tenant-1", got.TenantID)
	assert.Equal(t, business.PendingRefreshStatusPending, got.Status)
	assert.Nil(t, got.ResolvedAt)
}

func TestPendingRefreshStore_GetByID_NotFound(t *testing.T) {
	store := newInMemPendingRefreshStore()
	_, err := store.GetPendingRefreshByID(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

func TestPendingRefreshStore_UpdateRefreshStatus_ApprovedSetsResolvedAt(t *testing.T) {
	store := newInMemPendingRefreshStore()
	ctx := context.Background()

	require.NoError(t, store.AddPendingRefresh(ctx, newTestRefreshEntry("pr-appr", "dev-1", "t1")))

	before := time.Now().UTC()
	require.NoError(t, store.UpdateRefreshStatus(ctx, "pr-appr", business.PendingRefreshStatusApproved))

	got, err := store.GetPendingRefreshByID(ctx, "pr-appr")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusApproved, got.Status)
	require.NotNil(t, got.ResolvedAt)
	assert.WithinDuration(t, before, *got.ResolvedAt, 2*time.Second)
}

func TestPendingRefreshStore_UpdateRefreshStatus_NotFound(t *testing.T) {
	store := newInMemPendingRefreshStore()
	err := store.UpdateRefreshStatus(context.Background(), "missing", business.PendingRefreshStatusRejected)
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

func TestPendingRefreshStore_StoreClaimBundle_Contract(t *testing.T) {
	store := newInMemPendingRefreshStore()
	ctx := context.Background()

	require.NoError(t, store.AddPendingRefresh(ctx, newTestRefreshEntry("pr-bundle", "dev-2", "t1")))

	bundle := []byte(`{"nonce":"abc","sig":"deadbeef"}`)
	require.NoError(t, store.StoreClaimBundle(ctx, "pr-bundle", bundle))

	got, err := store.GetPendingRefreshByID(ctx, "pr-bundle")
	require.NoError(t, err)
	assert.Equal(t, bundle, got.ClaimBundle)
}

func TestPendingRefreshStore_StoreClaimBundle_NotFound(t *testing.T) {
	store := newInMemPendingRefreshStore()
	err := store.StoreClaimBundle(context.Background(), "missing", []byte("bundle"))
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

func TestPendingRefreshStore_ListPendingRefresh_TenantFilter(t *testing.T) {
	store := newInMemPendingRefreshStore()
	ctx := context.Background()

	require.NoError(t, store.AddPendingRefresh(ctx, newTestRefreshEntry("pr-a", "dev-a", "tenant-1")))
	require.NoError(t, store.AddPendingRefresh(ctx, newTestRefreshEntry("pr-b", "dev-b", "tenant-2")))

	all, err := store.ListPendingRefresh(ctx, "")
	require.NoError(t, err)
	assert.Len(t, all, 2)

	filtered, err := store.ListPendingRefresh(ctx, "tenant-1")
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	assert.Equal(t, "pr-a", filtered[0].PendingID)
}

func TestPendingRefreshStore_ExpireStaleRefresh_OnlyPending(t *testing.T) {
	store := newInMemPendingRefreshStore()
	ctx := context.Background()

	now := time.Now().UTC()

	stale := newTestRefreshEntry("pr-stale", "dev-stale", "t1")
	stale.ExpiresAt = now.Add(-1 * time.Hour)
	require.NoError(t, store.AddPendingRefresh(ctx, stale))

	approved := newTestRefreshEntry("pr-appr", "dev-appr", "t1")
	approved.ExpiresAt = now.Add(-1 * time.Hour)
	require.NoError(t, store.AddPendingRefresh(ctx, approved))
	require.NoError(t, store.UpdateRefreshStatus(ctx, "pr-appr", business.PendingRefreshStatusApproved))

	count, err := store.ExpireStaleRefresh(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "only pending entries may be expired")
}

func TestPendingRefreshStore_StatusConstants(t *testing.T) {
	assert.Equal(t, "pending", business.PendingRefreshStatusPending)
	assert.Equal(t, "approved", business.PendingRefreshStatusApproved)
	assert.Equal(t, "rejected", business.PendingRefreshStatusRejected)
	assert.Equal(t, "expired", business.PendingRefreshStatusExpired)
}

func TestErrPendingRefreshNotFound(t *testing.T) {
	assert.NotNil(t, business.ErrPendingRefreshNotFound)
	assert.Equal(t, "pending refresh not found", business.ErrPendingRefreshNotFound.Error())
}
