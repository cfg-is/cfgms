// SPDX-License-Identifier: Apache-2.0
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

// inMemPendingStore is a minimal in-memory PendingRegistrationStore for contract tests.
type inMemPendingStore struct {
	mu      sync.RWMutex
	entries map[string]*business.PendingRegistrationEntry
}

func newInMemPendingStore() business.PendingRegistrationStore {
	return &inMemPendingStore{entries: make(map[string]*business.PendingRegistrationEntry)}
}

func (s *inMemPendingStore) AddPending(_ context.Context, entry *business.PendingRegistrationEntry) error {
	if entry == nil {
		return ErrTestNilEntry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[entry.PendingID]; exists {
		return ErrTestDuplicate
	}
	cp := *entry
	if cp.Status == "" {
		cp.Status = business.PendingRegistrationStatusPending
	}
	if cp.RegisteredAt.IsZero() {
		cp.RegisteredAt = time.Now().UTC()
	}
	s.entries[entry.PendingID] = &cp
	return nil
}

func (s *inMemPendingStore) GetPendingByID(_ context.Context, pendingID string) (*business.PendingRegistrationEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[pendingID]
	if !ok {
		return nil, business.ErrPendingRegistrationNotFound
	}
	cp := *e
	return &cp, nil
}

func (s *inMemPendingStore) GetPendingByToken(_ context.Context, tokenStr string) (*business.PendingRegistrationEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.TokenStr == tokenStr {
			cp := *e
			return &cp, nil
		}
	}
	return nil, business.ErrPendingRegistrationNotFound
}

func (s *inMemPendingStore) UpdateStatus(_ context.Context, pendingID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[pendingID]
	if !ok {
		return business.ErrPendingRegistrationNotFound
	}
	e.Status = status
	if status == business.PendingRegistrationStatusClaimed {
		now := time.Now().UTC()
		e.ClaimedAt = &now
	}
	return nil
}

func (s *inMemPendingStore) ListPending(_ context.Context, tenantID string) ([]*business.PendingRegistrationEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.PendingRegistrationEntry
	for _, e := range s.entries {
		if tenantID == "" || e.TenantID == tenantID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *inMemPendingStore) ExpireStale(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, e := range s.entries {
		if e.Status == business.PendingRegistrationStatusPending && !e.ExpiresAt.After(cutoff) {
			e.Status = business.PendingRegistrationStatusExpired
			count++
		}
	}
	return count, nil
}

// test-only sentinel errors
var (
	ErrTestNilEntry  = errStr("nil entry")
	ErrTestDuplicate = errStr("duplicate pending_id")
)

type errStr string

func (e errStr) Error() string { return string(e) }

// Compile-time assertion.
var _ business.PendingRegistrationStore = (*inMemPendingStore)(nil)

// --- Contract tests ---

func newTestEntry(id, tenant, token string) *business.PendingRegistrationEntry {
	now := time.Now().UTC()
	return &business.PendingRegistrationEntry{
		PendingID:    id,
		StewardID:    "steward-" + id,
		TenantID:     tenant,
		TokenStr:     token,
		SourceIP:     "10.0.0.1",
		RegisteredAt: now,
		ExpiresAt:    now.Add(5 * 24 * time.Hour),
		Status:       business.PendingRegistrationStatusPending,
	}
}

func TestPendingRegistrationStore_AddAndGet(t *testing.T) {
	store := newInMemPendingStore()
	ctx := context.Background()

	entry := newTestEntry("p-1", "tenant-1", "tok-abc")
	require.NoError(t, store.AddPending(ctx, entry))

	got, err := store.GetPendingByID(ctx, "p-1")
	require.NoError(t, err)
	assert.Equal(t, "p-1", got.PendingID)
	assert.Equal(t, "tenant-1", got.TenantID)
	assert.Equal(t, "tok-abc", got.TokenStr)
	assert.Equal(t, business.PendingRegistrationStatusPending, got.Status)
	assert.Nil(t, got.ClaimedAt)
}

func TestPendingRegistrationStore_GetByToken(t *testing.T) {
	store := newInMemPendingStore()
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, newTestEntry("p-tok", "tenant-1", "tok-xyz")))

	got, err := store.GetPendingByToken(ctx, "tok-xyz")
	require.NoError(t, err)
	assert.Equal(t, "p-tok", got.PendingID)
}

func TestPendingRegistrationStore_GetByToken_NotFound(t *testing.T) {
	store := newInMemPendingStore()
	_, err := store.GetPendingByToken(context.Background(), "tok-missing")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

func TestPendingRegistrationStore_GetByID_NotFound(t *testing.T) {
	store := newInMemPendingStore()
	_, err := store.GetPendingByID(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

func TestPendingRegistrationStore_UpdateStatus_Claimed_SetsClaimed(t *testing.T) {
	store := newInMemPendingStore()
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, newTestEntry("p-c", "tenant-1", "tok-c")))
	require.NoError(t, store.UpdateStatus(ctx, "p-c", business.PendingRegistrationStatusApproved))

	before := time.Now().UTC()
	require.NoError(t, store.UpdateStatus(ctx, "p-c", business.PendingRegistrationStatusClaimed))

	got, err := store.GetPendingByID(ctx, "p-c")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusClaimed, got.Status)
	require.NotNil(t, got.ClaimedAt)
	assert.WithinDuration(t, before, *got.ClaimedAt, 2*time.Second)
}

func TestPendingRegistrationStore_UpdateStatus_NotFound(t *testing.T) {
	store := newInMemPendingStore()
	err := store.UpdateStatus(context.Background(), "missing", business.PendingRegistrationStatusDenied)
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

func TestPendingRegistrationStore_ListPending_TenantFilter(t *testing.T) {
	store := newInMemPendingStore()
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, newTestEntry("p-a", "tenant-1", "tok-a")))
	require.NoError(t, store.AddPending(ctx, newTestEntry("p-b", "tenant-2", "tok-b")))

	all, err := store.ListPending(ctx, "")
	require.NoError(t, err)
	assert.Len(t, all, 2)

	filtered, err := store.ListPending(ctx, "tenant-1")
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	assert.Equal(t, "p-a", filtered[0].PendingID)
}

func TestPendingRegistrationStore_ExpireStale_OnlyPending(t *testing.T) {
	store := newInMemPendingStore()
	ctx := context.Background()

	now := time.Now().UTC()
	stale := newTestEntry("p-stale", "tenant-1", "tok-stale")
	stale.ExpiresAt = now.Add(-1 * time.Hour)
	require.NoError(t, store.AddPending(ctx, stale))

	approved := newTestEntry("p-appr", "tenant-1", "tok-appr")
	approved.ExpiresAt = now.Add(-1 * time.Hour)
	require.NoError(t, store.AddPending(ctx, approved))
	require.NoError(t, store.UpdateStatus(ctx, "p-appr", business.PendingRegistrationStatusApproved))

	count, err := store.ExpireStale(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "only pending entries may be expired")
}

func TestPendingRegistrationStore_StatusConstants(t *testing.T) {
	assert.Equal(t, "pending", business.PendingRegistrationStatusPending)
	assert.Equal(t, "approved", business.PendingRegistrationStatusApproved)
	assert.Equal(t, "claimed", business.PendingRegistrationStatusClaimed)
	assert.Equal(t, "denied", business.PendingRegistrationStatusDenied)
	assert.Equal(t, "expired", business.PendingRegistrationStatusExpired)
}

func TestErrPendingRegistrationNotFound(t *testing.T) {
	assert.NotNil(t, business.ErrPendingRegistrationNotFound)
	assert.Equal(t, "pending registration not found", business.ErrPendingRegistrationNotFound.Error())
}
