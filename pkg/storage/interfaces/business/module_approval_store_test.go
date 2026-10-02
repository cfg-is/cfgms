// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package business_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// inMemModuleApprovalStore is a minimal in-memory ModuleApprovalStore used only for
// contract testing the interface semantics. It is NOT intended for production use.
type inMemModuleApprovalStore struct {
	mu     sync.Mutex
	status map[string]business.ModuleApprovalStatus
}

func newInMemModuleApprovalStore() business.ModuleApprovalStore {
	return &inMemModuleApprovalStore{status: make(map[string]business.ModuleApprovalStatus)}
}

func (s *inMemModuleApprovalStore) GetApprovalStatus(_ context.Context, addr string) (business.ModuleApprovalStatus, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.status[addr]
	return status, ok, nil
}

func (s *inMemModuleApprovalStore) PutApprovalStatusIfAbsent(_ context.Context, addr string, status business.ModuleApprovalStatus) (business.ModuleApprovalStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.status[addr]; ok {
		return existing, nil
	}
	s.status[addr] = status
	return status, nil
}

func (s *inMemModuleApprovalStore) CompareAndSetApprovalStatus(_ context.Context, addr string, expectedCurrent, newStatus business.ModuleApprovalStatus) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.status[addr]
	if !ok || current != expectedCurrent {
		return false, nil
	}
	s.status[addr] = newStatus
	return true, nil
}

// Compile-time assertion: inMemModuleApprovalStore satisfies the interface.
var _ business.ModuleApprovalStore = (*inMemModuleApprovalStore)(nil)

// seedModuleApproval records addr's first status through the ingestion primitive
// and asserts the record did not already exist, so a test that means "start from
// this status" cannot silently start from another.
func seedModuleApproval(t *testing.T, store business.ModuleApprovalStore, addr string, status business.ModuleApprovalStatus) {
	t.Helper()
	effective, err := store.PutApprovalStatusIfAbsent(context.Background(), addr, status)
	require.NoError(t, err)
	require.Equal(t, status, effective, "seeded address %q already carried a status", addr)
}

func TestModuleApprovalStore_GetNotFound(t *testing.T) {
	store := newInMemModuleApprovalStore()
	ctx := context.Background()

	_, found, err := store.GetApprovalStatus(ctx, "cfgms/hyperv/0.2.1/abc")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestModuleApprovalStore_PutIfAbsentThenGet(t *testing.T) {
	store := newInMemModuleApprovalStore()
	ctx := context.Background()

	seedModuleApproval(t, store, "cfgms/hyperv/0.2.1/abc", business.ModuleApprovalPending)

	status, found, err := store.GetApprovalStatus(ctx, "cfgms/hyperv/0.2.1/abc")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, business.ModuleApprovalPending, status)
}

// TestModuleApprovalStore_PutIfAbsentPreservesExistingStatus pins the contract
// that makes ingestion safe to run on every node: a bundle an operator has
// rejected is ingested again by the next cfg push that references it, and that
// second ingestion must neither reset the status to pending nor report pending
// to its caller — either would let the bundle be auto-approved afresh.
func TestModuleApprovalStore_PutIfAbsentPreservesExistingStatus(t *testing.T) {
	store := newInMemModuleApprovalStore()
	ctx := context.Background()

	seedModuleApproval(t, store, "addr-1", business.ModuleApprovalPending)
	ok, err := store.CompareAndSetApprovalStatus(ctx, "addr-1", business.ModuleApprovalPending, business.ModuleApprovalRejected)
	require.NoError(t, err)
	require.True(t, ok)

	effective, err := store.PutApprovalStatusIfAbsent(ctx, "addr-1", business.ModuleApprovalPending)
	require.NoError(t, err)
	assert.Equal(t, business.ModuleApprovalRejected, effective,
		"re-ingestion must report the standing decision, not the status it tried to write")

	status, found, err := store.GetApprovalStatus(ctx, "addr-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, business.ModuleApprovalRejected, status,
		"re-ingestion must not erase an operator's rejection")
}

func TestModuleApprovalStore_CompareAndSetSucceedsOnMatch(t *testing.T) {
	store := newInMemModuleApprovalStore()
	ctx := context.Background()
	seedModuleApproval(t, store, "addr-1", business.ModuleApprovalPending)

	ok, err := store.CompareAndSetApprovalStatus(ctx, "addr-1", business.ModuleApprovalPending, business.ModuleApprovalApproved)
	require.NoError(t, err)
	assert.True(t, ok)

	status, found, err := store.GetApprovalStatus(ctx, "addr-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, business.ModuleApprovalApproved, status)
}

func TestModuleApprovalStore_CompareAndSetFailsOnMismatch(t *testing.T) {
	store := newInMemModuleApprovalStore()
	ctx := context.Background()
	seedModuleApproval(t, store, "addr-1", business.ModuleApprovalApproved)

	ok, err := store.CompareAndSetApprovalStatus(ctx, "addr-1", business.ModuleApprovalPending, business.ModuleApprovalRejected)
	require.NoError(t, err)
	assert.False(t, ok, "a CAS against a stale expected status must not overwrite the current one")

	status, found, err := store.GetApprovalStatus(ctx, "addr-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, business.ModuleApprovalApproved, status, "the mismatched CAS must leave the stored status untouched")
}

func TestModuleApprovalStore_CompareAndSetFailsWhenNoRecordExists(t *testing.T) {
	store := newInMemModuleApprovalStore()
	ctx := context.Background()

	ok, err := store.CompareAndSetApprovalStatus(ctx, "never-set", business.ModuleApprovalPending, business.ModuleApprovalApproved)
	require.NoError(t, err)
	assert.False(t, ok)

	_, found, err := store.GetApprovalStatus(ctx, "never-set")
	require.NoError(t, err)
	assert.False(t, found, "a failed CAS against a non-existent record must not create one")
}

// TestModuleApprovalStore_ConcurrentApproveRejectConverges is the interface-level
// analogue of the database provider's required concurrency test: two concurrent
// CompareAndSetApprovalStatus calls from pending — one to approved, one to
// rejected — against the same address must converge on exactly one winner.
func TestModuleApprovalStore_ConcurrentApproveRejectConverges(t *testing.T) {
	store := newInMemModuleApprovalStore()
	ctx := context.Background()
	seedModuleApproval(t, store, "addr-1", business.ModuleApprovalPending)

	type casResult struct {
		ok  bool
		err error
	}
	var wg sync.WaitGroup
	results := make(chan casResult, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		ok, err := store.CompareAndSetApprovalStatus(ctx, "addr-1", business.ModuleApprovalPending, business.ModuleApprovalApproved)
		results <- casResult{ok, err}
	}()
	go func() {
		defer wg.Done()
		ok, err := store.CompareAndSetApprovalStatus(ctx, "addr-1", business.ModuleApprovalPending, business.ModuleApprovalRejected)
		results <- casResult{ok, err}
	}()
	wg.Wait()
	close(results)

	successes := 0
	for r := range results {
		require.NoError(t, r.err)
		if r.ok {
			successes++
		}
	}
	assert.Equal(t, 1, successes, "exactly one of the concurrent approve/reject transitions must win")

	status, found, err := store.GetApprovalStatus(ctx, "addr-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Contains(t, []business.ModuleApprovalStatus{business.ModuleApprovalApproved, business.ModuleApprovalRejected}, status)
}
