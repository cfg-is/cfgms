// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestLeaseStore(t *testing.T) *FlatFileLeaseStore {
	t.Helper()
	store, err := NewFlatFileLeaseStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestFlatFileLeaseStore_GetLease_NotFound(t *testing.T) {
	store := newTestLeaseStore(t)
	_, err := store.GetLease(context.Background(), "never-acquired")
	require.ErrorIs(t, err, business.ErrLeaseNotFound)
}

func TestFlatFileLeaseStore_AcquireOrRenew_FirstAcquisition(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	state, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Second)
	require.NoError(t, err)
	assert.True(t, state.Acquired)
	assert.Equal(t, uint64(1), state.Token)
	assert.Equal(t, "holder-1", state.HolderID)
}

func TestFlatFileLeaseStore_AcquireOrRenew_RenewByCurrentHolderKeepsToken(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Second)
	require.NoError(t, err)

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Second)
	require.NoError(t, err)
	assert.True(t, second.Acquired)
	assert.Equal(t, first.Token, second.Token)
}

func TestFlatFileLeaseStore_AcquireOrRenew_ContendedByDifferentHolder(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)
	require.True(t, first.Acquired)

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-2", time.Minute)
	require.NoError(t, err)
	assert.False(t, second.Acquired)
	assert.Equal(t, "holder-1", second.HolderID)
	assert.Equal(t, first.Token, second.Token)
}

func TestFlatFileLeaseStore_AcquireOrRenew_ExpiredLeaseAllowsTakeoverWithHigherToken(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", 10*time.Millisecond)
	require.NoError(t, err)
	require.True(t, first.Acquired)

	time.Sleep(20 * time.Millisecond)

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-2", time.Second)
	require.NoError(t, err)
	require.True(t, second.Acquired)
	assert.Greater(t, second.Token, first.Token)
}

// The store reports validity itself, evaluated against the clock that wrote
// ExpiresAt, so callers never compare the stored timestamp to their own notion
// of "now" (business.LeaseStore's "one clock only" contract). For this
// provider that clock is the local process's, since the store and its data
// live in one process.
func TestFlatFileLeaseStore_ReportsValidityAgainstItsOwnClock(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	fresh, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, fresh.Valid, "a freshly acquired lease must be reported valid")

	read, err := store.GetLease(ctx, "singleton-x")
	require.NoError(t, err)
	assert.True(t, read.Valid)

	// A contended read reports the current holder's row, which is valid by
	// definition — that is why the contender lost.
	contended, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-2", time.Minute)
	require.NoError(t, err)
	require.False(t, contended.Acquired)
	assert.True(t, contended.Valid)

	shortLived, err := store.AcquireOrRenew(ctx, "singleton-y", "holder-1", 10*time.Millisecond)
	require.NoError(t, err)
	require.True(t, shortLived.Acquired)
	time.Sleep(30 * time.Millisecond)

	expired, err := store.GetLease(ctx, "singleton-y")
	require.NoError(t, err)
	assert.False(t, expired.Valid, "a lapsed lease must be reported invalid")
	assert.Equal(t, "holder-1", expired.HolderID, "the last holder stays visible on an expired row")
}

func TestFlatFileLeaseStore_Release_PreservesTokenAsHighWaterMark(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)

	require.NoError(t, store.Release(ctx, "singleton-x", "holder-1", first.Token))

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-2", time.Minute)
	require.NoError(t, err)
	require.True(t, second.Acquired)
	assert.Greater(t, second.Token, first.Token)
}

func TestFlatFileLeaseStore_Release_StaleTokenIsNoOp(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)

	require.NoError(t, store.Release(ctx, "singleton-x", "holder-1", first.Token+1))

	current, err := store.GetLease(ctx, "singleton-x")
	require.NoError(t, err)
	assert.Equal(t, "holder-1", current.HolderID)
	assert.Equal(t, first.Token, current.Token)
}

func TestFlatFileLeaseStore_AcquireOrRenew_RejectsEmptyNameOrHolder(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	_, err := store.AcquireOrRenew(ctx, "", "holder-1", time.Second)
	require.Error(t, err)

	_, err = store.AcquireOrRenew(ctx, "singleton-x", "", time.Second)
	require.Error(t, err)
}

// TestFlatFileLeaseStore_SharedAcrossNodes_False pins the substrate declaration the
// controller's cluster-mode startup gate reads (ADR-031 Decision 5). Exclusion here
// is an in-process mutex over a file on one node's disk, which excludes no peer
// node.
func TestFlatFileLeaseStore_SharedAcrossNodes_False(t *testing.T) {
	var store business.LeaseStore = newTestLeaseStore(t)
	assert.False(t, business.LeaseStoreIsNodeShared(store),
		"a per-node JSON file is not a substrate shared across controller nodes")
}
