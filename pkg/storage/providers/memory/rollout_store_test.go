// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package memory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/memory"
)

func newMemTestRollout(id, tenantID string) *business.RolloutRecord {
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

func TestRolloutStore_Memory_InitializeAndHealthCheck(t *testing.T) {
	store := memory.NewRolloutStore()
	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx))
	require.NoError(t, store.HealthCheck(ctx))
	require.NoError(t, store.Close())
}

func TestRolloutStore_Memory_CreateAndGet(t *testing.T) {
	store := memory.NewRolloutStore()
	ctx := context.Background()

	rec := newMemTestRollout("r-1", "tenant-1")
	require.NoError(t, store.CreateRollout(ctx, rec))

	got, err := store.GetRollout(ctx, "r-1")
	require.NoError(t, err)
	assert.Equal(t, "r-1", got.ID)
	assert.Equal(t, "tenant-1", got.TenantID)
	assert.Equal(t, "v2.0.0", got.TargetVersion)
	assert.Equal(t, "canary", got.CurrentRing)
	assert.Equal(t, 0, got.RingsCompleted)
	assert.Equal(t, 4, got.RingsTotal)
	assert.Equal(t, business.RolloutStatusInProgress, got.Status)
	assert.Nil(t, got.HaltedAt)
	assert.Empty(t, got.Error)
}

func TestRolloutStore_Memory_CreateDuplicateIDReturnsError(t *testing.T) {
	store := memory.NewRolloutStore()
	ctx := context.Background()

	rec := newMemTestRollout("r-dup", "tenant-1")
	require.NoError(t, store.CreateRollout(ctx, rec))
	err := store.CreateRollout(ctx, rec)
	require.Error(t, err)
}

func TestRolloutStore_Memory_GetNotFound(t *testing.T) {
	store := memory.NewRolloutStore()
	_, err := store.GetRollout(context.Background(), "no-such-id")
	assert.ErrorIs(t, err, business.ErrRolloutNotFound)
}

func TestRolloutStore_Memory_UpdateRolloutProgress(t *testing.T) {
	store := memory.NewRolloutStore()
	ctx := context.Background()

	require.NoError(t, store.CreateRollout(ctx, newMemTestRollout("r-prog", "tenant-1")))

	require.NoError(t, store.UpdateRolloutProgress(ctx, "r-prog", business.RolloutStatusInProgress, "early", 1, nil, ""))
	got, err := store.GetRollout(ctx, "r-prog")
	require.NoError(t, err)
	assert.Equal(t, business.RolloutStatusInProgress, got.Status)
	assert.Equal(t, "early", got.CurrentRing)
	assert.Equal(t, 1, got.RingsCompleted)
	assert.Nil(t, got.HaltedAt)

	require.NoError(t, store.UpdateRolloutProgress(ctx, "r-prog", business.RolloutStatusCompleted, "", 4, nil, ""))
	got, err = store.GetRollout(ctx, "r-prog")
	require.NoError(t, err)
	assert.Equal(t, business.RolloutStatusCompleted, got.Status)
	assert.Equal(t, 4, got.RingsCompleted)
}

func TestRolloutStore_Memory_UpdateRolloutProgressHalted(t *testing.T) {
	store := memory.NewRolloutStore()
	ctx := context.Background()

	require.NoError(t, store.CreateRollout(ctx, newMemTestRollout("r-halt", "tenant-1")))

	haltTime := time.Now().UTC()
	require.NoError(t, store.UpdateRolloutProgress(ctx, "r-halt", business.RolloutStatusHalted, "canary", 0, &haltTime, "failure rate exceeded"))

	got, err := store.GetRollout(ctx, "r-halt")
	require.NoError(t, err)
	assert.Equal(t, business.RolloutStatusHalted, got.Status)
	assert.Equal(t, "failure rate exceeded", got.Error)
	require.NotNil(t, got.HaltedAt)
}

func TestRolloutStore_Memory_UpdateRolloutProgressNotFound(t *testing.T) {
	store := memory.NewRolloutStore()
	err := store.UpdateRolloutProgress(context.Background(), "ghost", business.RolloutStatusHalted, "", 0, nil, "")
	assert.ErrorIs(t, err, business.ErrRolloutNotFound)
}

func TestRolloutStore_Memory_AppendDeferredStewards(t *testing.T) {
	store := memory.NewRolloutStore()
	ctx := context.Background()

	require.NoError(t, store.CreateRollout(ctx, newMemTestRollout("r-deferred", "tenant-1")))

	require.NoError(t, store.AppendDeferredStewards(ctx, "r-deferred", []string{"s-1", "s-2"}))
	require.NoError(t, store.AppendDeferredStewards(ctx, "r-deferred", []string{"s-3"}))

	got, err := store.GetRollout(ctx, "r-deferred")
	require.NoError(t, err)
	assert.Equal(t, []string{"s-1", "s-2", "s-3"}, got.DeferredStewards)
}

func TestRolloutStore_Memory_AppendDeferredStewardsNotFound(t *testing.T) {
	store := memory.NewRolloutStore()
	err := store.AppendDeferredStewards(context.Background(), "ghost", []string{"s-x"})
	assert.ErrorIs(t, err, business.ErrRolloutNotFound)
}

func TestRolloutStore_Memory_ListRolloutsByTenant(t *testing.T) {
	store := memory.NewRolloutStore()
	ctx := context.Background()

	require.NoError(t, store.CreateRollout(ctx, newMemTestRollout("r-a1", "tenant-A")))
	require.NoError(t, store.CreateRollout(ctx, newMemTestRollout("r-a2", "tenant-A")))
	require.NoError(t, store.CreateRollout(ctx, newMemTestRollout("r-b1", "tenant-B")))

	listA, err := store.ListRolloutsByTenant(ctx, "tenant-A")
	require.NoError(t, err)
	assert.Len(t, listA, 2)

	listB, err := store.ListRolloutsByTenant(ctx, "tenant-B")
	require.NoError(t, err)
	assert.Len(t, listB, 1)
	assert.Equal(t, "r-b1", listB[0].ID)

	listNone, err := store.ListRolloutsByTenant(ctx, "tenant-unknown")
	require.NoError(t, err)
	assert.Empty(t, listNone)
}

func TestRolloutStore_Memory_ConcurrencySafe(t *testing.T) {
	store := memory.NewRolloutStore()
	ctx := context.Background()

	const workers = 20
	errs := make(chan error, workers*4)
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := range workers {
		go func(n int) {
			defer wg.Done()
			id := "concurrent-r-" + string(rune('a'+n))
			tenantID := "tenant-" + string(rune('a'+n%3))
			rec := newMemTestRollout(id, tenantID)
			if err := store.CreateRollout(ctx, rec); err != nil {
				errs <- err
				return
			}
			if _, err := store.GetRollout(ctx, id); err != nil {
				errs <- err
			}
			if err := store.UpdateRolloutProgress(ctx, id, business.RolloutStatusInProgress, "early", 1, nil, ""); err != nil {
				errs <- err
			}
			if _, err := store.ListRolloutsByTenant(ctx, tenantID); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}

func TestRolloutStore_Memory_CreateIsolatesFromMutation(t *testing.T) {
	store := memory.NewRolloutStore()
	ctx := context.Background()

	rec := newMemTestRollout("r-alias", "tenant-1")
	require.NoError(t, store.CreateRollout(ctx, rec))

	// Mutating original after create must not affect stored copy.
	rec.Status = business.RolloutStatusHalted
	rec.DeferredStewards = append(rec.DeferredStewards, "s-injected")

	got, err := store.GetRollout(ctx, "r-alias")
	require.NoError(t, err)
	assert.Equal(t, business.RolloutStatusInProgress, got.Status)
	assert.Empty(t, got.DeferredStewards, "DeferredStewards must be deep-copied on create")
}

func TestRolloutStore_Memory_GetIsolatesFromMutation(t *testing.T) {
	store := memory.NewRolloutStore()
	ctx := context.Background()

	require.NoError(t, store.CreateRollout(ctx, newMemTestRollout("r-get-alias", "tenant-1")))

	got, err := store.GetRollout(ctx, "r-get-alias")
	require.NoError(t, err)

	// Mutating returned copy must not affect stored value.
	got.Status = business.RolloutStatusHalted
	got.DeferredStewards = append(got.DeferredStewards, "s-extra")

	got2, err := store.GetRollout(ctx, "r-get-alias")
	require.NoError(t, err)
	assert.Equal(t, business.RolloutStatusInProgress, got2.Status)
	assert.Empty(t, got2.DeferredStewards, "DeferredStewards must be deep-copied on get")
}
