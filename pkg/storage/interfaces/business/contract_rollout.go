// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RolloutStoreContract verifies a RolloutStore round-trips rollout records,
// progress and halt updates, deferred stewards and the cross-tenant in-progress
// listing. IDs and tenants are unique per call, so the store need not be empty.
func RolloutStoreContract(t *testing.T, store RolloutStore) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	id := func(name string) string { return "rollout-" + name + "-" + suffix }
	tenantA := "tenant-a-" + suffix
	tenantB := "tenant-b-" + suffix
	started := time.Now().UTC().Truncate(time.Millisecond)

	newRecord := func(name, tenant string) *RolloutRecord {
		return &RolloutRecord{
			ID:               id(name),
			TenantID:         tenant,
			InitiatedBy:      "admin-1",
			TargetVersion:    "v2.0.0",
			CurrentRing:      "canary",
			RingsTotal:       4,
			Status:           RolloutStatusInProgress,
			StartedAt:        started,
			OwnerNodeID:      "node-a",
			DeferredStewards: []string{},
		}
	}

	require.NoError(t, store.Initialize(ctx))
	require.NoError(t, store.HealthCheck(ctx))

	t.Run("create and get round-trip", func(t *testing.T) {
		require.NoError(t, store.CreateRollout(ctx, newRecord("roundtrip", tenantA)))

		got, err := store.GetRollout(ctx, id("roundtrip"))
		require.NoError(t, err)
		assert.Equal(t, id("roundtrip"), got.ID)
		assert.Equal(t, tenantA, got.TenantID)
		assert.Equal(t, "admin-1", got.InitiatedBy)
		assert.Equal(t, "v2.0.0", got.TargetVersion)
		assert.Equal(t, "canary", got.CurrentRing)
		assert.Equal(t, 0, got.RingsCompleted)
		assert.Equal(t, 4, got.RingsTotal)
		assert.Equal(t, RolloutStatusInProgress, got.Status)
		assert.True(t, started.Equal(got.StartedAt), "started_at round-trips")
		assert.Equal(t, "node-a", got.OwnerNodeID, "the owner node round-trips")
		assert.Nil(t, got.HaltedAt)
		assert.Empty(t, got.Error)
		assert.Empty(t, got.DeferredStewards)
	})

	t.Run("empty owner round-trips", func(t *testing.T) {
		rec := newRecord("no-owner", tenantA)
		rec.OwnerNodeID = ""
		require.NoError(t, store.CreateRollout(ctx, rec))
		got, err := store.GetRollout(ctx, id("no-owner"))
		require.NoError(t, err)
		assert.Empty(t, got.OwnerNodeID)
	})

	t.Run("duplicate ID returns error", func(t *testing.T) {
		rec := newRecord("dup", tenantA)
		require.NoError(t, store.CreateRollout(ctx, rec))
		require.Error(t, store.CreateRollout(ctx, rec))
	})

	t.Run("get not found returns ErrRolloutNotFound", func(t *testing.T) {
		_, err := store.GetRollout(ctx, id("no-such-id"))
		assert.ErrorIs(t, err, ErrRolloutNotFound)
	})

	t.Run("UpdateRolloutProgress reflects in Get", func(t *testing.T) {
		require.NoError(t, store.CreateRollout(ctx, newRecord("progress", tenantA)))

		require.NoError(t, store.UpdateRolloutProgress(ctx, id("progress"), RolloutStatusInProgress, "early", 1, nil, ""))
		got, err := store.GetRollout(ctx, id("progress"))
		require.NoError(t, err)
		assert.Equal(t, RolloutStatusInProgress, got.Status)
		assert.Equal(t, "early", got.CurrentRing)
		assert.Equal(t, 1, got.RingsCompleted)
		assert.Nil(t, got.HaltedAt)
		assert.Equal(t, "node-a", got.OwnerNodeID, "a progress update leaves the owner alone")

		require.NoError(t, store.UpdateRolloutProgress(ctx, id("progress"), RolloutStatusCompleted, "", 4, nil, ""))
		got, err = store.GetRollout(ctx, id("progress"))
		require.NoError(t, err)
		assert.Equal(t, RolloutStatusCompleted, got.Status)
		assert.Equal(t, 4, got.RingsCompleted)
		assert.Empty(t, got.CurrentRing)
	})

	t.Run("UpdateRolloutProgress halted sets HaltedAt and error", func(t *testing.T) {
		require.NoError(t, store.CreateRollout(ctx, newRecord("halt", tenantA)))

		haltTime := time.Now().UTC().Truncate(time.Millisecond)
		require.NoError(t, store.UpdateRolloutProgress(ctx, id("halt"), RolloutStatusHalted, "canary", 0, &haltTime, "error rate exceeded threshold"))

		got, err := store.GetRollout(ctx, id("halt"))
		require.NoError(t, err)
		assert.Equal(t, RolloutStatusHalted, got.Status)
		assert.Equal(t, "error rate exceeded threshold", got.Error)
		require.NotNil(t, got.HaltedAt)
		assert.True(t, haltTime.Equal(*got.HaltedAt), "halted_at round-trips")
	})

	t.Run("UpdateRolloutProgress not found", func(t *testing.T) {
		err := store.UpdateRolloutProgress(ctx, id("ghost"), RolloutStatusHalted, "", 0, nil, "")
		assert.ErrorIs(t, err, ErrRolloutNotFound)
	})

	t.Run("deferred-retry list persists across appends", func(t *testing.T) {
		require.NoError(t, store.CreateRollout(ctx, newRecord("deferred", tenantA)))

		require.NoError(t, store.AppendDeferredStewards(ctx, id("deferred"), []string{"s-1", "s-2"}))
		require.NoError(t, store.AppendDeferredStewards(ctx, id("deferred"), []string{"s-3"}))

		got, err := store.GetRollout(ctx, id("deferred"))
		require.NoError(t, err)
		assert.Equal(t, []string{"s-1", "s-2", "s-3"}, got.DeferredStewards)
	})

	t.Run("AppendDeferredStewards not found", func(t *testing.T) {
		err := store.AppendDeferredStewards(ctx, id("ghost"), []string{"s-x"})
		assert.ErrorIs(t, err, ErrRolloutNotFound)
	})

	t.Run("ListRolloutsByTenant scopes by tenant", func(t *testing.T) {
		tenantC := "tenant-c-" + suffix
		require.NoError(t, store.CreateRollout(ctx, newRecord("tc-1", tenantC)))
		require.NoError(t, store.CreateRollout(ctx, newRecord("tc-2", tenantC)))
		require.NoError(t, store.CreateRollout(ctx, newRecord("td-1", "tenant-d-"+suffix)))

		listC, err := store.ListRolloutsByTenant(ctx, tenantC)
		require.NoError(t, err)
		assert.Len(t, listC, 2)

		listD, err := store.ListRolloutsByTenant(ctx, "tenant-d-"+suffix)
		require.NoError(t, err)
		require.Len(t, listD, 1)
		assert.Equal(t, id("td-1"), listD[0].ID)

		listNone, err := store.ListRolloutsByTenant(ctx, "tenant-unknown-"+suffix)
		require.NoError(t, err)
		assert.Empty(t, listNone)
	})

	t.Run("ListInProgressRollouts returns only in-progress records across tenants", func(t *testing.T) {
		require.NoError(t, store.CreateRollout(ctx, newRecord("ip-a", tenantB)))
		require.NoError(t, store.CreateRollout(ctx, newRecord("ip-b", "tenant-e-"+suffix)))
		require.NoError(t, store.CreateRollout(ctx, newRecord("ip-halted", tenantB)))
		require.NoError(t, store.CreateRollout(ctx, newRecord("ip-done", tenantB)))
		now := time.Now().UTC()
		require.NoError(t, store.UpdateRolloutProgress(ctx, id("ip-halted"), RolloutStatusHalted, "canary", 0, &now, "halted"))
		require.NoError(t, store.UpdateRolloutProgress(ctx, id("ip-done"), RolloutStatusCompleted, "", 4, nil, ""))

		list, err := store.ListInProgressRollouts(ctx)
		require.NoError(t, err)
		byID := map[string]*RolloutRecord{}
		for _, r := range list {
			assert.Equal(t, RolloutStatusInProgress, r.Status, "only in-progress records are listed")
			byID[r.ID] = r
		}
		assert.Contains(t, byID, id("ip-a"))
		assert.Contains(t, byID, id("ip-b"), "records of other tenants are listed too")
		assert.NotContains(t, byID, id("ip-halted"))
		assert.NotContains(t, byID, id("ip-done"))
		assert.Equal(t, "node-a", byID[id("ip-a")].OwnerNodeID)
	})

	require.NoError(t, store.Close())
}
