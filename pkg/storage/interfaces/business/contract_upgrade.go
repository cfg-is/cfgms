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

// UpgradeStoreContract verifies an UpgradeStore round-trips upgrade records and
// their publisher-signature provenance, applies status transitions, and lists
// records by steward and by tenant most-recent-first. IDs, stewards and tenants
// are unique per call, so the store need not be empty. The store is closed at
// the end of the call.
func UpgradeStoreContract(t *testing.T, store UpgradeStore) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	id := func(name string) string { return "upg-" + name + "-" + suffix }
	tenant1 := "tenant-1-" + suffix
	tenant2 := "tenant-2-" + suffix
	created := time.Now().UTC().Truncate(time.Millisecond)

	newRecord := func(name, stewardID, tenantID string) *UpgradeRecord {
		return &UpgradeRecord{
			ID:        id(name),
			StewardID: stewardID,
			TenantID:  tenantID,
			Version:   "v1.2.3",
			Platform:  "linux",
			Arch:      "amd64",
			SHA256:    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			Status:    UpgradeStatusDispatched,
			InitiatedBy: InitiatedByIdentity{
				Subject:    "operator@example.com",
				TenantID:   tenantID,
				AuthMethod: "api_key",
			},
			Publisher:       "cfgms",
			SignatureDigest: "deadbeefdeadbeefdeadbeefdeadbeef",
			BundleSignature: make([]byte, 64),
			CreatedAt:       created,
			OperationNonce:  make([]byte, 32),
			DispatchedAt:    created,
		}
	}

	require.NoError(t, store.Initialize(ctx))
	require.NoError(t, store.HealthCheck(ctx))

	t.Run("create and get round-trip", func(t *testing.T) {
		rec := newRecord("roundtrip", "steward-a-"+suffix, tenant1)
		rec.BundleSignature = []byte("ed25519-signature-over-content-hash-0123456789abcdef0123456789ab")
		rec.OperationNonce = []byte("32byterandomnoncefortheupgrade12")
		require.NoError(t, store.CreateUpgrade(ctx, rec))

		got, err := store.GetUpgrade(ctx, id("roundtrip"))
		require.NoError(t, err)
		assert.Equal(t, id("roundtrip"), got.ID)
		assert.Equal(t, "steward-a-"+suffix, got.StewardID)
		assert.Equal(t, tenant1, got.TenantID)
		assert.Equal(t, "v1.2.3", got.Version)
		assert.Equal(t, "linux", got.Platform)
		assert.Equal(t, "amd64", got.Arch)
		assert.Equal(t, rec.SHA256, got.SHA256)
		assert.Equal(t, UpgradeStatusDispatched, got.Status)
		assert.Equal(t, "operator@example.com", got.InitiatedBy.Subject)
		assert.Equal(t, tenant1, got.InitiatedBy.TenantID)
		assert.Equal(t, "api_key", got.InitiatedBy.AuthMethod)
		assert.Equal(t, "cfgms", got.Publisher)
		assert.Equal(t, rec.SignatureDigest, got.SignatureDigest)
		assert.Equal(t, rec.BundleSignature, got.BundleSignature)
		assert.Equal(t, rec.OperationNonce, got.OperationNonce)
		assert.True(t, created.Equal(got.CreatedAt), "created_at round-trips")
		assert.True(t, created.Equal(got.DispatchedAt), "dispatched_at round-trips")
		assert.Nil(t, got.CompletedAt)
		assert.Empty(t, got.ErrorMessage)
	})

	t.Run("get not found", func(t *testing.T) {
		_, err := store.GetUpgrade(ctx, id("no-such-id"))
		assert.ErrorIs(t, err, ErrUpgradeNotFound)
	})

	t.Run("create rejects empty BundleSignature", func(t *testing.T) {
		rec := newRecord("nosig", "steward-a-"+suffix, tenant1)
		rec.BundleSignature = nil
		require.Error(t, store.CreateUpgrade(ctx, rec), "CreateUpgrade must reject nil BundleSignature")

		rec.BundleSignature = []byte{}
		require.Error(t, store.CreateUpgrade(ctx, rec), "CreateUpgrade must reject empty BundleSignature")

		_, err := store.GetUpgrade(ctx, id("nosig"))
		assert.ErrorIs(t, err, ErrUpgradeNotFound, "a rejected record must not be stored")
	})

	t.Run("update status through all states", func(t *testing.T) {
		require.NoError(t, store.CreateUpgrade(ctx, newRecord("states", "steward-b-"+suffix, tenant1)))

		for _, s := range []UpgradeStatus{UpgradeStatusDownloaded, UpgradeStatusSwapped} {
			require.NoError(t, store.UpdateUpgradeStatus(ctx, id("states"), s, ""))
			got, err := store.GetUpgrade(ctx, id("states"))
			require.NoError(t, err)
			assert.Equal(t, s, got.Status)
			assert.Nil(t, got.CompletedAt, "a non-terminal status leaves CompletedAt unset")
		}

		require.NoError(t, store.UpdateUpgradeStatus(ctx, id("states"), UpgradeStatusCommitted, ""))
		got, err := store.GetUpgrade(ctx, id("states"))
		require.NoError(t, err)
		assert.Equal(t, UpgradeStatusCommitted, got.Status)
		require.NotNil(t, got.CompletedAt, "a terminal status sets CompletedAt")
		assert.False(t, got.CompletedAt.IsZero())
	})

	t.Run("update status to failed sets error message", func(t *testing.T) {
		require.NoError(t, store.CreateUpgrade(ctx, newRecord("fail", "steward-b-"+suffix, tenant1)))

		require.NoError(t, store.UpdateUpgradeStatus(ctx, id("fail"), UpgradeStatusFailed, "disk full"))
		got, err := store.GetUpgrade(ctx, id("fail"))
		require.NoError(t, err)
		assert.Equal(t, UpgradeStatusFailed, got.Status)
		assert.Equal(t, "disk full", got.ErrorMessage)
		require.NotNil(t, got.CompletedAt)
	})

	t.Run("update status to rolled_back sets error message", func(t *testing.T) {
		require.NoError(t, store.CreateUpgrade(ctx, newRecord("rb", "steward-c-"+suffix, tenant2)))

		require.NoError(t, store.UpdateUpgradeStatus(ctx, id("rb"), UpgradeStatusRolledBack, "health check failed"))
		got, err := store.GetUpgrade(ctx, id("rb"))
		require.NoError(t, err)
		assert.Equal(t, UpgradeStatusRolledBack, got.Status)
		assert.Equal(t, "health check failed", got.ErrorMessage)
		require.NotNil(t, got.CompletedAt)
	})

	t.Run("update status keeps provenance", func(t *testing.T) {
		rec := newRecord("prov", "steward-c-"+suffix, tenant2)
		rec.BundleSignature = []byte("signature-that-must-survive-a-status-update-0123456789abcdef-xyz")
		require.NoError(t, store.CreateUpgrade(ctx, rec))
		require.NoError(t, store.UpdateUpgradeStatus(ctx, id("prov"), UpgradeStatusFailed, "boom"))

		got, err := store.GetUpgrade(ctx, id("prov"))
		require.NoError(t, err)
		assert.Equal(t, rec.BundleSignature, got.BundleSignature)
		assert.Equal(t, "cfgms", got.Publisher)
		assert.Equal(t, rec.SignatureDigest, got.SignatureDigest)
		assert.Equal(t, rec.OperationNonce, got.OperationNonce)
	})

	t.Run("update status not found", func(t *testing.T) {
		err := store.UpdateUpgradeStatus(ctx, id("ghost"), UpgradeStatusFailed, "n/a")
		assert.ErrorIs(t, err, ErrUpgradeNotFound)
	})

	t.Run("list by steward", func(t *testing.T) {
		stewardX := "steward-x-" + suffix
		stewardY := "steward-y-" + suffix
		r1 := newRecord("ls-1", stewardX, tenant1)
		r1.CreatedAt = created.Add(-2 * time.Second)
		r2 := newRecord("ls-2", stewardX, tenant1)
		r2.CreatedAt = created.Add(-1 * time.Second)
		r3 := newRecord("ls-3", stewardY, tenant1)

		require.NoError(t, store.CreateUpgrade(ctx, r1))
		require.NoError(t, store.CreateUpgrade(ctx, r2))
		require.NoError(t, store.CreateUpgrade(ctx, r3))

		list, err := store.ListUpgradesBySteward(ctx, stewardX)
		require.NoError(t, err)
		require.Len(t, list, 2)
		assert.Equal(t, id("ls-2"), list[0].ID, "most recent first")
		assert.Equal(t, id("ls-1"), list[1].ID)

		listY, err := store.ListUpgradesBySteward(ctx, stewardY)
		require.NoError(t, err)
		assert.Len(t, listY, 1)

		listNone, err := store.ListUpgradesBySteward(ctx, "steward-unknown-"+suffix)
		require.NoError(t, err)
		assert.Empty(t, listNone, "an unknown steward is an empty list, not an error")
	})

	t.Run("list by tenant", func(t *testing.T) {
		tenantA := "tenant-A-" + suffix
		tenantB := "tenant-B-" + suffix
		r1 := newRecord("lt-1", "steward-p-"+suffix, tenantA)
		r1.CreatedAt = created.Add(-2 * time.Second)
		r2 := newRecord("lt-2", "steward-q-"+suffix, tenantA)
		r2.CreatedAt = created.Add(-1 * time.Second)
		r3 := newRecord("lt-3", "steward-p-"+suffix, tenantB)

		require.NoError(t, store.CreateUpgrade(ctx, r1))
		require.NoError(t, store.CreateUpgrade(ctx, r2))
		require.NoError(t, store.CreateUpgrade(ctx, r3))

		listA, err := store.ListUpgradesByTenant(ctx, tenantA)
		require.NoError(t, err)
		require.Len(t, listA, 2)
		assert.Equal(t, id("lt-2"), listA[0].ID, "most recent first")
		assert.Equal(t, id("lt-1"), listA[1].ID)

		listB, err := store.ListUpgradesByTenant(ctx, tenantB)
		require.NoError(t, err)
		require.Len(t, listB, 1)
		assert.Equal(t, id("lt-3"), listB[0].ID)

		listNone, err := store.ListUpgradesByTenant(ctx, "tenant-unknown-"+suffix)
		require.NoError(t, err)
		assert.Empty(t, listNone, "an unknown tenant is an empty list, not an error")
	})

	require.NoError(t, store.Close())
}
