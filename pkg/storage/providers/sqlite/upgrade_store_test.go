// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestUpgradeStore creates a file-backed SQLiteUpgradeStore for tests using a
// t.TempDir() path so the DB is cleaned up automatically.
func newTestUpgradeStore(t *testing.T) *SQLiteUpgradeStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "upgrade_test.db")
	store, err := NewUpgradeStoreSQLFromDSN("file:" + dbPath)
	require.NoError(t, err)
	require.NoError(t, store.Initialize(context.Background()))
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// testUpgradeRecord returns an UpgradeRecord with all mandatory fields populated.
func testUpgradeRecord(id string) *business.UpgradeRecord {
	return &business.UpgradeRecord{
		ID:        id,
		StewardID: "steward-" + id,
		TenantID:  "tenant-1",
		Version:   "v1.2.3",
		Platform:  "linux",
		Arch:      "amd64",
		SHA256:    "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
		Status:    business.UpgradeStatusDispatched,
		InitiatedBy: business.InitiatedByIdentity{
			Subject:    "admin@example.com",
			TenantID:   "tenant-1",
			AuthMethod: "api_key",
		},
		Publisher:       "cfgms",
		SignatureDigest: "sha256:deadbeef",
		BundleSignature: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		CreatedAt:       time.Now().UTC().Truncate(time.Second),
		OperationNonce:  []byte{0xde, 0xad, 0xbe, 0xef},
		DispatchedAt:    time.Now().UTC().Truncate(time.Second),
	}
}

func TestUpgradeStore_CreateAndGet(t *testing.T) {
	store := newTestUpgradeStore(t)
	ctx := context.Background()

	rec := testUpgradeRecord("upg-001")
	require.NoError(t, store.CreateUpgrade(ctx, rec))

	got, err := store.GetUpgrade(ctx, "upg-001")
	require.NoError(t, err)

	assert.Equal(t, rec.ID, got.ID)
	assert.Equal(t, rec.StewardID, got.StewardID)
	assert.Equal(t, rec.TenantID, got.TenantID)
	assert.Equal(t, rec.Version, got.Version)
	assert.Equal(t, rec.Platform, got.Platform)
	assert.Equal(t, rec.Arch, got.Arch)
	assert.Equal(t, rec.SHA256, got.SHA256)
	assert.Equal(t, rec.Status, got.Status)
	assert.Equal(t, rec.InitiatedBy.Subject, got.InitiatedBy.Subject)
	assert.Equal(t, rec.InitiatedBy.TenantID, got.InitiatedBy.TenantID)
	assert.Equal(t, rec.InitiatedBy.AuthMethod, got.InitiatedBy.AuthMethod)
	assert.Equal(t, rec.Publisher, got.Publisher)
	assert.Equal(t, rec.SignatureDigest, got.SignatureDigest)
	assert.Equal(t, rec.BundleSignature, got.BundleSignature)
	assert.Equal(t, rec.OperationNonce, got.OperationNonce)
	assert.Equal(t, rec.ErrorMessage, got.ErrorMessage)
	assert.Nil(t, got.CompletedAt)
	assert.False(t, got.CreatedAt.IsZero(), "CreatedAt should be set")
	assert.False(t, got.DispatchedAt.IsZero(), "DispatchedAt should be set")
}

func TestUpgradeStore_GetUpgrade_NotFound(t *testing.T) {
	store := newTestUpgradeStore(t)
	_, err := store.GetUpgrade(context.Background(), "does-not-exist")
	assert.ErrorIs(t, err, business.ErrUpgradeNotFound)
}

func TestUpgradeStore_UpdateStatus(t *testing.T) {
	store := newTestUpgradeStore(t)
	ctx := context.Background()

	rec := testUpgradeRecord("upg-upd")
	require.NoError(t, store.CreateUpgrade(ctx, rec))

	require.NoError(t, store.UpdateUpgradeStatus(ctx, "upg-upd", business.UpgradeStatusDownloaded, ""))

	got, err := store.GetUpgrade(ctx, "upg-upd")
	require.NoError(t, err)
	assert.Equal(t, business.UpgradeStatusDownloaded, got.Status)
	assert.Nil(t, got.CompletedAt, "completed_at should remain nil for non-terminal status")
}

func TestUpgradeStore_UpdateStatus_TerminalSetsCompletedAt(t *testing.T) {
	store := newTestUpgradeStore(t)
	ctx := context.Background()

	rec := testUpgradeRecord("upg-terminal")
	require.NoError(t, store.CreateUpgrade(ctx, rec))

	require.NoError(t, store.UpdateUpgradeStatus(ctx, "upg-terminal", business.UpgradeStatusFailed, "binary checksum mismatch"))

	got, err := store.GetUpgrade(ctx, "upg-terminal")
	require.NoError(t, err)
	assert.Equal(t, business.UpgradeStatusFailed, got.Status)
	assert.Equal(t, "binary checksum mismatch", got.ErrorMessage)
	require.NotNil(t, got.CompletedAt, "completed_at must be set for terminal status")
	assert.False(t, got.CompletedAt.IsZero())
}

func TestUpgradeStore_UpdateStatus_NotFound(t *testing.T) {
	store := newTestUpgradeStore(t)
	err := store.UpdateUpgradeStatus(context.Background(), "ghost", business.UpgradeStatusFailed, "")
	assert.ErrorIs(t, err, business.ErrUpgradeNotFound)
}

func TestUpgradeStore_CreateUpgrade_MissingSignature(t *testing.T) {
	store := newTestUpgradeStore(t)
	ctx := context.Background()

	rec := testUpgradeRecord("upg-nosig")
	rec.BundleSignature = nil
	err := store.CreateUpgrade(ctx, rec)
	assert.Error(t, err, "CreateUpgrade must reject nil BundleSignature")

	rec.BundleSignature = []byte{}
	err = store.CreateUpgrade(ctx, rec)
	assert.Error(t, err, "CreateUpgrade must reject empty BundleSignature")
}

func TestUpgradeStore_ListBySteward(t *testing.T) {
	store := newTestUpgradeStore(t)
	ctx := context.Background()

	r1 := testUpgradeRecord("upg-a")
	r1.StewardID = "steward-target"
	r1.CreatedAt = time.Now().UTC().Add(-2 * time.Second).Truncate(time.Second)
	require.NoError(t, store.CreateUpgrade(ctx, r1))

	r2 := testUpgradeRecord("upg-b")
	r2.StewardID = "steward-target"
	r2.CreatedAt = time.Now().UTC().Truncate(time.Second)
	require.NoError(t, store.CreateUpgrade(ctx, r2))

	other := testUpgradeRecord("upg-other")
	other.StewardID = "steward-other"
	require.NoError(t, store.CreateUpgrade(ctx, other))

	results, err := store.ListUpgradesBySteward(ctx, "steward-target")
	require.NoError(t, err)
	require.Len(t, results, 2)
	// Most recent first.
	assert.Equal(t, "upg-b", results[0].ID)
	assert.Equal(t, "upg-a", results[1].ID)
}

func TestUpgradeStore_ListBySteward_Empty(t *testing.T) {
	store := newTestUpgradeStore(t)
	results, err := store.ListUpgradesBySteward(context.Background(), "no-such-steward")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestUpgradeStore_ListByTenant(t *testing.T) {
	store := newTestUpgradeStore(t)
	ctx := context.Background()

	r1 := testUpgradeRecord("upg-ta")
	r1.TenantID = "tenant-target"
	r1.CreatedAt = time.Now().UTC().Add(-2 * time.Second).Truncate(time.Second)
	require.NoError(t, store.CreateUpgrade(ctx, r1))

	r2 := testUpgradeRecord("upg-tb")
	r2.TenantID = "tenant-target"
	r2.CreatedAt = time.Now().UTC().Truncate(time.Second)
	require.NoError(t, store.CreateUpgrade(ctx, r2))

	other := testUpgradeRecord("upg-other-tenant")
	other.TenantID = "tenant-other"
	require.NoError(t, store.CreateUpgrade(ctx, other))

	results, err := store.ListUpgradesByTenant(ctx, "tenant-target")
	require.NoError(t, err)
	require.Len(t, results, 2)
	// Most recent first.
	assert.Equal(t, "upg-tb", results[0].ID)
	assert.Equal(t, "upg-ta", results[1].ID)
}

func TestUpgradeStore_ListByTenant_Empty(t *testing.T) {
	store := newTestUpgradeStore(t)
	results, err := store.ListUpgradesByTenant(context.Background(), "no-such-tenant")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestUpgradeStore_Initialize_Idempotent(t *testing.T) {
	store := newTestUpgradeStore(t)
	// Initialize was already called in newTestUpgradeStore; calling again must not error.
	assert.NoError(t, store.Initialize(context.Background()))
	assert.NoError(t, store.Initialize(context.Background()))
}

func TestUpgradeStore_HealthCheck(t *testing.T) {
	store := newTestUpgradeStore(t)
	assert.NoError(t, store.HealthCheck(context.Background()))
}

// TestUpgradeStore_DurabilityAcrossRestart is the regression test for Issue #2464.
// It closes a store, reopens a new store against the same DSN (simulating a controller
// restart), and verifies that records created before the close are still readable.
func TestUpgradeStore_DurabilityAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "upgrade_persist.db")
	dsn := "file:" + dbPath
	ctx := context.Background()

	// First "controller instance": create a record and close.
	store1, err := NewUpgradeStoreSQLFromDSN(dsn)
	require.NoError(t, err)
	require.NoError(t, store1.Initialize(ctx))

	rec := testUpgradeRecord("upg-persist")
	require.NoError(t, store1.CreateUpgrade(ctx, rec))
	require.NoError(t, store1.UpdateUpgradeStatus(ctx, "upg-persist", business.UpgradeStatusDownloaded, ""))
	require.NoError(t, store1.Close())

	// Second "controller instance": reopen and verify the record survived.
	store2, err := NewUpgradeStoreSQLFromDSN(dsn)
	require.NoError(t, err)
	require.NoError(t, store2.Initialize(ctx))
	defer func() { _ = store2.Close() }()

	got, err := store2.GetUpgrade(ctx, "upg-persist")
	require.NoError(t, err, "upgrade record must survive a controller restart (SQLite durability)")
	assert.Equal(t, "upg-persist", got.ID)
	assert.Equal(t, business.UpgradeStatusDownloaded, got.Status)
	assert.Equal(t, rec.BundleSignature, got.BundleSignature)
	assert.Equal(t, rec.Publisher, got.Publisher)

	// ListBySteward must also return the record.
	list, err := store2.ListUpgradesBySteward(ctx, rec.StewardID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "upg-persist", list[0].ID)
}
