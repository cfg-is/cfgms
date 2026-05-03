// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/database"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// ---- compile-time interface checks -----------------------------------------

// TestStorageProvidersImplementTriggerStore verifies that all three providers
// satisfy StorageProvider, which now includes CreateTriggerStore.
func TestStorageProvidersImplementTriggerStore(t *testing.T) {
	var _ interfaces.StorageProvider = (*flatfile.FlatFileProvider)(nil)
	var _ interfaces.StorageProvider = (*database.DatabaseProvider)(nil)
	var _ interfaces.StorageProvider = (*sqlite.SQLiteProvider)(nil)
	var _ business.TriggerStore = (*sqlite.SQLiteTriggerStore)(nil)
}

// ---- factory tests ---------------------------------------------------------

// TestCreateTriggerStorePerProvider verifies each provider's CreateTriggerStore behaviour:
// - flatfile and database return ErrNotSupported
// - SQLite returns a real *SQLiteTriggerStore
func TestCreateTriggerStorePerProvider(t *testing.T) {
	t.Run("flatfile returns ErrNotSupported", func(t *testing.T) {
		p := &flatfile.FlatFileProvider{}
		_, err := p.CreateTriggerStore(map[string]interface{}{})
		require.Error(t, err)
		// flatfile uses its own package-level ErrNotSupported (separate from business.ErrNotSupported)
		assert.ErrorIs(t, err, flatfile.ErrNotSupported)
	})

	t.Run("database returns ErrNotSupported", func(t *testing.T) {
		p := &database.DatabaseProvider{}
		_, err := p.CreateTriggerStore(map[string]interface{}{})
		require.Error(t, err)
		assert.ErrorIs(t, err, business.ErrNotSupported)
	})

	t.Run("sqlite returns real TriggerStore", func(t *testing.T) {
		p := sqlite.NewSQLiteProvider(":memory:")
		store, err := p.CreateTriggerStore(map[string]interface{}{"path": ":memory:"})
		require.NoError(t, err)
		require.NotNil(t, store)
		t.Cleanup(func() { _ = store.Close() })
	})
}

// ---- helper ----------------------------------------------------------------

func newTestTriggerStore(t *testing.T) *sqlite.SQLiteTriggerStore {
	t.Helper()
	p := sqlite.NewSQLiteProvider(":memory:")
	store, err := p.CreateTriggerStore(map[string]interface{}{"path": ":memory:"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store.(*sqlite.SQLiteTriggerStore)
}

func testTriggerRecord(id, tenantID string) *business.TriggerRecord {
	return &business.TriggerRecord{
		ID:               id,
		TenantID:         tenantID,
		Name:             "on-push-" + id,
		Type:             "webhook",
		Status:           "active",
		WorkflowName:     "deploy",
		WebhookPath:      "/hooks/" + id,
		WebhookMethod:    []string{"POST"},
		BearerTokenRef:   "secrets/" + tenantID + "/" + id + "/bearer",
		HMACSecretRef:    "secrets/" + tenantID + "/" + id + "/hmac",
		APIKeyRef:        "",
		BasicUsernameRef: "",
		BasicPasswordRef: "",
		ConfigPayload:    []byte(`{"timeout":30}`),
	}
}

// ---- TestSQLiteTriggerStoreCRUD --------------------------------------------

// TestSQLiteTriggerStoreCRUD verifies store/retrieve/delete round-trip with no data loss.
func TestSQLiteTriggerStoreCRUD(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	rec := testTriggerRecord("trig-001", "tenant-a")
	rec.CreatedAt = time.Now().UTC().Truncate(time.Second)

	// Store
	require.NoError(t, store.StoreTrigger(ctx, rec))

	// Get — verify all fields preserved
	got, err := store.GetTrigger(ctx, "trig-001")
	require.NoError(t, err)
	assert.Equal(t, "trig-001", got.ID)
	assert.Equal(t, "tenant-a", got.TenantID)
	assert.Equal(t, "on-push-trig-001", got.Name)
	assert.Equal(t, "webhook", got.Type)
	assert.Equal(t, "active", got.Status)
	assert.Equal(t, "deploy", got.WorkflowName)
	assert.Equal(t, "/hooks/trig-001", got.WebhookPath)
	assert.Equal(t, []string{"POST"}, got.WebhookMethod)
	assert.Equal(t, "secrets/tenant-a/trig-001/bearer", got.BearerTokenRef)
	assert.Equal(t, "secrets/tenant-a/trig-001/hmac", got.HMACSecretRef)
	assert.Empty(t, got.APIKeyRef)
	assert.Empty(t, got.BasicUsernameRef)
	assert.Empty(t, got.BasicPasswordRef)
	assert.Equal(t, []byte(`{"timeout":30}`), got.ConfigPayload)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())

	// Update — change status and verify upsert
	rec.Status = "inactive"
	require.NoError(t, store.StoreTrigger(ctx, rec))
	got2, err := store.GetTrigger(ctx, "trig-001")
	require.NoError(t, err)
	assert.Equal(t, "inactive", got2.Status)

	// Delete
	require.NoError(t, store.DeleteTrigger(ctx, "trig-001"))

	// Confirm deleted
	_, err = store.GetTrigger(ctx, "trig-001")
	assert.ErrorIs(t, err, business.ErrTriggerNotFound)
}

// ---- TestTriggerStoreTenantIsolation ---------------------------------------

// TestTriggerStoreTenantIsolation verifies that ListTriggers filtered by tenant-b
// does NOT return records belonging to tenant-a.
func TestTriggerStoreTenantIsolation(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	trigA := testTriggerRecord("trig-a1", "tenant-a")
	trigB := testTriggerRecord("trig-b1", "tenant-b")

	require.NoError(t, store.StoreTrigger(ctx, trigA))
	require.NoError(t, store.StoreTrigger(ctx, trigB))

	// List for tenant-b must not include tenant-a's record.
	results, err := store.ListTriggers(ctx, business.TriggerStoreFilter{TenantID: "tenant-b"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "trig-b1", results[0].ID)
	assert.Equal(t, "tenant-b", results[0].TenantID)

	// Symmetrically, tenant-a query must not include tenant-b's record.
	results, err = store.ListTriggers(ctx, business.TriggerStoreFilter{TenantID: "tenant-a"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "trig-a1", results[0].ID)
}

// ---- error path tests -------------------------------------------------------

func TestSQLiteTriggerStore_StoreTrigger_NilRecord(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()
	err := store.StoreTrigger(ctx, nil)
	require.Error(t, err)
}

func TestSQLiteTriggerStore_StoreTrigger_EmptyID(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()
	rec := testTriggerRecord("", "tenant-a")
	err := store.StoreTrigger(ctx, rec)
	require.Error(t, err)
}

func TestSQLiteTriggerStore_StoreTrigger_EmptyTenantID(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()
	rec := testTriggerRecord("trig-notenant", "")
	err := store.StoreTrigger(ctx, rec)
	require.Error(t, err)
}

func TestSQLiteTriggerStore_GetTrigger_NotFound(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()
	_, err := store.GetTrigger(ctx, "nonexistent")
	require.ErrorIs(t, err, business.ErrTriggerNotFound)
}

func TestSQLiteTriggerStore_GetTrigger_EmptyID(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()
	_, err := store.GetTrigger(ctx, "")
	require.Error(t, err)
}

func TestSQLiteTriggerStore_DeleteTrigger_NotFound(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()
	err := store.DeleteTrigger(ctx, "nonexistent")
	require.ErrorIs(t, err, business.ErrTriggerNotFound)
}

func TestSQLiteTriggerStore_DeleteTrigger_EmptyID(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()
	err := store.DeleteTrigger(ctx, "")
	require.Error(t, err)
}

// ---- ListTriggers filter tests ----------------------------------------------

func TestSQLiteTriggerStore_ListTriggers_ByType(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	webhook := testTriggerRecord("t-webhook", "tenant-x")
	webhook.Type = "webhook"
	schedule := testTriggerRecord("t-schedule", "tenant-x")
	schedule.Type = "schedule"

	require.NoError(t, store.StoreTrigger(ctx, webhook))
	require.NoError(t, store.StoreTrigger(ctx, schedule))

	results, err := store.ListTriggers(ctx, business.TriggerStoreFilter{Type: "webhook"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "t-webhook", results[0].ID)
}

func TestSQLiteTriggerStore_ListTriggers_ByStatus(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	active := testTriggerRecord("t-active", "tenant-x")
	active.Status = "active"
	disabled := testTriggerRecord("t-disabled", "tenant-x")
	disabled.Status = "disabled"

	require.NoError(t, store.StoreTrigger(ctx, active))
	require.NoError(t, store.StoreTrigger(ctx, disabled))

	results, err := store.ListTriggers(ctx, business.TriggerStoreFilter{Status: "active"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "t-active", results[0].ID)
}

func TestSQLiteTriggerStore_ListTriggers_LimitOffset(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		id := "t-limit-" + string(rune('0'+i))
		rec := testTriggerRecord(id, "tenant-x")
		require.NoError(t, store.StoreTrigger(ctx, rec))
	}

	results, err := store.ListTriggers(ctx, business.TriggerStoreFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, results, 2)

	results2, err := store.ListTriggers(ctx, business.TriggerStoreFilter{Limit: 2, Offset: 2})
	require.NoError(t, err)
	assert.Len(t, results2, 2)
	assert.NotEqual(t, results[0].ID, results2[0].ID)
}

func TestSQLiteTriggerStore_ListTriggers_Empty(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	results, err := store.ListTriggers(ctx, business.TriggerStoreFilter{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
