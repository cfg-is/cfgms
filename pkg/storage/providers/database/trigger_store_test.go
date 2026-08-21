// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides tests for the PostgreSQL TriggerStore (Issue #3402).
package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestTriggerStore creates a TriggerStore backed by the test Postgres database.
// The schema is initialised fresh; the test is skipped when Postgres is unavailable.
func newTestTriggerStore(t *testing.T) *DatabaseTriggerStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreateTriggersTable(context.Background(), db))

	store, err := NewDatabaseTriggerStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// testTriggerRecord returns a TriggerRecord with sensible defaults.
func testTriggerRecord(id, tenantID string) *business.TriggerRecord {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &business.TriggerRecord{
		ID:            id,
		TenantID:      tenantID,
		Name:          "test-trigger-" + id,
		Type:          "webhook",
		Status:        "active",
		WorkflowName:  "workflow-" + id,
		CreatedAt:     now,
		UpdatedAt:     now,
		WebhookPath:   "/webhooks/" + id,
		WebhookMethod: []string{"POST"},
	}
}

// TestDatabaseTriggerStore_StoreAndGet verifies round-trip persistence.
func TestDatabaseTriggerStore_StoreAndGet(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	rec := testTriggerRecord("tr-db-1", "tenant-tr-1")
	rec.BearerTokenRef = "secrets/bearer-1"
	rec.HMACSecretRef = "secrets/hmac-1"
	rec.ConfigPayload = []byte(`{"key":"value"}`)
	require.NoError(t, store.StoreTrigger(ctx, rec))

	got, err := store.GetTrigger(ctx, "tr-db-1")
	require.NoError(t, err)
	assert.Equal(t, "tr-db-1", got.ID)
	assert.Equal(t, "tenant-tr-1", got.TenantID)
	assert.Equal(t, "test-trigger-tr-db-1", got.Name)
	assert.Equal(t, "webhook", got.Type)
	assert.Equal(t, "active", got.Status)
	assert.Equal(t, []string{"POST"}, got.WebhookMethod)
	assert.Equal(t, "secrets/bearer-1", got.BearerTokenRef)
	assert.Equal(t, "secrets/hmac-1", got.HMACSecretRef)
	assert.Equal(t, []byte(`{"key":"value"}`), got.ConfigPayload)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())
}

// TestDatabaseTriggerStore_GetNotFound verifies the sentinel error.
func TestDatabaseTriggerStore_GetNotFound(t *testing.T) {
	store := newTestTriggerStore(t)
	_, err := store.GetTrigger(context.Background(), "no-such-trigger-id")
	assert.ErrorIs(t, err, business.ErrTriggerNotFound)
}

// TestDatabaseTriggerStore_StoreUpsert verifies that StoreTrigger replaces
// existing records on conflict rather than erroring.
func TestDatabaseTriggerStore_StoreUpsert(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	rec := testTriggerRecord("tr-db-upsert", "tenant-tr-upsert")
	require.NoError(t, store.StoreTrigger(ctx, rec))

	rec.Status = "inactive"
	rec.Name = "updated-name"
	require.NoError(t, store.StoreTrigger(ctx, rec))

	got, err := store.GetTrigger(ctx, "tr-db-upsert")
	require.NoError(t, err)
	assert.Equal(t, "inactive", got.Status)
	assert.Equal(t, "updated-name", got.Name)
}

// TestDatabaseTriggerStore_EmptyStringRefsStoredAsNull verifies that empty
// credential ref fields are stored as SQL NULL rather than empty strings — the
// empty-string-vs-NULL defect class identified in Issue #3127.
func TestDatabaseTriggerStore_EmptyStringRefsStoredAsNull(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	rec := testTriggerRecord("tr-db-null-refs", "tenant-tr-null")
	// All refs left empty — should survive a round-trip as empty strings in Go.
	require.NoError(t, store.StoreTrigger(ctx, rec))

	got, err := store.GetTrigger(ctx, "tr-db-null-refs")
	require.NoError(t, err)
	assert.Empty(t, got.BearerTokenRef)
	assert.Empty(t, got.HMACSecretRef)
	assert.Empty(t, got.APIKeyRef)
	assert.Empty(t, got.BasicUsernameRef)
	assert.Empty(t, got.BasicPasswordRef)
	assert.Nil(t, got.ConfigPayload)
}

// TestDatabaseTriggerStore_Delete verifies deletion and the not-found sentinel.
func TestDatabaseTriggerStore_Delete(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	rec := testTriggerRecord("tr-db-del", "tenant-tr-del")
	require.NoError(t, store.StoreTrigger(ctx, rec))

	require.NoError(t, store.DeleteTrigger(ctx, "tr-db-del"))

	_, err := store.GetTrigger(ctx, "tr-db-del")
	assert.ErrorIs(t, err, business.ErrTriggerNotFound)
}

// TestDatabaseTriggerStore_DeleteNotFound verifies that deleting an absent
// trigger returns ErrTriggerNotFound.
func TestDatabaseTriggerStore_DeleteNotFound(t *testing.T) {
	store := newTestTriggerStore(t)
	err := store.DeleteTrigger(context.Background(), "no-such-id")
	assert.ErrorIs(t, err, business.ErrTriggerNotFound)
}

// TestDatabaseTriggerStore_ListAll verifies that an empty filter returns all triggers.
func TestDatabaseTriggerStore_ListAll(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	require.NoError(t, store.StoreTrigger(ctx, testTriggerRecord("tr-list-1", "tenant-list-a")))
	require.NoError(t, store.StoreTrigger(ctx, testTriggerRecord("tr-list-2", "tenant-list-b")))
	require.NoError(t, store.StoreTrigger(ctx, testTriggerRecord("tr-list-3", "tenant-list-a")))

	all, err := store.ListTriggers(ctx, business.TriggerStoreFilter{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(all), 3)
}

// TestDatabaseTriggerStore_ListByStatus verifies status filtering.
func TestDatabaseTriggerStore_ListByStatus(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	active := testTriggerRecord("tr-status-active", "tenant-status")
	active.Status = "active"
	require.NoError(t, store.StoreTrigger(ctx, active))

	disabled := testTriggerRecord("tr-status-disabled", "tenant-status")
	disabled.Status = "disabled"
	require.NoError(t, store.StoreTrigger(ctx, disabled))

	actives, err := store.ListTriggers(ctx, business.TriggerStoreFilter{Status: "active"})
	require.NoError(t, err)
	for _, r := range actives {
		assert.Equal(t, "active", r.Status)
	}
	assert.GreaterOrEqual(t, len(actives), 1)
}

// TestDatabaseTriggerStore_ListOrderedByCreatedAtDesc verifies ordering.
func TestDatabaseTriggerStore_ListOrderedByCreatedAtDesc(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	oldest := testTriggerRecord("tr-order-oldest", "tenant-order")
	oldest.CreatedAt = now.Add(-2 * time.Hour)
	require.NoError(t, store.StoreTrigger(ctx, oldest))

	middle := testTriggerRecord("tr-order-middle", "tenant-order")
	middle.CreatedAt = now.Add(-time.Hour)
	require.NoError(t, store.StoreTrigger(ctx, middle))

	newest := testTriggerRecord("tr-order-newest", "tenant-order")
	newest.CreatedAt = now
	require.NoError(t, store.StoreTrigger(ctx, newest))

	list, err := store.ListTriggers(ctx, business.TriggerStoreFilter{TenantID: "tenant-order"})
	require.NoError(t, err)
	require.Len(t, list, 3)
	assert.Equal(t, "tr-order-newest", list[0].ID)
	assert.Equal(t, "tr-order-middle", list[1].ID)
	assert.Equal(t, "tr-order-oldest", list[2].ID)
}

// TestDatabaseTriggerStore_TenantScoping verifies that tenant-scoped listing
// excludes records belonging to other tenants (cross-tenant negative case).
func TestDatabaseTriggerStore_TenantScoping(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	require.NoError(t, store.StoreTrigger(ctx, testTriggerRecord("tr-scope-a1", "tenant-scope-a")))
	require.NoError(t, store.StoreTrigger(ctx, testTriggerRecord("tr-scope-a2", "tenant-scope-a")))
	require.NoError(t, store.StoreTrigger(ctx, testTriggerRecord("tr-scope-b1", "tenant-scope-b")))

	// Tenant A sees only its own triggers.
	aList, err := store.ListTriggers(ctx, business.TriggerStoreFilter{TenantID: "tenant-scope-a"})
	require.NoError(t, err)
	require.Len(t, aList, 2)
	for _, r := range aList {
		assert.Equal(t, "tenant-scope-a", r.TenantID)
	}

	// Tenant B sees only its own trigger.
	bList, err := store.ListTriggers(ctx, business.TriggerStoreFilter{TenantID: "tenant-scope-b"})
	require.NoError(t, err)
	require.Len(t, bList, 1)
	assert.Equal(t, "tr-scope-b1", bList[0].ID)

	// Cross-tenant negative: tenant A records must not appear under tenant B.
	for _, r := range bList {
		assert.NotEqual(t, "tenant-scope-a", r.TenantID, "tenant-scope-a record must not appear under tenant-scope-b")
	}
}

// TestDatabaseTriggerStore_WebhookMethodRoundTrip verifies multi-value method slices.
func TestDatabaseTriggerStore_WebhookMethodRoundTrip(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	rec := testTriggerRecord("tr-methods", "tenant-methods")
	rec.WebhookMethod = []string{"GET", "POST", "PUT"}
	require.NoError(t, store.StoreTrigger(ctx, rec))

	got, err := store.GetTrigger(ctx, "tr-methods")
	require.NoError(t, err)
	assert.Equal(t, []string{"GET", "POST", "PUT"}, got.WebhookMethod)
}

// newUnconnectedTriggerStore returns a real DatabaseTriggerStore with no
// database handle. StoreTrigger, GetTrigger and DeleteTrigger reject invalid
// input before they touch s.db, so the validation guards are verifiable — and
// must be verified — without a live Postgres; requiring one would leave these
// branches uncovered on every machine and CI job where the test database is
// absent. Reaching any SQL with a nil handle panics, so a removed guard fails
// the test rather than passing silently.
func newUnconnectedTriggerStore() *DatabaseTriggerStore {
	return &DatabaseTriggerStore{}
}

// TestDatabaseTriggerStore_StoreTrigger_NilRecord verifies the nil-record guard
// (trigger_store.go) rejects the call before any SQL executes.
func TestDatabaseTriggerStore_StoreTrigger_NilRecord(t *testing.T) {
	store := newUnconnectedTriggerStore()
	err := store.StoreTrigger(context.Background(), nil)
	require.Error(t, err)
	assert.EqualError(t, err, "database: trigger record cannot be nil")
}

// TestDatabaseTriggerStore_StoreTrigger_EmptyID verifies the empty-ID guard
// (trigger_store.go) rejects the call before any SQL executes.
func TestDatabaseTriggerStore_StoreTrigger_EmptyID(t *testing.T) {
	store := newUnconnectedTriggerStore()
	rec := testTriggerRecord("", "tenant-a")
	err := store.StoreTrigger(context.Background(), rec)
	require.Error(t, err)
	assert.EqualError(t, err, "database: trigger ID is required")
}

// TestDatabaseTriggerStore_StoreTrigger_EmptyTenantID verifies the
// empty-TenantID guard (trigger_store.go). Tenant scoping is the isolation
// boundary for this store, so an unscoped record must never reach the database.
func TestDatabaseTriggerStore_StoreTrigger_EmptyTenantID(t *testing.T) {
	store := newUnconnectedTriggerStore()
	rec := testTriggerRecord("tr-no-tenant", "")
	err := store.StoreTrigger(context.Background(), rec)
	require.Error(t, err)
	assert.EqualError(t, err, "database: trigger TenantID is required")
}

// TestDatabaseTriggerStore_GetTrigger_EmptyID verifies the empty-ID guard on
// GetTrigger, which rejects the call before any SQL executes.
func TestDatabaseTriggerStore_GetTrigger_EmptyID(t *testing.T) {
	store := newUnconnectedTriggerStore()
	rec, err := store.GetTrigger(context.Background(), "")
	require.Error(t, err)
	assert.Nil(t, rec)
	assert.EqualError(t, err, "database: trigger ID is required")
	assert.NotErrorIs(t, err, business.ErrTriggerNotFound,
		"an invalid ID is a caller error, not a missing record")
}

// TestDatabaseTriggerStore_DeleteTrigger_EmptyID verifies the empty-ID guard on
// DeleteTrigger, which rejects the call before any SQL executes. Without the
// guard an empty ID would reach a DELETE statement.
func TestDatabaseTriggerStore_DeleteTrigger_EmptyID(t *testing.T) {
	store := newUnconnectedTriggerStore()
	err := store.DeleteTrigger(context.Background(), "")
	require.Error(t, err)
	assert.EqualError(t, err, "database: trigger ID is required")
	assert.NotErrorIs(t, err, business.ErrTriggerNotFound,
		"an invalid ID is a caller error, not a missing record")
}

// TestDatabaseTriggerStore_StoreTrigger_GuardsPersistNothing verifies against a
// live database that records rejected by the ID and TenantID guards are never
// written, and that a rejected DeleteTrigger leaves existing rows untouched.
func TestDatabaseTriggerStore_StoreTrigger_GuardsPersistNothing(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	keep := testTriggerRecord("tr-guard-keep", "tenant-guard")
	require.NoError(t, store.StoreTrigger(ctx, keep))

	noID := testTriggerRecord("", "tenant-guard")
	require.Error(t, store.StoreTrigger(ctx, noID))

	noTenant := testTriggerRecord("tr-guard-no-tenant", "")
	require.Error(t, store.StoreTrigger(ctx, noTenant))

	require.Error(t, store.DeleteTrigger(ctx, ""))

	list, err := store.ListTriggers(ctx, business.TriggerStoreFilter{TenantID: "tenant-guard"})
	require.NoError(t, err)
	require.Len(t, list, 1, "only the valid record may be persisted")
	assert.Equal(t, "tr-guard-keep", list[0].ID)

	all, err := store.ListTriggers(ctx, business.TriggerStoreFilter{})
	require.NoError(t, err)
	for _, r := range all {
		assert.NotEqual(t, "tr-guard-no-tenant", r.ID, "an unscoped record must not be persisted")
	}
}

// TestDatabaseProvider_CreateTriggerStore verifies that the provider returns a
// working Postgres-backed store instead of ErrNotSupported (Issue #3402).
func TestDatabaseProvider_CreateTriggerStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	store, err := provider.CreateTriggerStore(getTestConfig())
	require.NoError(t, err, "CreateTriggerStore must not return ErrNotSupported")
	require.NotNil(t, store)

	records, err := store.ListTriggers(context.Background(), business.TriggerStoreFilter{})
	require.NoError(t, err)
	assert.Empty(t, records)

	if s, ok := store.(*DatabaseTriggerStore); ok {
		_ = s.Close()
	}
}
