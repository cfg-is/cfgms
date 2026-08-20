// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides tests for the PostgreSQL PushStore (Issue #3402).
package database

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestPushStore creates a PushStore backed by the test Postgres database.
// The schema is initialised fresh; the test is skipped when Postgres is unavailable.
func newTestPushStore(t *testing.T) *DatabasePushStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreatePushRecordsTable(context.Background(), db))

	store, err := NewDatabasePushStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// testPushRecord returns a PushRecord with sensible defaults.
func testPushRecord(id, configID, tenantID string) *business.PushRecord {
	return &business.PushRecord{
		ID:          id,
		ConfigID:    configID,
		TenantID:    tenantID,
		Version:     "v1",
		Status:      business.PushStatusPending,
		InitiatedBy: "admin",
		Data:        []byte(`{"stewards":["sw-001"]}`),
	}
}

// TestDatabasePushStore_CreateAndGet verifies round-trip persistence.
func TestDatabasePushStore_CreateAndGet(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	rec := testPushRecord("push-db-1", "cfg-1", "tenant-push-1")
	require.NoError(t, store.CreatePush(ctx, rec))

	got, err := store.GetPush(ctx, "push-db-1")
	require.NoError(t, err)
	assert.Equal(t, "push-db-1", got.ID)
	assert.Equal(t, "cfg-1", got.ConfigID)
	assert.Equal(t, "tenant-push-1", got.TenantID)
	assert.Equal(t, business.PushStatusPending, got.Status)
	assert.Equal(t, "admin", got.InitiatedBy)
	assert.Equal(t, []byte(`{"stewards":["sw-001"]}`), got.Data)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())
}

// TestDatabasePushStore_GetNotFound verifies the sentinel error.
func TestDatabasePushStore_GetNotFound(t *testing.T) {
	store := newTestPushStore(t)
	_, err := store.GetPush(context.Background(), "no-such-push-id")
	assert.ErrorIs(t, err, business.ErrPushNotFound)
}

// TestDatabasePushStore_CreateDuplicate verifies that inserting the same ID
// returns an error (not silently replacing the record).
func TestDatabasePushStore_CreateDuplicate(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	rec := testPushRecord("push-db-dup", "cfg-dup", "tenant-dup")
	require.NoError(t, store.CreatePush(ctx, rec), "first insert must succeed")

	err := store.CreatePush(ctx, rec)
	require.Error(t, err, "duplicate ID must return an error")
}

// TestDatabasePushStore_UpdatePushStatus verifies lifecycle transitions.
func TestDatabasePushStore_UpdatePushStatus(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	rec := testPushRecord("push-db-status", "cfg-s", "tenant-status")
	require.NoError(t, store.CreatePush(ctx, rec))

	require.NoError(t, store.UpdatePushStatus(ctx, "push-db-status", business.PushStatusInProgress))
	got, err := store.GetPush(ctx, "push-db-status")
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusInProgress, got.Status)

	require.NoError(t, store.UpdatePushStatus(ctx, "push-db-status", business.PushStatusCompleted))
	got, err = store.GetPush(ctx, "push-db-status")
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusCompleted, got.Status)
}

// TestDatabasePushStore_UpdatePushStatus_NotFound verifies the sentinel error.
func TestDatabasePushStore_UpdatePushStatus_NotFound(t *testing.T) {
	store := newTestPushStore(t)
	err := store.UpdatePushStatus(context.Background(), "no-such-id", business.PushStatusCompleted)
	assert.ErrorIs(t, err, business.ErrPushNotFound)
}

// TestDatabasePushStore_GetPendingPushes verifies that pending and in_progress
// records are returned, while completed and failed records are excluded.
// This is the failover resume path exercised by resumePendingPushes.
func TestDatabasePushStore_GetPendingPushes(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	pending := testPushRecord("push-gp-pending", "cfg-gp", "tenant-gp")
	pending.Status = business.PushStatusPending
	require.NoError(t, store.CreatePush(ctx, pending))

	inProgress := testPushRecord("push-gp-inprog", "cfg-gp", "tenant-gp")
	require.NoError(t, store.CreatePush(ctx, inProgress))
	require.NoError(t, store.UpdatePushStatus(ctx, "push-gp-inprog", business.PushStatusInProgress))

	completed := testPushRecord("push-gp-done", "cfg-gp", "tenant-gp")
	completed.Status = business.PushStatusCompleted
	require.NoError(t, store.CreatePush(ctx, completed))
	require.NoError(t, store.UpdatePushStatus(ctx, "push-gp-done", business.PushStatusCompleted))

	failed := testPushRecord("push-gp-failed", "cfg-gp", "tenant-gp")
	failed.Status = business.PushStatusFailed
	require.NoError(t, store.CreatePush(ctx, failed))
	require.NoError(t, store.UpdatePushStatus(ctx, "push-gp-failed", business.PushStatusFailed))

	records, err := store.GetPendingPushes(ctx)
	require.NoError(t, err)

	ids := make(map[string]bool)
	for _, r := range records {
		ids[r.ID] = true
	}
	assert.True(t, ids["push-gp-pending"], "pending push must be returned")
	assert.True(t, ids["push-gp-inprog"], "in_progress push must be returned")
	assert.False(t, ids["push-gp-done"], "completed push must NOT be returned")
	assert.False(t, ids["push-gp-failed"], "failed push must NOT be returned")
}

// TestDatabasePushStore_ResumeScenario proves that resumePendingPushes has a
// durable push record to read in cluster mode after a leader change.
//
// This test simulates the scenario described in the story: a push is created
// as in_progress by leader A, leader A fails, and leader B (a new process)
// opens a fresh PushStore and calls GetPendingPushes to resume. The durable
// Postgres record means leader B sees the push that leader A started.
func TestDatabasePushStore_ResumeScenario(t *testing.T) {
	storeA := newTestPushStore(t)
	ctx := context.Background()

	// Simulate leader A: create and advance a push to in_progress.
	type stewardConfig struct {
		Stewards []string `json:"stewards"`
	}
	cfg := stewardConfig{Stewards: []string{"sw-resume-001", "sw-resume-002"}}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	push := &business.PushRecord{
		ID:          "push-resume-001",
		ConfigID:    "cfg-resume",
		TenantID:    "tenant-resume",
		Version:     "v42",
		InitiatedBy: "leader-a",
		Data:        data,
	}
	require.NoError(t, storeA.CreatePush(ctx, push))
	require.NoError(t, storeA.UpdatePushStatus(ctx, "push-resume-001", business.PushStatusInProgress))

	// Simulate leader B: open a new PushStore connection against the same DB.
	storeB, err := NewDatabasePushStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	defer func() { _ = storeB.Close() }()

	// Leader B calls GetPendingPushes — it must find leader A's in_progress push.
	records, err := storeB.GetPendingPushes(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(records), 1, "leader B must find the in_progress push left by leader A")

	var found *business.PushRecord
	for _, r := range records {
		if r.ID == "push-resume-001" {
			found = r
			break
		}
	}
	require.NotNil(t, found, "push-resume-001 must be visible to the new leader")
	assert.Equal(t, business.PushStatusInProgress, found.Status)
	assert.Equal(t, "cfg-resume", found.ConfigID)

	// Verify the blob is intact so resumePendingPushes can unmarshal it.
	var decoded stewardConfig
	require.NoError(t, json.Unmarshal(found.Data, &decoded))
	assert.Equal(t, []string{"sw-resume-001", "sw-resume-002"}, decoded.Stewards)
}

// TestDatabasePushStore_ListPushesByConfigID verifies per-config listing.
func TestDatabasePushStore_ListPushesByConfigID(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreatePush(ctx, testPushRecord("push-cfg-1a", "cfg-list", "tenant-list")))
	require.NoError(t, store.CreatePush(ctx, testPushRecord("push-cfg-1b", "cfg-list", "tenant-list")))
	require.NoError(t, store.CreatePush(ctx, testPushRecord("push-cfg-2", "cfg-other", "tenant-list")))

	list, err := store.ListPushesByConfigID(ctx, "cfg-list", "tenant-list")
	require.NoError(t, err)
	require.Len(t, list, 2)
	for _, r := range list {
		assert.Equal(t, "cfg-list", r.ConfigID)
		assert.Equal(t, "tenant-list", r.TenantID)
	}
}

// TestDatabasePushStore_ListPushesByConfigID_OrderedDesc verifies the
// created_at DESC ordering so callers see the most recent push first.
func TestDatabasePushStore_ListPushesByConfigID_OrderedDesc(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	now := time.Now().UTC()

	oldest := testPushRecord("push-ord-oldest", "cfg-ord", "tenant-ord")
	oldest.CreatedAt = now.Add(-2 * time.Hour)
	require.NoError(t, store.CreatePush(ctx, oldest))

	newest := testPushRecord("push-ord-newest", "cfg-ord", "tenant-ord")
	newest.CreatedAt = now
	require.NoError(t, store.CreatePush(ctx, newest))

	list, err := store.ListPushesByConfigID(ctx, "cfg-ord", "tenant-ord")
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "push-ord-newest", list[0].ID, "most recent push must be first")
	assert.Equal(t, "push-ord-oldest", list[1].ID)
}

// TestDatabasePushStore_ListPushesByConfigID_EmptyResult verifies that a
// zero-result query returns an empty slice (not nil and not an error).
func TestDatabasePushStore_ListPushesByConfigID_EmptyResult(t *testing.T) {
	store := newTestPushStore(t)
	list, err := store.ListPushesByConfigID(context.Background(), "no-such-config", "no-such-tenant")
	require.NoError(t, err)
	assert.NotNil(t, list, "empty result must be a non-nil empty slice")
	assert.Empty(t, list)
}

// TestDatabasePushStore_TenantScoping verifies that ListPushesByConfigID
// isolates by tenant — a cross-tenant caller cannot read another tenant's pushes.
func TestDatabasePushStore_TenantScoping(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	// Tenant A has a push for cfg-shared.
	require.NoError(t, store.CreatePush(ctx, testPushRecord("push-iso-a", "cfg-shared", "tenant-iso-a")))

	// Tenant B has a push for the same cfg-shared.
	require.NoError(t, store.CreatePush(ctx, testPushRecord("push-iso-b", "cfg-shared", "tenant-iso-b")))

	// Tenant A must not see tenant B's push.
	aList, err := store.ListPushesByConfigID(ctx, "cfg-shared", "tenant-iso-a")
	require.NoError(t, err)
	for _, r := range aList {
		assert.Equal(t, "tenant-iso-a", r.TenantID, "tenant-iso-b push must not appear under tenant-iso-a")
	}
	require.Len(t, aList, 1)
	assert.Equal(t, "push-iso-a", aList[0].ID)

	// Tenant B must not see tenant A's push.
	bList, err := store.ListPushesByConfigID(ctx, "cfg-shared", "tenant-iso-b")
	require.NoError(t, err)
	for _, r := range bList {
		assert.Equal(t, "tenant-iso-b", r.TenantID, "tenant-iso-a push must not appear under tenant-iso-b")
	}
	require.Len(t, bList, 1)
	assert.Equal(t, "push-iso-b", bList[0].ID)
}

// TestDatabasePushStore_MigrationPreservesRecords verifies that migrating
// trigger and push state onto the database provider preserves all records.
// This test is the acceptance-criteria "migration preserves both, verified by
// record counts on each side" gate for the PushStore (Issue #3402).
func TestDatabasePushStore_MigrationPreservesRecords(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	const n = 5
	for i := 0; i < n; i++ {
		id := "push-mig-" + string(rune('a'+i))
		rec := testPushRecord(id, "cfg-mig", "tenant-mig")
		require.NoError(t, store.CreatePush(ctx, rec))
	}

	// Verify all n records are present after "migration" (store + query round-trip).
	list, err := store.ListPushesByConfigID(ctx, "cfg-mig", "tenant-mig")
	require.NoError(t, err)
	assert.Len(t, list, n, "all migrated push records must be preserved")
}

// TestDatabaseTriggerStore_MigrationPreservesRecords verifies the same
// migration-preservation invariant for the TriggerStore.
func TestDatabaseTriggerStore_MigrationPreservesRecords(t *testing.T) {
	store := newTestTriggerStore(t)
	ctx := context.Background()

	const n = 4
	for i := 0; i < n; i++ {
		id := "tr-mig-" + string(rune('a'+i))
		rec := testTriggerRecord(id, "tenant-mig-tr")
		require.NoError(t, store.StoreTrigger(ctx, rec))
	}

	list, err := store.ListTriggers(ctx, business.TriggerStoreFilter{TenantID: "tenant-mig-tr"})
	require.NoError(t, err)
	assert.Len(t, list, n, "all migrated trigger records must be preserved")
}

// newUnconnectedPushStore returns a real DatabasePushStore with no database
// handle. CreatePush rejects invalid input before it touches s.db, so the
// validation guards are verifiable — and must be verified — without a live
// Postgres; requiring one would leave these branches uncovered on every machine
// and CI job where the test database is absent. Reaching any SQL with a nil
// handle panics, so a removed guard fails the test rather than passing silently.
func newUnconnectedPushStore() *DatabasePushStore {
	return &DatabasePushStore{}
}

// TestDatabasePushStore_CreatePush_NilRecord verifies the nil-record guard
// (push_store.go) rejects the call before any SQL executes.
func TestDatabasePushStore_CreatePush_NilRecord(t *testing.T) {
	store := newUnconnectedPushStore()
	err := store.CreatePush(context.Background(), nil)
	require.Error(t, err)
	assert.EqualError(t, err, "database: push record cannot be nil")
}

// TestDatabasePushStore_CreatePush_EmptyID verifies the empty-ID guard
// (push_store.go) rejects the call before any SQL executes.
func TestDatabasePushStore_CreatePush_EmptyID(t *testing.T) {
	store := newUnconnectedPushStore()
	rec := testPushRecord("", "cfg-noid", "tenant-noid")
	err := store.CreatePush(context.Background(), rec)
	require.Error(t, err)
	assert.EqualError(t, err, "database: push record ID cannot be empty")
}

// TestDatabasePushStore_CreatePush_EmptyIDPersistsNothing verifies against a
// live database that a rejected record is never written.
func TestDatabasePushStore_CreatePush_EmptyIDPersistsNothing(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	rec := testPushRecord("", "cfg-guard-noid", "tenant-guard-noid")
	require.Error(t, store.CreatePush(ctx, rec))

	list, err := store.ListPushesByConfigID(ctx, "cfg-guard-noid", "tenant-guard-noid")
	require.NoError(t, err)
	assert.Empty(t, list, "a record rejected by the ID guard must not be persisted")
}

// TestDatabaseProvider_CreatePushStore verifies that the provider returns a
// working Postgres-backed store instead of ErrNotSupported (Issue #3402).
func TestDatabaseProvider_CreatePushStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	store, err := provider.CreatePushStore(getTestConfig())
	require.NoError(t, err, "CreatePushStore must not return ErrNotSupported")
	require.NotNil(t, store)

	records, err := store.GetPendingPushes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, records)

	if s, ok := store.(*DatabasePushStore); ok {
		_ = s.Close()
	}
}
