// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL PendingRefreshStore (Issue #2329).
package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestPendingRefreshStore creates a PendingRefreshStore backed by the test Postgres
// database. The schema is initialised fresh; the test is skipped when Postgres is unavailable.
func newTestPendingRefreshStore(t *testing.T) *DatabasePendingRefreshStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreatePendingRefreshRequestsTable(ctx, db))

	store, err := NewDatabasePendingRefreshStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// samplePendingRefreshCSRPEM is a representative PEM CERTIFICATE REQUEST body for
// the csr_pem column (Issue #3781). The store treats the value as opaque text; its
// exact bytes are what must survive the round-trip.
const samplePendingRefreshCSRPEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBTESTCSRBODY\n-----END CERTIFICATE REQUEST-----\n"

func makeSamplePendingRefresh(pendingID, deviceID, tenantID string) *business.PendingRefreshEntry {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &business.PendingRefreshEntry{
		PendingID:               pendingID,
		DeviceID:                deviceID,
		TenantID:                tenantID,
		SourceIP:                "10.0.0.1",
		ProvenanceMatchedFields: 3,
		ProvenanceTotalFields:   5,
		CSRPEM:                  samplePendingRefreshCSRPEM,
		Status:                  business.PendingRefreshStatusPending,
		CreatedAt:               now,
		ExpiresAt:               now.Add(24 * time.Hour),
	}
}

// TestDatabasePendingRefreshStore_AddAndGet verifies round-trip for AddPendingRefresh
// and GetPendingRefreshByID.
func TestDatabasePendingRefreshStore_AddAndGet(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := makeSamplePendingRefresh("pr-001", "dev-001", "tenant-pr-a")
	entry.ClaimBundle = []byte(`{"key":"val"}`)

	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	got, err := store.GetPendingRefreshByID(ctx, "pr-001")
	require.NoError(t, err)
	assert.Equal(t, "pr-001", got.PendingID)
	assert.Equal(t, "dev-001", got.DeviceID)
	assert.Equal(t, "tenant-pr-a", got.TenantID)
	assert.Equal(t, "10.0.0.1", got.SourceIP)
	assert.Equal(t, 3, got.ProvenanceMatchedFields)
	assert.Equal(t, 5, got.ProvenanceTotalFields)
	// csr_pem occupies a new $-parameter position in the INSERT and sits between
	// claim_bundle and status in all three SELECT column lists (Issue #3781);
	// asserting it beside its neighbours is what catches a bound-parameter or
	// scan-order slip.
	assert.Equal(t, samplePendingRefreshCSRPEM, got.CSRPEM)
	assert.Equal(t, business.PendingRefreshStatusPending, got.Status)
	assert.Equal(t, []byte(`{"key":"val"}`), got.ClaimBundle)
	assert.Nil(t, got.ResolvedAt)
}

// TestDatabasePendingRefreshStore_CSRPEMListRoundTrip covers the second scan
// function: ListPendingRefresh reads csr_pem through scanPendingRefreshDBRows
// rather than scanPendingRefreshDBRow, so a column-position slip there is
// invisible to the AddAndGet round-trip. Distinct per-entry CSR bodies also prove
// the value is not being read from a neighbouring column.
func TestDatabasePendingRefreshStore_CSRPEMListRoundTrip(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	withCSR := makeSamplePendingRefresh("pr-csr-list-1", "dev-csr-1", "tenant-csr-list")
	withCSR.CSRPEM = "-----BEGIN CERTIFICATE REQUEST-----\nfirst\n-----END CERTIFICATE REQUEST-----\n"
	require.NoError(t, store.AddPendingRefresh(ctx, withCSR))

	// An entry written without a CSR must read back empty, not carrying the other
	// row's value or a neighbouring column's.
	withoutCSR := makeSamplePendingRefresh("pr-csr-list-2", "dev-csr-2", "tenant-csr-list")
	withoutCSR.CSRPEM = ""
	require.NoError(t, store.AddPendingRefresh(ctx, withoutCSR))

	list, err := store.ListPendingRefresh(ctx, "tenant-csr-list")
	require.NoError(t, err)
	require.Len(t, list, 2)

	byID := map[string]*business.PendingRefreshEntry{}
	for _, e := range list {
		byID[e.PendingID] = e
	}
	require.Contains(t, byID, "pr-csr-list-1")
	require.Contains(t, byID, "pr-csr-list-2")
	assert.Equal(t, withCSR.CSRPEM, byID["pr-csr-list-1"].CSRPEM)
	assert.Equal(t, business.PendingRefreshStatusPending, byID["pr-csr-list-1"].Status,
		"status must not be shifted by the csr_pem column")
	assert.Empty(t, byID["pr-csr-list-2"].CSRPEM, "an entry stored without a CSR must read back empty")
	assert.Equal(t, business.PendingRefreshStatusPending, byID["pr-csr-list-2"].Status)
}

// TestDatabasePendingRefreshStore_NotFound verifies ErrPendingRefreshNotFound is
// returned when the record does not exist.
func TestDatabasePendingRefreshStore_NotFound(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	_, err := store.GetPendingRefreshByID(ctx, "nonexistent-pending-id")
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

// TestDatabasePendingRefreshStore_DuplicateAdd verifies that adding an entry with
// the same PendingID returns a descriptive error.
func TestDatabasePendingRefreshStore_DuplicateAdd(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := makeSamplePendingRefresh("pr-dup", "dev-dup", "tenant-pr-dup")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	err := store.AddPendingRefresh(ctx, entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// TestDatabasePendingRefreshStore_UpdateStatus verifies UpdateRefreshStatus changes
// the status for a non-terminal transition.
func TestDatabasePendingRefreshStore_UpdateStatus(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := makeSamplePendingRefresh("pr-status", "dev-status", "tenant-pr-status")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	require.NoError(t, store.UpdateRefreshStatus(ctx, "pr-status", business.PendingRefreshStatusExpired))

	got, err := store.GetPendingRefreshByID(ctx, "pr-status")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusExpired, got.Status)
	assert.Nil(t, got.ResolvedAt, "non-terminal status must not set resolved_at")
}

// TestDatabasePendingRefreshStore_TerminalStatusSetsResolvedAt verifies that
// terminal statuses (approved, rejected) cause resolved_at to be set.
func TestDatabasePendingRefreshStore_TerminalStatusSetsResolvedAt(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := makeSamplePendingRefresh("pr-terminal", "dev-term", "tenant-pr-term")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	require.NoError(t, store.UpdateRefreshStatus(ctx, "pr-terminal", business.PendingRefreshStatusApproved))

	got, err := store.GetPendingRefreshByID(ctx, "pr-terminal")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusApproved, got.Status)
	require.NotNil(t, got.ResolvedAt, "approved terminal status must set resolved_at")
}

// TestDatabasePendingRefreshStore_UpdateStatusNotFound verifies ErrPendingRefreshNotFound
// when updating a non-existent record.
func TestDatabasePendingRefreshStore_UpdateStatusNotFound(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	err := store.UpdateRefreshStatus(ctx, "nonexistent", business.PendingRefreshStatusApproved)
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

// TestDatabasePendingRefreshStore_ListAll verifies ListPendingRefresh with an empty
// tenantID returns all entries across tenants.
func TestDatabasePendingRefreshStore_ListAll(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	for i, tid := range []string{"tenant-list-a", "tenant-list-b"} {
		e := makeSamplePendingRefresh(
			"pr-list-all-"+tid,
			"dev-list-"+tid,
			tid,
		)
		e.CreatedAt = time.Now().UTC().Add(time.Duration(i) * time.Millisecond)
		require.NoError(t, store.AddPendingRefresh(ctx, e))
	}

	list, err := store.ListPendingRefresh(ctx, "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(list), 2)
}

// TestDatabasePendingRefreshStore_ListByTenant verifies that ListPendingRefresh
// with a tenantID filters results to that tenant only.
func TestDatabasePendingRefreshStore_ListByTenant(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	eA := makeSamplePendingRefresh("pr-tenant-filter-a", "dev-fa", "tenant-filter-a")
	eB := makeSamplePendingRefresh("pr-tenant-filter-b", "dev-fb", "tenant-filter-b")
	require.NoError(t, store.AddPendingRefresh(ctx, eA))
	require.NoError(t, store.AddPendingRefresh(ctx, eB))

	listA, err := store.ListPendingRefresh(ctx, "tenant-filter-a")
	require.NoError(t, err)
	for _, e := range listA {
		assert.Equal(t, "tenant-filter-a", e.TenantID)
	}
	assert.GreaterOrEqual(t, len(listA), 1)

	listB, err := store.ListPendingRefresh(ctx, "tenant-filter-b")
	require.NoError(t, err)
	for _, e := range listB {
		assert.Equal(t, "tenant-filter-b", e.TenantID)
	}
	assert.GreaterOrEqual(t, len(listB), 1)
}

// TestDatabasePendingRefreshStore_ExpireStale verifies ExpireStaleRefresh marks
// pending entries with expires_at in the past as expired.
func TestDatabasePendingRefreshStore_ExpireStale(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	stale := makeSamplePendingRefresh("pr-stale", "dev-stale", "tenant-stale")
	stale.ExpiresAt = now.Add(-time.Minute) // already expired
	require.NoError(t, store.AddPendingRefresh(ctx, stale))

	fresh := makeSamplePendingRefresh("pr-fresh", "dev-fresh", "tenant-fresh")
	fresh.ExpiresAt = now.Add(time.Hour) // not yet expired
	require.NoError(t, store.AddPendingRefresh(ctx, fresh))

	n, err := store.ExpireStaleRefresh(ctx, now)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, 1)

	got, err := store.GetPendingRefreshByID(ctx, "pr-stale")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusExpired, got.Status)
	require.NotNil(t, got.ResolvedAt)

	gotFresh, err := store.GetPendingRefreshByID(ctx, "pr-fresh")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusPending, gotFresh.Status)
}

// TestDatabasePendingRefreshStore_StoreClaimBundle verifies that StoreClaimBundle
// updates the claim_bundle field for an existing entry.
func TestDatabasePendingRefreshStore_StoreClaimBundle(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := makeSamplePendingRefresh("pr-bundle", "dev-bundle", "tenant-bundle")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	bundle := []byte(`{"proof":"signed-data"}`)
	require.NoError(t, store.StoreClaimBundle(ctx, "pr-bundle", bundle))

	got, err := store.GetPendingRefreshByID(ctx, "pr-bundle")
	require.NoError(t, err)
	assert.Equal(t, bundle, got.ClaimBundle)
}

// TestDatabasePendingRefreshStore_StoreClaimBundleNotFound verifies
// ErrPendingRefreshNotFound when storing a bundle for a non-existent entry.
func TestDatabasePendingRefreshStore_StoreClaimBundleNotFound(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	err := store.StoreClaimBundle(ctx, "nonexistent-pending", []byte(`{}`))
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

// legacyPendingRefreshRequestsSchemaPG is the pending_refresh_requests DDL as
// shipped by Issue #2329, before Issue #3781 added csr_pem. Used to simulate a
// Postgres deployment that carried the refresh queue before the steward started
// submitting its own CSR with /refresh/complete.
const legacyPendingRefreshRequestsSchemaPG = `CREATE TABLE pending_refresh_requests (
	pending_id                  TEXT NOT NULL PRIMARY KEY,
	device_id                   TEXT NOT NULL,
	tenant_id                   TEXT NOT NULL,
	source_ip                   TEXT NOT NULL DEFAULT '',
	provenance_matched_fields   INTEGER NOT NULL DEFAULT 0,
	provenance_total_fields     INTEGER NOT NULL DEFAULT 0,
	claim_bundle                BYTEA NOT NULL DEFAULT ''::bytea,
	status                      TEXT NOT NULL DEFAULT 'pending',
	created_at                  TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at                  TIMESTAMP WITH TIME ZONE NOT NULL,
	resolved_at                 TIMESTAMP WITH TIME ZONE
)`

// pgPendingRefreshColumnExists reports whether the named column exists on
// pending_refresh_requests.
func pgPendingRefreshColumnExists(ctx context.Context, t *testing.T, db *sql.DB, column string) bool {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'pending_refresh_requests' AND column_name = $1
		)`, column).Scan(&exists)
	require.NoError(t, err)
	return exists
}

// seedLegacyPendingRefreshRequestsTable drops any existing table and creates the
// pre-#3781 shape, returning a clean database handle.
func seedLegacyPendingRefreshRequestsTable(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	_, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS pending_refresh_requests")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS pending_refresh_requests")
	})

	_, err = db.ExecContext(ctx, legacyPendingRefreshRequestsSchemaPG)
	require.NoError(t, err, "create legacy pending_refresh_requests table")
	return db, ctx
}

// TestCreatePendingRefreshRequestsTable_MigratesLegacyTable verifies that a table
// created before Issue #3781 gains csr_pem. CREATE TABLE IF NOT EXISTS cannot add
// a column, so without the ALTER every upgrading Postgres deployment would fail
// its next AddPendingRefresh with "column csr_pem of relation
// pending_refresh_requests does not exist".
func TestCreatePendingRefreshRequestsTable_MigratesLegacyTable(t *testing.T) {
	db, ctx := seedLegacyPendingRefreshRequestsTable(t)

	// A pre-#3781 row must survive the migration and take the column default.
	_, err := db.ExecContext(ctx, `
		INSERT INTO pending_refresh_requests
			(pending_id, device_id, tenant_id, created_at, expires_at)
		VALUES ('pr-pg-legacy', 'dev-pg-legacy', 'tenant-pg-legacy', now(), now() + interval '1 hour')`)
	require.NoError(t, err, "seed legacy row")

	require.False(t, pgPendingRefreshColumnExists(ctx, t, db, "csr_pem"),
		"pre-condition: csr_pem absent before migration")

	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreatePendingRefreshRequestsTable(ctx, db), "first migration pass")

	assert.True(t, pgPendingRefreshColumnExists(ctx, t, db, "csr_pem"),
		"csr_pem present after migration")

	// The migrated table must be usable by the store that reads and writes the
	// column — a column that exists but carries the wrong type would still break
	// the live path.
	store, err := NewDatabasePendingRefreshStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	legacy, err := store.GetPendingRefreshByID(ctx, "pr-pg-legacy")
	require.NoError(t, err, "legacy row must remain readable through the migrated column")
	assert.Empty(t, legacy.CSRPEM, "legacy row must default to an empty csr_pem")

	migrated := makeSamplePendingRefresh("pr-pg-migrated", "dev-pg-migrated", "tenant-pg-legacy")
	require.NoError(t, store.AddPendingRefresh(ctx, migrated), "migrated table must accept a full entry")

	got, err := store.GetPendingRefreshByID(ctx, "pr-pg-migrated")
	require.NoError(t, err)
	assert.Equal(t, samplePendingRefreshCSRPEM, got.CSRPEM,
		"csr_pem must round-trip through the migrated column")
	assert.Equal(t, business.PendingRefreshStatusPending, got.Status,
		"status must not be shifted by the migrated column")
}

// TestCreatePendingRefreshRequestsTable_MigrationIsIdempotent verifies that a
// second pass over an already-migrated table succeeds (ADD COLUMN IF NOT EXISTS
// suppresses the duplicate) and that rows written between the passes survive. The
// migration runs on every store open, so a non-idempotent pass would break every
// controller restart.
func TestCreatePendingRefreshRequestsTable_MigrationIsIdempotent(t *testing.T) {
	db, ctx := seedLegacyPendingRefreshRequestsTable(t)

	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreatePendingRefreshRequestsTable(ctx, db), "first migration pass")

	store, err := NewDatabasePendingRefreshStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.AddPendingRefresh(ctx,
		makeSamplePendingRefresh("pr-pg-survive", "dev-pg-survive", "tenant-pg-idem")))

	require.NoError(t, schemas.CreatePendingRefreshRequestsTable(ctx, db), "second migration pass")

	assert.True(t, pgPendingRefreshColumnExists(ctx, t, db, "csr_pem"),
		"csr_pem still present after second pass")

	got, err := store.GetPendingRefreshByID(ctx, "pr-pg-survive")
	require.NoError(t, err, "row must survive the idempotent second pass")
	assert.Equal(t, samplePendingRefreshCSRPEM, got.CSRPEM,
		"stored csr_pem must survive the second migration pass")
}

// TestCreatePendingRefreshRequestsTable_FreshTable verifies that a fresh database
// carries csr_pem from the CREATE TABLE statement, so the ALTER is a no-op on new
// deployments.
func TestCreatePendingRefreshRequestsTable_FreshTable(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreatePendingRefreshRequestsTable(ctx, db))

	assert.True(t, pgPendingRefreshColumnExists(ctx, t, db, "csr_pem"),
		"csr_pem present on a freshly created table")
}
