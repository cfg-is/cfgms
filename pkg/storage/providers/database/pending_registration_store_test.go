// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL PendingRegistrationStore
// (Issue #1696, status-filtered ListPending: Issue #3173).
package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestPendingRegistrationStore creates a PendingRegistrationStore backed by the test
// Postgres database. The schema is initialised fresh; the test is skipped when Postgres
// is unavailable (matches the established pattern for this package).
func newTestPendingRegistrationStore(t *testing.T) *DatabasePendingRegistrationStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreatePendingRegistrationsTable(context.Background(), db))

	store, err := NewDatabasePendingRegistrationStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// testDBDeviceIdentity derives a deterministic device identity for pendingID: a
// 64-char lowercase hex DeviceID and the 32-byte Ed25519-sized public key it
// fingerprints, matching the production shapes (ADR-010 §1).
func testDBDeviceIdentity(pendingID string) (deviceID string, keyPub []byte) {
	sum := sha256.Sum256([]byte(pendingID))
	return hex.EncodeToString(sum[:]), append([]byte(nil), sum[:]...)
}

// testDBPendingEntry returns a PendingRegistrationEntry with sensible defaults,
// including the device-identity fields the claim step reads back (Issue #3403).
func testDBPendingEntry(pendingID, tenantID string) *business.PendingRegistrationEntry {
	now := time.Now().UTC().Truncate(time.Millisecond)
	deviceID, keyPub := testDBDeviceIdentity(pendingID)
	return &business.PendingRegistrationEntry{
		PendingID:          pendingID,
		StewardID:          "steward-" + pendingID,
		TenantID:           tenantID,
		TokenStr:           "cfgms_reg_tok_" + pendingID,
		SourceIP:           "10.0.0.5",
		RegisteredAt:       now,
		ExpiresAt:          now.Add(5 * 24 * time.Hour),
		Status:             business.PendingRegistrationStatusPending,
		DeviceID:           deviceID,
		IdentityKeyPub:     keyPub,
		KeyProtectionLevel: "tpm",
		CSRPEM:             "-----BEGIN CERTIFICATE REQUEST-----\n" + pendingID + "\n-----END CERTIFICATE REQUEST-----",
		Hostname:           "host-" + pendingID,
		Platform:           "linux",
	}
}

// assertDBDeviceIdentity asserts that got carries the device-identity fields
// testDBPendingEntry wrote for pendingID. A swapped column in the INSERT or in any
// of the four SELECT/scan paths shows up here rather than at claim time in
// production, where a wrong identity_key_pub means the wrong device is trusted.
func assertDBDeviceIdentity(t *testing.T, pendingID string, got *business.PendingRegistrationEntry) {
	t.Helper()
	deviceID, keyPub := testDBDeviceIdentity(pendingID)
	assert.Equal(t, deviceID, got.DeviceID, "device_id must round-trip")
	assert.Equal(t, keyPub, got.IdentityKeyPub, "identity_key_pub must round-trip byte-for-byte")
	assert.Equal(t, "tpm", got.KeyProtectionLevel, "key_protection_level must round-trip")
	assert.Equal(t, "-----BEGIN CERTIFICATE REQUEST-----\n"+pendingID+"\n-----END CERTIFICATE REQUEST-----", got.CSRPEM, "csr_pem must round-trip")
	assert.Equal(t, "host-"+pendingID, got.Hostname, "hostname must round-trip")
	assert.Equal(t, "linux", got.Platform, "platform must round-trip")
}

// TestDatabasePendingRegistrationStore_AddAndGetByID verifies round-trip persistence
// including the token lookup-key hashing performed on write.
func TestDatabasePendingRegistrationStore_AddAndGetByID(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	entry := testDBPendingEntry("pr-db-1", "tenant-db-1")
	require.NoError(t, store.AddPending(ctx, entry))

	got, err := store.GetPendingByID(ctx, "pr-db-1")
	require.NoError(t, err)
	assert.Equal(t, "pr-db-1", got.PendingID)
	assert.Equal(t, "steward-pr-db-1", got.StewardID)
	assert.Equal(t, "tenant-db-1", got.TenantID)
	assert.Equal(t, business.RegistrationTokenLookupKey("cfgms_reg_tok_pr-db-1"), got.TokenStr)
	assert.Equal(t, business.PendingRegistrationStatusPending, got.Status)
	assert.Nil(t, got.ClaimedAt)
	assertDBDeviceIdentity(t, "pr-db-1", got)
}

// TestDatabasePendingRegistrationStore_DeviceIdentityRoundTripsEveryReadPath verifies
// that the five device-identity columns survive the write and come back correctly from
// all four read paths — GetPendingByID, GetPendingByToken, ListPending and ListAll.
// Each path spells its own SELECT column list and feeds one of the two scanners, so a
// swapped column order or a wrong scan type in any of them is a distinct regression
// (Issue #3403).
func TestDatabasePendingRegistrationStore_DeviceIdentityRoundTripsEveryReadPath(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	const pendingID = "pr-db-identity"
	entry := testDBPendingEntry(pendingID, "tenant-db-identity")
	require.NoError(t, store.AddPending(ctx, entry))

	byID, err := store.GetPendingByID(ctx, pendingID)
	require.NoError(t, err)
	assertDBDeviceIdentity(t, pendingID, byID)

	byToken, err := store.GetPendingByToken(ctx, "cfgms_reg_tok_"+pendingID)
	require.NoError(t, err)
	require.Equal(t, pendingID, byToken.PendingID)
	assertDBDeviceIdentity(t, pendingID, byToken)

	pending, err := store.ListPending(ctx, "tenant-db-identity")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assertDBDeviceIdentity(t, pendingID, pending[0])

	all, err := store.ListAll(ctx, "tenant-db-identity")
	require.NoError(t, err)
	require.Len(t, all, 1)
	assertDBDeviceIdentity(t, pendingID, all[0])
}

// TestDatabasePendingRegistrationStore_DeviceIdentityAbsent verifies the empty-value
// path: an entry written without device identity (a legacy steward, or a caller that
// omits the optional hints) must insert against the NOT NULL columns and read back with
// a nil IdentityKeyPub rather than an empty non-nil slice, so the claim step can tell
// "no key recorded" from "key recorded" (Issue #3403).
func TestDatabasePendingRegistrationStore_DeviceIdentityAbsent(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, store.AddPending(ctx, &business.PendingRegistrationEntry{
		PendingID:    "pr-db-no-identity",
		StewardID:    "steward-pr-db-no-identity",
		TenantID:     "tenant-db-no-identity",
		TokenStr:     "cfgms_reg_tok_pr-db-no-identity",
		RegisteredAt: now,
		ExpiresAt:    now.Add(time.Hour),
		Status:       business.PendingRegistrationStatusPending,
	}), "a nil IdentityKeyPub must not violate the NOT NULL column")

	got, err := store.GetPendingByID(ctx, "pr-db-no-identity")
	require.NoError(t, err)
	assert.Empty(t, got.DeviceID)
	assert.Nil(t, got.IdentityKeyPub, "an absent key must read back as nil, not an empty slice")
	assert.Empty(t, got.KeyProtectionLevel)
	assert.Empty(t, got.Hostname)
	assert.Empty(t, got.Platform)

	all, err := store.ListAll(ctx, "tenant-db-no-identity")
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Nil(t, all[0].IdentityKeyPub, "the row scanner must agree with the single-row scanner")
}

// TestDatabasePendingRegistrationStore_GetByIDNotFound verifies the sentinel error.
func TestDatabasePendingRegistrationStore_GetByIDNotFound(t *testing.T) {
	store := newTestPendingRegistrationStore(t)

	_, err := store.GetPendingByID(context.Background(), "no-such-pending-id")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

// TestDatabasePendingRegistrationStore_UpdateStatus verifies a status transition is
// durable and observable through GetPendingByID.
func TestDatabasePendingRegistrationStore_UpdateStatus(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-status", "tenant-db-status")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-status", business.PendingRegistrationStatusApproved))

	got, err := store.GetPendingByID(ctx, "pr-db-status")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusApproved, got.Status)
}

// TestDatabasePendingRegistrationStore_ListPending_ExcludesResolved verifies that
// ListPending returns only entries in "pending" status — approved, denied, claimed,
// and expired entries must be excluded (Issue #3173).
func TestDatabasePendingRegistrationStore_ListPending_ExcludesResolved(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	// pending — must appear
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-keep", "tenant-db-resolved")))

	// approved — must NOT appear
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-appr", "tenant-db-resolved")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-appr", business.PendingRegistrationStatusApproved))

	// claimed — must NOT appear (claimed is only reachable from approved)
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-claim", "tenant-db-resolved")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-claim", business.PendingRegistrationStatusApproved))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-claim", business.PendingRegistrationStatusClaimed))

	// denied — must NOT appear
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-deny", "tenant-db-resolved")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-deny", business.PendingRegistrationStatusDenied))

	// expired — must NOT appear
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-exp", "tenant-db-resolved")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-exp", business.PendingRegistrationStatusExpired))

	entries, err := store.ListPending(ctx, "")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "pr-db-keep", entries[0].PendingID)
	assert.Equal(t, business.PendingRegistrationStatusPending, entries[0].Status)
}

// TestDatabasePendingRegistrationStore_ListPending_PendingWithTenantFilter is a
// regression guard: tenant scoping must still work after the status filter was added
// (Issue #3173).
func TestDatabasePendingRegistrationStore_ListPending_PendingWithTenantFilter(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	// pending in tenant-1 — must appear
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-t1-pend", "tenant-db-1")))

	// approved in tenant-1 — must NOT appear (resolved)
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-t1-appr", "tenant-db-1")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-t1-appr", business.PendingRegistrationStatusApproved))

	// pending in tenant-2 — must NOT appear (different tenant)
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-t2-pend", "tenant-db-2")))

	entries, err := store.ListPending(ctx, "tenant-db-1")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "pr-db-t1-pend", entries[0].PendingID)
	assert.Equal(t, business.PendingRegistrationStatusPending, entries[0].Status)
}

// TestDatabasePendingRegistrationStore_ListPending_OrdersByRegisteredAt verifies the
// ascending registered_at ordering contract survives the status predicate.
func TestDatabasePendingRegistrationStore_ListPending_OrdersByRegisteredAt(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Millisecond)

	newest := testDBPendingEntry("pr-db-order-newest", "tenant-db-order")
	newest.RegisteredAt = now
	require.NoError(t, store.AddPending(ctx, newest))

	oldest := testDBPendingEntry("pr-db-order-oldest", "tenant-db-order")
	oldest.RegisteredAt = now.Add(-2 * time.Hour)
	require.NoError(t, store.AddPending(ctx, oldest))

	middle := testDBPendingEntry("pr-db-order-middle", "tenant-db-order")
	middle.RegisteredAt = now.Add(-time.Hour)
	require.NoError(t, store.AddPending(ctx, middle))

	entries, err := store.ListPending(ctx, "tenant-db-order")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, "pr-db-order-oldest", entries[0].PendingID)
	assert.Equal(t, "pr-db-order-middle", entries[1].PendingID)
	assert.Equal(t, "pr-db-order-newest", entries[2].PendingID)
}

// TestDatabasePendingRegistrationStore_ExpireStale_RemovesFromListPending verifies the
// end-to-end effect of expiry on the operator list view.
func TestDatabasePendingRegistrationStore_ExpireStale_RemovesFromListPending(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	now := time.Now().UTC()

	stale := testDBPendingEntry("pr-db-stale", "tenant-db-expiry")
	stale.ExpiresAt = now.Add(-time.Minute)
	require.NoError(t, store.AddPending(ctx, stale))

	fresh := testDBPendingEntry("pr-db-fresh", "tenant-db-expiry")
	fresh.ExpiresAt = now.Add(time.Hour)
	require.NoError(t, store.AddPending(ctx, fresh))

	n, err := store.ExpireStale(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	entries, err := store.ListPending(ctx, "tenant-db-expiry")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "pr-db-fresh", entries[0].PendingID)
}

// TestDatabasePendingRegistrationStore_ListAll_IncludesEveryStatus verifies that
// ListAll, unlike ListPending, returns entries in every lifecycle status. Storage
// migration relies on this full-fidelity enumeration path (Issue #3173).
func TestDatabasePendingRegistrationStore_ListAll_IncludesEveryStatus(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-all-pend", "tenant-db-all")))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-all-appr", "tenant-db-all")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-all-appr", business.PendingRegistrationStatusApproved))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-all-claim", "tenant-db-all")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-all-claim", business.PendingRegistrationStatusApproved))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-all-claim", business.PendingRegistrationStatusClaimed))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-all-deny", "tenant-db-all")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-all-deny", business.PendingRegistrationStatusDenied))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-all-exp", "tenant-db-all")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-all-exp", business.PendingRegistrationStatusExpired))

	entries, err := store.ListAll(ctx, "tenant-db-all")
	require.NoError(t, err)

	byID := make(map[string]*business.PendingRegistrationEntry, len(entries))
	for _, e := range entries {
		byID[e.PendingID] = e
	}
	require.Len(t, byID, 5, "ListAll must return entries in every status")
	assert.Equal(t, business.PendingRegistrationStatusPending, byID["pr-db-all-pend"].Status)
	assert.Equal(t, business.PendingRegistrationStatusApproved, byID["pr-db-all-appr"].Status)
	assert.Equal(t, business.PendingRegistrationStatusClaimed, byID["pr-db-all-claim"].Status)
	assert.Equal(t, business.PendingRegistrationStatusDenied, byID["pr-db-all-deny"].Status)
	assert.Equal(t, business.PendingRegistrationStatusExpired, byID["pr-db-all-exp"].Status)
}

// TestDatabasePendingRegistrationStore_ListAll_TenantFilter verifies ListAll's
// optional tenant_id predicate scopes results without also filtering by status.
func TestDatabasePendingRegistrationStore_ListAll_TenantFilter(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-allt-t1-pend", "tenant-db-allt-1")))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-allt-t1-appr", "tenant-db-allt-1")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-allt-t1-appr", business.PendingRegistrationStatusApproved))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-allt-t2-pend", "tenant-db-allt-2")))

	entries, err := store.ListAll(ctx, "tenant-db-allt-1")
	require.NoError(t, err)

	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.PendingID)
	}
	assert.ElementsMatch(t, []string{"pr-db-allt-t1-pend", "pr-db-allt-t1-appr"}, ids)
}

// TestDatabasePendingRegistrationStore_AddDuplicate verifies that adding a second
// entry with the same PendingID returns an error, matching the SQLite implementation's
// contract so the migrator's idempotent retry (which pre-checks via GetPendingByID)
// continues to work.
func TestDatabasePendingRegistrationStore_AddDuplicate(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	entry := testDBPendingEntry("pr-db-dup", "tenant-db-dup")
	require.NoError(t, store.AddPending(ctx, entry), "first insert must succeed")

	err := store.AddPending(ctx, entry)
	require.Error(t, err, "duplicate PendingID must return an error")
}

// TestDatabasePendingRegistrationStore_GetPendingByToken verifies that GetPendingByToken
// finds an entry by hashed token and returns ErrPendingRegistrationNotFound for
// an unknown token.
func TestDatabasePendingRegistrationStore_GetPendingByToken(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	entry := testDBPendingEntry("pr-db-tok", "tenant-db-tok")
	rawToken := "cfgms_reg_tok_pr-db-tok"
	entry.TokenStr = rawToken
	require.NoError(t, store.AddPending(ctx, entry))

	got, err := store.GetPendingByToken(ctx, rawToken)
	require.NoError(t, err)
	assert.Equal(t, "pr-db-tok", got.PendingID)
	assert.Equal(t, business.RegistrationTokenLookupKey(rawToken), got.TokenStr)

	_, err = store.GetPendingByToken(ctx, "no-such-token")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

// TestDatabasePendingRegistrationStore_UpdateStatus_NotFound verifies that
// UpdateStatus returns ErrPendingRegistrationNotFound when no row matches.
func TestDatabasePendingRegistrationStore_UpdateStatus_NotFound(t *testing.T) {
	store := newTestPendingRegistrationStore(t)

	err := store.UpdateStatus(context.Background(), "no-such-id", business.PendingRegistrationStatusApproved)
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

// TestDatabasePendingRegistrationStore_UpdateStatus_Claimed_SetsClaimed verifies that
// transitioning to "claimed" also sets claimed_at to a non-nil time.
func TestDatabasePendingRegistrationStore_UpdateStatus_Claimed_SetsClaimed(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-claimed-at", "tenant-db-claimed")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-claimed-at", business.PendingRegistrationStatusApproved))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-claimed-at", business.PendingRegistrationStatusClaimed))

	got, err := store.GetPendingByID(ctx, "pr-db-claimed-at")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusClaimed, got.Status)
	require.NotNil(t, got.ClaimedAt, "claimed_at must be set when status transitions to claimed")
}

// TestDatabasePendingRegistrationStore_TenantScoping verifies the three-way scoping
// contract for ListPending: an unscoped caller (empty tenantID) sees all entries,
// a tenant-scoped caller sees only its own, and a cross-tenant lookup is empty.
func TestDatabasePendingRegistrationStore_TenantScoping(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-scope-t1a", "tenant-scope-1")))
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-scope-t1b", "tenant-scope-1")))
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-scope-t2a", "tenant-scope-2")))

	// Unscoped caller sees all three.
	all, err := store.ListPending(ctx, "")
	require.NoError(t, err)
	ids := make([]string, 0, len(all))
	for _, e := range all {
		ids = append(ids, e.PendingID)
	}
	assert.ElementsMatch(t, []string{"pr-db-scope-t1a", "pr-db-scope-t1b", "pr-db-scope-t2a"}, ids, "unscoped caller must see all tenants")

	// Tenant-1 scoped caller sees only its own two entries.
	t1Entries, err := store.ListPending(ctx, "tenant-scope-1")
	require.NoError(t, err)
	require.Len(t, t1Entries, 2)
	for _, e := range t1Entries {
		assert.Equal(t, "tenant-scope-1", e.TenantID)
	}

	// Cross-tenant negative: tenant-2 caller must not see tenant-1 entries.
	t2Entries, err := store.ListPending(ctx, "tenant-scope-2")
	require.NoError(t, err)
	require.Len(t, t2Entries, 1)
	assert.Equal(t, "pr-db-scope-t2a", t2Entries[0].PendingID)
}

// legacyCfgmsPendingRegistrationsSchemaPG is the cfgms_pending_registrations DDL as
// shipped by Issue #1696, before Issue #3403 added the five device-identity columns.
// Used to simulate a Postgres deployment upgrading in place.
const legacyCfgmsPendingRegistrationsSchemaPG = `
	CREATE TABLE cfgms_pending_registrations (
		pending_id    TEXT PRIMARY KEY,
		steward_id    TEXT NOT NULL DEFAULT '',
		tenant_id     TEXT NOT NULL,
		token_str     TEXT NOT NULL,
		source_ip     TEXT NOT NULL DEFAULT '',
		registered_at TIMESTAMP WITH TIME ZONE NOT NULL,
		expires_at    TIMESTAMP WITH TIME ZONE NOT NULL,
		claimed_at    TIMESTAMP WITH TIME ZONE,
		status        TEXT NOT NULL DEFAULT 'pending'
	)`

// pgPendingDeviceIdentityColumns are the five columns added by Issue #3403,
// plus csr_pem added by Issue #3780.
var pgPendingDeviceIdentityColumns = []string{
	"device_id", "identity_key_pub", "key_protection_level", "csr_pem", "hostname", "platform",
}

// pgPendingColumnExists reports whether the named column exists on
// cfgms_pending_registrations.
func pgPendingColumnExists(ctx context.Context, t *testing.T, db *sql.DB, column string) bool {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'cfgms_pending_registrations' AND column_name = $1
		)`, column).Scan(&exists)
	require.NoError(t, err)
	return exists
}

// seedLegacyPendingRegistrationsTable drops any existing table and creates the
// pre-#3403 shape, returning a clean database handle.
func seedLegacyPendingRegistrationsTable(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	_, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS cfgms_pending_registrations")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS cfgms_pending_registrations")
	})

	_, err = db.ExecContext(ctx, legacyCfgmsPendingRegistrationsSchemaPG)
	require.NoError(t, err, "create legacy cfgms_pending_registrations table")
	return db, ctx
}

// TestCreatePendingRegistrationsTable_MigratesLegacyTable verifies that a table created
// before Issue #3403 gains the five device-identity columns. CREATE TABLE IF NOT EXISTS
// cannot add columns, so without the ALTER sequence every upgrading Postgres deployment
// would fail its next AddPending with "column device_id of relation ... does not exist".
func TestCreatePendingRegistrationsTable_MigratesLegacyTable(t *testing.T) {
	db, ctx := seedLegacyPendingRegistrationsTable(t)

	// A pre-#3403 row must survive the migration and take the column defaults.
	_, err := db.ExecContext(ctx, `
		INSERT INTO cfgms_pending_registrations
			(pending_id, steward_id, tenant_id, token_str, registered_at, expires_at)
		VALUES ('pg-legacy', 'steward-pg-legacy', 'tenant-pg-legacy', 'tok-pg-legacy', now(), now() + interval '1 hour')`)
	require.NoError(t, err, "seed legacy row")

	for _, col := range pgPendingDeviceIdentityColumns {
		require.False(t, pgPendingColumnExists(ctx, t, db, col),
			"pre-condition: %s absent before migration", col)
	}

	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreatePendingRegistrationsTable(ctx, db), "first migration pass")

	for _, col := range pgPendingDeviceIdentityColumns {
		assert.True(t, pgPendingColumnExists(ctx, t, db, col), "%s present after migration", col)
	}

	// The legacy row keeps its data and picks up the NOT NULL defaults.
	var deviceID, keyProtection, csrPEM, hostname, platform string
	var keyPub []byte
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT device_id, identity_key_pub, key_protection_level, csr_pem, hostname, platform
		FROM cfgms_pending_registrations WHERE pending_id = 'pg-legacy'`).
		Scan(&deviceID, &keyPub, &keyProtection, &csrPEM, &hostname, &platform))
	assert.Empty(t, deviceID, "legacy row must default to an empty device_id")
	assert.Empty(t, keyPub, "legacy row must default to an empty identity_key_pub")
	assert.Empty(t, keyProtection)
	assert.Empty(t, csrPEM, "legacy row must default to an empty csr_pem")
	assert.Empty(t, hostname)
	assert.Empty(t, platform)

	// The migrated table must be usable by the store that reads and writes those
	// columns — a column that exists but carries the wrong type would still break
	// the live path.
	store := &DatabasePendingRegistrationStore{db: db, schemas: schemas}
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pg-migrated", "tenant-pg-legacy")),
		"migrated table must accept a full entry")

	got, err := store.GetPendingByID(ctx, "pg-migrated")
	require.NoError(t, err)
	assertDBDeviceIdentity(t, "pg-migrated", got)
}

// TestCreatePendingRegistrationsTable_MigrationIsIdempotent verifies that a second pass
// over an already-migrated table succeeds (ADD COLUMN IF NOT EXISTS suppresses the
// duplicate) and that rows written between the passes survive. The migration runs on
// every store open, so a non-idempotent pass would break every controller restart.
func TestCreatePendingRegistrationsTable_MigrationIsIdempotent(t *testing.T) {
	db, ctx := seedLegacyPendingRegistrationsTable(t)

	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreatePendingRegistrationsTable(ctx, db), "first migration pass")

	store := &DatabasePendingRegistrationStore{db: db, schemas: schemas}
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pg-survive", "tenant-pg-idem")))

	require.NoError(t, schemas.CreatePendingRegistrationsTable(ctx, db), "second migration pass")

	for _, col := range pgPendingDeviceIdentityColumns {
		assert.True(t, pgPendingColumnExists(ctx, t, db, col), "%s still present after second pass", col)
	}

	got, err := store.GetPendingByID(ctx, "pg-survive")
	require.NoError(t, err, "row must survive the idempotent second pass")
	assertDBDeviceIdentity(t, "pg-survive", got)
}

// TestCreatePendingRegistrationsTable_PartialLegacyTable covers the interrupted-upgrade
// case: a deployment whose ALTER sequence died part-way through leaves some of the five
// columns present. IF NOT EXISTS must add only the missing ones rather than failing.
func TestCreatePendingRegistrationsTable_PartialLegacyTable(t *testing.T) {
	db, ctx := seedLegacyPendingRegistrationsTable(t)

	_, err := db.ExecContext(ctx,
		`ALTER TABLE cfgms_pending_registrations ADD COLUMN device_id TEXT NOT NULL DEFAULT ''`)
	require.NoError(t, err, "seed a partially migrated table")

	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreatePendingRegistrationsTable(ctx, db),
		"a half-migrated table must not fail the migration")

	for _, col := range pgPendingDeviceIdentityColumns {
		assert.True(t, pgPendingColumnExists(ctx, t, db, col),
			"%s present after migrating a partially migrated table", col)
	}

	store := &DatabasePendingRegistrationStore{db: db, schemas: schemas}
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pg-partial", "tenant-pg-partial")))
	got, err := store.GetPendingByID(ctx, "pg-partial")
	require.NoError(t, err)
	assertDBDeviceIdentity(t, "pg-partial", got)
}

// TestCreatePendingRegistrationsTable_FreshTable verifies a fresh database carries all
// five columns from the CREATE TABLE statement, so the ALTER sequence is a no-op.
func TestCreatePendingRegistrationsTable_FreshTable(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreatePendingRegistrationsTable(ctx, db), "fresh table creation")
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS cfgms_pending_registrations")
	})

	for _, col := range pgPendingDeviceIdentityColumns {
		assert.True(t, pgPendingColumnExists(ctx, t, db, col), "%s present on a fresh table", col)
	}
}

// TestCreatePendingRegistrationsTable_PropagatesFailure verifies that a failing
// statement is reported rather than swallowed. The migration runs on every store open,
// so a silently ignored failure would let the controller start against an un-migrated
// table and fail at enrollment instead.
func TestCreatePendingRegistrationsTable_PropagatesFailure(t *testing.T) {
	db := getTestDB(t)
	require.NoError(t, db.Close())

	err := NewDatabaseSchemas().CreatePendingRegistrationsTable(context.Background(), db)
	require.Error(t, err, "a closed database must produce an error")
	assert.Contains(t, err.Error(), "cfgms_pending_registrations",
		"the error must name the table whose migration failed")
}

// TestCreatePendingRegistrationsTable_AlterFailurePropagates verifies the ALTER stage
// specifically: a relation named cfgms_pending_registrations that is not a table cannot
// take ADD COLUMN, and that failure must surface rather than leaving a controller
// running against a relation the store cannot write.
func TestCreatePendingRegistrationsTable_AlterFailurePropagates(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	_, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS cfgms_pending_registrations")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `
		CREATE VIEW cfgms_pending_registrations AS
		SELECT ''::TEXT AS pending_id, ''::TEXT AS tenant_id`)
	require.NoError(t, err, "shadow the table name with a non-table relation")
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP VIEW IF EXISTS cfgms_pending_registrations") })

	err = NewDatabaseSchemas().CreatePendingRegistrationsTable(ctx, db)
	require.Error(t, err, "the migration must not report success against a non-table relation")
	assert.Contains(t, err.Error(), "cfgms_pending_registrations",
		"the error must name the relation whose migration failed")
}
