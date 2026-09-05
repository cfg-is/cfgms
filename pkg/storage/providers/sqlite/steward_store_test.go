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

// newTestStewardStore creates an in-memory SQLite StewardStore for tests.
func newTestStewardStore(t *testing.T) *SQLiteStewardStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLiteStewardStore{db: db}
}

// testStewardRec returns a StewardRecord with sensible defaults.
func testStewardRec(id string) *business.StewardRecord {
	return &business.StewardRecord{
		ID:        id,
		Hostname:  "host-" + id,
		Platform:  "linux",
		Arch:      "amd64",
		Version:   "1.0.0",
		IPAddress: "10.0.0.1",
		Status:    business.StewardStatusRegistered,
	}
}

func TestSQLiteStewardStore_RegisterAndGet(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := testStewardRec("s-001")
	require.NoError(t, store.RegisterSteward(ctx, rec))

	got, err := store.GetSteward(ctx, "s-001")
	require.NoError(t, err)
	assert.Equal(t, "s-001", got.ID)
	assert.Equal(t, "linux", got.Platform)
	assert.Equal(t, business.StewardStatusRegistered, got.Status)
	assert.False(t, got.RegisteredAt.IsZero())
	assert.False(t, got.LastSeen.IsZero())
}

func TestSQLiteStewardStore_RegisterDuplicate(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := testStewardRec("s-dup")
	require.NoError(t, store.RegisterSteward(ctx, rec))
	err := store.RegisterSteward(ctx, rec)
	assert.ErrorIs(t, err, business.ErrStewardAlreadyExists)
}

func TestSQLiteStewardStore_GetNotFound(t *testing.T) {
	store := newTestStewardStore(t)
	_, err := store.GetSteward(context.Background(), "does-not-exist")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestSQLiteStewardStore_UpdateHeartbeat(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-hb")))

	before := time.Now().Add(-time.Second)
	require.NoError(t, store.UpdateHeartbeat(ctx, "s-hb"))

	got, err := store.GetSteward(ctx, "s-hb")
	require.NoError(t, err)
	assert.True(t, got.LastHeartbeatAt.After(before), "LastHeartbeatAt should be updated")
	assert.True(t, got.LastSeen.After(before), "LastSeen should be updated")
}

func TestSQLiteStewardStore_UpdateHeartbeat_NotFound(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.UpdateHeartbeat(context.Background(), "ghost")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestSQLiteStewardStore_ListStewards(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	for _, id := range []string{"s-a", "s-b", "s-c"} {
		require.NoError(t, store.RegisterSteward(ctx, testStewardRec(id)))
	}

	records, err := store.ListStewards(ctx)
	require.NoError(t, err)
	assert.Len(t, records, 3)
}

func TestSQLiteStewardStore_ListStewardsByStatus(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-reg")))

	active := testStewardRec("s-active")
	active.Status = business.StewardStatusActive
	require.NoError(t, store.RegisterSteward(ctx, active))

	regs, err := store.ListStewardsByStatus(ctx, business.StewardStatusRegistered)
	require.NoError(t, err)
	assert.Len(t, regs, 1)
	assert.Equal(t, "s-reg", regs[0].ID)

	acts, err := store.ListStewardsByStatus(ctx, business.StewardStatusActive)
	require.NoError(t, err)
	assert.Len(t, acts, 1)
	assert.Equal(t, "s-active", acts[0].ID)
}

func TestSQLiteStewardStore_UpdateStewardStatus(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-upd")))
	require.NoError(t, store.UpdateStewardStatus(ctx, "s-upd", business.StewardStatusActive))

	got, err := store.GetSteward(ctx, "s-upd")
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusActive, got.Status)
}

func TestSQLiteStewardStore_DeregisterSteward(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-dereg")))
	require.NoError(t, store.DeregisterSteward(ctx, "s-dereg"))

	got, err := store.GetSteward(ctx, "s-dereg")
	require.NoError(t, err)
	// Record retained but status changed
	assert.Equal(t, business.StewardStatusDeregistered, got.Status)
}

func TestSQLiteStewardStore_GetStewardsSeen(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-seen")))

	cutoff := time.Now().Add(-time.Minute)
	seen, err := store.GetStewardsSeen(ctx, cutoff)
	require.NoError(t, err)
	assert.Len(t, seen, 1)

	futureCutoff := time.Now().Add(time.Minute)
	notSeen, err := store.GetStewardsSeen(ctx, futureCutoff)
	require.NoError(t, err)
	assert.Empty(t, notSeen)
}

// TestSQLiteStewardStore_RestartPersistence verifies that records survive a store restart.
// Uses a real SQLite file to simulate controller restart.
func TestSQLiteStewardStore_RestartPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "stewards.db")
	ctx := context.Background()

	// First store instance — populate data
	db1, err := openAndInit(dbPath)
	require.NoError(t, err)
	store1 := &SQLiteStewardStore{db: db1}

	require.NoError(t, store1.RegisterSteward(ctx, testStewardRec("s-persist")))
	require.NoError(t, store1.UpdateHeartbeat(ctx, "s-persist"))
	require.NoError(t, store1.UpdateStewardStatus(ctx, "s-persist", business.StewardStatusActive))
	require.NoError(t, store1.Close())

	// Second store instance — same file, simulates controller restart
	db2, err := openAndInit(dbPath)
	require.NoError(t, err)
	store2 := &SQLiteStewardStore{db: db2}
	defer func() { _ = store2.Close() }()

	got, err := store2.GetSteward(ctx, "s-persist")
	require.NoError(t, err)
	assert.Equal(t, "s-persist", got.ID)
	assert.Equal(t, business.StewardStatusActive, got.Status)
	assert.False(t, got.LastHeartbeatAt.IsZero())

	all, err := store2.ListStewards(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)
}

func TestSQLiteStewardStore_HealthCheck(t *testing.T) {
	store := newTestStewardStore(t)
	assert.NoError(t, store.HealthCheck(context.Background()))
}

func TestSQLiteStewardStore_Initialize(t *testing.T) {
	store := newTestStewardStore(t)
	// Safe to call multiple times
	assert.NoError(t, store.Initialize(context.Background()))
	assert.NoError(t, store.Initialize(context.Background()))
}

func TestSQLiteStewardStore_RegisterNilRecord(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.RegisterSteward(context.Background(), nil)
	assert.Error(t, err)
}

func TestSQLiteStewardStore_RegisterEmptyID(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.RegisterSteward(context.Background(), &business.StewardRecord{})
	assert.Error(t, err)
}

func TestSQLiteStewardStore_UpdateStatusNotFound(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.UpdateStewardStatus(context.Background(), "ghost", business.StewardStatusLost)
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestSQLiteStewardStore_DeregisterNotFound(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.DeregisterSteward(context.Background(), "ghost")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestSQLiteStewardStore_GetStewardByDeviceID(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	const deviceID = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	rec := testStewardRec("s-dvc")
	rec.DeviceID = deviceID
	rec.IdentityKeyPub = []byte{1, 2, 3, 4}
	rec.KeyProtectionLevel = "file"
	rec.LastProvenanceJSON = `{"hostname":"host-s-dvc"}`
	require.NoError(t, store.RegisterSteward(ctx, rec))

	got, err := store.GetStewardByDeviceID(ctx, deviceID)
	require.NoError(t, err)
	assert.Equal(t, "s-dvc", got.ID)
	assert.Equal(t, deviceID, got.DeviceID)
	assert.Equal(t, []byte{1, 2, 3, 4}, got.IdentityKeyPub)
	assert.Equal(t, "file", got.KeyProtectionLevel)
	assert.Equal(t, `{"hostname":"host-s-dvc"}`, got.LastProvenanceJSON)

	_, err = store.GetStewardByDeviceID(ctx, "0000000000000000000000000000000000000000000000000000000000000000")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestSQLiteStewardStore_GetStewardByDeviceID_EmptyID(t *testing.T) {
	store := newTestStewardStore(t)
	_, err := store.GetStewardByDeviceID(context.Background(), "")
	require.Error(t, err, "empty device ID must return an error")
}

// TestSQLiteStewardStore_MigrationIdempotent verifies that calling initializeSchema
// twice on a populated database returns no error and existing rows survive.
func TestSQLiteStewardStore_MigrationIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migration.db")
	ctx := context.Background()

	// First init — populate with a record.
	db1, err := openAndInit(dbPath)
	require.NoError(t, err)
	store1 := &SQLiteStewardStore{db: db1}
	require.NoError(t, store1.RegisterSteward(ctx, testStewardRec("s-mig")))
	require.NoError(t, db1.Close())

	// Reopen the raw DB and call initializeSchema a second time.
	db2, err := openDB(dbPath)
	require.NoError(t, err)
	defer func() { _ = db2.Close() }()

	require.NoError(t, initializeSchema(ctx, db2), "second initializeSchema must not error")

	store2 := &SQLiteStewardStore{db: db2}
	got, err := store2.GetSteward(ctx, "s-mig")
	require.NoError(t, err)
	assert.Equal(t, "s-mig", got.ID, "row must survive second initializeSchema")
}

func TestSQLiteStewardStore_UpdateStewardTenant(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := testStewardRec("s-move")
	rec.TenantID = "tenant-src"
	require.NoError(t, store.RegisterSteward(ctx, rec))

	require.NoError(t, store.UpdateStewardTenant(ctx, "s-move", "tenant-src", "tenant-dst"))

	got, err := store.GetSteward(ctx, "s-move")
	require.NoError(t, err)
	assert.Equal(t, "tenant-dst", got.TenantID)
	// Status must not be promoted.
	assert.Equal(t, business.StewardStatusRegistered, got.Status)
}

func TestSQLiteStewardStore_UpdateStewardTenant_NotFound(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.UpdateStewardTenant(context.Background(), "nonexistent", "tenant-src", "tenant-dst")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

// TestSQLiteStewardStore_UpdateStewardTenant_StaleExpectedTenantLoses is the
// [REQUIRED TEST] regression coverage for Issue #3895 at the storage layer: a
// CAS write whose expectedTenantID no longer matches the record's current
// tenant (a concurrent writer already moved it) must lose cleanly
// (ErrStewardNotFound) without applying, mirroring the not-found/conflict
// ambiguity persistAccountCAS and PendingRegistrationStore.UpdateStatus share.
func TestSQLiteStewardStore_UpdateStewardTenant_StaleExpectedTenantLoses(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := testStewardRec("s-move-cas")
	rec.TenantID = "tenant-src"
	require.NoError(t, store.RegisterSteward(ctx, rec))

	// Winner moves tenant-src -> tenant-dst-a.
	require.NoError(t, store.UpdateStewardTenant(ctx, "s-move-cas", "tenant-src", "tenant-dst-a"))

	// Loser still holds the stale "tenant-src" snapshot read before the winner's
	// write landed, and tries to move to a different destination.
	err := store.UpdateStewardTenant(ctx, "s-move-cas", "tenant-src", "tenant-dst-b")
	assert.ErrorIs(t, err, business.ErrStewardNotFound, "a stale expectedTenantID CAS must lose cleanly")

	got, err := store.GetSteward(ctx, "s-move-cas")
	require.NoError(t, err)
	assert.Equal(t, "tenant-dst-a", got.TenantID, "the winner's destination must survive; the loser's must never apply")
}

func TestSQLiteStewardStore_SetStewardHidden(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-hide")))

	// Default: not hidden.
	got, err := store.GetSteward(ctx, "s-hide")
	require.NoError(t, err)
	assert.False(t, got.Hidden, "freshly registered steward must not be hidden")

	// Hide it.
	require.NoError(t, store.SetStewardHidden(ctx, "s-hide", true))
	got, err = store.GetSteward(ctx, "s-hide")
	require.NoError(t, err)
	assert.True(t, got.Hidden, "GetSteward must reflect hidden=true after SetStewardHidden")

	// Un-hide it.
	require.NoError(t, store.SetStewardHidden(ctx, "s-hide", false))
	got, err = store.GetSteward(ctx, "s-hide")
	require.NoError(t, err)
	assert.False(t, got.Hidden, "GetSteward must reflect hidden=false after SetStewardHidden")
}

func TestSQLiteStewardStore_SetStewardHidden_NotFound(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.SetStewardHidden(context.Background(), "ghost", true)
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

// TestSQLiteStewardStore_BackfillHidden verifies that a pre-existing stewards table
// without the hidden column is backfilled correctly on open and defaults Hidden to false.
func TestSQLiteStewardStore_BackfillHidden(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "backfill-hidden.db")
	ctx := context.Background()

	// Create a legacy-shape database without the hidden column.
	db, err := openDB(dbPath)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS stewards (
		id TEXT PRIMARY KEY, hostname TEXT NOT NULL DEFAULT '',
		platform TEXT NOT NULL DEFAULT '', arch TEXT NOT NULL DEFAULT '',
		version TEXT NOT NULL DEFAULT '', ip_address TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'registered',
		registered_at TEXT NOT NULL, last_seen TEXT NOT NULL,
		last_heartbeat_at TEXT NOT NULL DEFAULT '',
		device_id TEXT NOT NULL DEFAULT '',
		identity_key_pub BLOB NOT NULL DEFAULT '',
		key_protection_level TEXT NOT NULL DEFAULT '',
		last_provenance_json TEXT NOT NULL DEFAULT '',
		tenant_id TEXT NOT NULL DEFAULT ''
	)`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx,
		`INSERT INTO stewards (id, registered_at, last_seen) VALUES ('s-legacy','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	// Re-open with migration: backfillStewardColumns must add the hidden column.
	db2, err := openAndInit(dbPath)
	require.NoError(t, err)
	defer func() { _ = db2.Close() }()

	store := &SQLiteStewardStore{db: db2}
	got, err := store.GetSteward(ctx, "s-legacy")
	require.NoError(t, err)
	assert.False(t, got.Hidden, "backfilled row must have hidden=false (default)")

	// Verify the flag can be set on the backfilled row.
	require.NoError(t, store.SetStewardHidden(ctx, "s-legacy", true))
	got2, err := store.GetSteward(ctx, "s-legacy")
	require.NoError(t, err)
	assert.True(t, got2.Hidden, "hidden flag must be settable after backfill")
}

func TestSQLiteStewardStore_TenantID_PersistedByRegisterAndRetrieved(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := testStewardRec("s-tenid")
	rec.TenantID = "my-tenant"
	require.NoError(t, store.RegisterSteward(ctx, rec))

	got, err := store.GetSteward(ctx, "s-tenid")
	require.NoError(t, err)
	assert.Equal(t, "my-tenant", got.TenantID)
}

// TestSQLiteStewardStore_BackfillTenantID verifies that backfillStewardColumns adds the
// tenant_id column to a pre-existing stewards table that was created without it (Issue #2341).
func TestSQLiteStewardStore_BackfillTenantID(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "backfill.db")
	ctx := context.Background()

	// Create a database with the old schema (no tenant_id).
	db, err := openDB(dbPath)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS stewards (
		id TEXT PRIMARY KEY, hostname TEXT NOT NULL DEFAULT '',
		platform TEXT NOT NULL DEFAULT '', arch TEXT NOT NULL DEFAULT '',
		version TEXT NOT NULL DEFAULT '', ip_address TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'registered',
		registered_at TEXT NOT NULL, last_seen TEXT NOT NULL,
		last_heartbeat_at TEXT NOT NULL DEFAULT '',
		device_id TEXT NOT NULL DEFAULT '',
		identity_key_pub BLOB NOT NULL DEFAULT '',
		key_protection_level TEXT NOT NULL DEFAULT '',
		last_provenance_json TEXT NOT NULL DEFAULT ''
	)`)
	require.NoError(t, err)
	// Insert a row without tenant_id.
	_, err = db.ExecContext(ctx,
		`INSERT INTO stewards (id, registered_at, last_seen) VALUES ('s-old','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	// Re-open with migration: backfillStewardColumns must add tenant_id.
	db2, err := openAndInit(dbPath)
	require.NoError(t, err)
	defer func() { _ = db2.Close() }()

	store := &SQLiteStewardStore{db: db2}
	got, err := store.GetSteward(ctx, "s-old")
	require.NoError(t, err)
	assert.Equal(t, "", got.TenantID, "backfilled row must have empty tenant_id default")

	// Update the tenant and verify round-trip.
	require.NoError(t, store.UpdateStewardTenant(ctx, "s-old", "", "post-migration-tenant"))
	got2, err := store.GetSteward(ctx, "s-old")
	require.NoError(t, err)
	assert.Equal(t, "post-migration-tenant", got2.TenantID)
}

// TestSQLiteStewardStore_DeviceIDUniquePerTenant covers the database-level backstop
// for the tenant-scoped duplicate-device_id guard (Issue #3403).
//
// The guard in features/controller/api/handlers_registration.go is check-then-act:
// it reads GetStewardByDeviceID, then writes RegisterSteward. Two claims can both
// complete the read before either writes, and the writes key on distinct steward
// IDs so nothing makes them collide at the row level. The partial unique index on
// (tenant_id, device_id) is what actually decides a winner, and this test exercises
// it directly rather than through the handler — a handler-level race is timing
// dependent and passes with or without the index, so it cannot prove the backstop.
func TestSQLiteStewardStore_DeviceIDUniquePerTenant(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	const deviceID = "device-shared-1"

	first := testStewardRec("steward-dup-a")
	first.TenantID = "tenant-1"
	first.DeviceID = deviceID
	require.NoError(t, store.RegisterSteward(ctx, first))

	// A different steward asserting the same device_id in the same tenant.
	second := testStewardRec("steward-dup-b")
	second.TenantID = "tenant-1"
	second.DeviceID = deviceID
	err := store.RegisterSteward(ctx, second)
	require.Error(t, err, "a second steward must not take a device_id already held in the tenant")
	assert.ErrorIs(t, err, business.ErrStewardDeviceIDConflict,
		"the conflict must be reported as ErrStewardDeviceIDConflict, not the benign ErrStewardAlreadyExists")

	// Cross-tenant is a separate namespace and must still be allowed.
	other := testStewardRec("steward-dup-c")
	other.TenantID = "tenant-2"
	other.DeviceID = deviceID
	assert.NoError(t, store.RegisterSteward(ctx, other),
		"the same device_id under a different tenant is a distinct namespace")

	// Empty device_id means "not asserted" and must not collide with itself.
	blankA := testStewardRec("steward-blank-a")
	blankA.TenantID = "tenant-1"
	blankA.DeviceID = ""
	blankB := testStewardRec("steward-blank-b")
	blankB.TenantID = "tenant-1"
	blankB.DeviceID = ""
	require.NoError(t, store.RegisterSteward(ctx, blankA))
	assert.NoError(t, store.RegisterSteward(ctx, blankB),
		"rows with no device_id must be excluded from the unique index")

	// Re-registering the SAME steward is still the benign duplicate, not a device conflict.
	dupSelf := testStewardRec("steward-dup-a")
	dupSelf.TenantID = "tenant-1"
	dupSelf.DeviceID = deviceID
	selfErr := store.RegisterSteward(ctx, dupSelf)
	require.Error(t, selfErr)
	assert.ErrorIs(t, selfErr, business.ErrStewardAlreadyExists,
		"the same steward written twice stays ErrStewardAlreadyExists so idempotent retries remain benign")

	// GetStewardByDeviceID stays unambiguous within the tenant — the property the
	// revocation gate in handlers_registration_refresh.go depends on.
	got, getErr := store.GetStewardByDeviceID(ctx, deviceID)
	require.NoError(t, getErr)
	require.NotNil(t, got)
}
