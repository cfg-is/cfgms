// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"

	_ "modernc.org/sqlite"
)

// legacyAuditSchema is the audit_entries DDL from before sequence_number /
// previous_checksum were added. Tests use this to simulate a pre-existing DB.
const legacyAuditSchema = `CREATE TABLE IF NOT EXISTS audit_entries (
	id               TEXT PRIMARY KEY,
	tenant_id        TEXT NOT NULL,
	timestamp        TEXT NOT NULL,
	event_type       TEXT NOT NULL,
	action           TEXT NOT NULL,
	user_id          TEXT NOT NULL,
	user_type        TEXT NOT NULL,
	session_id       TEXT NOT NULL DEFAULT '',
	resource_type    TEXT NOT NULL,
	resource_id      TEXT NOT NULL,
	resource_name    TEXT NOT NULL DEFAULT '',
	result           TEXT NOT NULL,
	error_code       TEXT NOT NULL DEFAULT '',
	error_message    TEXT NOT NULL DEFAULT '',
	request_id       TEXT NOT NULL DEFAULT '',
	ip_address       TEXT NOT NULL DEFAULT '',
	user_agent       TEXT NOT NULL DEFAULT '',
	method           TEXT NOT NULL DEFAULT '',
	path             TEXT NOT NULL DEFAULT '',
	details          TEXT NOT NULL DEFAULT '{}',
	changes          TEXT NOT NULL DEFAULT '{}',
	tags             TEXT NOT NULL DEFAULT '[]',
	severity         TEXT NOT NULL,
	source           TEXT NOT NULL,
	version          TEXT NOT NULL DEFAULT '',
	checksum         TEXT NOT NULL
)`

// openMemDB opens a shared in-memory SQLite database for testing.
func openMemDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := openDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// hasColumn reports whether the named column exists in table.
// SQLite PRAGMA does not support ? binding; table is always a hardcoded literal in these tests.
func hasColumn(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	// #nosec G202 -- PRAGMA does not support ? binding; caller passes only literals.
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dfltValue sql.NullString
		require.NoError(t, rows.Scan(&cid, &name, &typ, &notNull, &dfltValue, &pk))
		if name == column {
			return true
		}
	}
	require.NoError(t, rows.Err())
	return false
}

// hasIndex reports whether the named index exists on table.
func hasIndex(t *testing.T, db *sql.DB, table, index string) bool {
	t.Helper()
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name=? AND name=?`,
		table, index,
	).Scan(&count)
	require.NoError(t, err)
	return count > 0
}

// TestBackfill_LegacyAuditEntries verifies that initializeSchema adds the
// missing columns and index to a pre-existing legacy audit_entries table.
func TestBackfill_LegacyAuditEntries(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	// Seed a legacy-shape table without sequence_number / previous_checksum.
	_, err := db.ExecContext(ctx, legacyAuditSchema)
	require.NoError(t, err, "seed legacy schema")

	assert.False(t, hasColumn(t, db, "audit_entries", "sequence_number"), "pre-condition: column absent before back-fill")
	assert.False(t, hasColumn(t, db, "audit_entries", "previous_checksum"), "pre-condition: column absent before back-fill")

	// First invocation — should back-fill the missing columns and create indexes.
	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	assert.True(t, hasColumn(t, db, "audit_entries", "sequence_number"), "sequence_number present after back-fill")
	assert.True(t, hasColumn(t, db, "audit_entries", "previous_checksum"), "previous_checksum present after back-fill")
	assert.True(t, hasIndex(t, db, "audit_entries", "idx_audit_entries_tenant_seq"), "composite index present after back-fill")
}

// TestBackfill_Idempotent verifies that calling initializeSchema a second time
// on an already-migrated database succeeds without errors.
func TestBackfill_Idempotent(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	// Seed legacy table and migrate once.
	_, err := db.ExecContext(ctx, legacyAuditSchema)
	require.NoError(t, err, "seed legacy schema")
	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	// Second invocation must also succeed.
	require.NoError(t, initializeSchema(ctx, db), "second initializeSchema call (idempotency check)")

	assert.True(t, hasColumn(t, db, "audit_entries", "sequence_number"), "sequence_number still present")
	assert.True(t, hasColumn(t, db, "audit_entries", "previous_checksum"), "previous_checksum still present")
	assert.True(t, hasIndex(t, db, "audit_entries", "idx_audit_entries_tenant_seq"), "composite index still present")
}

// TestBackfill_FreshDB verifies that a fresh database initializes cleanly
// without the back-fill pass interfering with the full modern schema.
func TestBackfill_FreshDB(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	// No legacy seeding — fresh DB path.
	require.NoError(t, initializeSchema(ctx, db), "fresh DB initialization")

	assert.True(t, hasColumn(t, db, "audit_entries", "sequence_number"), "sequence_number present on fresh DB")
	assert.True(t, hasColumn(t, db, "audit_entries", "previous_checksum"), "previous_checksum present on fresh DB")
	assert.True(t, hasIndex(t, db, "audit_entries", "idx_audit_entries_tenant_seq"), "composite index present on fresh DB")
}

// TestBackfill_ProbeFailure verifies that tableExists failures propagate
// correctly and do not silently succeed.
func TestBackfill_ProbeFailure(t *testing.T) {
	ctx := context.Background()

	// Open and immediately close the DB so all subsequent operations fail.
	db, err := openDB(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	err = backfillAuditEntries(ctx, db)
	require.Error(t, err, "closed DB must return an error")
	assert.Contains(t, err.Error(), "back-fill probe failed", "error must identify the probe stage")
}

// TestBackfill_AlterFailure verifies that an ALTER TABLE failure (not caused
// by a duplicate column) propagates and is not silently ignored.
func TestBackfill_AlterFailure(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "readonly.db")

	// Create a file DB and seed the legacy table.
	setup, err := openDB(dbPath)
	require.NoError(t, err)
	_, err = setup.ExecContext(context.Background(), legacyAuditSchema)
	require.NoError(t, err)
	require.NoError(t, setup.Close())

	// Re-open in read-only mode — reads succeed but writes (ALTER) fail.
	roDB, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = roDB.Close() })
	require.NoError(t, roDB.Ping())

	err = backfillAuditEntries(context.Background(), roDB)
	require.Error(t, err, "ALTER TABLE on read-only DB must return an error")
	assert.Contains(t, err.Error(), "back-fill", "error must identify the back-fill stage")
}

// legacyStewardsSchema is the stewards DDL from before the four registration-refresh
// identity columns were added. Used to simulate a pre-existing deployment.
const legacyStewardsSchema = `CREATE TABLE IF NOT EXISTS stewards (
	id                TEXT PRIMARY KEY,
	hostname          TEXT NOT NULL DEFAULT '',
	platform          TEXT NOT NULL DEFAULT '',
	arch              TEXT NOT NULL DEFAULT '',
	version           TEXT NOT NULL DEFAULT '',
	ip_address        TEXT NOT NULL DEFAULT '',
	status            TEXT NOT NULL DEFAULT 'registered',
	registered_at     TEXT NOT NULL DEFAULT '',
	last_seen         TEXT NOT NULL DEFAULT '',
	last_heartbeat_at TEXT NOT NULL DEFAULT ''
)`

// TestBackfillStewardColumns_LegacyStewards verifies that initializeSchema adds the
// four new identity columns to a pre-existing stewards table that lacks them.
func TestBackfillStewardColumns_LegacyStewards(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	// Seed a legacy-shape stewards table without the four new columns.
	_, err := db.ExecContext(ctx, legacyStewardsSchema)
	require.NoError(t, err, "seed legacy stewards schema")

	for _, col := range []string{"device_id", "identity_key_pub", "key_protection_level", "last_provenance_json"} {
		assert.False(t, hasColumn(t, db, "stewards", col), "pre-condition: %s absent before back-fill", col)
	}

	// First invocation — should back-fill the missing columns and create the device_id index.
	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	for _, col := range []string{"device_id", "identity_key_pub", "key_protection_level", "last_provenance_json"} {
		assert.True(t, hasColumn(t, db, "stewards", col), "%s present after back-fill", col)
	}
	assert.True(t, hasIndex(t, db, "stewards", "idx_stewards_device_id"), "device_id index present after back-fill")
}

// TestBackfillStewardColumns_Idempotent verifies that calling initializeSchema a second
// time on an already-migrated stewards table succeeds and existing rows survive.
func TestBackfillStewardColumns_Idempotent(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	// Seed legacy table and migrate once.
	_, err := db.ExecContext(ctx, legacyStewardsSchema)
	require.NoError(t, err, "seed legacy stewards schema")
	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	// Insert a row to prove it survives the second pass.
	_, err = db.ExecContext(ctx, `
		INSERT INTO stewards (id, registered_at, last_seen)
		VALUES ('s-survive', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err, "insert test row")

	// Second invocation must also succeed and leave rows intact.
	require.NoError(t, initializeSchema(ctx, db), "second initializeSchema call (idempotency check)")

	for _, col := range []string{"device_id", "identity_key_pub", "key_protection_level", "last_provenance_json"} {
		assert.True(t, hasColumn(t, db, "stewards", col), "%s still present after second pass", col)
	}

	var count int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM stewards WHERE id='s-survive'`).Scan(&count))
	assert.Equal(t, 1, count, "row must survive second initializeSchema")
}

// TestBackfillStewardColumns_FreshDB verifies that a fresh database initializes cleanly
// with all four columns present from the CREATE TABLE statement.
func TestBackfillStewardColumns_FreshDB(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	require.NoError(t, initializeSchema(ctx, db), "fresh DB initialization")

	for _, col := range []string{"device_id", "identity_key_pub", "key_protection_level", "last_provenance_json"} {
		assert.True(t, hasColumn(t, db, "stewards", col), "%s present on fresh DB", col)
	}
	assert.True(t, hasIndex(t, db, "stewards", "idx_stewards_device_id"), "device_id index on fresh DB")
}

// sessionTokenContinuityColumns are the four device-continuity columns added in Issue #2788.
var sessionTokenContinuityColumns = []string{"assurance", "bound_ip", "last_proven_at", "credential_id"}

// legacySessionTokenRecordsSchema is the session_token_records DDL from Issue #2775, before
// the four device-continuity columns (Issue #2788) were added. Used to simulate a
// pre-#2788 deployment upgrading in place.
const legacySessionTokenRecordsSchema = `CREATE TABLE IF NOT EXISTS session_token_records (
	token_hash            TEXT PRIMARY KEY,
	session_id            TEXT NOT NULL,
	principal_id          TEXT NOT NULL,
	connection_name       TEXT NOT NULL,
	tenant_id             TEXT NOT NULL,
	issued_at             TEXT NOT NULL,
	last_activity         TEXT NOT NULL,
	absolute_expires_at   TEXT NOT NULL,
	hash_expires_at       TEXT
)`

// TestBackfillSessionTokenRecords_LegacyRecords verifies that initializeSchema adds the
// four device-continuity columns to a pre-existing session_token_records table that lacks
// them, and that a pre-existing human-session row receives assurance=1 (AssuranceBasic).
func TestBackfillSessionTokenRecords_LegacyRecords(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	// Seed a legacy-shape table without the four continuity columns.
	_, err := db.ExecContext(ctx, legacySessionTokenRecordsSchema)
	require.NoError(t, err, "seed legacy session_token_records schema")

	// Insert a pre-#2788 human-session row so we can prove the assurance default applies.
	_, err = db.ExecContext(ctx, `
		INSERT INTO session_token_records
			(token_hash, session_id, principal_id, connection_name, tenant_id,
			 issued_at, last_activity, absolute_expires_at)
		VALUES ('legacy-hash', 'legacy-sess', 'admin', 'ctrl', 'tenant-1',
			'2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T08:00:00Z')`)
	require.NoError(t, err, "seed legacy row")

	for _, col := range sessionTokenContinuityColumns {
		assert.False(t, hasColumn(t, db, "session_token_records", col), "pre-condition: %s absent before back-fill", col)
	}

	// First invocation — should back-fill the four missing columns.
	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	for _, col := range sessionTokenContinuityColumns {
		assert.True(t, hasColumn(t, db, "session_token_records", col), "%s present after back-fill", col)
	}

	// The pre-existing human-session row must default to assurance=1 (AssuranceBasic)
	// and empty bound_ip, with the nullable columns left NULL.
	var assurance int
	var boundIP string
	var lastProven, credentialID sql.NullString
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT assurance, bound_ip, last_proven_at, credential_id
		FROM session_token_records WHERE token_hash='legacy-hash'`).
		Scan(&assurance, &boundIP, &lastProven, &credentialID))
	assert.Equal(t, 1, assurance, "legacy row must default to assurance=1 (AssuranceBasic)")
	assert.Equal(t, "", boundIP, "legacy row must default to empty bound_ip")
	assert.False(t, lastProven.Valid, "legacy row last_proven_at must be NULL")
	assert.False(t, credentialID.Valid, "legacy row credential_id must be NULL")
}

// TestBackfillSessionTokenRecords_Idempotent verifies that calling initializeSchema a second
// time on an already-migrated session_token_records table succeeds and existing rows survive.
func TestBackfillSessionTokenRecords_Idempotent(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	// Seed legacy table and migrate once.
	_, err := db.ExecContext(ctx, legacySessionTokenRecordsSchema)
	require.NoError(t, err, "seed legacy session_token_records schema")
	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	// Insert a row to prove it survives the second pass.
	_, err = db.ExecContext(ctx, `
		INSERT INTO session_token_records
			(token_hash, session_id, principal_id, connection_name, tenant_id,
			 issued_at, last_activity, absolute_expires_at)
		VALUES ('survive-hash', 'survive-sess', 'admin', 'ctrl', 'tenant-1',
			'2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T08:00:00Z')`)
	require.NoError(t, err, "insert test row")

	// Second invocation must also succeed and leave rows intact.
	require.NoError(t, initializeSchema(ctx, db), "second initializeSchema call (idempotency check)")

	for _, col := range sessionTokenContinuityColumns {
		assert.True(t, hasColumn(t, db, "session_token_records", col), "%s still present after second pass", col)
	}

	var count int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM session_token_records WHERE token_hash='survive-hash'`).Scan(&count))
	assert.Equal(t, 1, count, "row must survive second initializeSchema")
}

// TestBackfillSessionTokenRecords_FreshDB verifies that a fresh database initializes cleanly
// with all four continuity columns present from the CREATE TABLE statement.
func TestBackfillSessionTokenRecords_FreshDB(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	require.NoError(t, initializeSchema(ctx, db), "fresh DB initialization")

	for _, col := range sessionTokenContinuityColumns {
		assert.True(t, hasColumn(t, db, "session_token_records", col), "%s present on fresh DB", col)
	}
	assert.True(t, hasIndex(t, db, "session_token_records", "idx_session_token_records_session_id"),
		"session_id index present on fresh DB")
}

// TestBackfillSessionTokenRecords_ProbeFailure verifies that a tableExists failure propagates
// from backfillSessionTokenRecords rather than silently succeeding.
func TestBackfillSessionTokenRecords_ProbeFailure(t *testing.T) {
	ctx := context.Background()

	// Open and immediately close the DB so all subsequent operations fail.
	db, err := openDB(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	err = backfillSessionTokenRecords(ctx, db)
	require.Error(t, err, "closed DB must return an error")
	assert.Contains(t, err.Error(), "back-fill probe failed", "error must identify the probe stage")
}

// TestBackfillSessionTokenRecords_AlterFailure verifies that an ALTER TABLE failure on a
// read-only database propagates instead of being silently ignored.
func TestBackfillSessionTokenRecords_AlterFailure(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "readonly-sessiontokens.db")

	// Create a file DB and seed the legacy table (no continuity columns).
	setup, err := openDB(dbPath)
	require.NoError(t, err)
	_, err = setup.ExecContext(context.Background(), legacySessionTokenRecordsSchema)
	require.NoError(t, err)
	require.NoError(t, setup.Close())

	// Re-open in read-only mode — reads succeed but writes (ALTER) fail.
	roDB, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = roDB.Close() })
	require.NoError(t, roDB.Ping())

	err = backfillSessionTokenRecords(context.Background(), roDB)
	require.Error(t, err, "ALTER TABLE on read-only DB must return an error")
	assert.Contains(t, err.Error(), "back-fill", "error must identify the back-fill stage")
}

// legacyRegistrationTokensSchema is the registration_tokens DDL from before the id
// column was added in Issue #2970.
const legacyRegistrationTokensSchema = `CREATE TABLE IF NOT EXISTS registration_tokens (
	token          TEXT PRIMARY KEY,
	tenant_id      TEXT NOT NULL,
	controller_url TEXT NOT NULL,
	group_name     TEXT NOT NULL DEFAULT '',
	created_at     TEXT NOT NULL,
	expires_at     TEXT,
	revoked        INTEGER NOT NULL DEFAULT 0,
	revoked_at     TEXT
)`

// TestBackfillRegistrationTokenID_LegacyRowsGetUUIDs verifies that a pre-existing
// registration_tokens table gains the id column AND that every legacy row is assigned
// a UUID (Issue #2970). Without the row back-fill the oldest tokens — the ones most
// likely to need revoking — would report an empty token_id forever and could never be
// revoked or deleted from the web UI.
func TestBackfillRegistrationTokenID_LegacyRowsGetUUIDs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-regtokens.db")
	ctx := context.Background()

	setup, err := openDB(dbPath)
	require.NoError(t, err)
	_, err = setup.ExecContext(ctx, legacyRegistrationTokensSchema)
	require.NoError(t, err)
	require.False(t, hasColumn(t, setup, "registration_tokens", "id"), "legacy table has no id column")
	for _, tok := range []string{"legacy-a", "legacy-b"} {
		_, err = setup.ExecContext(ctx,
			`INSERT INTO registration_tokens (token, tenant_id, controller_url, created_at)
			 VALUES (?, 'tenant-legacy', 'grpc://controller:7443', '2026-01-01T00:00:00Z')`, tok)
		require.NoError(t, err)
	}
	require.NoError(t, setup.Close())

	// Re-open with migration.
	db, err := openAndInit(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	require.True(t, hasColumn(t, db, "registration_tokens", "id"), "migration must add the id column")

	store := &SQLiteRegistrationTokenStore{db: db}
	ids := make(map[string]string, 2)
	for _, tok := range []string{"legacy-a", "legacy-b"} {
		got, err := store.GetToken(ctx, tok)
		require.NoError(t, err)
		require.NotEmpty(t, got.ID, "legacy row %q must be assigned a UUID", tok)
		assert.Regexp(t,
			`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
			got.ID, "backfilled id must be a UUID v4")

		byID, err := store.GetTokenByID(ctx, got.ID)
		require.NoError(t, err, "backfilled token must be addressable by id")
		assert.Equal(t, tok, byID.Token)

		ids[tok] = got.ID
	}
	assert.NotEqual(t, ids["legacy-a"], ids["legacy-b"], "each legacy row gets a distinct id")

	// Re-running the migration must be idempotent — ids stay stable.
	require.NoError(t, backfillRegistrationTokenID(ctx, db))
	for tok, id := range ids {
		got, err := store.GetToken(ctx, tok)
		require.NoError(t, err)
		assert.Equal(t, id, got.ID, "re-running the back-fill must not reassign %q", tok)
	}
}

// TestBackfillRegistrationTokenID_NullIDRowsGetUUIDs covers a table that already has the
// id column but holds rows written before ids were persisted (NULL id).
func TestBackfillRegistrationTokenID_NullIDRowsGetUUIDs(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()
	require.NoError(t, initializeSchema(ctx, db))

	_, err := db.ExecContext(ctx,
		`INSERT INTO registration_tokens (token, id, tenant_id, controller_url, created_at)
		 VALUES ('null-id-token', NULL, 'tenant-legacy', 'grpc://controller:7443', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)

	require.NoError(t, backfillRegistrationTokenID(ctx, db))

	store := &SQLiteRegistrationTokenStore{db: db}
	got, err := store.GetToken(ctx, "null-id-token")
	require.NoError(t, err)
	require.NotEmpty(t, got.ID, "NULL-id row must be assigned a UUID")

	byID, err := store.GetTokenByID(ctx, got.ID)
	require.NoError(t, err)
	assert.Equal(t, "null-id-token", byID.Token)
}

// TestSaveToken_HealsEmptyStoredID covers a row whose stored id is the empty string rather
// than NULL — the second half of the back-fill's "missing id" predicate. Such a row is
// unaddressable by GetTokenByID, so a save that upserts onto it must heal the id instead
// of preserving the empty value forever.
func TestSaveToken_HealsEmptyStoredID(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()
	require.NoError(t, initializeSchema(ctx, db))

	store := &SQLiteRegistrationTokenStore{db: db}
	_, err := db.ExecContext(ctx,
		`INSERT INTO registration_tokens (token, id, tenant_id, controller_url, created_at)
		 VALUES ('empty-id-token', '', 'tenant-legacy', 'grpc://controller:7443', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)

	stale, err := store.GetToken(ctx, "empty-id-token")
	require.NoError(t, err)
	require.Empty(t, stale.ID, "precondition: the row is unaddressable by id")

	resaved := &business.RegistrationTokenData{
		Token:         "empty-id-token",
		TenantID:      "tenant-legacy",
		ControllerURL: "grpc://controller:7443",
	}
	require.NoError(t, store.SaveToken(ctx, resaved))
	require.NotEmpty(t, resaved.ID, "an empty stored id must be healed, not preserved")

	byID, err := store.GetTokenByID(ctx, resaved.ID)
	require.NoError(t, err)
	assert.Equal(t, business.RegistrationTokenLookupKey("empty-id-token"), byID.Token)
}

// TestBackfillRegistrationTokenID_FreshDB verifies a fresh database carries the id column
// from the CREATE TABLE statement, so the back-fill is a no-op.
func TestBackfillRegistrationTokenID_FreshDB(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	require.NoError(t, initializeSchema(ctx, db), "fresh DB initialization")
	assert.True(t, hasColumn(t, db, "registration_tokens", "id"), "id column present on fresh DB")
	require.NoError(t, backfillRegistrationTokenID(ctx, db), "back-fill is a no-op on a fresh DB")
}

// TestBackfillRegistrationTokenID_ProbeFailure verifies that a tableExists failure
// propagates rather than being silently ignored.
func TestBackfillRegistrationTokenID_ProbeFailure(t *testing.T) {
	db, err := openDB(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	err = backfillRegistrationTokenID(context.Background(), db)
	require.Error(t, err, "closed DB must return an error")
	assert.Contains(t, err.Error(), "back-fill probe failed", "error must identify the probe stage")
}

// TestBackfillRegistrationTokenID_UpdateFailure verifies that a failure to write the
// generated ids propagates instead of leaving rows silently unaddressable.
func TestBackfillRegistrationTokenID_UpdateFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "readonly-regtokens.db")
	ctx := context.Background()

	setup, err := openDB(dbPath)
	require.NoError(t, err)
	_, err = setup.ExecContext(ctx, legacyRegistrationTokensSchema)
	require.NoError(t, err)
	_, err = setup.ExecContext(ctx, `ALTER TABLE registration_tokens ADD COLUMN id TEXT`)
	require.NoError(t, err)
	_, err = setup.ExecContext(ctx,
		`INSERT INTO registration_tokens (token, tenant_id, controller_url, created_at)
		 VALUES ('ro-token', 'tenant-legacy', 'grpc://controller:7443', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	require.NoError(t, setup.Close())

	roDB, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = roDB.Close() })
	require.NoError(t, roDB.Ping())

	err = backfillRegistrationTokenID(ctx, roDB)
	require.Error(t, err, "UPDATE on read-only DB must return an error")
	assert.Contains(t, err.Error(), "back-fill update failed", "error must identify the update stage")
}

// legacyTenantsSchema is the tenants DDL from before the ADR-027 Decision 2
// suspension provenance columns were added in migration 008.
const legacyTenantsSchema = `CREATE TABLE IF NOT EXISTS tenants (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	parent_id   TEXT,
	metadata    TEXT NOT NULL DEFAULT '{}',
	status      TEXT NOT NULL DEFAULT 'active',
	created_at  TEXT NOT NULL,
	updated_at  TEXT NOT NULL
)`

// TestBackfillTenantLifecycle_LegacyTable verifies that initializeSchema adds the
// ADR-027 provenance columns to a pre-existing tenants table that lacks them.
func TestBackfillTenantLifecycle_LegacyTable(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacyTenantsSchema)
	require.NoError(t, err, "seed legacy tenants schema")

	for _, col := range []string{"directly_suspended", "cascade_suspended_from"} {
		assert.False(t, hasColumn(t, db, "tenants", col), "pre-condition: %s absent before back-fill", col)
	}

	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	assert.True(t, hasColumn(t, db, "tenants", "directly_suspended"), "directly_suspended present after back-fill")
	assert.True(t, hasColumn(t, db, "tenants", "cascade_suspended_from"), "cascade_suspended_from present after back-fill")
}

// TestBackfillTenantLifecycle_Idempotent verifies that calling initializeSchema a
// second time on an already-migrated tenants table succeeds and existing rows survive.
func TestBackfillTenantLifecycle_Idempotent(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacyTenantsSchema)
	require.NoError(t, err, "seed legacy tenants schema")
	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	_, err = db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, created_at, updated_at) VALUES ('t-survive', 'Survive', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err, "insert test row")

	require.NoError(t, initializeSchema(ctx, db), "second initializeSchema call (idempotency check)")

	for _, col := range []string{"directly_suspended", "cascade_suspended_from"} {
		assert.True(t, hasColumn(t, db, "tenants", col), "%s still present after second pass", col)
	}
	var count int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tenants WHERE id='t-survive'`).Scan(&count))
	assert.Equal(t, 1, count, "row must survive second initializeSchema")
}

// TestBackfillTenantLifecycle_FreshDB verifies that a fresh database carries
// both provenance columns from the CREATE TABLE statement, so the back-fill is a no-op.
func TestBackfillTenantLifecycle_FreshDB(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	require.NoError(t, initializeSchema(ctx, db), "fresh DB initialization")

	assert.True(t, hasColumn(t, db, "tenants", "directly_suspended"), "directly_suspended present on fresh DB")
	assert.True(t, hasColumn(t, db, "tenants", "cascade_suspended_from"), "cascade_suspended_from present on fresh DB")
}

// legacyCfgmsPendingRegistrationsSchema is the cfgms_pending_registrations DDL as
// shipped by Issue #1696, before Issue #3403 added the five device-identity
// columns that let the claim step write a complete StewardRecord.
const legacyCfgmsPendingRegistrationsSchema = `CREATE TABLE IF NOT EXISTS cfgms_pending_registrations (
	pending_id    TEXT PRIMARY KEY,
	steward_id    TEXT NOT NULL DEFAULT '',
	tenant_id     TEXT NOT NULL,
	token_str     TEXT NOT NULL,
	source_ip     TEXT NOT NULL DEFAULT '',
	registered_at TEXT NOT NULL,
	expires_at    TEXT NOT NULL,
	claimed_at    TEXT,
	status        TEXT NOT NULL DEFAULT 'pending'
)`

// cfgmsPendingDeviceIdentityColumns are the five columns added by Issue #3403,
// plus csr_pem added by Issue #3780.
var cfgmsPendingDeviceIdentityColumns = []string{
	"device_id", "identity_key_pub", "key_protection_level", "csr_pem", "hostname", "platform",
}

// TestBackfillCfgmsPendingRegistrationColumns_LegacyTable verifies that
// initializeSchema adds the five device-identity columns to a pre-existing
// cfgms_pending_registrations table created before Issue #3403. CREATE TABLE IF
// NOT EXISTS cannot add columns, so without the back-fill every upgrading
// deployment would fail its next AddPending with "no such column: device_id".
func TestBackfillCfgmsPendingRegistrationColumns_LegacyTable(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacyCfgmsPendingRegistrationsSchema)
	require.NoError(t, err, "seed legacy cfgms_pending_registrations schema")

	for _, col := range cfgmsPendingDeviceIdentityColumns {
		require.False(t, hasColumn(t, db, "cfgms_pending_registrations", col),
			"pre-condition: %s absent before back-fill", col)
	}

	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	for _, col := range cfgmsPendingDeviceIdentityColumns {
		assert.True(t, hasColumn(t, db, "cfgms_pending_registrations", col),
			"%s present after back-fill", col)
	}

	// The migrated table must actually be usable by the store that reads and
	// writes those columns — a column that exists but has the wrong affinity or
	// a NOT NULL without a default would still break the live path.
	store := &SQLitePendingRegistrationStore{db: db}
	entry := &business.PendingRegistrationEntry{
		PendingID:          "pend-legacy",
		TenantID:           "tenant-a",
		TokenStr:           "tok-legacy",
		RegisteredAt:       time.Now().UTC().Truncate(time.Second),
		ExpiresAt:          time.Now().UTC().Add(time.Hour).Truncate(time.Second),
		DeviceID:           "dev-legacy",
		IdentityKeyPub:     []byte{0x01, 0x02, 0x03},
		KeyProtectionLevel: "tpm",
		CSRPEM:             "-----BEGIN CERTIFICATE REQUEST-----\nlegacy\n-----END CERTIFICATE REQUEST-----",
		Hostname:           "host-legacy",
		Platform:           "linux",
	}
	require.NoError(t, store.AddPending(ctx, entry), "back-filled table must accept a full entry")

	got, err := store.GetPendingByID(ctx, "pend-legacy")
	require.NoError(t, err)
	assert.Equal(t, "dev-legacy", got.DeviceID)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, got.IdentityKeyPub)
	assert.Equal(t, "tpm", got.KeyProtectionLevel)
	assert.Equal(t, entry.CSRPEM, got.CSRPEM)
	assert.Equal(t, "host-legacy", got.Hostname)
	assert.Equal(t, "linux", got.Platform)
}

// TestBackfillCfgmsPendingRegistrationColumns_Idempotent verifies that a second
// initializeSchema pass over an already-migrated table succeeds (the PRAGMA
// column probe suppresses the duplicate ALTER) and that rows written between
// the two passes survive.
func TestBackfillCfgmsPendingRegistrationColumns_Idempotent(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacyCfgmsPendingRegistrationsSchema)
	require.NoError(t, err, "seed legacy cfgms_pending_registrations schema")
	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	_, err = db.ExecContext(ctx,
		`INSERT INTO cfgms_pending_registrations
			(pending_id, tenant_id, token_str, registered_at, expires_at, device_id, hostname, platform)
		 VALUES ('pend-survive', 'tenant-a', 'tok-survive', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', 'dev-survive', 'host-survive', 'linux')`)
	require.NoError(t, err, "insert test row")

	require.NoError(t, initializeSchema(ctx, db), "second initializeSchema call (idempotency check)")

	for _, col := range cfgmsPendingDeviceIdentityColumns {
		assert.True(t, hasColumn(t, db, "cfgms_pending_registrations", col),
			"%s still present after second pass", col)
	}

	var deviceID, hostname string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT device_id, hostname FROM cfgms_pending_registrations WHERE pending_id = 'pend-survive'`).
		Scan(&deviceID, &hostname))
	assert.Equal(t, "dev-survive", deviceID, "row must survive second initializeSchema")
	assert.Equal(t, "host-survive", hostname, "back-filled values must survive second initializeSchema")
}

// TestBackfillCfgmsPendingRegistrationColumns_PartialLegacyTable covers the
// interrupted-upgrade case: a deployment whose ALTER sequence died part-way
// through leaves some of the five columns present. The per-column PRAGMA probe
// must add only the missing ones rather than failing on a duplicate column.
func TestBackfillCfgmsPendingRegistrationColumns_PartialLegacyTable(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacyCfgmsPendingRegistrationsSchema)
	require.NoError(t, err, "seed legacy cfgms_pending_registrations schema")
	_, err = db.ExecContext(ctx,
		`ALTER TABLE cfgms_pending_registrations ADD COLUMN device_id TEXT NOT NULL DEFAULT ''`)
	require.NoError(t, err, "seed a partially migrated table")

	require.NoError(t, backfillCfgmsPendingRegistrationColumns(ctx, db),
		"a half-migrated table must not fail the back-fill")

	for _, col := range cfgmsPendingDeviceIdentityColumns {
		assert.True(t, hasColumn(t, db, "cfgms_pending_registrations", col),
			"%s present after back-fill over a partially migrated table", col)
	}
}

// TestBackfillCfgmsPendingRegistrationColumns_FreshDB verifies that a fresh
// database carries all five columns from CREATE TABLE, so the back-fill is a
// no-op on new deployments.
func TestBackfillCfgmsPendingRegistrationColumns_FreshDB(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	require.NoError(t, initializeSchema(ctx, db), "fresh DB initialization")

	for _, col := range cfgmsPendingDeviceIdentityColumns {
		assert.True(t, hasColumn(t, db, "cfgms_pending_registrations", col),
			"%s present on fresh DB", col)
	}
}

// TestBackfillCfgmsPendingRegistrationColumns_TableAbsent verifies the
// table-absent short-circuit: a database that has never carried the table must
// be left untouched rather than erroring on the PRAGMA/ALTER.
func TestBackfillCfgmsPendingRegistrationColumns_TableAbsent(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	require.NoError(t, backfillCfgmsPendingRegistrationColumns(ctx, db),
		"absent table must be a no-op, not an error")

	var count int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cfgms_pending_registrations'`).Scan(&count))
	assert.Equal(t, 0, count, "back-fill must not create the table itself")
}

// TestBackfillCfgmsPendingRegistrationColumns_ProbeFailure verifies that a
// tableExists failure propagates instead of silently reporting success — the
// back-fill runs on every database open, so a swallowed probe error would let
// the controller start against an un-migrated table.
func TestBackfillCfgmsPendingRegistrationColumns_ProbeFailure(t *testing.T) {
	ctx := context.Background()

	db, err := openDB(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	err = backfillCfgmsPendingRegistrationColumns(ctx, db)
	require.Error(t, err, "closed DB must return an error")
	assert.Contains(t, err.Error(), "back-fill probe failed", "error must identify the probe stage")
}

// TestBackfillCfgmsPendingRegistrationColumns_AlterFailure verifies that an
// ALTER TABLE failure propagates rather than leaving a half-migrated table
// behind a successful startup.
func TestBackfillCfgmsPendingRegistrationColumns_AlterFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "readonly-pending.db")

	setup, err := openDB(dbPath)
	require.NoError(t, err)
	_, err = setup.ExecContext(context.Background(), legacyCfgmsPendingRegistrationsSchema)
	require.NoError(t, err)
	require.NoError(t, setup.Close())

	roDB, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = roDB.Close() })
	require.NoError(t, roDB.Ping())

	err = backfillCfgmsPendingRegistrationColumns(context.Background(), roDB)
	require.Error(t, err, "ALTER TABLE on read-only DB must return an error")
	assert.Contains(t, err.Error(), "back-fill failed", "error must identify the back-fill stage")
}

// legacyCommandsSchema is the commands DDL as shipped by Issue #665, before
// Issue #3757 added the outbox delivery-lifecycle columns. Used to simulate a
// pre-#3757 controller or steward database upgrading in place.
const legacyCommandsSchema = `CREATE TABLE IF NOT EXISTS commands (
	id            TEXT PRIMARY KEY,
	type          TEXT NOT NULL,
	steward_id    TEXT NOT NULL,
	tenant_id     TEXT NOT NULL DEFAULT '',
	payload       TEXT NOT NULL DEFAULT '{}',
	status        TEXT NOT NULL DEFAULT 'pending',
	issued_at     TEXT NOT NULL,
	started_at    TEXT,
	completed_at  TEXT,
	result        TEXT NOT NULL DEFAULT '{}',
	error_message TEXT NOT NULL DEFAULT '',
	issued_by     TEXT NOT NULL DEFAULT ''
)`

// commandDeliveryColumns are the two columns added by Issue #3757.
var commandDeliveryColumns = []string{"delivery_status", "delivery_detail"}

// seedLegacyCommandRow inserts a pre-#3757-shaped row into a legacy commands
// table (no delivery columns), so tests can prove what the migration does to
// records that already exist on an upgrading deployment.
func seedLegacyCommandRow(t *testing.T, db *sql.DB, id, stewardID string) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO commands
			(id, type, steward_id, tenant_id, payload, status, issued_at, result, error_message, issued_by)
		VALUES (?, 'sync_config', ?, 'tenant-legacy', '{}', 'pending', '2026-01-01T00:00:00Z', '{}', '', 'admin@example.com')`,
		id, stewardID)
	require.NoError(t, err, "seed legacy command row %s", id)
}

// TestBackfillCommandDeliveryColumns_LegacyTable verifies that initializeSchema
// adds the two delivery-lifecycle columns and the reconnect-drain index to a
// pre-existing commands table created before Issue #3757. CREATE TABLE IF NOT
// EXISTS cannot add columns, so without the back-fill every upgrading
// deployment would fail its next command dispatch with "no such column:
// delivery_status".
func TestBackfillCommandDeliveryColumns_LegacyTable(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacyCommandsSchema)
	require.NoError(t, err, "seed legacy commands schema")
	seedLegacyCommandRow(t, db, "cmd-legacy", "steward-legacy")

	for _, col := range commandDeliveryColumns {
		require.False(t, hasColumn(t, db, "commands", col),
			"pre-condition: %s absent before back-fill", col)
	}

	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	for _, col := range commandDeliveryColumns {
		assert.True(t, hasColumn(t, db, "commands", col), "%s present after back-fill", col)
	}
	assert.True(t, hasIndex(t, db, "commands", "idx_commands_steward_delivery"),
		"reconnect-drain index present after back-fill")

	// A row written under the retired fire-and-forget goroutine has an unknown
	// delivery outcome, so it must land on 'pending' — a drain re-attempts it
	// rather than silently treating it as delivered.
	store := &SQLiteCommandStore{db: db}
	got, err := store.GetCommandRecord(ctx, "cmd-legacy")
	require.NoError(t, err, "back-filled table must be readable by the store")
	assert.Equal(t, business.DeliveryStatusPending, got.DeliveryStatus,
		"pre-existing rows must default to pending, not delivered")
	assert.Equal(t, "", got.DeliveryDetail, "pre-existing rows must default to empty detail")

	// The migrated table must actually be usable by the live outbox paths — a
	// column that exists but carries the wrong name or affinity would still
	// break dispatch after a successful startup.
	pending, err := store.ListPendingDeliveries(ctx, "steward-legacy", "tenant-legacy")
	require.NoError(t, err)
	require.Len(t, pending, 1, "the legacy row must be drainable on reconnect")
	assert.Equal(t, "cmd-legacy", pending[0].ID)

	require.NoError(t, store.UpdateDeliveryStatus(ctx, "cmd-legacy", business.DeliveryStatusDelivered, ""),
		"back-filled table must accept a delivery transition")
	drained, err := store.ListPendingDeliveries(ctx, "steward-legacy", "tenant-legacy")
	require.NoError(t, err)
	assert.Empty(t, drained, "a delivered row must leave the pending set")

	// New records must also insert cleanly against the migrated table.
	require.NoError(t, store.CreateCommandRecord(ctx, testCommandRecord("cmd-after-migration")),
		"back-filled table must accept a newly created record")
}

// TestBackfillCommandDeliveryColumns_Idempotent verifies that a second
// initializeSchema pass over an already-migrated commands table succeeds (the
// PRAGMA column probe suppresses the duplicate ALTER) and that rows written
// between the two passes survive with their delivery state intact.
func TestBackfillCommandDeliveryColumns_Idempotent(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacyCommandsSchema)
	require.NoError(t, err, "seed legacy commands schema")
	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	store := &SQLiteCommandStore{db: db}
	require.NoError(t, store.CreateCommandRecord(ctx, testCommandRecord("cmd-survive")))
	require.NoError(t, store.UpdateDeliveryStatus(ctx, "cmd-survive", business.DeliveryStatusFailed, "steward unreachable"))

	require.NoError(t, initializeSchema(ctx, db), "second initializeSchema call (idempotency check)")

	for _, col := range commandDeliveryColumns {
		assert.True(t, hasColumn(t, db, "commands", col), "%s still present after second pass", col)
	}
	assert.True(t, hasIndex(t, db, "commands", "idx_commands_steward_delivery"),
		"reconnect-drain index still present after second pass")

	got, err := store.GetCommandRecord(ctx, "cmd-survive")
	require.NoError(t, err, "row must survive second initializeSchema")
	assert.Equal(t, business.DeliveryStatusFailed, got.DeliveryStatus,
		"delivery state must survive second initializeSchema")
	assert.Equal(t, "steward unreachable", got.DeliveryDetail,
		"delivery detail must survive second initializeSchema")
}

// TestBackfillCommandDeliveryColumns_PartialLegacyTable covers the
// interrupted-upgrade case: a deployment whose ALTER sequence died between the
// two columns. The per-column PRAGMA probe must add only the missing one rather
// than failing on a duplicate column.
func TestBackfillCommandDeliveryColumns_PartialLegacyTable(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacyCommandsSchema)
	require.NoError(t, err, "seed legacy commands schema")
	_, err = db.ExecContext(ctx,
		`ALTER TABLE commands ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'pending'`)
	require.NoError(t, err, "seed a partially migrated table")

	require.NoError(t, backfillCommandDeliveryColumns(ctx, db),
		"a half-migrated table must not fail the back-fill")

	for _, col := range commandDeliveryColumns {
		assert.True(t, hasColumn(t, db, "commands", col),
			"%s present after back-fill over a partially migrated table", col)
	}
	assert.True(t, hasIndex(t, db, "commands", "idx_commands_steward_delivery"),
		"reconnect-drain index created over a partially migrated table")
}

// TestBackfillCommandDeliveryColumns_FreshDB verifies that a fresh database
// carries both delivery columns and the drain index from CREATE TABLE, so the
// back-fill is a no-op on new deployments.
func TestBackfillCommandDeliveryColumns_FreshDB(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	require.NoError(t, initializeSchema(ctx, db), "fresh DB initialization")

	for _, col := range commandDeliveryColumns {
		assert.True(t, hasColumn(t, db, "commands", col), "%s present on fresh DB", col)
	}
	assert.True(t, hasIndex(t, db, "commands", "idx_commands_steward_delivery"),
		"reconnect-drain index present on fresh DB")
	require.NoError(t, backfillCommandDeliveryColumns(ctx, db), "back-fill is a no-op on a fresh DB")
}

// TestBackfillCommandDeliveryColumns_TableAbsent verifies the table-absent
// short-circuit: a database that has never carried the commands table must be
// left untouched rather than erroring on the PRAGMA/ALTER or creating the table
// (or its index) as a side effect.
func TestBackfillCommandDeliveryColumns_TableAbsent(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	require.NoError(t, backfillCommandDeliveryColumns(ctx, db),
		"absent table must be a no-op, not an error")

	var count int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='commands'`).Scan(&count))
	assert.Equal(t, 0, count, "back-fill must not create the table itself")
	assert.False(t, hasIndex(t, db, "commands", "idx_commands_steward_delivery"),
		"back-fill must not create the index without the table")
}

// TestBackfillCommandDeliveryColumns_ProbeFailure verifies that a tableExists
// failure propagates instead of silently reporting success — the back-fill runs
// on every database open, so a swallowed probe error would let the controller
// start against an un-migrated commands table and lose every queued delivery.
func TestBackfillCommandDeliveryColumns_ProbeFailure(t *testing.T) {
	ctx := context.Background()

	db, err := openDB(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	err = backfillCommandDeliveryColumns(ctx, db)
	require.Error(t, err, "closed DB must return an error")
	assert.Contains(t, err.Error(), "back-fill probe failed", "error must identify the probe stage")
}

// TestBackfillCommandDeliveryColumns_AlterFailure verifies that an ALTER TABLE
// failure propagates rather than leaving a half-migrated table behind a
// successful startup.
func TestBackfillCommandDeliveryColumns_AlterFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "readonly-commands.db")

	setup, err := openDB(dbPath)
	require.NoError(t, err)
	_, err = setup.ExecContext(context.Background(), legacyCommandsSchema)
	require.NoError(t, err)
	require.NoError(t, setup.Close())

	roDB, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = roDB.Close() })
	require.NoError(t, roDB.Ping())

	err = backfillCommandDeliveryColumns(context.Background(), roDB)
	require.Error(t, err, "ALTER TABLE on read-only DB must return an error")
	assert.Contains(t, err.Error(), "back-fill failed", "error must identify the back-fill stage")
}

// TestBackfillCommandDeliveryColumns_IndexFailure covers the branch past the
// ALTERs: a table that already has both columns but not the drain index. A
// failure to create it must propagate, because ListPendingDeliveries would
// otherwise fall back to a full scan of every command ever issued.
func TestBackfillCommandDeliveryColumns_IndexFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "readonly-commands-index.db")
	ctx := context.Background()

	setup, err := openDB(dbPath)
	require.NoError(t, err)
	_, err = setup.ExecContext(ctx, legacyCommandsSchema)
	require.NoError(t, err)
	for _, ddl := range []string{
		`ALTER TABLE commands ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'pending'`,
		`ALTER TABLE commands ADD COLUMN delivery_detail TEXT NOT NULL DEFAULT ''`,
	} {
		_, err = setup.ExecContext(ctx, ddl)
		require.NoError(t, err)
	}
	require.NoError(t, setup.Close())

	roDB, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = roDB.Close() })
	require.NoError(t, roDB.Ping())

	err = backfillCommandDeliveryColumns(ctx, roDB)
	require.Error(t, err, "CREATE INDEX on read-only DB must return an error")
	assert.Contains(t, err.Error(), "delivery index back-fill failed", "error must identify the index stage")
}

// legacyPendingRefreshRequestsSchema is the pending_refresh_requests DDL as
// shipped by Issue #2093, before Issue #3781 added csr_pem. Used to simulate a
// controller or steward database that carried the refresh queue before the
// steward started submitting its own CSR with /refresh/complete.
const legacyPendingRefreshRequestsSchema = `CREATE TABLE IF NOT EXISTS pending_refresh_requests (
	pending_id               TEXT PRIMARY KEY,
	device_id                TEXT NOT NULL,
	tenant_id                TEXT NOT NULL,
	source_ip                TEXT NOT NULL DEFAULT '',
	provenance_matched_fields INTEGER NOT NULL DEFAULT 0,
	provenance_total_fields   INTEGER NOT NULL DEFAULT 0,
	claim_bundle             BLOB NOT NULL DEFAULT '',
	status                   TEXT NOT NULL DEFAULT 'pending',
	created_at               TEXT NOT NULL,
	expires_at               TEXT NOT NULL,
	resolved_at              TEXT
)`

// TestBackfillPendingRefreshCSR_LegacyTable verifies that initializeSchema adds
// csr_pem to a pre-existing pending_refresh_requests table created before Issue
// #3781. CREATE TABLE IF NOT EXISTS cannot add a column, so without the
// back-fill every upgrading deployment would fail its next AddPendingRefresh
// with "table pending_refresh_requests has no column named csr_pem".
func TestBackfillPendingRefreshCSR_LegacyTable(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacyPendingRefreshRequestsSchema)
	require.NoError(t, err, "seed legacy pending_refresh_requests schema")

	// A pre-#3781 row must survive the migration and take the column default.
	_, err = db.ExecContext(ctx, `
		INSERT INTO pending_refresh_requests
			(pending_id, device_id, tenant_id, created_at, expires_at)
		VALUES ('pr-legacy', 'dev-legacy', 'tenant-legacy', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')`)
	require.NoError(t, err, "seed legacy row")

	require.False(t, hasColumn(t, db, "pending_refresh_requests", "csr_pem"),
		"pre-condition: csr_pem absent before back-fill")

	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	assert.True(t, hasColumn(t, db, "pending_refresh_requests", "csr_pem"),
		"csr_pem present after back-fill")

	// The migrated table must actually be usable by the store that reads and
	// writes the column — a column that exists but is NOT NULL without a default
	// would still break the live path for legacy rows and new inserts alike.
	store := &SQLitePendingRefreshStore{db: db}
	legacy, err := store.GetPendingRefreshByID(ctx, "pr-legacy")
	require.NoError(t, err, "legacy row must remain readable through the back-filled column")
	assert.Empty(t, legacy.CSRPEM, "legacy row must default to an empty csr_pem")

	const csr = "-----BEGIN CERTIFICATE REQUEST-----\nrefresh-legacy\n-----END CERTIFICATE REQUEST-----\n"
	entry := testRefreshEntry("pr-migrated", "dev-migrated", "tenant-legacy")
	entry.CSRPEM = csr
	require.NoError(t, store.AddPendingRefresh(ctx, entry), "back-filled table must accept a full entry")

	got, err := store.GetPendingRefreshByID(ctx, "pr-migrated")
	require.NoError(t, err)
	assert.Equal(t, csr, got.CSRPEM, "csr_pem must round-trip through the back-filled column")
}

// TestBackfillPendingRefreshCSR_Idempotent verifies that a second initializeSchema
// pass over an already-migrated table succeeds (the PRAGMA column probe suppresses
// the duplicate ALTER) and that rows written between the two passes survive. The
// back-fill runs on every database open, so a non-idempotent pass would break
// every restart.
func TestBackfillPendingRefreshCSR_Idempotent(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacyPendingRefreshRequestsSchema)
	require.NoError(t, err, "seed legacy pending_refresh_requests schema")
	require.NoError(t, initializeSchema(ctx, db), "first initializeSchema call")

	store := &SQLitePendingRefreshStore{db: db}
	const csr = "-----BEGIN CERTIFICATE REQUEST-----\nsurvive\n-----END CERTIFICATE REQUEST-----\n"
	entry := testRefreshEntry("pr-survive", "dev-survive", "tenant-idem")
	entry.CSRPEM = csr
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	require.NoError(t, initializeSchema(ctx, db), "second initializeSchema call (idempotency check)")

	assert.True(t, hasColumn(t, db, "pending_refresh_requests", "csr_pem"),
		"csr_pem still present after second pass")

	got, err := store.GetPendingRefreshByID(ctx, "pr-survive")
	require.NoError(t, err, "row must survive the idempotent second pass")
	assert.Equal(t, csr, got.CSRPEM, "back-filled value must survive second initializeSchema")
}

// TestBackfillPendingRefreshCSR_FreshDB verifies that a fresh database carries
// csr_pem from CREATE TABLE, so the back-fill is a no-op on new deployments.
func TestBackfillPendingRefreshCSR_FreshDB(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	require.NoError(t, initializeSchema(ctx, db), "fresh DB initialization")

	assert.True(t, hasColumn(t, db, "pending_refresh_requests", "csr_pem"),
		"csr_pem present on fresh DB")
}

// TestBackfillPendingRefreshCSR_TableAbsent verifies the table-absent
// short-circuit: a database that has never carried pending_refresh_requests must
// be left untouched rather than erroring on the PRAGMA/ALTER.
func TestBackfillPendingRefreshCSR_TableAbsent(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	require.NoError(t, backfillPendingRefreshCSR(ctx, db),
		"absent table must be a no-op, not an error")

	var count int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='pending_refresh_requests'`).Scan(&count))
	assert.Equal(t, 0, count, "back-fill must not create the table itself")
}

// TestBackfillPendingRefreshCSR_ProbeFailure verifies that a tableExists failure
// propagates instead of silently reporting success — the back-fill runs on every
// database open, so a swallowed probe error would let the controller start
// against an un-migrated table.
func TestBackfillPendingRefreshCSR_ProbeFailure(t *testing.T) {
	ctx := context.Background()

	db, err := openDB(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	err = backfillPendingRefreshCSR(ctx, db)
	require.Error(t, err, "closed DB must return an error")
	assert.Contains(t, err.Error(), "back-fill probe failed", "error must identify the probe stage")
}

// TestBackfillPendingRefreshCSR_AlterFailure verifies that an ALTER TABLE failure
// propagates rather than leaving a half-migrated table behind a successful
// startup.
func TestBackfillPendingRefreshCSR_AlterFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "readonly-pending-refresh.db")
	ctx := context.Background()

	setup, err := openDB(dbPath)
	require.NoError(t, err)
	_, err = setup.ExecContext(ctx, legacyPendingRefreshRequestsSchema)
	require.NoError(t, err)
	require.NoError(t, setup.Close())

	roDB, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = roDB.Close() })
	require.NoError(t, roDB.Ping())

	err = backfillPendingRefreshCSR(ctx, roDB)
	require.Error(t, err, "ALTER TABLE on read-only DB must return an error")
	assert.Contains(t, err.Error(), "back-fill failed", "error must identify the back-fill stage")
}

// legacySingleDeviceClaimSchema is the registration_token_claims DDL as first
// shipped: one claim row per token, for the token's whole lifetime.
const legacySingleDeviceClaimSchema = `CREATE TABLE IF NOT EXISTS registration_token_claims (
	token      TEXT PRIMARY KEY,
	claim_id   TEXT NOT NULL,
	claimed_at TEXT NOT NULL
)`

// A database created before the fix carries a primary key that admits one device
// per token forever, so an existing controller would keep refusing to enrol the
// rest of its fleet even after upgrading. CREATE TABLE IF NOT EXISTS cannot
// change a key, so the migration has to rebuild the table.
func TestMigrate_LegacySingleDeviceRegistrationClaimKey(t *testing.T) {
	db := openMemDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, legacySingleDeviceClaimSchema)
	require.NoError(t, err, "seed legacy claims schema")
	_, err = db.ExecContext(ctx,
		`INSERT INTO registration_token_claims (token, claim_id, claimed_at) VALUES ('tok', 'device-a', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err, "seed a claim held under the legacy key")

	require.NoError(t, initializeSchema(ctx, db), "initializeSchema must migrate the claims table")

	// A second device on the same token is the case the legacy key rejected.
	_, err = db.ExecContext(ctx,
		`INSERT INTO registration_token_claims (token, claim_id, claimed_at) VALUES ('tok', 'device-a', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err, "first device claims the token")
	_, err = db.ExecContext(ctx,
		`INSERT INTO registration_token_claims (token, claim_id, claimed_at) VALUES ('tok', 'device-b', '2026-01-01T00:00:01Z')`)
	require.NoError(t, err, "a second device must be able to claim the same perennial token")

	// The same device twice must still collide, so it cannot be issued two keys.
	_, err = db.ExecContext(ctx,
		`INSERT INTO registration_token_claims (token, claim_id, claimed_at) VALUES ('tok', 'device-b', '2026-01-01T00:00:02Z')`)
	require.Error(t, err, "a device must not hold two claims on one token")

	// Re-running must not drop the migrated table or its rows.
	require.NoError(t, initializeSchema(ctx, db), "second initializeSchema call (idempotency check)")
	var claims int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM registration_token_claims WHERE token = 'tok'`).Scan(&claims))
	assert.Equal(t, 2, claims, "migrated claims must survive a later startup")
}
