// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

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
