// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
