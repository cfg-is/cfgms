// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestInitializeSchema_BackfillsLegacyAuditColumns reproduces issue #849:
// a sqlite file that was created before `sequence_number` and
// `previous_checksum` were added to the `audit_entries` table used to
// fail on a second run with "no such column: sequence_number" during
// index creation. The back-fill introduced in this file must pick up
// those missing columns without erroring on the duplicate columns that
// newer files already have.
func TestInitializeSchema_BackfillsLegacyAuditColumns(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")

	// Create a legacy audit_entries table without sequence_number /
	// previous_checksum. The surrounding column set is irrelevant to the
	// index — only the two new ones matter.
	db, err := openDB(path)
	require.NoError(t, err)
	legacy := `CREATE TABLE audit_entries (
		id            TEXT PRIMARY KEY,
		tenant_id     TEXT NOT NULL,
		timestamp     TEXT NOT NULL,
		event_type    TEXT NOT NULL,
		action        TEXT NOT NULL,
		user_id       TEXT NOT NULL,
		user_type     TEXT NOT NULL,
		session_id    TEXT NOT NULL DEFAULT '',
		resource_type TEXT NOT NULL,
		resource_id   TEXT NOT NULL,
		resource_name TEXT NOT NULL DEFAULT '',
		result        TEXT NOT NULL,
		error_code    TEXT NOT NULL DEFAULT '',
		error_message TEXT NOT NULL DEFAULT '',
		request_id    TEXT NOT NULL DEFAULT '',
		ip_address    TEXT NOT NULL DEFAULT '',
		user_agent    TEXT NOT NULL DEFAULT '',
		method        TEXT NOT NULL DEFAULT '',
		path          TEXT NOT NULL DEFAULT '',
		details       TEXT NOT NULL DEFAULT '{}',
		changes       TEXT NOT NULL DEFAULT '{}',
		tags          TEXT NOT NULL DEFAULT '[]',
		severity      TEXT NOT NULL,
		source        TEXT NOT NULL,
		version       TEXT NOT NULL DEFAULT '',
		checksum      TEXT NOT NULL
	)`
	_, err = db.ExecContext(ctx, legacy)
	require.NoError(t, err)

	// initializeSchema should back-fill the two missing columns and then
	// successfully create the tenant_seq composite index — no "no such
	// column" error.
	require.NoError(t, initializeSchema(ctx, db))
	requireColumn(t, db, "audit_entries", "sequence_number")
	requireColumn(t, db, "audit_entries", "previous_checksum")
	requireIndex(t, db, "idx_audit_entries_tenant_seq")

	// Running it a second time must be idempotent: the back-fill ALTERs
	// now hit "duplicate column name" and the helper swallows the error.
	require.NoError(t, initializeSchema(ctx, db))

	require.NoError(t, db.Close())
}

func requireColumn(t *testing.T, db *sql.DB, table, column string) {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, typ        string
			dflt             sql.NullString
		)
		require.NoError(t, rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk))
		if name == column {
			return
		}
	}
	t.Fatalf("column %s.%s not present after initializeSchema", table, column)
}

func requireIndex(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	var got string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&got)
	require.NoError(t, err, "index %s missing after initializeSchema", name)
}
