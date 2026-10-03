// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides tests for schema initialization over databases
// written by earlier releases (Issue #4499)
package database

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditIndexExists reports whether auditSequenceUniqueIndex is present.
func auditIndexExists(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	require.NoError(t, db.QueryRowContext(context.Background(),
		"SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1)",
		auditSequenceUniqueIndex).Scan(&exists))
	return exists
}

// insertRawAuditRow writes an audit row directly, bypassing AppendChainedEntry,
// the way a pre-Issue #3754 writer could.
func insertRawAuditRow(t *testing.T, db *sql.DB, id, tenantID string, sequence int64) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO audit_entries
			(id, tenant_id, event_type, action, user_id, resource_type, resource_id, result, source, checksum, sequence_number)
		VALUES ($1, $2, 'system', 'test', 'system', 'test', 'r', 'success', 'test', $3, $4)`,
		id, tenantID, fmt.Sprintf("%064d", sequence), sequence)
	require.NoError(t, err)
}

func countAuditRows(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM audit_entries").Scan(&n))
	return n
}

// TestCreateAuditEntriesTable_CreatesSequenceIndexOnCleanData covers the normal
// path: with no colliding rows the defense-in-depth index is created.
func TestCreateAuditEntriesTable_CreatesSequenceIndexOnCleanData(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	schemas := NewDatabaseSchemas()

	require.NoError(t, schemas.CreateAuditEntriesTable(ctx, db))
	assert.True(t, auditIndexExists(t, db), "unique index must be created on a clean table")

	// Running initialization again is a no-op.
	require.NoError(t, schemas.CreateAuditEntriesTable(ctx, db))
	assert.True(t, auditIndexExists(t, db))
}

// TestCreateAuditEntriesTable_ToleratesPreFixDuplicateSequences reproduces
// Issue #4499: a database written before Issue #3754 holds colliding
// (tenant_id, sequence_number) pairs, and schema initialization previously
// failed with 23505 while building the unique index, so the controller could
// not start after upgrading.
func TestCreateAuditEntriesTable_ToleratesPreFixDuplicateSequences(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	schemas := NewDatabaseSchemas()

	// A pre-#3754 database: the table exists without the unique index.
	require.NoError(t, schemas.CreateAuditEntriesTable(ctx, db))
	_, err := db.ExecContext(ctx, "DROP INDEX "+auditSequenceUniqueIndex)
	require.NoError(t, err)

	insertRawAuditRow(t, db, "a1", "system", 1)
	insertRawAuditRow(t, db, "a2", "system", 2)
	insertRawAuditRow(t, db, "a2-dup", "system", 2) // collision from concurrent writers
	insertRawAuditRow(t, db, "b1", "tenant-b", 1)
	before := countAuditRows(t, db)

	require.NoError(t, schemas.CreateAuditEntriesTable(ctx, db),
		"schema initialization must succeed over pre-fix duplicate sequence numbers")
	assert.False(t, auditIndexExists(t, db), "unique index cannot be built over duplicates and must be skipped")
	assert.Equal(t, before, countAuditRows(t, db), "audit rows must not be modified or deleted")
}

// TestCreateAuditEntriesTable_LegacyZeroSequencesDoNotBlockIndex confirms that
// pre-chain legacy rows (sequence_number = 0, many per tenant) are not counted
// as collisions: the index is partial and excludes them.
func TestCreateAuditEntriesTable_LegacyZeroSequencesDoNotBlockIndex(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	schemas := NewDatabaseSchemas()

	require.NoError(t, schemas.CreateAuditEntriesTable(ctx, db))
	_, err := db.ExecContext(ctx, "DROP INDEX "+auditSequenceUniqueIndex)
	require.NoError(t, err)

	insertRawAuditRow(t, db, "legacy-1", "system", 0)
	insertRawAuditRow(t, db, "legacy-2", "system", 0)
	insertRawAuditRow(t, db, "chained-1", "system", 1)

	require.NoError(t, schemas.CreateAuditEntriesTable(ctx, db))
	assert.True(t, auditIndexExists(t, db), "legacy zero-sequence rows must not prevent the index")
}

// TestCreateCommandRecordsTable_UpgradesPreOutboxTable reproduces the second
// Issue #4499 failure: a command_records table created before Issue #3757 has
// no delivery columns, and CREATE TABLE IF NOT EXISTS does not add them, so
// building idx_command_records_steward_delivery failed with 42703 and the
// controller could not start.
func TestCreateCommandRecordsTable_UpgradesPreOutboxTable(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	// The pre-#3757 shape of command_records.
	_, err := db.ExecContext(ctx, `
		CREATE TABLE command_records (
			id            TEXT NOT NULL PRIMARY KEY,
			type          TEXT NOT NULL,
			steward_id    TEXT NOT NULL,
			tenant_id     TEXT NOT NULL,
			payload       JSONB NOT NULL DEFAULT '{}',
			status        TEXT NOT NULL,
			issued_at     TIMESTAMP WITH TIME ZONE NOT NULL,
			started_at    TIMESTAMP WITH TIME ZONE,
			completed_at  TIMESTAMP WITH TIME ZONE,
			result        JSONB NOT NULL DEFAULT '{}',
			error_message TEXT NOT NULL DEFAULT '',
			issued_by     TEXT NOT NULL DEFAULT ''
		);`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO command_records (id, type, steward_id, tenant_id, status, issued_at)
		VALUES ('cmd-1', 'sync_config', 'steward-1', 'tenant-a', 'completed', NOW())`)
	require.NoError(t, err)

	require.NoError(t, NewDatabaseSchemas().CreateCommandRecordsTable(ctx, db),
		"schema initialization must upgrade a pre-outbox command_records table")

	var deliveryStatus string
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT delivery_status FROM command_records WHERE id = 'cmd-1'").Scan(&deliveryStatus))
	assert.Equal(t, "pending", deliveryStatus, "pre-existing rows default to pending")

	var indexExists bool
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'idx_command_records_steward_delivery')").Scan(&indexExists))
	assert.True(t, indexExists)
}
