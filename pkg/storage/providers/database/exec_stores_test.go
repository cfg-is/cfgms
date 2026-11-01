// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestScriptRunStore_Contract runs the shared ScriptRunStore contract (Issue
// #4528) against PostgreSQL.
func TestScriptRunStore_Contract(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseScriptRunStore(db, getTestConfig())
	require.NoError(t, err)
	business.ScriptRunStoreContract(t, store)
}

// TestExecutionQueueStore_Contract runs the shared ExecutionQueueStore contract
// (Issue #4528), including the concurrent-claim guarantee, against PostgreSQL.
func TestExecutionQueueStore_Contract(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseExecutionQueueStore(db, getTestConfig())
	require.NoError(t, err)
	business.ExecutionQueueStoreContract(t, store)
}

// TestScriptRunTables_UseCfgmsPrefix asserts the shared run tables carry the
// cfgms_ prefix and that the unprefixed names are not created (Issue #4548).
// Schema creation runs twice to prove it is idempotent.
func TestScriptRunTables_UseCfgmsPrefix(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreateScriptRunTables(ctx, db))
	require.NoError(t, schemas.CreateScriptRunTables(ctx, db))

	exists := func(name string) bool {
		var reg *string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, name).Scan(&reg))
		return reg != nil
	}
	for _, name := range []string{"cfgms_script_runs", "cfgms_script_run_jobs", "cfgms_execution_grants"} {
		require.True(t, exists(name), "%s must exist", name)
	}
	for _, name := range []string{"script_runs", "script_run_jobs", "execution_grants"} {
		require.False(t, exists(name), "%s must not exist", name)
	}
}
