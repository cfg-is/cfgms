// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
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
