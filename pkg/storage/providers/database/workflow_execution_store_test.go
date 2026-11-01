// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestWorkflowExecutionStore_Contract runs the shared WorkflowExecutionStore contract
// (Issue #4675) against PostgreSQL.
func TestWorkflowExecutionStore_Contract(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseWorkflowExecutionStore(db, getTestConfig())
	require.NoError(t, err)
	business.WorkflowExecutionStoreContract(t, store)
}
