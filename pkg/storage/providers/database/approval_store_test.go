// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestApprovalStore_Contract runs the shared ApprovalStore contract (Issue #4607),
// including the concurrent decide and claim guarantees, against PostgreSQL.
func TestApprovalStore_Contract(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseApprovalStore(db, getTestConfig())
	require.NoError(t, err)
	business.ApprovalStoreContract(t, store)
}
