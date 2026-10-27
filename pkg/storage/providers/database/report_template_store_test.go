// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestReportTemplateStore_Contract runs the shared ReportTemplateStore contract
// (Issue #5527) against PostgreSQL.
func TestReportTemplateStore_Contract(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseReportTemplateStore(db, getTestConfig())
	require.NoError(t, err)
	business.ReportTemplateStoreContract(t, store)
}
