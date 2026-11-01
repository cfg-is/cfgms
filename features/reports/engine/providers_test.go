// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package engine

// Concrete test-store construction for tests in this package.
// The custom template manager tests exercise a real (not mocked)
// business.ReportTemplateStore per CLAUDE.md's no-mocks rule, which necessarily
// names a concrete provider. Isolated to this file so custom_templates_test.go
// imports pkg/storage/interfaces only; */providers_test.go is the allowlisted
// location for that import in scripts/check-providers.sh.

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newTestReportTemplateStore returns a real sqlite-backed ReportTemplateStore in a
// temp dir, closed on test cleanup.
func newTestReportTemplateStore(t *testing.T) business.ReportTemplateStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfgms.db")
	store, err := sqlite.NewSQLiteProvider(path).CreateReportTemplateStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	sqliteStore, ok := store.(*sqlite.SQLiteReportTemplateStore)
	require.True(t, ok, "unexpected store type %T", store)
	t.Cleanup(func() { require.NoError(t, sqliteStore.Close()) })
	return store
}
