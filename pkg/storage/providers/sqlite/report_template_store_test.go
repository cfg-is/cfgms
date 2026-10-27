// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestReportTemplateStoreAt builds the store through the provider factory so the tests
// also cover config parsing and path resolution.
func newTestReportTemplateStoreAt(t *testing.T, path string) business.ReportTemplateStore {
	t.Helper()
	store, err := NewSQLiteProvider(path).CreateReportTemplateStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.(*SQLiteReportTemplateStore).Close() })
	return store
}

func TestSQLiteReportTemplateStore_Contract(t *testing.T) {
	business.ReportTemplateStoreContract(t, newTestReportTemplateStoreAt(t, filepath.Join(t.TempDir(), "cfgms.db")))
}

// TestSQLiteReportTemplateStore_SurvivesRestart proves templates and shares are durable.
func TestSQLiteReportTemplateStore_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	ctx := context.Background()
	first := newTestReportTemplateStoreAt(t, path)
	require.NoError(t, first.Save(ctx, "t1", &business.ReportTemplate{
		ID: "r1", TenantID: "t1", Name: "n", Definition: json.RawMessage(`{"q": 1}`),
		SharedWith: []business.ReportTemplateShare{{TenantID: "t2"}},
	}))
	require.NoError(t, first.(*SQLiteReportTemplateStore).Close())

	second := newTestReportTemplateStoreAt(t, path)
	got, err := second.GetByID(ctx, "t2", "r1")
	require.NoError(t, err)
	assert.Equal(t, `{"q": 1}`, string(got.Definition), "the definition round-trips byte for byte")
}
