// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func TestFlatFileReportTemplateStore_Contract(t *testing.T) {
	store, err := NewFlatFileReportTemplateStore(t.TempDir())
	require.NoError(t, err)
	business.ReportTemplateStoreContract(t, store)
}

// TestFlatFileReportTemplateStore_TraversalCreatesNoFileOutsideRoot runs traversal-shaped
// identifiers against a store nested one level inside a scratch directory and asserts that
// nothing is written anywhere in that directory except the report-template root.
func TestFlatFileReportTemplateStore_TraversalCreatesNoFileOutsideRoot(t *testing.T) {
	scratch := t.TempDir()
	root := filepath.Join(scratch, "root")
	store, err := NewFlatFileReportTemplateStore(root)
	require.NoError(t, err)
	ctx := context.Background()

	for _, tc := range []struct{ tenant, id string }{
		{"root/../x", "ok"}, {"..", "ok"}, {"t", ".."}, {"t", "../escape"}, {"t", `a\b`}, {"t", "a/b"}, {"t", "a\x00b"},
	} {
		err := store.Save(ctx, tc.tenant, &business.ReportTemplate{ID: tc.id, TenantID: tc.tenant})
		assert.Error(t, err, "%q/%q", tc.tenant, tc.id)
	}
	err = store.Save(ctx, "t", &business.ReportTemplate{
		ID: "ok", TenantID: "t",
		SharedWith: []business.ReportTemplateShare{{TenantID: "root/../x"}},
	})
	assert.Error(t, err)

	var files []string
	require.NoError(t, filepath.WalkDir(scratch, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}
		return err
	}))
	assert.Empty(t, files, "rejected input must create no file anywhere under the scratch directory")
	_, err = store.GetByID(ctx, "t", "ok")
	assert.ErrorIs(t, err, business.ErrReportTemplateNotFound)
}

// TestFlatFileReportTemplateStore_SurvivesRestart proves templates and shares are durable.
func TestFlatFileReportTemplateStore_SurvivesRestart(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	first, err := NewFlatFileReportTemplateStore(root)
	require.NoError(t, err)
	require.NoError(t, first.Save(ctx, "t1", &business.ReportTemplate{
		ID: "r1", TenantID: "t1", Name: "n", Definition: json.RawMessage(`{"q":1}`),
		SharedWith: []business.ReportTemplateShare{{TenantID: "t2"}},
	}))

	second, err := NewFlatFileReportTemplateStore(root)
	require.NoError(t, err)
	got, err := second.GetByID(ctx, "t2", "r1")
	require.NoError(t, err)
	assert.JSONEq(t, `{"q":1}`, string(got.Definition))
}
