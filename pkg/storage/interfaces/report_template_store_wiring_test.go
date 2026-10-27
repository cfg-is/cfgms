// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Report-template-store wiring tests (Issue #5527). These live in the external
// interfaces_test package because the real ReportTemplateStore implementations ship in
// pkg/storage/providers/*, which import pkg/storage/interfaces.
package interfaces_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestCreateOSSStorageManager_ReportTemplateStore verifies the OSS manager wires a durable
// ReportTemplateStore and that a template survives closing and reopening the manager.
func TestCreateOSSStorageManager_ReportTemplateStore(t *testing.T) {
	ffRoot, dbPath := t.TempDir(), filepath.Join(t.TempDir(), "oss-report-templates.db")
	ctx := context.Background()

	sm, err := interfaces.CreateOSSStorageManager(ffRoot, dbPath)
	require.NoError(t, err)
	store := sm.GetReportTemplateStore()
	require.NotNil(t, store, "GetReportTemplateStore must be wired by the OSS storage manager")
	assert.True(t, sm.HasStore(interfaces.StoreNameReportTemplate))
	require.NoError(t, store.Save(ctx, "t1", &business.ReportTemplate{ID: "r1", TenantID: "t1", Name: "n"}))
	require.NoError(t, sm.Close())

	reopened, err := interfaces.CreateOSSStorageManager(ffRoot, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	got, err := reopened.GetReportTemplateStore().GetByID(ctx, "t1", "r1")
	require.NoError(t, err)
	assert.Equal(t, "n", got.Name)
}

// TestCreateAllStoresFromConfig_ReportTemplateStore verifies the single-provider
// construction path wires a report template store with sqlite.
func TestCreateAllStoresFromConfig_ReportTemplateStore(t *testing.T) {
	configs := map[string]map[string]interface{}{
		"sqlite": {"path": filepath.Join(t.TempDir(), "single-report-templates.db")},
	}
	for name, cfg := range configs {
		t.Run(name, func(t *testing.T) {
			sm, err := interfaces.CreateAllStoresFromConfig(name, cfg) //nolint:staticcheck // single-provider path is the one under test
			require.NoError(t, err)
			t.Cleanup(func() { _ = sm.Close() })
			store := sm.GetReportTemplateStore()
			require.NotNil(t, store)
			assert.True(t, sm.HasStore(interfaces.StoreNameReportTemplate))
			ctx := context.Background()
			require.NoError(t, store.Save(ctx, "t1", &business.ReportTemplate{ID: "r1", TenantID: "t1", Name: "n"}))
			got, err := store.GetByID(ctx, "t1", "r1")
			require.NoError(t, err)
			assert.Equal(t, "n", got.Name)
		})
	}
}
