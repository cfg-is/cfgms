// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package interfaces_test — provider factory for contract tests.
// Kept in a file named providers_test.go so that the check-providers.sh
// architecture script allows the direct flatfile/sqlite import (*/providers_test.go exception).
package interfaces_test

import (
	"context"
	"path/filepath"
	"testing"

	routerinterfaces "github.com/cfgis/cfgms/pkg/configrouting/interfaces"
	controllerrouter "github.com/cfgis/cfgms/pkg/configrouting/providers/controller"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	flatfile "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// controllerRouterFactory creates a ControllerRouter backed by a FlatFileConfigStore
// and a real SQLite TenantStore with the required 3-level hierarchy (root → msp → client).
func controllerRouterFactory(t *testing.T) (routerinterfaces.ConfigSourceRouter, func()) {
	t.Helper()

	flatfileRoot := t.TempDir()
	cs, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	if err != nil {
		t.Fatalf("failed to create flatfile store: %v", err)
	}

	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	ts, err := p.CreateTenantStore(map[string]interface{}{"path": filepath.Join(dir, "tenants.db")})
	if err != nil {
		t.Fatalf("failed to create sqlite tenant store: %v", err)
	}

	ctx := context.Background()
	for _, td := range []*business.TenantData{
		{ID: "root", Name: "Root", Status: business.TenantStatusActive},
		{ID: "msp", Name: "MSP", ParentID: "root", Status: business.TenantStatusActive},
		{ID: "client", Name: "Client", ParentID: "msp", Status: business.TenantStatusActive},
	} {
		if err := ts.CreateTenant(ctx, td); err != nil {
			t.Fatalf("failed to create tenant %s: %v", td.ID, err)
		}
	}

	router := controllerrouter.NewControllerRouter(cs, ts)
	return router, func() { _ = ts.Close() }
}

// TestControllerRouter_ContractSuite runs all ConfigSourceRouter contract tests against
// the Phase 1 controller provider implementation.
func TestControllerRouter_ContractSuite(t *testing.T) {
	RunRouterContractTests(t, controllerRouterFactory)
}
