// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/tenant"
	cfgpkg "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestServer_TenantManager_AuditWiring_RecordsConfigSourceEvent is an integration
// test that verifies the production wiring: tenant.NewManager is chained with
// WithAuditManager so that UpdateTenant config-source changes produce durable
// audit events (Issue #3180).
//
// This test exercises the full production construction path via New(), not an
// isolated manager with a hand-injected audit manager.
func TestServer_TenantManager_AuditWiring_RecordsConfigSourceEvent(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: createTestStorageConfig(tempDir, "tenant-audit-wiring"),
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })

	// Verify audit manager is wired — nil here means the wiring bug regressed.
	auditMgr := srv.GetAuditManager()
	require.NotNil(t, auditMgr, "audit manager must be non-nil after server construction")

	ctx := context.Background()
	tenantMgr := srv.GetTenantManager()
	require.NotNil(t, tenantMgr)

	// Create a tenant with no config source initially.
	td, err := tenantMgr.CreateTenant(ctx, &tenant.TenantRequest{
		Name: "audit-wiring-test",
	})
	require.NoError(t, err)

	// Update to git config source — this is the path that calls recordConfigSourceEvent.
	_, err = tenantMgr.UpdateTenant(ctx, td.ID, &tenant.TenantRequest{
		Name: td.Name,
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType: string(cfgpkg.ConfigSourceTypeGit),
			cfgpkg.MetaKeyConfigSourceURL:  "https://example.com/configs.git",
		},
	})
	require.NoError(t, err)

	// Flush drains the async audit queue so the event is durable before querying.
	require.NoError(t, auditMgr.Flush(ctx))

	entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
		TenantID: td.ID,
		Actions:  []string{"config_source_created"},
	})
	require.NoError(t, err)
	require.Len(t, entries, 1, "expected exactly one config_source_created audit entry")
	assert.Equal(t, "config_source_created", entries[0].Action)
	assert.Equal(t, td.ID, entries[0].TenantID)
}
