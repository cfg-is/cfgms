// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testutil"
)

func TestSigningMigrationService_RunMovesLocalSignerToSharedIdentity(t *testing.T) {
	ctx := context.Background()
	secrets := testutil.NewMemSecretStore()
	cursor, err := cert.NewFileSigningCursorStore(t.TempDir())
	require.NoError(t, err)

	dir := t.TempDir()
	build := func(withKeys bool) *cert.Manager {
		cfg := &cert.ManagerConfig{
			StoragePath:        dir,
			CAConfig:           &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
			SigningCursorStore: cursor,
		}
		if withKeys {
			ks, err := cert.NewSecretStoreSigningKeyStore(secrets, "cluster-ca-tenant", "")
			require.NoError(t, err)
			cfg.SigningKeyStore = ks
		}
		m, err := cert.NewManagerFromSecretStore(ctx, secrets, "cluster-ca-tenant", "cluster-ca", cfg)
		require.NoError(t, err)
		return m
	}
	legacy := build(false)
	require.NoError(t, legacy.EnsureSigningCertificate(&cert.SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 365, KeySize: 2048}))
	local, err := legacy.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)

	node := build(true)
	auditMgr, err := audit.NewManager(pkgtesting.SetupTestStorage(t).GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(ctx) })
	svc := NewSigningMigrationService(node, logging.NewNoopLogger())
	svc.SetAuditManager(auditMgr)

	// No cursor and no explicit choice: the node imports but stays LegacyLocal.
	require.NoError(t, svc.Run(ctx))
	mode, err := node.SigningIdentityMode(ctx)
	require.NoError(t, err)
	assert.Equal(t, cert.SigningIdentityLegacyLocal, mode)
	assert.Len(t, signingKeyPaths(t, dir), 1, "a legacy node keeps its key")

	// Once the cursor names the serial the next pass promotes it and removes the key.
	_, created, err := cursor.SeedCursorIfAbsent(ctx, local.SerialNumber)
	require.NoError(t, err)
	require.True(t, created)
	require.NoError(t, svc.Run(ctx))
	require.NoError(t, svc.Run(ctx), "a repeat pass is a no-op")

	mode, err = node.SigningIdentityMode(ctx)
	require.NoError(t, err)
	assert.Equal(t, cert.SigningIdentityShared, mode)
	assert.Empty(t, signingKeyPaths(t, dir))

	require.NoError(t, auditMgr.Flush(ctx))
	entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{TenantID: audit.SystemTenantID})
	require.NoError(t, err)
	seen := map[string]int{}
	for _, e := range entries {
		seen[e.Action]++
		raw, err := json.Marshal(e)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "-----BEGIN")
	}
	assert.Equal(t, 1, seen[cert.SigningMigrationImported])
	assert.Equal(t, 1, seen[cert.SigningMigrationPromoted])
	assert.Equal(t, 1, seen[cert.SigningMigrationKeyRemoved])
}

func TestSigningMigrationService_SingleNodeManagerIsANoOp(t *testing.T) {
	m, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
	})
	require.NoError(t, err)
	svc := NewSigningMigrationService(m, logging.NewNoopLogger())
	assert.NoError(t, svc.Run(context.Background()))
	assert.NoError(t, NewSigningMigrationService(nil, logging.NewNoopLogger()).Run(context.Background()))
}

func signingKeyPaths(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "key.pem" && filepath.Base(filepath.Dir(p)) != "ca" {
			found = append(found, p)
		}
		return err
	}))
	return found
}
