// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/migrate"
	migratestorage "github.com/cfgis/cfgms/pkg/migrate/storage"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// TestStorageMigrateValidation verifies that runStorageMigrate returns a clear
// error when required flags or backend configuration are missing.
//
// When the "storage" migrator is registered (via pkg/migrate/storage imported
// from cmd/cfg/cmd/migrate.go), runStorageMigrate delegates to that migrator.
// The test cases therefore use backend names and error strings that match the
// new migrator's validation rather than the legacy git-inline fallback.
func TestStorageMigrateValidation(t *testing.T) {
	tests := []struct {
		name           string
		from           string
		to             string
		dryRun         bool
		wantErrContain string
	}{
		{
			// "git" is not a supported backend in the registered storage migrator.
			name:           "git backend unsupported",
			from:           "git",
			to:             "oss",
			wantErrContain: "git",
		},
		{
			// Neither "git" nor "memory" are supported backends; the first
			// unknown backend ("git") is what we detect in the error message.
			name:           "unsupported from and to backends",
			from:           "git",
			to:             "memory",
			wantErrContain: "git",
		},
		{
			// database backend without DSN must fail with a clear message.
			name:           "database backend missing DSN",
			from:           "database",
			to:             "oss",
			wantErrContain: "CFGMS_STORAGE_CLUSTER_POSTGRES_DSN",
		},
		{
			// oss backend without env vars must fail with a clear message.
			name:           "oss backend missing flatfile root",
			from:           "oss",
			to:             "database",
			wantErrContain: "CFGMS_STORAGE_FLATFILE_ROOT",
		},
		{
			// --dry-run still validates backend names — an unknown source fails.
			name:           "dry-run still validates backend",
			from:           "git",
			to:             "oss",
			dryRun:         true,
			wantErrContain: "git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear oss-related env vars to trigger the expected error.
			t.Setenv("CFGMS_STORAGE_FLATFILE_ROOT", "")
			t.Setenv("CFGMS_STORAGE_SQLITE_PATH", "")
			t.Setenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "")

			// Save and restore global flags.
			origFrom := migrateFrom
			origTo := migrateTo
			origDryRun := storageMigrateDryRun
			defer func() {
				migrateFrom = origFrom
				migrateTo = origTo
				storageMigrateDryRun = origDryRun
			}()

			migrateFrom = tt.from
			migrateTo = tt.to
			storageMigrateDryRun = tt.dryRun

			err := runStorageMigrate(nil, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrContain)
		})
	}
}

// TestStorageMigrateGitBackendRejected verifies that attempting to use the
// legacy "git" backend through runStorageMigrate now returns an unsupported-backend
// error from the storage migrator (the git-inline fallback is no longer reached
// once the "storage" migrator is registered).
func TestStorageMigrateGitBackendRejected(t *testing.T) {
	t.Setenv("CFGMS_STORAGE_FLATFILE_ROOT", "")
	t.Setenv("CFGMS_STORAGE_SQLITE_PATH", "")
	t.Setenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "")

	origFrom := migrateFrom
	origTo := migrateTo
	origGitRoot := migrateGitRoot
	origFlatfileRoot := migrateFlatfileRoot
	defer func() {
		migrateFrom = origFrom
		migrateTo = origTo
		migrateGitRoot = origGitRoot
		migrateFlatfileRoot = origFlatfileRoot
	}()

	migrateFrom = "git"
	migrateTo = "oss"
	migrateGitRoot = t.TempDir()
	migrateFlatfileRoot = t.TempDir()

	err := runStorageMigrate(nil, nil)
	require.Error(t, err)
	// The registered storage migrator reports "git" as an unknown backend.
	assert.Contains(t, err.Error(), "git")
}

// TestStorageMigrateDryRun_FlatfileSQLiteTargetRemainsEmpty verifies that
// running cfg storage migrate with --dry-run leaves the target flatfile+sqlite
// config, registration-token, and tenant stores empty while the migration
// reports the source record counts (reads all records but writes none).
//
// The "storage" migrator factory is temporarily overridden to inject
// pre-built OSS managers with separate source and target directories so that
// the target can be inspected independently of the source after the run.
func TestStorageMigrateDryRun_FlatfileSQLiteTargetRemainsEmpty(t *testing.T) {
	ctx := context.Background()

	// Build a seeded source OSS manager.
	srcDir := t.TempDir()
	srcMgr, err := interfaces.CreateOSSStorageManager(srcDir+"/flat", srcDir+"/cfgms.db")
	require.NoError(t, err, "create source storage manager")
	t.Cleanup(func() { _ = srcMgr.Close() })

	// Seed source config store.
	require.NoError(t, srcMgr.GetConfigStore().StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:       &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "ns", Name: "cfg"},
		Data:      []byte("key: val"),
		Version:   1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))

	// Seed source tenant store.
	srcTS := srcMgr.GetTenantStore()
	require.NoError(t, srcTS.Initialize(ctx))
	require.NoError(t, srcTS.CreateTenant(ctx, &business.TenantData{
		ID:        "t1",
		Name:      "Tenant One",
		Status:    business.TenantStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))

	// Seed source registration token store.
	srcRTS := srcMgr.GetRegistrationTokenStore()
	require.NoError(t, srcRTS.Initialize(ctx))
	require.NoError(t, srcRTS.SaveToken(ctx, &business.RegistrationTokenData{
		Token:     "token-1",
		TenantID:  "t1",
		CreatedAt: time.Now(),
	}))

	// Build an empty target OSS manager.
	dstDir := t.TempDir()
	dstMgr, err := interfaces.CreateOSSStorageManager(dstDir+"/flat", dstDir+"/cfgms.db")
	require.NoError(t, err, "create target storage manager")
	t.Cleanup(func() { _ = dstMgr.Close() })

	// Override the "storage" factory for this test with a real StorageMigrator
	// using the pre-built managers instead of env-var-configured backends.
	prevFactory, prevErr := migrate.Lookup("storage")
	migrate.Register("storage", func(from, to string) (migrate.Migrator, error) {
		return migratestorage.NewStorageMigrator(srcMgr, dstMgr), nil
	})
	t.Cleanup(func() {
		if prevErr == nil {
			migrate.Register("storage", prevFactory)
		}
	})

	// Save and restore global flag state.
	origFrom, origTo := migrateFrom, migrateTo
	origDryRun := storageMigrateDryRun
	t.Cleanup(func() {
		migrateFrom, migrateTo = origFrom, origTo
		storageMigrateDryRun = origDryRun
	})

	migrateFrom = "oss"
	migrateTo = "oss"
	storageMigrateDryRun = true

	err = runStorageMigrate(nil, nil)
	require.NoError(t, err, "dry-run must succeed")

	// Target config store must remain empty — no writes performed.
	entries, err := dstMgr.GetConfigStore().ListConfigs(ctx, &cfgconfig.ConfigFilter{})
	require.NoError(t, err)
	assert.Empty(t, entries, "dry-run must not write config records to target")

	// Target tenant store must remain empty.
	dstTS := dstMgr.GetTenantStore()
	require.NoError(t, dstTS.Initialize(ctx))
	tenants, err := dstTS.ListTenants(ctx, &business.TenantFilter{})
	require.NoError(t, err)
	assert.Empty(t, tenants, "dry-run must not write tenant records to target")

	// Target registration token store must remain empty.
	dstRTS := dstMgr.GetRegistrationTokenStore()
	require.NoError(t, dstRTS.Initialize(ctx))
	tokens, err := dstRTS.ListTokens(ctx, &business.RegistrationTokenFilter{})
	require.NoError(t, err)
	assert.Empty(t, tokens, "dry-run must not write registration token records to target")
}
