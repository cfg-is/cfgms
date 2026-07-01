//go:build integration

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package secrets_test contains integration tests for the secrets migrator.
//
// Prerequisites:
//
//	docker compose --profile openbao -f docker-compose.test.yml up -d openbao-test
//
// Environment variables:
//
//	OPENBAO_ADDR=http://localhost:8201  (default)
//	OPENBAO_TOKEN=root                  (default for dev mode)
package secrets_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	migratesecrets "github.com/cfgis/cfgms/pkg/migrate/secrets"
	"github.com/cfgis/cfgms/pkg/cert"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// testOpenBaoStore creates a store connected to the docker-compose openbao-test instance.
func testOpenBaoStore(t *testing.T) secretsinterfaces.SecretStore {
	t.Helper()

	addr := os.Getenv("OPENBAO_ADDR")
	if addr == "" {
		addr = "http://localhost:8201"
	}
	token := os.Getenv("OPENBAO_TOKEN")
	if token == "" {
		token = "root"
	}

	store, err := secretsinterfaces.CreateSecretStoreFromConfig("openbao", map[string]interface{}{
		"address":    addr,
		"token":      token,
		"mount_path": "secret",
	})
	require.NoError(t, err, "failed to create OpenBao test store")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, store.HealthCheck(ctx), "OpenBao health check failed — is the container running?")

	return store
}

// TestSecretsMigrate_FileToOpenBaoIncludingCA migrates secrets from a SOPS/flatfile
// source to a real OpenBao target, then relocates a file-based CA private key into
// the vault path via StoreCAToSecretStore, verifying that no cleartext key is written
// to disk during the migration.
func TestSecretsMigrate_FileToOpenBaoIncludingCA(t *testing.T) {
	ctx := context.Background()

	// Source: SOPS store backed by flatfile in a temp dir (no SOPS encryption needed for tests).
	srcDir := t.TempDir()
	srcStore, err := secretsinterfaces.CreateSecretStoreFromConfig("sops", map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": srcDir},
		"cache_enabled":    false,
	})
	require.NoError(t, err, "failed to create source SOPS store")

	tenantID := fmt.Sprintf("test-tenant-%d", time.Now().UnixNano())

	// Populate source with test secrets.
	testSecrets := map[string]string{
		"api-key":     "test-api-value-1",
		"db-password": "test-db-value-2",
	}
	for key, value := range testSecrets {
		require.NoError(t, srcStore.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
			Key:         key,
			Value:       value,
			TenantID:    tenantID,
			CreatedBy:   "test",
			Description: "migration test secret",
		}))
	}

	// Create a file-based CA to exercise the CA relocation sub-step.
	caDir := t.TempDir()
	caConfig := &cert.CAConfig{
		Organization: "Test CA Org",
		StoragePath:  caDir,
		ValidityDays: 365,
		KeySize:      2048,
	}
	ca, err := cert.NewCA(caConfig)
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(caConfig))

	// Confirm ca.key exists on disk before migration.
	caKeyOnDisk := filepath.Join(caDir, "ca.key")
	_, err = os.Stat(caKeyOnDisk)
	require.NoError(t, err, "ca.key must exist on disk before migration")

	// Target: real OpenBao store.
	dstStore := testOpenBaoStore(t)

	caSecretKeyPath := "cluster-ca"
	t.Cleanup(func() {
		cleanCtx := context.Background()
		for key := range testSecrets {
			_ = dstStore.DeleteSecret(cleanCtx, tenantID+"/"+key)
		}
		_ = dstStore.DeleteSecret(cleanCtx, tenantID+"/"+caSecretKeyPath)
		_ = dstStore.DeleteSecret(cleanCtx, tenantID+"/"+caSecretKeyPath+"-key")
	})

	// Run migration: SOPS → OpenBao including CA sub-step.
	m := migratesecrets.NewSecretsMigrator(srcStore, dstStore, caDir, tenantID, caSecretKeyPath)
	report, err := m.Run(ctx)
	require.NoError(t, err, "migration must succeed")

	// Verify secret and CA counts.
	assert.Equal(t, len(testSecrets), report.Counts["secret"], "all secrets must be migrated")
	assert.Equal(t, 1, report.Counts["ca"], "CA sub-step must be counted")

	// Report must contain the residual key path warning (operator action required).
	caWarn, hasWarn := report.Errors["ca_source_key_path"]
	require.True(t, hasWarn, "report must warn about residual ca.key requiring operator removal")
	assert.Contains(t, caWarn.Error(), "ca.key", "warning must reference the source key file path")

	// All secrets must be readable from the target with correct values.
	for key, want := range testSecrets {
		got, err := dstStore.GetSecret(ctx, tenantID+"/"+key)
		require.NoErrorf(t, err, "secret %q must be readable from target", key)
		assert.Equalf(t, want, got.Value, "secret %q value must match after migration", key)
	}

	// CA must load from the target store — no cleartext ca.key on disk required.
	caFromStore := &cert.CA{}
	err = caFromStore.LoadCAFromSecretStore(ctx, dstStore, tenantID, caSecretKeyPath)
	require.NoError(t, err, "CA must load from secret store after migration")
	assert.True(t, caFromStore.IsInitialized(), "migrated CA must be initialized")

	// Verify no cleartext key was written to the sops source directory during migration.
	_, err = os.Stat(filepath.Join(srcDir, "ca.key"))
	assert.ErrorIs(t, err, os.ErrNotExist, "ca.key must not be written to the sops source dir during migration")
}
