// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package secrets_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/migrate"
	migratesecrets "github.com/cfgis/cfgms/pkg/migrate/secrets"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// TestSecretsMigratorFactory_Registered verifies that importing pkg/migrate/secrets
// registers the "secrets" factory in the migrate registry.
func TestSecretsMigratorFactory_Registered(t *testing.T) {
	factory, err := migrate.Lookup("secrets")
	require.NoError(t, err, "secrets factory must be registered via init()")
	assert.NotNil(t, factory)
}

// TestSecretsMigratorFactory_UnknownBackend verifies that the factory rejects an
// unknown backend name with a descriptive error.
func TestSecretsMigratorFactory_UnknownBackend(t *testing.T) {
	factory, err := migrate.Lookup("secrets")
	require.NoError(t, err)

	_, err = factory("bogus-backend", "sops")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus-backend")
}

// TestSecretsMigratorFactory_SopsMissingEnv verifies that the factory returns an
// error when the sops backend is selected but the required env var is absent.
func TestSecretsMigratorFactory_SopsMissingEnv(t *testing.T) {
	t.Setenv("CFGMS_SECRETS_SOPS_STORAGE_ROOT", "")

	factory, err := migrate.Lookup("secrets")
	require.NoError(t, err)

	_, err = factory("sops", "sops")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_SECRETS_SOPS_STORAGE_ROOT")
}

// TestNewSecretsMigrator_NilPanics verifies that passing nil stores panics with a clear message.
func TestNewSecretsMigrator_NilPanics(t *testing.T) {
	assert.Panics(t, func() {
		migratesecrets.NewSecretsMigrator(nil, nil, "", "", "")
	})
}

// TestSecretsMigrator_PlanEmpty verifies that Plan on an empty store returns zero counts.
func TestSecretsMigrator_PlanEmpty(t *testing.T) {
	src := newSOPSStore(t)
	dst := newSOPSStore(t)

	m := migratesecrets.NewSecretsMigrator(src, dst, "", "", "")
	report, err := m.Plan(context.Background())
	require.NoError(t, err)
	total := 0
	for _, c := range report.Counts {
		total += c
	}
	assert.Equal(t, 0, total, "empty source must produce zero-count plan")
}

// TestSecretsMigrator_RunEmpty verifies that migrating an empty source succeeds with zero records.
func TestSecretsMigrator_RunEmpty(t *testing.T) {
	src := newSOPSStore(t)
	dst := newSOPSStore(t)

	m := migratesecrets.NewSecretsMigrator(src, dst, "", "", "")
	report, err := m.Run(context.Background())
	require.NoError(t, err)
	total := 0
	for _, c := range report.Counts {
		total += c
	}
	assert.Equal(t, 0, total, "empty source must produce zero-count run report")
}

// TestSecretsMigrator_SOPStoSOPS verifies a full secret round-trip between two SOPS stores
// without external services.
func TestSecretsMigrator_SOPStoSOPS(t *testing.T) {
	ctx := context.Background()

	src := newSOPSStore(t)
	dst := newSOPSStore(t)

	tenantID := fmt.Sprintf("test-%d", time.Now().UnixNano())

	wantSecrets := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	for key, val := range wantSecrets {
		require.NoError(t, src.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
			Key: key, Value: val, TenantID: tenantID, CreatedBy: "test",
		}))
	}

	m := migratesecrets.NewSecretsMigrator(src, dst, "", "", "")
	report, err := m.Run(ctx)
	require.NoError(t, err, "SOPS→SOPS migration must succeed")
	assert.Equal(t, len(wantSecrets), report.Counts["secret"], "all secrets must be migrated")
	assert.Empty(t, report.Errors, "no errors expected without CA sub-step")

	for key, want := range wantSecrets {
		got, err := dst.GetSecret(ctx, tenantID+"/"+key)
		require.NoErrorf(t, err, "secret %q must be readable from destination", key)
		assert.Equalf(t, want, got.Value, "secret %q value must match", key)
	}
}

// TestSecretsMigrator_SOPStoSOPS_Idempotent verifies that running the migration twice
// yields identical counts with no duplicates.
func TestSecretsMigrator_SOPStoSOPS_Idempotent(t *testing.T) {
	ctx := context.Background()

	src := newSOPSStore(t)
	dst := newSOPSStore(t)

	tenantID := fmt.Sprintf("test-%d", time.Now().UnixNano())
	require.NoError(t, src.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
		Key: "mykey", Value: "myval", TenantID: tenantID, CreatedBy: "test",
	}))

	m := migratesecrets.NewSecretsMigrator(src, dst, "", "", "")

	report1, err := m.Run(ctx)
	require.NoError(t, err, "first run must succeed")

	report2, err := m.Run(ctx)
	require.NoError(t, err, "second run must succeed (idempotent)")

	for kind, c1 := range report1.Counts {
		c2, ok := report2.Counts[kind]
		assert.True(t, ok, "second run must include kind %q", kind)
		assert.Equal(t, c1, c2, "second run count for %q must match first", kind)
	}
}

// newSOPSStore creates a SOPS secret store backed by flatfile in a per-test temp dir.
// No external services are required.
func newSOPSStore(t *testing.T) secretsinterfaces.SecretStore {
	t.Helper()
	dir := t.TempDir()
	store, err := secretsinterfaces.CreateSecretStoreFromConfig("sops", map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": dir},
		"cache_enabled":    false,
	})
	require.NoError(t, err, "create SOPS test store")
	t.Cleanup(func() { _ = store.Close() })
	return store
}
