//go:build integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package openbao — integration tests for OpenBaoSecretStore.
// Requires a running OpenBao dev instance:
//
//	docker compose --profile openbao -f docker-compose.test.yml up -d openbao-test
//
// Environment variables:
//
//	OPENBAO_ADDR=http://localhost:8201  (default)
//	OPENBAO_TOKEN=root                  (default for dev mode)
package openbao

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// testStore creates a store connected to the docker-compose openbao-test instance.
func testStore(t *testing.T) *OpenBaoSecretStore {
	t.Helper()

	addr := os.Getenv("OPENBAO_ADDR")
	if addr == "" {
		addr = "http://localhost:8201"
	}

	token := os.Getenv("OPENBAO_TOKEN")
	if token == "" {
		token = "root"
	}

	store, err := newOpenBaoSecretStore(&OpenBaoConfig{
		Address:   addr,
		Token:     token,
		MountPath: "secret",
	})
	require.NoError(t, err, "failed to create test store")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, store.HealthCheck(ctx), "OpenBao health check failed — is the container running?")

	return store
}

// uniqueTenant returns a unique tenant ID per test to guarantee isolation.
func uniqueTenant(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test-tenant-%d", time.Now().UnixNano())
}

// cleanupKey removes a secret key after the test completes, ignoring errors.
func cleanupKey(t *testing.T, store *OpenBaoSecretStore, tenantID, key string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = store.DeleteSecret(ctx, tenantID+"/"+key)
	})
}

func TestStore_StoreAndGetSecret(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, store, tenantID, "mykey")

	req := &interfaces.SecretRequest{
		Key:         "mykey",
		Value:       "s3cr3t",
		TenantID:    tenantID,
		CreatedBy:   "test",
		Description: "test secret",
		Tags:        []string{"env:test", "service:core"},
		Metadata:    map[string]string{"secret_type": "password"},
	}

	require.NoError(t, store.StoreSecret(ctx, req))

	secret, err := store.GetSecret(ctx, tenantID+"/mykey")
	require.NoError(t, err)

	assert.Equal(t, "mykey", secret.Key)
	assert.Equal(t, "s3cr3t", secret.Value)
	assert.Equal(t, tenantID, secret.TenantID)
	assert.Equal(t, "test", secret.CreatedBy)
	assert.Equal(t, "test secret", secret.Description)
	assert.Contains(t, secret.Tags, "env:test")
	assert.Contains(t, secret.Tags, "service:core")
}

func TestStore_StoreSecret_EmptyTenantID(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:   "somekey",
		Value: "value",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, cfgconfig.ErrTenantRequired)
}

func TestStore_GetSecret_NotFound(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	_, err := store.GetSecret(ctx, tenantID+"/nonexistent")
	require.Error(t, err)
}

func TestStore_DeleteSecret(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	req := &interfaces.SecretRequest{
		Key:      "deletekey",
		Value:    "v",
		TenantID: tenantID,
	}
	require.NoError(t, store.StoreSecret(ctx, req))

	require.NoError(t, store.DeleteSecret(ctx, tenantID+"/deletekey"))

	_, err := store.GetSecret(ctx, tenantID+"/deletekey")
	require.Error(t, err, "secret should not be accessible after deletion")
}

func TestStore_DeleteSecret_NotFound(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	err := store.DeleteSecret(ctx, tenantID+"/no-such-secret")
	require.Error(t, err)
}

func TestStore_ListSecrets_TenantIsolation(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantA := uniqueTenant(t)
	tenantB := uniqueTenant(t)

	// Write two secrets under tenantA and one under tenantB.
	for _, key := range []string{"keyA1", "keyA2"} {
		cleanupKey(t, store, tenantA, key)
		require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
			Key: key, Value: "v", TenantID: tenantA,
		}))
	}
	cleanupKey(t, store, tenantB, "keyB1")
	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key: "keyB1", Value: "v", TenantID: tenantB,
	}))

	// ListSecrets for tenantA should return exactly tenantA's keys.
	results, err := store.ListSecrets(ctx, &interfaces.SecretFilter{TenantID: tenantA})
	require.NoError(t, err)
	require.Len(t, results, 2)

	for _, m := range results {
		assert.Equal(t, tenantA, m.TenantID, "all results should belong to tenantA")
	}
}

func TestStore_ListSecrets_PrefixFilter(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	for _, key := range []string{"app/db-password", "app/api-key", "infra/ssh-key"} {
		cleanupKey(t, store, tenantID, key)
		require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
			Key: key, Value: "v", TenantID: tenantID,
		}))
	}

	results, err := store.ListSecrets(ctx, &interfaces.SecretFilter{
		TenantID:  tenantID,
		KeyPrefix: "app/",
	})
	require.NoError(t, err)
	require.Len(t, results, 2, "only app/ prefixed keys should be returned")

	for _, m := range results {
		assert.Truef(t, len(m.Key) > 4 && m.Key[:4] == "app/",
			"key %q should start with app/", m.Key)
	}
}

func TestStore_Versioning(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, store, tenantID, "verkey")

	// Write version 1.
	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key: "verkey", Value: "v1", TenantID: tenantID,
	}))

	// Write version 2.
	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key: "verkey", Value: "v2", TenantID: tenantID,
	}))

	// Current (version 2) should be "v2".
	current, err := store.GetSecret(ctx, tenantID+"/verkey")
	require.NoError(t, err)
	assert.Equal(t, "v2", current.Value)

	// Version 1 should still be "v1".
	v1, err := store.GetSecretVersion(ctx, tenantID+"/verkey", 1)
	require.NoError(t, err)
	assert.Equal(t, "v1", v1.Value)

	// ListSecretVersions should include both.
	versions, err := store.ListSecretVersions(ctx, tenantID+"/verkey")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(versions), 2)
}

func TestStore_RotateSecret(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, store, tenantID, "rotkey")

	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key: "rotkey", Value: "old-value", TenantID: tenantID,
	}))

	require.NoError(t, store.RotateSecret(ctx, tenantID+"/rotkey", "new-value"))

	current, err := store.GetSecret(ctx, tenantID+"/rotkey")
	require.NoError(t, err)
	assert.Equal(t, "new-value", current.Value)

	// Old version should still be retrievable.
	old, err := store.GetSecretVersion(ctx, tenantID+"/rotkey", 1)
	require.NoError(t, err)
	assert.Equal(t, "old-value", old.Value)

	// Metadata should record rotation timestamp.
	assert.NotEmpty(t, current.Metadata[interfaces.MetadataKeyLastRotated])
}

func TestStore_UpdateSecretMetadata(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, store, tenantID, "metakey")

	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key: "metakey", Value: "v", TenantID: tenantID,
	}))

	require.NoError(t, store.UpdateSecretMetadata(ctx, tenantID+"/metakey", map[string]string{
		"owner": "team-infra",
	}))

	meta, err := store.GetSecretMetadata(ctx, tenantID+"/metakey")
	require.NoError(t, err)
	assert.Equal(t, "team-infra", meta.Metadata["owner"])
}

func TestStore_BulkOperations(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	keys := []string{"bulk1", "bulk2", "bulk3"}
	for _, k := range keys {
		cleanupKey(t, store, tenantID, k)
	}

	batch := make(map[string]*interfaces.SecretRequest, len(keys))
	for _, k := range keys {
		batch[k] = &interfaces.SecretRequest{
			Key: k, Value: "v-" + k, TenantID: tenantID,
		}
	}

	require.NoError(t, store.StoreSecrets(ctx, batch))

	fullKeys := make([]string, len(keys))
	for i, k := range keys {
		fullKeys[i] = tenantID + "/" + k
	}

	results, err := store.GetSecrets(ctx, fullKeys)
	require.NoError(t, err, "all keys should be retrievable")
	assert.Len(t, results, len(keys))
}

func TestStore_HealthCheck(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	assert.NoError(t, store.HealthCheck(ctx))
}

func TestStore_Close(t *testing.T) {
	store := testStore(t)
	assert.NoError(t, store.Close())
}

func TestStore_ExpireSecret(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)

	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key: "expkey", Value: "v", TenantID: tenantID,
	}))

	require.NoError(t, store.ExpireSecret(ctx, tenantID+"/expkey"))

	_, err := store.GetSecret(ctx, tenantID+"/expkey")
	require.Error(t, err, "expired (deleted) secret should not be retrievable")
}

func TestStore_GetSecretMetadata(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, store, tenantID, "metaget")

	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:         "metaget",
		Value:       "v",
		TenantID:    tenantID,
		Description: "metadata test",
		Tags:        []string{"test"},
	}))

	meta, err := store.GetSecretMetadata(ctx, tenantID+"/metaget")
	require.NoError(t, err)
	assert.Equal(t, "metaget", meta.Key)
	assert.Equal(t, tenantID, meta.TenantID)
	assert.Greater(t, meta.Version, 0)
}

func TestStore_TTLExpirationFieldIsSet(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, store, tenantID, "ttlkey")

	ttl := 10 * time.Minute // Use a future TTL so the secret is still readable.
	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:      "ttlkey",
		Value:    "v",
		TenantID: tenantID,
		TTL:      ttl,
	}))

	sec, err := store.GetSecret(ctx, tenantID+"/ttlkey")
	require.NoError(t, err)
	require.NotNil(t, sec.ExpiresAt, "ExpiresAt should be set when TTL is provided")
	assert.True(t, sec.ExpiresAt.After(time.Now()), "ExpiresAt should be in the future for a live secret")
}
