// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package steward

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *StewardSecretStore {
	t.Helper()

	// The steward secrets provider requires OS-level machine identity for key derivation.
	// On Linux this is /etc/machine-id. Skip gracefully when it's absent (e.g. containers).
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}

	tmpDir := t.TempDir()

	provider := &StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": tmpDir,
	})
	require.NoError(t, err)
	require.NotNil(t, store)

	s := store.(*StewardSecretStore)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStoreSecret_RoundTrip(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:         "test/api-key",
		Value:       "sk-secret-value-12345",
		Metadata:    map[string]string{"service": "test"},
		Tags:        []string{"api", "test"},
		CreatedBy:   "test-user",
		TenantID:    "tenant-1",
		Description: "Test API key",
	})
	require.NoError(t, err)

	secret, err := store.GetSecret(ctx, "test/api-key")
	require.NoError(t, err)
	require.NotNil(t, secret)

	assert.Equal(t, "test/api-key", secret.Key)
	assert.Equal(t, "sk-secret-value-12345", secret.Value)
	assert.Equal(t, map[string]string{"service": "test"}, secret.Metadata)
	assert.Equal(t, []string{"api", "test"}, secret.Tags)
	assert.Equal(t, 1, secret.Version)
	assert.Equal(t, "test-user", secret.CreatedBy)
	assert.Equal(t, "tenant-1", secret.TenantID)
	assert.Equal(t, "Test API key", secret.Description)
}

func TestStoreSecret_Update(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	// Store initial
	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:       "my-secret",
		Value:     "value-v1",
		CreatedBy: "user-1",
		TenantID:  "tenant-1",
	})
	require.NoError(t, err)

	// Update
	err = store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:       "my-secret",
		Value:     "value-v2",
		CreatedBy: "user-2",
		TenantID:  "tenant-1",
	})
	require.NoError(t, err)

	secret, err := store.GetSecret(ctx, "my-secret")
	require.NoError(t, err)
	assert.Equal(t, "value-v2", secret.Value)
	assert.Equal(t, 2, secret.Version)
	assert.Equal(t, "user-2", secret.UpdatedBy)
}

func TestDeleteSecret(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:       "to-delete",
		Value:     "value",
		CreatedBy: "user",
		TenantID:  "t1",
	})
	require.NoError(t, err)

	err = store.DeleteSecret(ctx, "to-delete")
	require.NoError(t, err)

	_, err = store.GetSecret(ctx, "to-delete")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDeleteSecret_NotFound(t *testing.T) {
	store := newTestStore(t)

	err := store.DeleteSecret(context.Background(), "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListSecrets(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	// Store multiple secrets
	for _, key := range []string{"app/key-1", "app/key-2", "other/key-3"} {
		err := store.StoreSecret(ctx, &interfaces.SecretRequest{
			Key:       key,
			Value:     "value-" + key,
			CreatedBy: "user",
			TenantID:  "tenant-1",
			Tags:      []string{"env:prod"},
		})
		require.NoError(t, err)
	}

	// List all
	results, err := store.ListSecrets(ctx, &interfaces.SecretFilter{})
	require.NoError(t, err)
	assert.Len(t, results, 3)

	// Filter by prefix
	results, err = store.ListSecrets(ctx, &interfaces.SecretFilter{
		KeyPrefix: "app/",
	})
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// Filter by tenant
	results, err = store.ListSecrets(ctx, &interfaces.SecretFilter{
		TenantID: "tenant-1",
	})
	require.NoError(t, err)
	assert.Len(t, results, 3)

	results, err = store.ListSecrets(ctx, &interfaces.SecretFilter{
		TenantID: "nonexistent",
	})
	require.NoError(t, err)
	assert.Len(t, results, 0)
}

func TestSecretExpiration(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	// Store with very short TTL
	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:       "expiring",
		Value:     "temp-value",
		TTL:       50 * time.Millisecond,
		CreatedBy: "user",
		TenantID:  "t1",
	})
	require.NoError(t, err)

	// Should be readable immediately
	secret, err := store.GetSecret(ctx, "expiring")
	require.NoError(t, err)
	assert.Equal(t, "temp-value", secret.Value)

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	_, err = store.GetSecret(ctx, "expiring")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestExpireSecret(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:       "force-expire",
		Value:     "value",
		CreatedBy: "user",
		TenantID:  "t1",
	})
	require.NoError(t, err)

	err = store.ExpireSecret(ctx, "force-expire")
	require.NoError(t, err)

	_, err = store.GetSecret(ctx, "force-expire")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestRotateSecret(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:       "rotate-me",
		Value:     "old-value",
		Metadata:  map[string]string{"service": "test"},
		Tags:      []string{"rotate"},
		CreatedBy: "user",
		TenantID:  "t1",
	})
	require.NoError(t, err)

	err = store.RotateSecret(ctx, "rotate-me", "new-value")
	require.NoError(t, err)

	secret, err := store.GetSecret(ctx, "rotate-me")
	require.NoError(t, err)
	assert.Equal(t, "new-value", secret.Value)
	assert.Equal(t, []string{"rotate"}, secret.Tags)
	assert.NotEmpty(t, secret.Metadata[interfaces.MetadataKeyLastRotated])
}

func TestGetSecretMetadata(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:         "meta-test",
		Value:       "secret-value",
		Metadata:    map[string]string{"env": "prod"},
		Description: "A test secret",
		CreatedBy:   "user",
		TenantID:    "t1",
	})
	require.NoError(t, err)

	meta, err := store.GetSecretMetadata(ctx, "meta-test")
	require.NoError(t, err)
	assert.Equal(t, "meta-test", meta.Key)
	assert.Equal(t, "A test secret", meta.Description)
	assert.Equal(t, map[string]string{"env": "prod"}, meta.Metadata)
}

func TestUpdateSecretMetadata(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:       "update-meta",
		Value:     "value",
		Metadata:  map[string]string{"a": "1"},
		CreatedBy: "user",
		TenantID:  "t1",
	})
	require.NoError(t, err)

	err = store.UpdateSecretMetadata(ctx, "update-meta", map[string]string{"b": "2"})
	require.NoError(t, err)

	meta, err := store.GetSecretMetadata(ctx, "update-meta")
	require.NoError(t, err)
	assert.Equal(t, "1", meta.Metadata["a"])
	assert.Equal(t, "2", meta.Metadata["b"])
}

func TestGetSecrets_Bulk(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	for _, key := range []string{"bulk-1", "bulk-2", "bulk-3"} {
		err := store.StoreSecret(ctx, &interfaces.SecretRequest{
			Key:       key,
			Value:     "value-" + key,
			CreatedBy: "user",
			TenantID:  "t1",
		})
		require.NoError(t, err)
	}

	secrets, err := store.GetSecrets(ctx, []string{"bulk-1", "bulk-2", "nonexistent"})
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
	assert.Equal(t, "value-bulk-1", secrets["bulk-1"].Value)
	assert.Equal(t, "value-bulk-2", secrets["bulk-2"].Value)
}

func TestStoreSecrets_Bulk(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	err := store.StoreSecrets(ctx, map[string]*interfaces.SecretRequest{
		"batch-1": {Key: "batch-1", Value: "v1", CreatedBy: "user", TenantID: "t1"},
		"batch-2": {Key: "batch-2", Value: "v2", CreatedBy: "user", TenantID: "t1"},
	})
	require.NoError(t, err)

	s1, err := store.GetSecret(ctx, "batch-1")
	require.NoError(t, err)
	assert.Equal(t, "v1", s1.Value)

	s2, err := store.GetSecret(ctx, "batch-2")
	require.NoError(t, err)
	assert.Equal(t, "v2", s2.Value)
}

func TestGetSecretVersion_NotSupported(t *testing.T) {
	store := newTestStore(t)

	_, err := store.GetSecretVersion(context.Background(), "any-key", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "versioning not supported")
}

func TestListSecretVersions_Empty(t *testing.T) {
	store := newTestStore(t)

	versions, err := store.ListSecretVersions(context.Background(), "any-key")
	require.NoError(t, err)
	assert.Empty(t, versions)
}

func TestHealthCheck(t *testing.T) {
	store := newTestStore(t)

	err := store.HealthCheck(context.Background())
	require.NoError(t, err)
}

func TestStoreSecret_Validation(t *testing.T) {
	store := newTestStore(t)

	ctx := context.Background()

	// Empty key
	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:       "",
		Value:     "value",
		CreatedBy: "user",
		TenantID:  "t1",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key cannot be empty")
}

func TestStore_PersistenceAcrossReload(t *testing.T) {
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}

	tmpDir := t.TempDir()
	ctx := context.Background()

	// Store a secret
	provider := &StewardProvider{}
	store1, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": tmpDir,
	})
	require.NoError(t, err)

	err = store1.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:       "persist-test",
		Value:     "persistent-value",
		CreatedBy: "user",
		TenantID:  "t1",
	})
	require.NoError(t, err)
	require.NoError(t, store1.Close())

	// Reopen and verify
	store2, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": tmpDir,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store2.Close() })

	secret, err := store2.GetSecret(ctx, "persist-test")
	require.NoError(t, err)
	assert.Equal(t, "persistent-value", secret.Value)
}

func TestProviderRegistration(t *testing.T) {
	// Verify provider is registered via init()
	provider, err := interfaces.GetSecretProvider("steward")
	require.NoError(t, err)
	require.NotNil(t, provider)

	assert.Equal(t, "steward", provider.Name())
	assert.Equal(t, "1.0.0", provider.GetVersion())

	caps := provider.GetCapabilities()
	assert.True(t, caps.SupportsEncryption)
	assert.True(t, caps.SupportsRotation)
	assert.True(t, caps.SupportsMetadata)
	assert.True(t, caps.SupportsTags)
	assert.False(t, caps.SupportsVersioning)
	assert.Equal(t, 1*1024*1024, caps.MaxSecretSize)
}

func TestStore_EncryptedAtRest(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	secretValue := "this-should-not-appear-in-plaintext-on-disk"

	err := store.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:       "encrypted-check",
		Value:     secretValue,
		CreatedBy: "user",
		TenantID:  "t1",
	})
	require.NoError(t, err)

	// Read the blob file directly from disk
	blobFile := keyToBlobFile("encrypted-check")
	blobData, err := readBlobFile(store.secretsDir, blobFile)
	require.NoError(t, err)

	// The raw data on disk should NOT contain the plaintext value
	assert.NotContains(t, string(blobData), secretValue,
		"secret value should be encrypted on disk, not stored in plaintext")

	require.NoError(t, store.Close())
}

// readBlobFile reads raw bytes from a blob file for verification.
func readBlobFile(secretsDir, blobFile string) ([]byte, error) {
	return os.ReadFile(filepath.Join(secretsDir, "blobs", blobFile)) //#nosec G304
}
