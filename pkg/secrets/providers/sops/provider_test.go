// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sops

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

func TestSOPSProvider_ClusterCapable_False(t *testing.T) {
	p := &SOPSProvider{}
	assert.False(t, p.ClusterCapable(), "SOPSProvider must not be cluster-capable (git-backed file store cannot serve as shared state across controller nodes)")
}

func writeTestKey(t *testing.T, dir string) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	return keyPath
}

func TestSOPSProvider_FailsClosedWithoutExternalKey(t *testing.T) {
	p := &SOPSProvider{}
	_, err := p.CreateSecretStore(map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": t.TempDir()},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key_file is required")
}

func TestSOPSProvider_EncryptsCanaryAtRest(t *testing.T) {
	base := t.TempDir()
	dataRoot := filepath.Join(base, "data")
	keyPath := writeTestKey(t, base)
	p := &SOPSProvider{}
	store, err := p.CreateSecretStore(map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": dataRoot},
		"cache_enabled":    false,
		"key_file":         keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	const canary = "cfgms-plaintext-canary-do-not-persist"
	require.NoError(t, store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:       "api-key",
		Value:     canary,
		TenantID:  "tenant-a",
		CreatedBy: "security-test",
	}))

	var stored []byte
	require.NoError(t, filepath.Walk(dataRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		stored = append(stored, data...)
		return nil
	}))
	assert.NotContains(t, string(stored), canary)

	got, err := store.GetSecret(context.Background(), "tenant-a/api-key")
	require.NoError(t, err)
	assert.Equal(t, canary, got.Value)
}

func TestSOPSProvider_RejectsKeyStoredWithSecretData(t *testing.T) {
	dataRoot := t.TempDir()
	keyPath := writeTestKey(t, dataRoot)
	p := &SOPSProvider{}
	_, err := p.CreateSecretStore(map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": dataRoot},
		"key_file":         keyPath,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stored separately")
}

func TestSOPSProvider_RejectsOverPermissiveKeyFile(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	base := t.TempDir()
	keyPath := writeTestKey(t, base)
	require.NoError(t, os.Chmod(keyPath, 0o644))
	p := &SOPSProvider{}
	_, err := p.CreateSecretStore(map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": filepath.Join(base, "data")},
		"key_file":         keyPath,
	})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "permissions"), err.Error())
}

func TestSOPSProvider_EnforcesSecretSizeLimit(t *testing.T) {
	base := t.TempDir()
	store, err := NewSOPSSecretStore(&SOPSSecretStoreConfig{
		StorageProvider: "flatfile",
		StorageConfig:   map[string]interface{}{"root": filepath.Join(base, "data")},
		KeyFile:         writeTestKey(t, base),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	err = store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:      "too-large",
		Value:    strings.Repeat("x", (1<<20)+1),
		TenantID: "tenant-a",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1048576 byte limit")
}

func TestSOPSProvider_BulkReadFailsOnTamperedCiphertext(t *testing.T) {
	base := t.TempDir()
	store, err := NewSOPSSecretStore(&SOPSSecretStoreConfig{
		StorageProvider: "flatfile",
		StorageConfig:   map[string]interface{}{"root": filepath.Join(base, "data")},
		CacheEnabled:    false,
		KeyFile:         writeTestKey(t, base),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	require.NoError(t, store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:      "api-key",
		Value:    "canary",
		TenantID: "tenant-a",
	}))

	entry, err := store.configStore.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID: "tenant-a", Namespace: "secrets", Name: "api-key",
	})
	require.NoError(t, err)
	entry.Data = []byte(`{"version":1,"algorithm":"AES-256-GCM","nonce":"bad","ciphertext":"bad"}`)
	require.NoError(t, store.configStore.StoreConfig(context.Background(), entry))

	_, err = store.GetSecrets(context.Background(), []string{"tenant-a/api-key"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve secret")
}
