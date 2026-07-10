// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package network_activedirectory

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

func newTestSecretStore(t *testing.T) secretsinterfaces.SecretStore {
	t.Helper()
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}
	tmpDir := t.TempDir()
	provider := &steward.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": tmpDir,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestResolvePassword_Success(t *testing.T) {
	store := newTestSecretStore(t)
	ctx := context.Background()

	err := store.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
		Key:       "ad/test.example.com/svc_password",
		Value:     "super-secret-password",
		CreatedBy: "test",
		TenantID:  "test",
	})
	require.NoError(t, err)

	config := &ADModuleConfig{
		Domain:            "test.example.com",
		AuthMethod:        "simple",
		PasswordSecretKey: "ad/test.example.com/svc_password",
	}
	authManager := NewAuthenticationManager(config, store)

	password, err := authManager.resolvePassword(ctx)
	require.NoError(t, err)
	assert.Equal(t, "super-secret-password", password)
}

func TestResolvePassword_MissingKey(t *testing.T) {
	store := newTestSecretStore(t)
	ctx := context.Background()

	config := &ADModuleConfig{
		Domain:     "test.example.com",
		AuthMethod: "simple",
		// PasswordSecretKey intentionally empty
	}
	authManager := NewAuthenticationManager(config, store)

	_, err := authManager.resolvePassword(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PasswordSecretKey is required")
}

func TestResolvePassword_KeyNotFound(t *testing.T) {
	store := newTestSecretStore(t)
	ctx := context.Background()

	// Key is set but the secret has not been stored
	config := &ADModuleConfig{
		Domain:            "test.example.com",
		AuthMethod:        "simple",
		PasswordSecretKey: "ad/test.example.com/nonexistent",
	}
	authManager := NewAuthenticationManager(config, store)

	_, err := authManager.resolvePassword(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve password from secret store")
}

func TestResolvePassword_NilStore(t *testing.T) {
	ctx := context.Background()

	config := &ADModuleConfig{
		Domain:            "test.example.com",
		AuthMethod:        "simple",
		PasswordSecretKey: "ad/test.example.com/svc_password",
	}
	authManager := NewAuthenticationManager(config, nil)

	_, err := authManager.resolvePassword(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no SecretStore configured")
}
