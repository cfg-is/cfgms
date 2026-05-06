// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package saas

import (
	"os"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	stewardprovider "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// compile-time assertion: SecretStoreCredentialStore must implement auth.CredentialStore.
var _ auth.CredentialStore = (*SecretStoreCredentialStore)(nil)

// newTestCredentialStore creates a SecretStoreCredentialStore backed by a real steward
// store in a temporary directory. Tests are skipped when /etc/machine-id is absent
// (required for OS-native key derivation on Linux).
func newTestCredentialStore(t *testing.T) auth.CredentialStore {
	t.Helper()
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}

	tmpDir := t.TempDir()
	provider := &stewardprovider.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": tmpDir,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close secret store: %v", err)
		}
	})

	return NewSecretStoreCredentialStore(store)
}

// newBenchCredentialStore creates a SecretStoreCredentialStore backed by a real steward
// store for use in benchmarks.
func newBenchCredentialStore(b *testing.B) auth.CredentialStore {
	b.Helper()
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		b.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}

	tmpDir := b.TempDir()
	provider := &stewardprovider.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": tmpDir,
	})
	if err != nil {
		b.Fatalf("failed to create secret store: %v", err)
	}
	b.Cleanup(func() {
		if err := store.Close(); err != nil {
			b.Errorf("failed to close secret store: %v", err)
		}
	})

	return NewSecretStoreCredentialStore(store)
}

func TestSecretStoreCredentialStore_StoreAndGetToken(t *testing.T) {
	cs := newTestCredentialStore(t)

	token := &auth.AccessToken{
		Token:         "access-token-abc",
		RefreshToken:  "refresh-token-xyz",
		TokenType:     "Bearer",
		ExpiresAt:     time.Now().Add(1 * time.Hour).Truncate(time.Second),
		TenantID:      "test-tenant",
		GrantedScopes: []string{"read", "write"},
	}

	err := cs.StoreToken("test-tenant", token)
	require.NoError(t, err)

	got, err := cs.GetToken("test-tenant")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, token.Token, got.Token)
	assert.Equal(t, token.RefreshToken, got.RefreshToken)
	assert.Equal(t, token.TokenType, got.TokenType)
	assert.Equal(t, token.TenantID, got.TenantID)
	assert.Equal(t, token.GrantedScopes, got.GrantedScopes)
	assert.Equal(t, token.ExpiresAt.Unix(), got.ExpiresAt.Unix())
}

func TestSecretStoreCredentialStore_DeleteToken(t *testing.T) {
	cs := newTestCredentialStore(t)

	token := &auth.AccessToken{
		Token:     "access-token",
		TokenType: "Bearer",
		TenantID:  "del-tenant",
	}

	require.NoError(t, cs.StoreToken("del-tenant", token))

	got, err := cs.GetToken("del-tenant")
	require.NoError(t, err)
	require.NotNil(t, got)

	require.NoError(t, cs.DeleteToken("del-tenant"))

	_, err = cs.GetToken("del-tenant")
	require.Error(t, err)
}

func TestSecretStoreCredentialStore_GetToken_NotFound(t *testing.T) {
	cs := newTestCredentialStore(t)

	_, err := cs.GetToken("nonexistent-tenant")
	require.Error(t, err)
}

func TestSecretStoreCredentialStore_StoreDelegatedToken(t *testing.T) {
	cs := newTestCredentialStore(t)

	token := &auth.AccessToken{
		Token:       "delegated-token",
		TokenType:   "Bearer",
		TenantID:    "tenant-1",
		IsDelegated: true,
	}

	err := cs.StoreDelegatedToken("tenant-1", "user-1", token)
	require.NoError(t, err)

	got, err := cs.GetDelegatedToken("tenant-1", "user-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "delegated-token", got.Token)
	assert.True(t, got.IsDelegated)

	require.NoError(t, cs.DeleteDelegatedToken("tenant-1", "user-1"))
	_, err = cs.GetDelegatedToken("tenant-1", "user-1")
	require.Error(t, err)
}

func TestSecretStoreCredentialStore_StoreUserContext(t *testing.T) {
	cs := newTestCredentialStore(t)

	userCtx := &auth.UserContext{
		UserID:            "user-1",
		UserPrincipalName: "user@example.com",
		DisplayName:       "Test User",
		Roles:             []string{"admin"},
	}

	err := cs.StoreUserContext("tenant-1", "user-1", userCtx)
	require.NoError(t, err)

	got, err := cs.GetUserContext("tenant-1", "user-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "user-1", got.UserID)
	assert.Equal(t, "user@example.com", got.UserPrincipalName)
	assert.Equal(t, []string{"admin"}, got.Roles)

	require.NoError(t, cs.DeleteUserContext("tenant-1", "user-1"))
	_, err = cs.GetUserContext("tenant-1", "user-1")
	require.Error(t, err)
}

func TestSecretStoreCredentialStore_StoreConfig(t *testing.T) {
	cs := newTestCredentialStore(t)

	config := &auth.OAuth2Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		TenantID:     "tenant-1",
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}

	err := cs.StoreConfig("tenant-1", config)
	require.NoError(t, err)

	got, err := cs.GetConfig("tenant-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "test-client-id", got.ClientID)
	assert.Equal(t, "test-secret", got.ClientSecret)
	assert.Equal(t, "tenant-1", got.TenantID)
	assert.Equal(t, config.Scopes, got.Scopes)
}

func TestSecretStoreCredentialStore_GetConfig_NotFound(t *testing.T) {
	cs := newTestCredentialStore(t)

	_, err := cs.GetConfig("nonexistent-tenant")
	require.Error(t, err)
}

func TestSecretStoreCredentialStore_IsAvailable(t *testing.T) {
	cs := newTestCredentialStore(t)

	assert.True(t, cs.IsAvailable())
}

func TestSecretStoreCredentialStore_IsolatedPerTenant(t *testing.T) {
	cs := newTestCredentialStore(t)

	tokenA := &auth.AccessToken{Token: "token-a", TenantID: "tenant-a"}
	tokenB := &auth.AccessToken{Token: "token-b", TenantID: "tenant-b"}

	require.NoError(t, cs.StoreToken("tenant-a", tokenA))
	require.NoError(t, cs.StoreToken("tenant-b", tokenB))

	gotA, err := cs.GetToken("tenant-a")
	require.NoError(t, err)
	assert.Equal(t, "token-a", gotA.Token)

	gotB, err := cs.GetToken("tenant-b")
	require.NoError(t, err)
	assert.Equal(t, "token-b", gotB.Token)
}
