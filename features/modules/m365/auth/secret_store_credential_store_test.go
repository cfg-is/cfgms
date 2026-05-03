// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package auth

import (
	"os"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	stewardprovider "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCredentialStore creates a SecretStoreCredentialStore backed by a real steward store.
// Skips the test if /etc/machine-id is absent (required for platform key derivation on Linux).
func newTestCredentialStore(tb testing.TB) *SecretStoreCredentialStore {
	tb.Helper()
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		tb.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}
	provider := &stewardprovider.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": tb.TempDir(),
	})
	if err != nil {
		tb.Fatalf("create steward store: %v", err)
	}
	tb.Cleanup(func() { _ = store.Close() })
	return NewSecretStoreCredentialStore(store)
}

func TestSecretStoreCredentialStore_StoreAndGetToken(t *testing.T) {
	cs := newTestCredentialStore(t)

	token := &AccessToken{
		Token:        "test-access-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(time.Hour),
		TenantID:     "tenant-abc",
		Scope:        "https://graph.microsoft.com/.default",
		RefreshToken: "test-refresh-token",
	}

	err := cs.StoreToken("tenant-abc", token)
	require.NoError(t, err)

	got, err := cs.GetToken("tenant-abc")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, token.Token, got.Token)
	assert.Equal(t, token.TokenType, got.TokenType)
	assert.Equal(t, token.TenantID, got.TenantID)
	assert.Equal(t, token.Scope, got.Scope)
	assert.Equal(t, token.RefreshToken, got.RefreshToken)
}

func TestSecretStoreCredentialStore_StoreAndGetConfig(t *testing.T) {
	cs := newTestCredentialStore(t)

	cfg := &OAuth2Config{
		ClientID:             "client-xyz",
		ClientSecret:         "secret-xyz",
		TenantID:             "tenant-xyz",
		Scopes:               []string{"User.Read", "Directory.Read.All"},
		UseClientCredentials: true,
		SupportDelegatedAuth: true,
	}

	err := cs.StoreConfig("tenant-xyz", cfg)
	require.NoError(t, err)

	got, err := cs.GetConfig("tenant-xyz")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, cfg.ClientID, got.ClientID)
	assert.Equal(t, cfg.ClientSecret, got.ClientSecret)
	assert.Equal(t, cfg.TenantID, got.TenantID)
	assert.Equal(t, cfg.Scopes, got.Scopes)
	assert.Equal(t, cfg.UseClientCredentials, got.UseClientCredentials)
	assert.Equal(t, cfg.SupportDelegatedAuth, got.SupportDelegatedAuth)
}

func TestSecretStoreCredentialStore_StoreAndGetDelegatedToken(t *testing.T) {
	cs := newTestCredentialStore(t)

	token := &AccessToken{
		Token:         "delegated-token-val",
		TokenType:     "Bearer",
		TenantID:      "tenant-del",
		IsDelegated:   true,
		ExpiresAt:     time.Now().Add(time.Hour),
		GrantedScopes: []string{"User.Read", "Directory.Read.All"},
	}

	err := cs.StoreDelegatedToken("tenant-del", "user-001", token)
	require.NoError(t, err)

	got, err := cs.GetDelegatedToken("tenant-del", "user-001")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, token.Token, got.Token)
	assert.Equal(t, token.IsDelegated, got.IsDelegated)
	assert.Equal(t, token.GrantedScopes, got.GrantedScopes)
}

func TestSecretStoreCredentialStore_StoreAndGetUserContext(t *testing.T) {
	cs := newTestCredentialStore(t)

	uctx := &UserContext{
		UserID:            "user-ctx-001",
		UserPrincipalName: "alice@example.com",
		DisplayName:       "Alice",
		Roles:             []string{"User", "Admin"},
		SessionID:         "sess-xyz",
	}

	err := cs.StoreUserContext("tenant-ctx", "user-ctx-001", uctx)
	require.NoError(t, err)

	got, err := cs.GetUserContext("tenant-ctx", "user-ctx-001")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, uctx.UserID, got.UserID)
	assert.Equal(t, uctx.UserPrincipalName, got.UserPrincipalName)
	assert.Equal(t, uctx.DisplayName, got.DisplayName)
	assert.Equal(t, uctx.Roles, got.Roles)
	assert.Equal(t, uctx.SessionID, got.SessionID)
}

func TestSecretStoreCredentialStore_DeleteToken(t *testing.T) {
	cs := newTestCredentialStore(t)

	token := &AccessToken{Token: "to-delete", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}

	require.NoError(t, cs.StoreToken("tenant-del-tok", token))
	require.NoError(t, cs.DeleteToken("tenant-del-tok"))

	_, err := cs.GetToken("tenant-del-tok")
	assert.Error(t, err, "token should be gone after delete")
}

func TestSecretStoreCredentialStore_DeleteToken_NotFound(t *testing.T) {
	cs := newTestCredentialStore(t)
	// Deleting a non-existent token must silently succeed.
	assert.NoError(t, cs.DeleteToken("no-such-tenant"))
}

func TestSecretStoreCredentialStore_DeleteDelegatedToken_NotFound(t *testing.T) {
	cs := newTestCredentialStore(t)
	assert.NoError(t, cs.DeleteDelegatedToken("no-such-tenant", "no-such-user"))
}

func TestSecretStoreCredentialStore_DeleteUserContext_NotFound(t *testing.T) {
	cs := newTestCredentialStore(t)
	assert.NoError(t, cs.DeleteUserContext("no-such-tenant", "no-such-user"))
}

func TestSecretStoreCredentialStore_GetToken_NotFound(t *testing.T) {
	cs := newTestCredentialStore(t)

	_, err := cs.GetToken("unknown-tenant")
	require.Error(t, err)
	assert.ErrorIs(t, err, interfaces.ErrSecretNotFound)
}

func TestSecretStoreCredentialStore_GetConfig_NotFound(t *testing.T) {
	cs := newTestCredentialStore(t)

	_, err := cs.GetConfig("unknown-tenant")
	require.Error(t, err)
	assert.ErrorIs(t, err, interfaces.ErrSecretNotFound)
}

func TestSecretStoreCredentialStore_IsAvailable(t *testing.T) {
	cs := newTestCredentialStore(t)
	assert.True(t, cs.IsAvailable())
}

func TestSecretStoreCredentialStore_TenantIsolation(t *testing.T) {
	cs := newTestCredentialStore(t)

	tokenA := &AccessToken{Token: "token-for-a", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}
	tokenB := &AccessToken{Token: "token-for-b", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}

	require.NoError(t, cs.StoreToken("tenant-a", tokenA))
	require.NoError(t, cs.StoreToken("tenant-b", tokenB))

	gotA, err := cs.GetToken("tenant-a")
	require.NoError(t, err)
	assert.Equal(t, "token-for-a", gotA.Token)

	gotB, err := cs.GetToken("tenant-b")
	require.NoError(t, err)
	assert.Equal(t, "token-for-b", gotB.Token)
}

func TestSecretStoreCredentialStore_SlashSanitization(t *testing.T) {
	cs := newTestCredentialStore(t)

	// tenantID containing slash — must not create path-traversal or store error
	tenantID := "parent/child"
	token := &AccessToken{Token: "slash-token", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}

	require.NoError(t, cs.StoreToken(tenantID, token))

	got, err := cs.GetToken(tenantID)
	require.NoError(t, err)
	assert.Equal(t, "slash-token", got.Token)
}
