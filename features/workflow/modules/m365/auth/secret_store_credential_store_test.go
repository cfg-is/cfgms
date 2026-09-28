// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
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

// TestSecretStoreCredentialStore_HierarchicalTenantsDoNotCollide covers the pair
// that a "/"->"_" flattening mapped onto one key. Both tenant IDs are valid CFGMS
// tenant IDs, and each must keep its own OAuth2 client secret and access token.
func TestSecretStoreCredentialStore_HierarchicalTenantsDoNotCollide(t *testing.T) {
	cs := newTestCredentialStore(t)

	const tenantA = "root/acme/corp"
	const tenantB = "root/acme_corp"

	require.NotEqual(t, tokenKey(tenantA), tokenKey(tenantB), "token keys must not collide")
	require.NotEqual(t, configKey(tenantA), configKey(tenantB), "config keys must not collide")
	require.NotEqual(t, delegatedKey(tenantA, "u1"), delegatedKey(tenantB, "u1"))
	require.NotEqual(t, userContextKey(tenantA, "u1"), userContextKey(tenantB, "u1"))

	require.NoError(t, cs.StoreToken(tenantA, &AccessToken{
		Token: "token-a", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour),
	}))
	require.NoError(t, cs.StoreToken(tenantB, &AccessToken{
		Token: "token-b", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour),
	}))
	require.NoError(t, cs.StoreConfig(tenantA, &OAuth2Config{ClientID: "id-a", ClientSecret: "secret-a"}))
	require.NoError(t, cs.StoreConfig(tenantB, &OAuth2Config{ClientID: "id-b", ClientSecret: "secret-b"}))

	gotA, err := cs.GetToken(tenantA)
	require.NoError(t, err)
	assert.Equal(t, "token-a", gotA.Token)
	gotB, err := cs.GetToken(tenantB)
	require.NoError(t, err)
	assert.Equal(t, "token-b", gotB.Token)

	cfgA, err := cs.GetConfig(tenantA)
	require.NoError(t, err)
	assert.Equal(t, "secret-a", cfgA.ClientSecret)
	cfgB, err := cs.GetConfig(tenantB)
	require.NoError(t, err)
	assert.Equal(t, "secret-b", cfgB.ClientSecret)

	// Deleting one must leave the other intact.
	require.NoError(t, cs.DeleteToken(tenantA))
	_, err = cs.GetToken(tenantA)
	require.Error(t, err)
	stillB, err := cs.GetToken(tenantB)
	require.NoError(t, err)
	assert.Equal(t, "token-b", stillB.Token)
}

// TestSecretStoreCredentialStore_UnderscoreEscapeIsUnambiguous checks that the
// segment encoding stays injective for inputs that differ only in where the
// separator and the former escape character appear.
func TestSecretStoreCredentialStore_UnderscoreEscapeIsUnambiguous(t *testing.T) {
	seen := map[string]string{}
	for _, tenantID := range []string{
		"root/acme/corp", "root/acme_corp", "root_acme/corp", "root_acme_corp",
		"a_/b", "a/_b", "a%2Fb", "a%b",
	} {
		key := tokenKey(tenantID)
		prev, dup := seen[key]
		require.False(t, dup, "tenant %q and %q both derive key %q", prev, tenantID, key)
		seen[key] = tenantID
	}
}

func TestSecretStoreCredentialStore_RejectsEmptyTenantID(t *testing.T) {
	cs := newTestCredentialStore(t)

	// An empty tenant would address the shared bucket "m365//token"; the steward
	// provider does not enforce ErrTenantRequired, so this store must.
	require.ErrorIs(t, cs.StoreToken("", &AccessToken{Token: "x"}), interfaces.ErrTenantRequired)
	_, err := cs.GetToken("")
	require.ErrorIs(t, err, interfaces.ErrTenantRequired)
	require.ErrorIs(t, cs.DeleteToken(""), interfaces.ErrTenantRequired)
	require.ErrorIs(t, cs.StoreConfig("", &OAuth2Config{}), interfaces.ErrTenantRequired)
	_, err = cs.GetConfig("")
	require.ErrorIs(t, err, interfaces.ErrTenantRequired)
	require.ErrorIs(t, cs.StoreDelegatedToken("", "u", &AccessToken{}), interfaces.ErrTenantRequired)
	_, err = cs.GetDelegatedToken("", "u")
	require.ErrorIs(t, err, interfaces.ErrTenantRequired)
	require.ErrorIs(t, cs.DeleteDelegatedToken("", "u"), interfaces.ErrTenantRequired)
	require.ErrorIs(t, cs.StoreUserContext("", "u", &UserContext{}), interfaces.ErrTenantRequired)
	_, err = cs.GetUserContext("", "u")
	require.ErrorIs(t, err, interfaces.ErrTenantRequired)
	require.ErrorIs(t, cs.DeleteUserContext("", "u"), interfaces.ErrTenantRequired)
}

func TestSecretStoreCredentialStore_RejectsMalformedTenantID(t *testing.T) {
	cs := newTestCredentialStore(t)

	for _, tenantID := range []string{
		"/leading", "trailing/", "double//slash", "root/../escape", "root/./here",
		"back\\slash", "null\x00byte",
	} {
		err := cs.StoreToken(tenantID, &AccessToken{Token: "x"})
		require.Error(t, err, "tenant %q must be rejected", tenantID)
		assert.NotContains(t, err.Error(), tenantID, "error must not echo the tenant ID")

		_, getErr := cs.GetToken(tenantID)
		require.Error(t, getErr, "tenant %q must be rejected on read", tenantID)
	}
}

// TestSecretStoreCredentialStore_ReadRejectsForeignTenantRecord proves the
// read-side cross-check is load-bearing: GetSecret resolves purely by key, so a
// record sitting at this tenant's key but recorded against another tenant must
// not be handed back.
func TestSecretStoreCredentialStore_ReadRejectsForeignTenantRecord(t *testing.T) {
	cs := newTestCredentialStore(t)

	require.NoError(t, cs.StoreToken("tenant-owner", &AccessToken{
		Token: "owner-token", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour),
	}))

	// Overwrite the value at tenant-owner's key while recording a different
	// tenant, exactly as a key collision would.
	require.NoError(t, cs.store.StoreSecret(context.Background(), &interfaces.SecretRequest{
		Key:       tokenKey("tenant-owner"),
		Value:     `{"access_token":"attacker-token"}`,
		TenantID:  "tenant-attacker",
		CreatedBy: "test",
	}))

	_, err := cs.GetToken("tenant-owner")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantMismatch)
}
