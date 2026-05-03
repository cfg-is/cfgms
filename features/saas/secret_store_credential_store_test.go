// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package saas

import (
	"os"
	"testing"
	"time"

	stewardprovider "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCredentialStore creates a SecretStoreCredentialStore backed by a real steward
// store in a temporary directory. Tests are skipped when /etc/machine-id is absent
// (required for OS-native key derivation on Linux).
func newTestCredentialStore(t *testing.T) CredentialStore {
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
func newBenchCredentialStore(b *testing.B) CredentialStore {
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

func TestSecretStoreCredentialStore_StoreAndGetClientSecret(t *testing.T) {
	cs := newTestCredentialStore(t)

	err := cs.StoreClientSecret("test-provider", "super-secret-value")
	require.NoError(t, err)

	got, err := cs.GetClientSecret("test-provider")
	require.NoError(t, err)
	assert.Equal(t, "super-secret-value", got)
}

func TestSecretStoreCredentialStore_StoreAndGetTokenSet(t *testing.T) {
	cs := newTestCredentialStore(t)

	tokens := &TokenSet{
		AccessToken:  "access-token-abc",
		RefreshToken: "refresh-token-xyz",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour).Truncate(time.Second),
		Scopes:       []string{"read", "write"},
	}

	err := cs.StoreTokenSet("test-provider", tokens)
	require.NoError(t, err)

	got, err := cs.GetTokenSet("test-provider")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, tokens.AccessToken, got.AccessToken)
	assert.Equal(t, tokens.RefreshToken, got.RefreshToken)
	assert.Equal(t, tokens.TokenType, got.TokenType)
	assert.Equal(t, tokens.Scopes, got.Scopes)
	assert.Equal(t, tokens.ExpiresAt.Unix(), got.ExpiresAt.Unix())
}

func TestSecretStoreCredentialStore_DeleteTokenSet(t *testing.T) {
	cs := newTestCredentialStore(t)

	tokens := &TokenSet{
		AccessToken: "access-token",
		TokenType:   "Bearer",
	}

	require.NoError(t, cs.StoreTokenSet("del-provider", tokens))

	got, err := cs.GetTokenSet("del-provider")
	require.NoError(t, err)
	require.NotNil(t, got)

	require.NoError(t, cs.DeleteTokenSet("del-provider"))

	_, err = cs.GetTokenSet("del-provider")
	require.Error(t, err)
}

func TestSecretStoreCredentialStore_GetClientSecret_NotFound(t *testing.T) {
	cs := newTestCredentialStore(t)

	_, err := cs.GetClientSecret("nonexistent-provider")
	require.Error(t, err)
}

func TestSecretStoreCredentialStore_GetTokenSet_NotFound(t *testing.T) {
	cs := newTestCredentialStore(t)

	_, err := cs.GetTokenSet("nonexistent-provider")
	require.Error(t, err)
}

func TestSecretStoreCredentialStore_IsAvailable(t *testing.T) {
	cs := newTestCredentialStore(t)

	assert.True(t, cs.IsAvailable())
}

func TestSecretStoreCredentialStore_IsolatedPerProvider(t *testing.T) {
	cs := newTestCredentialStore(t)

	require.NoError(t, cs.StoreClientSecret("provider-a", "secret-a"))
	require.NoError(t, cs.StoreClientSecret("provider-b", "secret-b"))

	gotA, err := cs.GetClientSecret("provider-a")
	require.NoError(t, err)
	assert.Equal(t, "secret-a", gotA)

	gotB, err := cs.GetClientSecret("provider-b")
	require.NoError(t, err)
	assert.Equal(t, "secret-b", gotB)
}
