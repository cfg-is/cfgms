// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for the entra_group module binary's environment-driven wiring. The
// process entry point itself (main) is not called here — it blocks serving
// gRPC and calls log.Fatalf on misconfiguration — but every branch it depends
// on before that point is: provider selection, the required env vars, the
// provider-specific config map, and construction of a real auth provider over
// a real pkg/secrets store (no mocks; temp dirs via t.TempDir).
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
)

// clearModuleEnv puts every env var buildAuthProvider reads into a known-unset
// state, so a test only exercises the vars it sets itself regardless of what
// the surrounding environment (or a CI runner) happens to export. t.Setenv
// restores the prior values at test end.
func clearModuleEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CFGMS_M365_SECRETS_PROVIDER", "")
	t.Setenv("CFGMS_M365_SECRETS_DIR", "")
	t.Setenv("CFGMS_M365_SECRETS_KEY_FILE", "")
}

// writeSecretsKeyFile writes a 32-byte AES key, base64-encoded, at 0600 — the
// shape pkg/secrets/providers/sops requires of an external key file.
func writeSecretsKeyFile(t *testing.T, dir string) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	return keyPath
}

func TestSecretStoreConfigFromEnvDefaultsToStewardProvider(t *testing.T) {
	clearModuleEnv(t)
	secretsDir := t.TempDir()
	t.Setenv("CFGMS_M365_SECRETS_DIR", secretsDir)

	providerName, config, err := secretStoreConfigFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "steward", providerName, "an unset CFGMS_M365_SECRETS_PROVIDER must fall back to the steward provider")
	assert.Equal(t, map[string]interface{}{"secrets_dir": secretsDir}, config)
}

func TestSecretStoreConfigFromEnvExplicitStewardProvider(t *testing.T) {
	clearModuleEnv(t)
	secretsDir := t.TempDir()
	t.Setenv("CFGMS_M365_SECRETS_PROVIDER", "steward")
	t.Setenv("CFGMS_M365_SECRETS_DIR", secretsDir)

	providerName, config, err := secretStoreConfigFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "steward", providerName)
	assert.Equal(t, map[string]interface{}{"secrets_dir": secretsDir}, config)
}

func TestSecretStoreConfigFromEnvSopsProvider(t *testing.T) {
	clearModuleEnv(t)
	// The key file must live outside the secret data root: the sops provider
	// rejects a key stored alongside the data it protects.
	secretsDir := filepath.Join(t.TempDir(), "data")
	keyFile := writeSecretsKeyFile(t, t.TempDir())
	t.Setenv("CFGMS_M365_SECRETS_PROVIDER", "sops")
	t.Setenv("CFGMS_M365_SECRETS_DIR", secretsDir)
	t.Setenv("CFGMS_M365_SECRETS_KEY_FILE", keyFile)

	providerName, config, err := secretStoreConfigFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "sops", providerName)
	assert.Equal(t, keyFile, config["key_file"])
	assert.Equal(t, "flatfile", config["storage_provider"])
	// "root" — not "path" — is the key the flatfile storage provider reads; any
	// other key leaves the root empty and construction fails.
	assert.Equal(t, map[string]interface{}{"root": secretsDir}, config["storage_config"])
}

func TestSecretStoreConfigFromEnvRequiresSecretsDir(t *testing.T) {
	for _, providerName := range []string{"", "steward", "sops"} {
		name := providerName
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			clearModuleEnv(t)
			t.Setenv("CFGMS_M365_SECRETS_PROVIDER", providerName)
			// A key file is present so the sops case fails on the missing
			// directory specifically, not on the missing key.
			t.Setenv("CFGMS_M365_SECRETS_KEY_FILE", writeSecretsKeyFile(t, t.TempDir()))

			_, _, err := secretStoreConfigFromEnv()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "CFGMS_M365_SECRETS_DIR")
		})
	}
}

func TestSecretStoreConfigFromEnvRequiresKeyFileForSops(t *testing.T) {
	clearModuleEnv(t)
	t.Setenv("CFGMS_M365_SECRETS_PROVIDER", "sops")
	t.Setenv("CFGMS_M365_SECRETS_DIR", t.TempDir())

	_, _, err := secretStoreConfigFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_M365_SECRETS_KEY_FILE")
}

func TestSecretStoreConfigFromEnvRejectsUnsupportedProvider(t *testing.T) {
	clearModuleEnv(t)
	t.Setenv("CFGMS_M365_SECRETS_PROVIDER", "openbao")
	t.Setenv("CFGMS_M365_SECRETS_DIR", t.TempDir())

	_, _, err := secretStoreConfigFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "openbao")
	assert.Contains(t, err.Error(), "steward")
	assert.Contains(t, err.Error(), "sops")
}

func TestBuildAuthProviderStewardConstructsRealStore(t *testing.T) {
	clearModuleEnv(t)
	secretsDir := t.TempDir()
	t.Setenv("CFGMS_M365_SECRETS_DIR", secretsDir)

	provider, err := buildAuthProvider()
	require.NoError(t, err)
	require.NotNil(t, provider)

	// The steward store is real, not a stand-in: it lays out its encrypted
	// blob directory under the configured secrets dir on construction.
	blobs, statErr := os.Stat(filepath.Join(secretsDir, "blobs"))
	require.NoError(t, statErr)
	assert.True(t, blobs.IsDir())

	assertFailsClosedWithoutTenantConfig(t, provider)
}

func TestBuildAuthProviderSopsConstructsRealStore(t *testing.T) {
	clearModuleEnv(t)
	secretsDir := filepath.Join(t.TempDir(), "data")
	t.Setenv("CFGMS_M365_SECRETS_PROVIDER", "sops")
	t.Setenv("CFGMS_M365_SECRETS_DIR", secretsDir)
	t.Setenv("CFGMS_M365_SECRETS_KEY_FILE", writeSecretsKeyFile(t, t.TempDir()))

	provider, err := buildAuthProvider()
	require.NoError(t, err)
	require.NotNil(t, provider)

	assertFailsClosedWithoutTenantConfig(t, provider)
}

func TestBuildAuthProviderPropagatesStoreConstructionErrors(t *testing.T) {
	clearModuleEnv(t)
	// A regular file where the secrets directory should be: the steward
	// provider's MkdirAll fails, and that failure must surface rather than
	// yielding a provider backed by no store.
	notADir := filepath.Join(t.TempDir(), "secrets")
	require.NoError(t, os.WriteFile(notADir, []byte("not a directory"), 0o600))
	t.Setenv("CFGMS_M365_SECRETS_DIR", notADir)

	provider, err := buildAuthProvider()
	require.Error(t, err)
	assert.Nil(t, provider)
}

func TestBuildAuthProviderPropagatesEnvErrors(t *testing.T) {
	clearModuleEnv(t)

	provider, err := buildAuthProvider()
	require.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "CFGMS_M365_SECRETS_DIR")
}

// assertFailsClosedWithoutTenantConfig checks the no-default-OAuth2Config
// decision documented on buildAuthProvider: a tenant with nothing on file must
// be refused rather than served from a shared, env-supplied app registration.
// It also proves the provider is wired to the freshly created (empty) store,
// since that is where the lookup for the tenant's config lands.
func assertFailsClosedWithoutTenantConfig(t *testing.T, provider auth.Provider) {
	t.Helper()
	token, err := provider.GetAccessToken(context.Background(), "tenant-with-no-config")
	require.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "OAuth2 configuration")
}
