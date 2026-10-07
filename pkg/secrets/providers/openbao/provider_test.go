// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package openbao — unit tests for OpenBaoProvider, config parsing, and production guard.
// These tests do NOT require a running OpenBao instance or Docker.
package openbao

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenBaoProvider_Name(t *testing.T) {
	p := &OpenBaoProvider{}
	assert.Equal(t, "openbao", p.Name())
}

func TestOpenBaoProvider_Description(t *testing.T) {
	p := &OpenBaoProvider{}
	assert.NotEmpty(t, p.Description())
}

func TestOpenBaoProvider_GetVersion(t *testing.T) {
	p := &OpenBaoProvider{}
	assert.NotEmpty(t, p.GetVersion())
}

func TestOpenBaoProvider_GetCapabilities(t *testing.T) {
	p := &OpenBaoProvider{}
	caps := p.GetCapabilities()
	assert.True(t, caps.SupportsVersioning, "KV v2 supports versioning")
	assert.True(t, caps.SupportsLeasing, "provider supports leasing")
	assert.True(t, caps.SupportsRenewal, "provider supports lease renewal")
	assert.True(t, caps.SupportsRevocation, "provider supports revocation")
	assert.True(t, caps.SupportsMetadata, "KV v2 supports metadata")
	assert.Greater(t, caps.MaxSecretSize, 0)
	assert.Greater(t, caps.MaxKeyLength, 0)
}

func TestOpenBaoProvider_ClusterCapable_True(t *testing.T) {
	p := &OpenBaoProvider{}
	assert.True(t, p.ClusterCapable(), "OpenBaoProvider must be cluster-capable (OpenBao cluster supports shared state across controller nodes)")
}

// TestProductionGuard_Reject verifies that a dev-mode token is refused when
// CFGMS_TELEMETRY_ENVIRONMENT=production.
func TestProductionGuard_Reject(t *testing.T) {
	t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", "production")

	err := enforceProductionGuard(&OpenBaoConfig{Token: "root"})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "dev-mode"),
		"error should mention dev-mode, got: %s", err.Error())
}

// TestProductionGuard_RejectDevModeEnvVar verifies rejection when BAO_DEV_MODE=true
// in production.
func TestProductionGuard_RejectDevModeEnvVar(t *testing.T) {
	t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", "production")
	t.Setenv("BAO_DEV_MODE", "true")

	err := enforceProductionGuard(&OpenBaoConfig{Token: "someServiceToken"})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "dev-mode"),
		"error should mention dev-mode, got: %s", err.Error())
}

// TestProductionGuard_RejectVaultDevModeEnvVar verifies rejection when
// VAULT_DEV_MODE=true in production.
func TestProductionGuard_RejectVaultDevModeEnvVar(t *testing.T) {
	t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", "production")
	t.Setenv("VAULT_DEV_MODE", "true")

	err := enforceProductionGuard(&OpenBaoConfig{Token: "someServiceToken"})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "dev-mode"),
		"error should mention dev-mode, got: %s", err.Error())
}

// TestProductionGuard_AcceptNonProduction verifies that a dev-mode token is
// allowed in non-production environments.
func TestProductionGuard_AcceptNonProduction(t *testing.T) {
	for _, env := range []string{"development", "staging", "test", ""} {
		t.Run("env="+env, func(t *testing.T) {
			if env == "" {
				t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", "")
			} else {
				t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", env)
			}

			err := enforceProductionGuard(&OpenBaoConfig{Token: "root"})
			assert.NoError(t, err, "dev-mode token should be accepted in non-production env %q", env)
		})
	}
}

// TestProductionGuard_AcceptProductionWithServiceToken verifies that a real
// service token passes the guard in production.
func TestProductionGuard_AcceptProductionWithServiceToken(t *testing.T) {
	t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", "production")

	err := enforceProductionGuard(&OpenBaoConfig{Token: "hvs.AAAA..."})
	assert.NoError(t, err, "a non-dev token should be accepted in production")
}

// TestProductionGuard_RejectHTTPAddress verifies that an http:// vault address is
// refused in production to prevent CA keys from being transmitted in cleartext.
func TestProductionGuard_RejectHTTPAddress(t *testing.T) {
	t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", "production")

	err := enforceProductionGuard(&OpenBaoConfig{
		Token:   "hvs.AAAA",
		Address: "http://vault.example.com:8200",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "http://",
		"error should reference the plaintext address, got: %s", err.Error())
	assert.Contains(t, err.Error(), "https://",
		"error should suggest using https://, got: %s", err.Error())
}

// TestProductionGuard_AcceptHTTPSAddress verifies that an https:// vault address
// passes the production guard.
func TestProductionGuard_AcceptHTTPSAddress(t *testing.T) {
	t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", "production")

	err := enforceProductionGuard(&OpenBaoConfig{
		Token:   "hvs.AAAA",
		Address: "https://vault.example.com:8200",
	})
	assert.NoError(t, err, "https:// vault address must be accepted in production")
}

// TestProductionGuard_HTTPAddressAllowedInDev verifies that an http:// vault address
// is accepted in non-production environments (dev/test).
func TestProductionGuard_HTTPAddressAllowedInDev(t *testing.T) {
	t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", "development")

	err := enforceProductionGuard(&OpenBaoConfig{
		Token:   "root",
		Address: "http://127.0.0.1:8200",
	})
	assert.NoError(t, err, "http:// vault address must be accepted in non-production")
}

func TestParseOpenBaoConfig_Defaults(t *testing.T) {
	cfg, err := parseOpenBaoConfig(map[string]interface{}{})
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8200", cfg.Address)
	assert.Equal(t, "secret", cfg.MountPath)
}

func TestParseOpenBaoConfig_Overrides(t *testing.T) {
	cfg, err := parseOpenBaoConfig(map[string]interface{}{
		"address":    "http://vault.example.com:8200",
		"token":      "mytoken",
		"mount_path": "kv",
		"namespace":  "admin",
		"tls_cert":   "/etc/certs/ca.pem",
	})
	require.NoError(t, err)
	assert.Equal(t, "http://vault.example.com:8200", cfg.Address)
	assert.Equal(t, "mytoken", cfg.Token)
	assert.Equal(t, "kv", cfg.MountPath)
	assert.Equal(t, "admin", cfg.Namespace)
	assert.Equal(t, "/etc/certs/ca.pem", cfg.TLSCert)
}

func TestParseOpenBaoConfig_EnvFallback(t *testing.T) {
	t.Setenv("OPENBAO_TOKEN", "env-token")
	t.Setenv("OPENBAO_ADDR", "http://env-bao:8200")

	cfg, err := parseOpenBaoConfig(map[string]interface{}{})
	require.NoError(t, err)
	assert.Equal(t, "env-token", cfg.Token)
	assert.Equal(t, "http://env-bao:8200", cfg.Address)
}

func TestSplitKey_Valid(t *testing.T) {
	tenantID, keyName, err := splitKey("tenant1/mykey")
	require.NoError(t, err)
	assert.Equal(t, "tenant1", tenantID)
	assert.Equal(t, "mykey", keyName)
}

func TestSplitKey_WithDeepPath(t *testing.T) {
	tenantID, keyName, err := splitKey("tenant1/sub/path/key")
	require.NoError(t, err)
	assert.Equal(t, "tenant1", tenantID)
	assert.Equal(t, "sub/path/key", keyName)
}

func TestSplitKey_Invalid(t *testing.T) {
	_, _, err := splitKey("notenantid")
	require.Error(t, err)
}

func TestSplitKey_EmptyTenant(t *testing.T) {
	_, _, err := splitKey("/key")
	require.Error(t, err)
}

func TestSplitKey_EmptyKey(t *testing.T) {
	_, _, err := splitKey("tenant/")
	require.Error(t, err)
}
