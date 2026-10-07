// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicBetaExecutionSecurityValidation(t *testing.T) {
	valid := DefaultConfig()
	valid.SecurityProfile = SecurityProfilePublicBeta
	valid.Execution.RequireSignedAdhoc = true
	require.NoError(t, valid.ValidateExecutionSecurity())

	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "unsigned ad-hoc disabled",
			mutate: func(cfg *Config) {
				cfg.Execution.RequireSignedAdhoc = false
			},
			want: "require_signed_adhoc",
		},
		{
			name: "certificate management disabled",
			mutate: func(cfg *Config) {
				cfg.Certificate.EnableCertManagement = false
			},
			want: "certificate management",
		},
		{
			name: "transport certificate manager disabled",
			mutate: func(cfg *Config) {
				cfg.Transport.UseCertManager = false
			},
			want: "use_cert_manager",
		},
		{
			name: "connected transport missing",
			mutate: func(cfg *Config) {
				cfg.Transport = nil
			},
			want: "connected transport",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SecurityProfile = SecurityProfilePublicBeta
			cfg.Execution.RequireSignedAdhoc = true
			tc.mutate(cfg)
			require.ErrorContains(t, cfg.ValidateExecutionSecurity(), tc.want)
		})
	}
}

func TestPublicBetaExecutionSecurityFileAndEnvironmentPaths(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")
	require.NoError(t, os.WriteFile(configPath, []byte(`
security_profile: public-beta
execution:
  require_signed_adhoc: true
certificate:
  enable_cert_management: true
transport:
  use_cert_manager: true
`), 0600))

	t.Run("reviewed file loads", func(t *testing.T) {
		t.Setenv("CFGMS_SECURITY_PROFILE", "")
		t.Setenv("CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC", "")
		cfg, err := LoadWithPath(configPath)
		require.NoError(t, err)
		assert.Equal(t, SecurityProfilePublicBeta, cfg.SecurityProfile)
		assert.True(t, cfg.Execution.RequireSignedAdhoc)
	})

	t.Run("environment cannot disable signatures", func(t *testing.T) {
		t.Setenv("CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC", "false")
		_, err := LoadWithPath(configPath)
		require.ErrorContains(t, err, "require_signed_adhoc")
	})

	t.Run("malformed environment value fails closed", func(t *testing.T) {
		t.Setenv("CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC", "sometimes")
		_, err := LoadWithPath(configPath)
		require.ErrorContains(t, err, "invalid CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC")
	})

	t.Run("environment cannot downgrade profile", func(t *testing.T) {
		t.Setenv("CFGMS_SECURITY_PROFILE", SecurityProfileDevelopment)
		_, err := LoadWithPath(configPath)
		require.ErrorContains(t, err, "cannot downgrade")
	})

	t.Run("environment can only elevate with signed execution enabled", func(t *testing.T) {
		developmentPath := filepath.Join(dir, "development-controller.cfg")
		require.NoError(t, os.WriteFile(developmentPath, []byte(`
security_profile: development
certificate:
  enable_cert_management: true
transport:
  use_cert_manager: true
`), 0600))

		t.Setenv("CFGMS_SECURITY_PROFILE", SecurityProfilePublicBeta)
		t.Setenv("CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC", "true")
		cfg, err := LoadWithPath(developmentPath)
		require.NoError(t, err)
		assert.Equal(t, SecurityProfilePublicBeta, cfg.SecurityProfile)
		assert.True(t, cfg.Execution.RequireSignedAdhoc)
	})
}
