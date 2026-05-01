// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// hardcodedTestTokens lists the token strings that must never appear in a
// production-mode controller store.  This list is the source of truth for
// the no-seeding assertion; update it if token names change.
var hardcodedTestTokens = []string{
	"dockertest_standalone",
	"integration_reusable",
	"integration_expired",
	"integration_revoked",
	"integration_singleuse",
}

// TestServer_ProductionStartup_NoHardcodedTokens verifies that a controller
// started without CFGMS_SEED_TEST_TOKENS does not create any well-known test
// tokens in the registration store.
func TestServer_ProductionStartup_NoHardcodedTokens(t *testing.T) {
	// Ensure the guard env var is absent — t.Setenv restores on cleanup.
	t.Setenv("CFGMS_SEED_TEST_TOKENS", "")

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	store := srv.GetRegistrationTokenStore()
	require.NotNil(t, store, "registration token store must be initialized")

	ctx := context.Background()
	for _, tokenStr := range hardcodedTestTokens {
		tok, err := store.GetToken(ctx, tokenStr)
		assert.Error(t, err, "token %q must not exist in production startup", tokenStr)
		assert.Nil(t, tok, "token %q must not be returned in production startup", tokenStr)
	}
}

// TestServer_SeedTestTokens_WhenEnvVarEnabled verifies that setting
// CFGMS_SEED_TEST_TOKENS=1 causes the controller to create all expected test
// tokens in the registration store.
func TestServer_SeedTestTokens_WhenEnvVarEnabled(t *testing.T) {
	t.Setenv("CFGMS_SEED_TEST_TOKENS", "1")

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	store := srv.GetRegistrationTokenStore()
	require.NotNil(t, store, "registration token store must be initialized")

	ctx := context.Background()
	for _, tokenStr := range hardcodedTestTokens {
		tok, err := store.GetToken(ctx, tokenStr)
		assert.NoError(t, err, "token %q should exist when CFGMS_SEED_TEST_TOKENS=1", tokenStr)
		if assert.NotNil(t, tok, "token %q should be retrievable when CFGMS_SEED_TEST_TOKENS=1", tokenStr) {
			assert.Equal(t, tokenStr, tok.Token)
		}
	}
}

// TestServer_SeedTestTokens_DefaultOff confirms the env var must be exactly "1"
// to enable seeding — empty string, "true", "yes", and "0" must all leave the
// store empty.
func TestServer_SeedTestTokens_DefaultOff(t *testing.T) {
	for _, val := range []string{"", "0", "true", "yes", "false"} {
		t.Run("env="+val, func(t *testing.T) {
			t.Setenv("CFGMS_SEED_TEST_TOKENS", val)

			tempDir := t.TempDir()
			cfg := &config.Config{
				ListenAddr: "127.0.0.1:0",
				Certificate: &config.CertificateConfig{
					EnableCertManagement: false,
				},
				Storage: &config.StorageConfig{
					Provider:     "flatfile",
					FlatfileRoot: tempDir + "/flatfile",
					SQLitePath:   tempDir + "/cfgms.db",
				},
			}

			srv, err := New(cfg, logging.NewNoopLogger())
			require.NoError(t, err)
			require.NotNil(t, srv)
			t.Cleanup(func() { _ = srv.Stop() })

			store := srv.GetRegistrationTokenStore()
			require.NotNil(t, store)

			ctx := context.Background()
			for _, tokenStr := range hardcodedTestTokens {
				tok, err := store.GetToken(ctx, tokenStr)
				assert.Error(t, err, "token %q must not exist when CFGMS_SEED_TEST_TOKENS=%q", tokenStr, val)
				assert.Nil(t, tok)
			}
		})
	}
}

// TestServer_ProductionStartup_EnvVarNotSet confirms the guard is off when
// the env var has not been set to "1".
func TestServer_ProductionStartup_EnvVarNotSet(t *testing.T) {
	// Use t.Setenv so the restore-on-cleanup hook runs and the test is race-safe.
	t.Setenv("CFGMS_SEED_TEST_TOKENS", "")

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	store := srv.GetRegistrationTokenStore()
	require.NotNil(t, store)

	ctx := context.Background()
	for _, tokenStr := range hardcodedTestTokens {
		tok, err := store.GetToken(ctx, tokenStr)
		assert.Error(t, err, "token %q must not exist when env var is absent", tokenStr)
		assert.Nil(t, tok)
	}
}
