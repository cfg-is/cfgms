// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
)

// hardcodedTestTokens lists the token strings that must never appear in a
// production-mode controller store.  This list is the source of truth for
// the no-seeding assertion; update it if token names change.
var hardcodedTestTokens = []string{
	"dockertest_standalone",
	"integration_reusable",
	"integration_expired",
	"integration_revoked",
	"dockertest_fleet",
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

// TestInitializeHAManager_UsesDefaultConfig verifies initializeHAManager succeeds using
// ha.DefaultConfig() without requiring a controller config or LoadFromEnvironment call.
// This confirms no regression from removing LoadFromEnvironment from the call site.
func TestInitializeHAManager_UsesDefaultConfig(t *testing.T) {
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

	// Build a real StorageManager via the server constructor so we have a
	// production-quality storage backend (no nil storageManager in any build).
	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	// initializeHAManager is exercised during New(); verify the constructed
	// server exposes a healthy HA manager consistent with SingleServerMode defaults.
	haManager := srv.GetHAManager()
	require.NotNil(t, haManager, "HA manager must be initialized")

	// Single-server mode: always the leader, node ID auto-generated.
	assert.True(t, haManager.IsLeader(), "single-server node must always be leader")

	node := haManager.GetLocalNode()
	require.NotNil(t, node)
	assert.NotEmpty(t, node.ID, "auto-generated node ID must not be empty")
}

// TestBuiltinWorkflowSeedingIPTrust verifies that a controller started with no
// registration config (defaulting to ip-trust) does NOT seed a built-in workflow,
// because ip-trust approval is handled by the IPTrustApprovalHook directly in code
// rather than through the workflow engine (Issue #1695).
func TestBuiltinWorkflowSeedingIPTrust(t *testing.T) {
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
		// No Registration block: defaults to ip-trust mode, which does not seed a workflow.
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	ctx := context.Background()
	store := workflow.NewWorkflowStore(srv.GetConfigStore(), builtinWorkflowTenantID)
	_, err = store.GetLatestWorkflow(ctx, "steward-registration-approval")
	require.Error(t, err, "ip-trust mode must NOT seed a built-in workflow — approval is handled by IPTrustApprovalHook in code")
}

// TestBuiltinWorkflowSeedingAutoApprove verifies that a controller explicitly configured
// with registration.workflow=auto-approve seeds the auto-approve built-in workflow (Issue #1527).
func TestBuiltinWorkflowSeedingAutoApprove(t *testing.T) {
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
		Registration: &config.RegistrationConfig{
			Workflow: "auto-approve",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	ctx := context.Background()
	// Built-in workflows are seeded under the root tenant scope.
	store := workflow.NewWorkflowStore(srv.GetConfigStore(), builtinWorkflowTenantID)
	vw, err := store.GetLatestWorkflow(ctx, "steward-registration-approval")
	require.NoError(t, err, "auto-approve workflow must be seeded in root tenant scope on startup")
	require.NotNil(t, vw)

	policy, ok := vw.Variables["policy"].(string)
	require.True(t, ok, "auto-approve workflow must have a string 'policy' variable")
	assert.Equal(t, "accept", policy, "auto-approve workflow must set policy=accept for short-circuit approval")
}

// TestBuiltinWorkflowSeedingManualReview verifies that a controller started with
// registration.workflow: manual-review seeds the manual-review built-in workflow (Issue #1527).
func TestBuiltinWorkflowSeedingManualReview(t *testing.T) {
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
		Registration: &config.RegistrationConfig{
			Workflow: "manual-review",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	ctx := context.Background()
	// Built-in workflows are seeded under the root tenant scope.
	store := workflow.NewWorkflowStore(srv.GetConfigStore(), builtinWorkflowTenantID)
	vw, err := store.GetLatestWorkflow(ctx, "steward-registration-approval")
	require.NoError(t, err, "manual-review workflow must be seeded in root tenant scope on startup")
	require.NotNil(t, vw)

	decision, ok := vw.Variables["registration_decision"].(string)
	require.True(t, ok, "manual-review workflow must have a string 'registration_decision' variable")
	assert.Equal(t, "quarantine", decision, "manual-review workflow must set registration_decision=quarantine")
}
