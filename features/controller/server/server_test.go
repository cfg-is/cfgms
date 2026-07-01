// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// recordingLogger implements logging.Logger and captures every log call so
// tests can assert on what was (or was not) logged.
var _ logging.Logger = (*recordingLogger)(nil)

type recordingLogger struct {
	mu      sync.Mutex
	entries []recordedLogEntry
}

type recordedLogEntry struct {
	msg string
	kvs []interface{}
}

func (r *recordingLogger) record(msg string, keysAndValues ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, recordedLogEntry{msg: msg, kvs: keysAndValues})
}

// containsAny returns true if any captured message or string value contains s.
func (r *recordingLogger) containsAny(s string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if strings.Contains(e.msg, s) {
			return true
		}
		for _, v := range e.kvs {
			if str, ok := v.(string); ok && strings.Contains(str, s) {
				return true
			}
		}
	}
	return false
}

func (r *recordingLogger) Debug(msg string, kvs ...interface{}) { r.record(msg, kvs...) }
func (r *recordingLogger) Info(msg string, kvs ...interface{})  { r.record(msg, kvs...) }
func (r *recordingLogger) Warn(msg string, kvs ...interface{})  { r.record(msg, kvs...) }
func (r *recordingLogger) Error(msg string, kvs ...interface{}) { r.record(msg, kvs...) }
func (r *recordingLogger) Fatal(msg string, kvs ...interface{}) { r.record(msg, kvs...) }
func (r *recordingLogger) DebugCtx(_ context.Context, msg string, kvs ...interface{}) {
	r.record(msg, kvs...)
}
func (r *recordingLogger) InfoCtx(_ context.Context, msg string, kvs ...interface{}) {
	r.record(msg, kvs...)
}
func (r *recordingLogger) WarnCtx(_ context.Context, msg string, kvs ...interface{}) {
	r.record(msg, kvs...)
}
func (r *recordingLogger) ErrorCtx(_ context.Context, msg string, kvs ...interface{}) {
	r.record(msg, kvs...)
}
func (r *recordingLogger) FatalCtx(_ context.Context, msg string, kvs ...interface{}) {
	r.record(msg, kvs...)
}

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

// allKnownTestTokenValues is the exhaustive set of token values seeded when
// CFGMS_SEED_TEST_TOKENS=1.  Used by the clear-text-logging test to verify
// that no raw token value appears in any log output (CodeQL #775).
var allKnownTestTokenValues = []string{
	"dockertest_standalone",
	"integration_reusable",
	"integration_expired",
	"integration_revoked",
	"dockertest_fleet",
	"dockertest_fleet_child_a",
	"dockertest_fleet_child_b",
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

// TestInitializeHAManager_UsesConfigMode verifies that initializeHAManager transfers
// the YAML-configured deployment mode into the ha.Config before calling ha.NewManager.
// This is the root-cause fix for the split-brain where every node assumed SingleServerMode
// because DefaultConfig() hardcodes it regardless of the YAML ha.mode field.
//
// The env pre-load ordering is also verified: CFGMS_NODE_ID (required by Validate() for
// non-single modes) must be set in the environment before NewManager's Validate() runs,
// or every cluster-mode controller crashes at startup.
func TestInitializeHAManager_UsesConfigMode(t *testing.T) {
	t.Setenv("CFGMS_NODE_ID", "test-cluster-node-uses-config-mode")

	tempDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(
		tempDir+"/flatfile",
		tempDir+"/cfgms.db",
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	cfg := &config.Config{
		HA: &config.HAConfig{
			Mode: "cluster",
		},
	}

	haManager, err := initializeHAManager(cfg, logging.NewNoopLogger(), sm)
	require.NoError(t, err, "initializeHAManager must succeed with ha.mode=cluster and CFGMS_NODE_ID set")
	require.NotNil(t, haManager)
	t.Cleanup(func() { _ = haManager.Stop(context.Background()) })

	assert.Equal(t, ha.ClusterMode, haManager.GetDeploymentMode(),
		"HA manager must report ClusterMode when cfg.HA.Mode is \"cluster\"")
}

// TestInitializeHAManager_InvalidMode verifies that an unrecognised ha.mode string
// surfaces an error instead of silently falling back to single-server mode.
func TestInitializeHAManager_InvalidMode(t *testing.T) {
	tempDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(
		tempDir+"/flatfile",
		tempDir+"/cfgms.db",
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	cfg := &config.Config{
		HA: &config.HAConfig{
			Mode: "clustr", // deliberate typo
		},
	}

	_, err = initializeHAManager(cfg, logging.NewNoopLogger(), sm)
	require.Error(t, err, "initializeHAManager must return error for invalid ha.mode")
	assert.Contains(t, err.Error(), "invalid HA mode",
		"error must identify the bad mode string")
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

// TestServer_New_Fails_BindAll_NoExternalAddress verifies that server.New() returns
// a non-nil error when transport.listen_addr binds 0.0.0.0 and neither
// transport.external_address nor CFGMS_EXTERNAL_HOSTNAME is configured.
func TestServer_New_Fails_BindAll_NoExternalAddress(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
		Transport: &config.TransportConfig{
			ListenAddr: "0.0.0.0:4433",
		},
	}

	_, err := New(cfg, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transport.listen_addr binds 0.0.0.0 but no external address is configured")
	assert.Contains(t, err.Error(), "transport.external_address")
	assert.Contains(t, err.Error(), "CFGMS_EXTERNAL_HOSTNAME")
}

// TestServer_New_Succeeds_BindAll_WithExternalAddressConfig verifies that server.New()
// succeeds when transport.listen_addr binds 0.0.0.0 and transport.external_address is set.
func TestServer_New_Succeeds_BindAll_WithExternalAddressConfig(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")

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
		Transport: &config.TransportConfig{
			ListenAddr:      "0.0.0.0:4433",
			ExternalAddress: "controller.example.com",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })
}

// TestServer_New_Succeeds_BindAll_WithEnvVar verifies that server.New() succeeds when
// transport.listen_addr binds 0.0.0.0 and CFGMS_EXTERNAL_HOSTNAME is set.
func TestServer_New_Succeeds_BindAll_WithEnvVar(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "env-controller.example.com")

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
		Transport: &config.TransportConfig{
			ListenAddr: "0.0.0.0:4433",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })
}

// TestSeedTestTokens_LogsNoRawTokenValues asserts that when CFGMS_SEED_TEST_TOKENS=1,
// the controller startup path never writes a raw registration-token value to any log
// call.  This is the required behavioural test for CodeQL alert #775
// (go/clear-text-logging, high): a registration token is a credential and must never
// appear in clear text in log output, even on a dev/test-only path.
func TestSeedTestTokens_LogsNoRawTokenValues(t *testing.T) {
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

	rec := &recordingLogger{}
	srv, err := New(cfg, rec)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	for _, tokenVal := range allKnownTestTokenValues {
		assert.False(t, rec.containsAny(tokenVal),
			"raw token %q must not appear in any log output (CodeQL alert #775)", tokenVal)
	}
}

// TestSeedTestTokens_LogsUsefulNonSensitiveInfo asserts that even after suppressing
// raw token values, the seeding path still emits an observable, non-empty log line
// that includes the tenant ID so operations remain diagnosable.
func TestSeedTestTokens_LogsUsefulNonSensitiveInfo(t *testing.T) {
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

	rec := &recordingLogger{}
	srv, err := New(cfg, rec)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	assert.True(t, rec.containsAny("Seeded test registration token"),
		"seeding path must emit at least one observable log line")
	assert.True(t, rec.containsAny("test-tenant"),
		"seeding log must include the tenant ID for observability")
}
