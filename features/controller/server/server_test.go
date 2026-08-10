// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// newTestCertManager creates a real cert.Manager for tests that exercise cluster mode,
// which requires a cert manager to generate the mTLS peer transport certificate.
func newTestCertManager(t *testing.T) *cert.Manager {
	t.Helper()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cert.CAConfig{
			Organization: "CFGMS Server Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)
	return mgr
}

// testNonClusterProvider implements interfaces.StorageProvider with ClusterCapable() == false.
// All store factory methods return business.ErrNotSupported. Used to verify that
// assertClusterBackendsReady rejects non-cluster-capable backends.
type testNonClusterProvider struct{}

var _ interfaces.StorageProvider = (*testNonClusterProvider)(nil)

func (p *testNonClusterProvider) Name() string { return "test-noncluster" }
func (p *testNonClusterProvider) Description() string {
	return "test-only non-cluster-capable provider"
}
func (p *testNonClusterProvider) GetVersion() string       { return "0.0.1-test" }
func (p *testNonClusterProvider) Available() (bool, error) { return true, nil }
func (p *testNonClusterProvider) ClusterCapable() bool     { return false }
func (p *testNonClusterProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{}
}
func (p *testNonClusterProvider) CreateClientTenantStore(_ map[string]interface{}) (business.ClientTenantStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreateConfigStore(_ map[string]interface{}) (cfgconfig.ConfigStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreateAuditStore(_ map[string]interface{}) (business.AuditStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreateRBACStore(_ map[string]interface{}) (business.RBACStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreateTenantStore(_ map[string]interface{}) (business.TenantStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreateRegistrationTokenStore(_ map[string]interface{}) (business.RegistrationTokenStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreateSessionStore(_ map[string]interface{}) (business.SessionStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreateStewardStore(_ map[string]interface{}) (business.StewardStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreateCommandStore(_ map[string]interface{}) (business.CommandStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreateTriggerStore(_ map[string]interface{}) (business.TriggerStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreatePushStore(_ map[string]interface{}) (business.PushStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreatePendingRegistrationStore(_ map[string]interface{}) (business.PendingRegistrationStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNonClusterProvider) CreateIPTrustStore(_ map[string]interface{}) (business.IPTrustStore, error) {
	return nil, business.ErrNotSupported
}

// testClusterProvider implements interfaces.StorageProvider with ClusterCapable() == true.
// All store factory methods return business.ErrNotSupported. Used to isolate the S3 gate
// in assertClusterBackendsReady without requiring a real Postgres connection.
type testClusterProvider struct{}

var _ interfaces.StorageProvider = (*testClusterProvider)(nil)

func (p *testClusterProvider) Name() string             { return "test-cluster" }
func (p *testClusterProvider) Description() string      { return "test-only cluster-capable provider" }
func (p *testClusterProvider) GetVersion() string       { return "0.0.1-test" }
func (p *testClusterProvider) Available() (bool, error) { return true, nil }
func (p *testClusterProvider) ClusterCapable() bool     { return true }
func (p *testClusterProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{}
}
func (p *testClusterProvider) CreateClientTenantStore(_ map[string]interface{}) (business.ClientTenantStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreateConfigStore(_ map[string]interface{}) (cfgconfig.ConfigStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreateAuditStore(_ map[string]interface{}) (business.AuditStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreateRBACStore(_ map[string]interface{}) (business.RBACStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreateTenantStore(_ map[string]interface{}) (business.TenantStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreateRegistrationTokenStore(_ map[string]interface{}) (business.RegistrationTokenStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreateSessionStore(_ map[string]interface{}) (business.SessionStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreateStewardStore(_ map[string]interface{}) (business.StewardStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreateCommandStore(_ map[string]interface{}) (business.CommandStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreateTriggerStore(_ map[string]interface{}) (business.TriggerStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreatePushStore(_ map[string]interface{}) (business.PushStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreatePendingRegistrationStore(_ map[string]interface{}) (business.PendingRegistrationStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testClusterProvider) CreateIPTrustStore(_ map[string]interface{}) (business.IPTrustStore, error) {
	return nil, business.ErrNotSupported
}

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

	haManager, err := initializeHAManager(cfg, logging.NewNoopLogger(), sm, newTestCertManager(t))
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

	_, err = initializeHAManager(cfg, logging.NewNoopLogger(), sm, nil)
	require.Error(t, err, "initializeHAManager must return error for invalid ha.mode")
	assert.Contains(t, err.Error(), "invalid HA mode",
		"error must identify the bad mode string")
}

// TestNew_ClusterModeRequiresClusterCapableProviders verifies that assertClusterBackendsReady
// rejects a non-cluster-capable storage provider and a missing S3 bucket, and that the gate
// is not triggered in non-cluster mode, leaving New() free to succeed with a flatfile backend.
func TestNew_ClusterModeRequiresClusterCapableProviders(t *testing.T) {
	t.Run("cluster mode with non-cluster-capable provider returns error", func(t *testing.T) {
		t.Setenv("CFGMS_S3_INSTALLER_BUCKET", "")

		// Register a non-cluster-capable test provider and create a StorageManager from it.
		// CreateAllStoresFromConfig accepts ErrNotSupported from individual store factories,
		// so the resulting manager is valid but has nil stores — sufficient for the gate check.
		interfaces.RegisterStorageProvider(&testNonClusterProvider{})
		t.Cleanup(func() { interfaces.UnregisterStorageProvider("test-noncluster") })
		//nolint:staticcheck // CreateAllStoresFromConfig is retained for single-provider and test use
		sm, err := interfaces.CreateAllStoresFromConfig("test-noncluster", nil)
		require.NoError(t, err, "test-noncluster storage manager must initialise without error")

		backendErr := assertClusterBackendsReady(nil, sm)
		require.Error(t, backendErr, "cluster mode with non-cluster-capable provider must fail")
		assert.Contains(t, backendErr.Error(), "cluster-capable",
			"error must explain that a cluster-capable backend is required")
		assert.Contains(t, backendErr.Error(), "test-noncluster",
			"error must name the offending provider")
	})

	t.Run("cluster mode with cluster-capable provider but no S3 bucket returns error", func(t *testing.T) {
		t.Setenv("CFGMS_S3_INSTALLER_BUCKET", "")

		// database provider is cluster-capable; use it directly via NewStorageManagerFromStores
		// with a nil provider override constructed manually to avoid a real Postgres connection.
		// We need a StorageManager whose GetProvider() is cluster-capable, so register a
		// cluster-capable test provider instead.
		clusterProvider := &testClusterProvider{}
		interfaces.RegisterStorageProvider(clusterProvider)
		t.Cleanup(func() { interfaces.UnregisterStorageProvider("test-cluster") })
		//nolint:staticcheck // CreateAllStoresFromConfig is retained for single-provider and test use
		sm, err := interfaces.CreateAllStoresFromConfig("test-cluster", nil)
		require.NoError(t, err, "test-cluster storage manager must initialise without error")

		backendErr := assertClusterBackendsReady(nil, sm)
		require.Error(t, backendErr, "cluster mode with no S3 bucket must fail")
		assert.Contains(t, backendErr.Error(), "CFGMS_S3_INSTALLER_BUCKET",
			"error must name the missing environment variable")
	})

	t.Run("non-cluster mode does not invoke cluster gate", func(t *testing.T) {
		// CFGMS_S3_INSTALLER_BUCKET is deliberately unset: if the cluster gate fired,
		// New() would fail on the S3 prerequisite. Passing here proves the gate is
		// not called for non-cluster deployments.
		t.Setenv("CFGMS_S3_INSTALLER_BUCKET", "")

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
		require.NoError(t, err, "non-cluster mode with flatfile must not trigger the cluster-capable gate")
		require.NotNil(t, srv)
		t.Cleanup(func() { _ = srv.Stop() })
	})
}

// TestLoadExistingCertificateManager_ClusterMode_UsesVaultNotLocalDisk is the
// REQUIRED regression test for Issue #3130: a cluster-mode CA's private key is
// never written to local disk (cert.NewManagerFromSecretStore keeps it
// in-process only, sourced from the shared OpenBao vault), so the *regular*
// (non---init) controller startup path must re-fetch it from the vault on every
// process start rather than falling back to cert.NewManager's LoadExistingCA
// path, which hard-requires a local ca.key and would make every cluster node
// fail to restart after its one-time --init. This is exercised without a live
// OpenBao instance: an unreachable vault_address still proves which branch was
// taken, because the two paths fail with distinguishable errors.
func TestLoadExistingCertificateManager_ClusterMode_UsesVaultNotLocalDisk(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")

	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			RenewalThresholdDays: 7,
			Server: &config.ServerCertificateConfig{
				CommonName:   "test-controller",
				Organization: "Test Org",
			},
			ClusterCA: &config.ClusterCAConfig{
				// Deliberately unreachable: proves the vault branch was taken
				// without requiring a live OpenBao instance in this test.
				VaultAddress: "https://127.0.0.1:1/",
				VaultKeyPath: "test-tenant/cluster-ca",
			},
		},
		HA: &config.HAConfig{Mode: "cluster"},
	}

	_, err := loadExistingCertificateManager(cfg, logging.NewNoopLogger())
	require.Error(t, err, "unreachable vault must surface as an error, not a silent local-disk fallback")
	assert.Contains(t, strings.ToLower(err.Error()), "vault",
		"error must come from the vault-loading branch (Issue #3130)")
	assert.NotContains(t, strings.ToLower(err.Error()), "ca.key",
		"must not fall through to the local-disk LoadExistingCA path, which cluster nodes never have a ca.key for")
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

func TestServerNewPublicBetaRejectsUnsignedAdhocConfiguration(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SecurityProfile = config.SecurityProfilePublicBeta
	cfg.Execution.RequireSignedAdhoc = false

	server, err := New(cfg, logging.NewNoopLogger())

	require.Nil(t, server)
	require.ErrorContains(t, err, "require_signed_adhoc")
}

func TestServerNewPublicBetaRejectsMissingSigningRoots(t *testing.T) {
	root := t.TempDir()
	keyPath := filepath.Join(root, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, make([]byte, 32), 0600))
	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(root, "secrets"))

	cfg := config.DefaultConfig()
	cfg.SecurityProfile = config.SecurityProfilePublicBeta
	cfg.Execution.RequireSignedAdhoc = true
	cfg.DataDir = filepath.Join(root, "data")
	cfg.Storage.Provider = "flatfile"
	cfg.Storage.FlatfileRoot = filepath.Join(root, "flatfile")
	cfg.Storage.SQLitePath = filepath.Join(root, "cfgms.db")
	cfg.Certificate.CAPath = filepath.Join(root, "missing-ca")
	cfg.Transport.ExternalAddress = "controller.test"

	server, err := New(cfg, logging.NewNoopLogger())

	require.Nil(t, server)
	require.ErrorIs(t, err, ErrNotInitialized)
}

func TestServerNewPublicBetaRejectsInvalidSigningRoots(t *testing.T) {
	root := t.TempDir()
	keyPath := filepath.Join(root, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, make([]byte, 32), 0600))
	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(root, "secrets"))

	certRoot := filepath.Join(root, "certs")
	caRoot := filepath.Join(certRoot, "ca")
	require.NoError(t, os.MkdirAll(caRoot, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(caRoot, "ca.crt"), []byte("invalid CA certificate"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(caRoot, "ca.key"), []byte("invalid CA key"), 0600))
	// Marker lives at caRoot (== cfg.Certificate.CAPath) so IsInitialized(caRoot) is true.
	require.NoError(t, initialization.CreateLegacyMarker(caRoot))

	cfg := config.DefaultConfig()
	cfg.SecurityProfile = config.SecurityProfilePublicBeta
	cfg.Execution.RequireSignedAdhoc = true
	cfg.DataDir = filepath.Join(root, "data")
	cfg.Storage = createTestStorageConfig(root, "public-beta-invalid-roots")
	cfg.Certificate.CAPath = caRoot
	cfg.Transport.ExternalAddress = "controller.test"

	server, err := New(cfg, logging.NewNoopLogger())

	require.Nil(t, server)
	require.ErrorContains(t, err, "failed to load certificate manager")
	require.ErrorContains(t, err, "failed to decode CA certificate PEM")
}

func TestServerNewPublicBetaRejectsExpiredSigningRoots(t *testing.T) {
	root := t.TempDir()
	keyPath := filepath.Join(root, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, make([]byte, 32), 0600))
	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(root, "secrets"))

	certRoot := filepath.Join(root, "certs")
	caRoot := filepath.Join(certRoot, "ca")
	// cert.NewManager stores the CA at certRoot/ca/ (StoragePath/ca/).
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certRoot,
		CAConfig: &cert.CAConfig{
			Organization: "Expired Public Beta Root",
			Country:      "US",
			ValidityDays: -1,
		},
	})
	require.NoError(t, err)
	// Marker lives at caRoot (== cfg.Certificate.CAPath) so IsInitialized(caRoot) is true.
	require.NoError(t, initialization.CreateLegacyMarker(caRoot))

	cfg := config.DefaultConfig()
	cfg.SecurityProfile = config.SecurityProfilePublicBeta
	cfg.Execution.RequireSignedAdhoc = true
	cfg.DataDir = filepath.Join(root, "data")
	cfg.Storage = createTestStorageConfig(root, "public-beta-expired-roots")
	cfg.Certificate.CAPath = caRoot
	cfg.Transport.ExternalAddress = "controller.test"

	server, err := New(cfg, logging.NewNoopLogger())

	require.Nil(t, server)
	require.ErrorContains(t, err, "public-beta signing roots are invalid")
	require.ErrorContains(t, err, "not currently valid")
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

// TestUpgradeStore_SurvivesControllerRestart_WhenSQLiteConfigured verifies that
// upgrade records written through initializeUpgradeStore survive a simulated controller
// restart (close + reopen against the same SQLitePath). This is the integration-level
// regression test for Issue #2464.
func TestUpgradeStore_SurvivesControllerRestart_WhenSQLiteConfigured(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "upgrade_restart.db")
	cfg := &config.Config{
		Storage: &config.StorageConfig{
			SQLitePath: dbPath,
		},
	}
	ctx := context.Background()
	logger := logging.NewNoopLogger()

	// First "controller instance": open the store, create a record, then close.
	store1 := initializeUpgradeStore(ctx, cfg, logger)
	require.NotNil(t, store1, "initializeUpgradeStore must return a non-nil store")

	rec := &business.UpgradeRecord{
		ID:        "upg-restart-001",
		StewardID: "steward-abc",
		TenantID:  "tenant-restart",
		Version:   "v2.0.0",
		Platform:  "linux",
		Arch:      "amd64",
		SHA256:    "deadbeefdeadbeefdeadbeefdeadbeef",
		Status:    business.UpgradeStatusDispatched,
		InitiatedBy: business.InitiatedByIdentity{
			Subject:    "operator@example.com",
			TenantID:   "tenant-restart",
			AuthMethod: "mtls",
		},
		Publisher:       "cfgms",
		SignatureDigest: "sha256:cafebabe",
		BundleSignature: []byte{0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04},
		CreatedAt:       time.Now().UTC(),
		DispatchedAt:    time.Now().UTC(),
	}
	require.NoError(t, store1.CreateUpgrade(ctx, rec))
	require.NoError(t, store1.Close(), "store1 close (simulated shutdown) must not error")

	// Second "controller instance": reopen the same path and verify durability.
	store2 := initializeUpgradeStore(ctx, cfg, logger)
	require.NotNil(t, store2)
	defer func() { _ = store2.Close() }()

	got, err := store2.GetUpgrade(ctx, "upg-restart-001")
	require.NoError(t, err, "upgrade record must be readable after simulated controller restart")
	assert.Equal(t, "upg-restart-001", got.ID)
	assert.Equal(t, business.UpgradeStatusDispatched, got.Status)
	assert.Equal(t, "steward-abc", got.StewardID)
	assert.Equal(t, rec.BundleSignature, got.BundleSignature)
}

// TestInitializeUpgradeStore_NoSQLitePath_FallsBackToInMemory covers the
// degrade-gracefully branch at server.go:2270: when the SQLite path is not
// configured (nil Storage or empty SQLitePath), initializeUpgradeStore must
// return a functional non-nil in-memory store and log a durability warning
// rather than failing controller startup.
func TestInitializeUpgradeStore_NoSQLitePath_FallsBackToInMemory(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{name: "nil Storage", cfg: &config.Config{}},
		{name: "empty SQLitePath", cfg: &config.Config{Storage: &config.StorageConfig{SQLitePath: ""}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingLogger{}

			store := initializeUpgradeStore(ctx, tc.cfg, rec)
			require.NotNil(t, store, "must return a non-nil store even without SQLite configured")
			requireInMemoryUpgradeStore(t, store,
				"unconfigured SQLite path must degrade to the in-memory store")
			t.Cleanup(func() { _ = store.Close() })

			assert.True(t, rec.containsAny("records will not survive restart"),
				"silent degradation to non-durable storage must emit an observable warning")

			// The fallback store must actually be usable, not just non-nil.
			assertUpgradeStoreFunctional(t, ctx, store)
		})
	}
}

// TestInitializeUpgradeStore_OpenFailure_FallsBackToInMemory covers the branch
// at server.go:2282: when the SQLite database cannot be opened (here the DSN
// points at a directory rather than a writable file), initializeUpgradeStore
// must fall back to a functional in-memory store and warn instead of crashing.
func TestInitializeUpgradeStore_OpenFailure_FallsBackToInMemory(t *testing.T) {
	ctx := context.Background()
	rec := &recordingLogger{}

	// A directory can never be opened as a SQLite database file, so the open
	// (busy_timeout PRAGMA) fails deterministically across platforms.
	cfg := &config.Config{
		Storage: &config.StorageConfig{SQLitePath: t.TempDir()},
	}

	store := initializeUpgradeStore(ctx, cfg, rec)
	require.NotNil(t, store)
	requireInMemoryUpgradeStore(t, store,
		"an unopenable SQLite DSN must degrade to the in-memory store")
	t.Cleanup(func() { _ = store.Close() })

	assert.True(t, rec.containsAny("failed to open SQLite"),
		"open failure must emit an observable warning")
	assertUpgradeStoreFunctional(t, ctx, store)
}

// TestInitializeUpgradeStore_InitializeFailure_FallsBackToInMemory covers the
// branch at server.go:2286: the DSN opens but schema Initialize fails because
// the file already holds non-SQLite content. initializeUpgradeStore must close
// the half-open handle, fall back to a functional in-memory store, and warn.
func TestInitializeUpgradeStore_InitializeFailure_FallsBackToInMemory(t *testing.T) {
	ctx := context.Background()
	rec := &recordingLogger{}

	dbPath := filepath.Join(t.TempDir(), "corrupt.db")
	// Pre-place garbage so sql.Open succeeds (header is only read on first DDL)
	// but the CREATE TABLE inside Initialize fails with "file is not a database".
	require.NoError(t, os.WriteFile(dbPath, []byte("not a sqlite database, just raw bytes"), 0o600))

	cfg := &config.Config{
		Storage: &config.StorageConfig{SQLitePath: dbPath},
	}

	store := initializeUpgradeStore(ctx, cfg, rec)
	require.NotNil(t, store)
	requireInMemoryUpgradeStore(t, store,
		"a schema-init failure must degrade to the in-memory store")
	t.Cleanup(func() { _ = store.Close() })

	assert.True(t, rec.containsAny("failed to initialize schema"),
		"initialize failure must emit an observable warning")
	assertUpgradeStoreFunctional(t, ctx, store)
}

// ---------------------------------------------------------------------------
// initializeTagStore degradation tests (Issue #2542 / #2544)
//
// initializeTagStore returns nil (not a fallback) on any failure — the
// controller must start even when tag persistence is unavailable.
// ---------------------------------------------------------------------------

// TestInitializeTagStore_NoSQLitePath_ReturnsNil verifies that initializeTagStore
// returns nil and logs a warning when the Storage config is absent or SQLitePath
// is empty, instead of blocking controller startup.
func TestInitializeTagStore_NoSQLitePath_ReturnsNil(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{name: "nil Storage", cfg: &config.Config{}},
		{name: "empty SQLitePath", cfg: &config.Config{Storage: &config.StorageConfig{SQLitePath: ""}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingLogger{}
			store := initializeTagStore(ctx, tc.cfg, rec)
			assert.Nil(t, store, "unconfigured SQLitePath must degrade to nil, not panic")
			assert.True(t, rec.containsAny("not configured"),
				"silent degradation must emit an observable warning")
		})
	}
}

// TestInitializeTagStore_OpenFailure_ReturnsNil verifies that initializeTagStore
// returns nil and warns when the SQLite DSN cannot be opened (e.g. DSN points
// at a directory rather than a writable file).
func TestInitializeTagStore_OpenFailure_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	rec := &recordingLogger{}

	// A directory path causes the busy_timeout PRAGMA to fail (not a valid DB file).
	cfg := &config.Config{
		Storage: &config.StorageConfig{SQLitePath: t.TempDir()},
	}

	store := initializeTagStore(ctx, cfg, rec)
	assert.Nil(t, store, "an unopenable SQLite DSN must degrade to nil")
	assert.True(t, rec.containsAny("failed to open"),
		"open failure must emit an observable warning")
}

// TestInitializeTagStore_InitializeFailure_ReturnsNil verifies that
// initializeTagStore returns nil and warns when the DSN opens but schema
// initialization fails (corrupt/non-SQLite file content).
func TestInitializeTagStore_InitializeFailure_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	rec := &recordingLogger{}

	dbPath := filepath.Join(t.TempDir(), "corrupt_tags.db")
	require.NoError(t, os.WriteFile(dbPath, []byte("not a sqlite database, just raw bytes"), 0o600))

	cfg := &config.Config{
		Storage: &config.StorageConfig{SQLitePath: dbPath},
	}

	store := initializeTagStore(ctx, cfg, rec)
	assert.Nil(t, store, "a schema-init failure must degrade to nil")
	assert.True(t, rec.containsAny("failed to initialize"),
		"initialize failure must emit an observable warning")
}

// TestInitializeTagStore_HappyPath_ReturnsUsableStore verifies that a valid
// SQLitePath produces a non-nil store that accepts tag round-trips.
func TestInitializeTagStore_HappyPath_ReturnsUsableStore(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "tags.db")
	cfg := &config.Config{
		Storage: &config.StorageConfig{SQLitePath: dbPath},
	}

	store := initializeTagStore(ctx, cfg, logging.NewNoopLogger())
	require.NotNil(t, store, "valid SQLitePath must return a non-nil store")
	t.Cleanup(func() { _ = store.Close() })

	// Round-trip: store must accept writes and serve reads.
	require.NoError(t, store.Set(ctx, "steward-1", []string{"env-prod"}))
	tags, err := store.Get(ctx, "steward-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"env-prod"}, tags)
}

// assertUpgradeStoreFunctional performs a round-trip write/read to prove the
// fallback store is genuinely usable, not merely non-nil.
func assertUpgradeStoreFunctional(t *testing.T, ctx context.Context, store business.UpgradeStore) {
	t.Helper()
	rec := &business.UpgradeRecord{
		ID:        "upg-fallback-001",
		StewardID: "steward-fallback",
		TenantID:  "tenant-fallback",
		Version:   "v1.0.0",
		Platform:  "linux",
		Arch:      "amd64",
		SHA256:    "feedfacefeedfacefeedfacefeedface",
		Status:    business.UpgradeStatusDispatched,
		InitiatedBy: business.InitiatedByIdentity{
			Subject:    "operator@example.com",
			TenantID:   "tenant-fallback",
			AuthMethod: "mtls",
		},
		Publisher:       "cfgms",
		SignatureDigest: "sha256:feedface",
		BundleSignature: []byte{0xfe, 0xed, 0xfa, 0xce},
		CreatedAt:       time.Now().UTC(),
		DispatchedAt:    time.Now().UTC(),
	}
	require.NoError(t, store.CreateUpgrade(ctx, rec), "fallback store must accept writes")

	got, err := store.GetUpgrade(ctx, "upg-fallback-001")
	require.NoError(t, err, "fallback store must serve reads")
	assert.Equal(t, "upg-fallback-001", got.ID)
	assert.Equal(t, business.UpgradeStatusDispatched, got.Status)
}

// TestInitializeSessionStore_SQLitePath verifies that a configured SQLite path yields a
// durable, disk-backed session store rather than the in-memory fallback. The assertion is
// behavioral (durability across a fresh store on the same path) plus a negative check on the
// in-memory type, so the test does not need to import the concrete provider package
// (pkg/storage/providers/sqlite is off the architecture import allowlist for this file).
func TestInitializeSessionStore_SQLitePath(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Storage: &config.StorageConfig{
			SQLitePath: filepath.Join(tempDir, "sessions.db"),
		},
	}

	store := initializeSessionStore(context.Background(), cfg, logging.NewNoopLogger())
	require.NotNil(t, store)

	// A configured SQLite path must NOT yield the in-memory fallback.
	_, isMem := store.(*session.MemStore)
	assert.False(t, isMem, "expected durable SQLite-backed store, got *session.MemStore")

	// Prove durability through the session.Store contract: a session written here must
	// survive a fresh store opened on the same path. An in-memory store could not.
	ctx := context.Background()
	tokenHash := "hash-durable-2774"
	now := time.Now().UTC().Truncate(time.Second)
	sess := &session.Session{
		ID:                "sess-durable-2774",
		ConnectionName:    "conn-a",
		PrincipalID:       "admin-a",
		TenantID:          "root",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, store.Set(ctx, tokenHash, sess))

	// Close the first handle to prove it is owned and releasable, and to let the second
	// store own the file cleanly. The concrete durable store implements io.Closer.
	closer, ok := store.(io.Closer)
	require.True(t, ok, "durable store must implement io.Closer, got %T", store)
	require.NoError(t, closer.Close(), "durable store must own and release its handle")

	// Reopen on the same path and confirm the session persisted to disk.
	reopened := initializeSessionStore(context.Background(), cfg, logging.NewNoopLogger())
	require.NotNil(t, reopened)
	t.Cleanup(func() {
		if c, isCloser := reopened.(io.Closer); isCloser {
			_ = c.Close()
		}
	})

	got, err := reopened.Get(ctx, tokenHash)
	require.NoError(t, err, "session written before restart must survive on disk")
	require.NotNil(t, got)
	assert.Equal(t, sess.ID, got.ID)
	assert.Equal(t, sess.PrincipalID, got.PrincipalID)
	assert.Equal(t, sess.TenantID, got.TenantID)
}

// TestInitializeSessionStore_EmptyPath verifies that initializeSessionStore returns a
// *session.MemStore when cfg.Storage.SQLitePath is empty.
func TestInitializeSessionStore_EmptyPath(t *testing.T) {
	cfg := &config.Config{
		Storage: &config.StorageConfig{
			SQLitePath: "",
		},
	}

	store := initializeSessionStore(context.Background(), cfg, logging.NewNoopLogger())
	require.NotNil(t, store)

	_, ok := store.(*session.MemStore)
	assert.True(t, ok, "expected *session.MemStore, got %T", store)

	if memStore, cast := store.(*session.MemStore); cast {
		memStore.Close()
	}
}

// TestInitializeSessionStore_NilStorage verifies that initializeSessionStore returns
// a *session.MemStore when cfg.Storage is nil.
func TestInitializeSessionStore_NilStorage(t *testing.T) {
	cfg := &config.Config{
		Storage: nil,
	}

	store := initializeSessionStore(context.Background(), cfg, logging.NewNoopLogger())
	require.NotNil(t, store)

	_, ok := store.(*session.MemStore)
	assert.True(t, ok, "expected *session.MemStore on nil Storage, got %T", store)

	if memStore, cast := store.(*session.MemStore); cast {
		memStore.Close()
	}
}

// TestInitializeSessionStore_BadPath verifies that initializeSessionStore falls back to
// a *session.MemStore without panicking or returning an error when the SQLite path is
// unwritable (open failure path).
func TestInitializeSessionStore_BadPath(t *testing.T) {
	cfg := &config.Config{
		Storage: &config.StorageConfig{
			// Deliberately unwritable: directory that does not exist under a read-only root.
			SQLitePath: "/nonexistent-readonly-dir/sessions.db",
		},
	}

	store := initializeSessionStore(context.Background(), cfg, logging.NewNoopLogger())
	require.NotNil(t, store, "fallback must not be nil even on SQLite open failure")

	_, ok := store.(*session.MemStore)
	assert.True(t, ok, "expected *session.MemStore fallback on bad path, got %T", store)

	if memStore, cast := store.(*session.MemStore); cast {
		memStore.Close()
	}
}

// TestInitializeSessionStore_ClusterMode_NoDSN verifies that cluster mode with no Postgres
// DSN configured falls through to the single-node SQLite path unchanged.
func TestInitializeSessionStore_ClusterMode_NoDSN(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		HA: &config.HAConfig{Mode: "cluster"},
		Storage: &config.StorageConfig{
			SQLitePath: filepath.Join(tempDir, "sessions.db"),
			// Cluster is nil — no PostgresDSN configured; branch must fall through.
		},
	}

	store := initializeSessionStore(context.Background(), cfg, logging.NewNoopLogger())
	require.NotNil(t, store)

	// Without a cluster DSN the function falls through to the single-node SQLite path.
	_, isMem := store.(*session.MemStore)
	assert.False(t, isMem, "cluster mode without DSN must fall through to SQLite, not MemStore")

	if c, ok := store.(io.Closer); ok {
		t.Cleanup(func() { _ = c.Close() })
	}
}

// TestInitializeSessionStore_ClusterMode_BadDSN verifies that a Postgres connection failure
// in cluster mode falls back to the SQLite/mem path without blocking startup.
func TestInitializeSessionStore_ClusterMode_BadDSN(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		HA: &config.HAConfig{Mode: "cluster"},
		Storage: &config.StorageConfig{
			SQLitePath: filepath.Join(tempDir, "sessions.db"),
			Cluster: &config.ClusterStorageConfig{
				// Unreachable DSN — CreateSessionTokenStore ping will fail; fallback must engage.
				PostgresDSN: "postgres://invalid-host-does-not-exist:5432/cfgms?sslmode=disable&connect_timeout=1",
			},
		},
	}

	store := initializeSessionStore(context.Background(), cfg, logging.NewNoopLogger())
	require.NotNil(t, store, "cluster-mode Postgres failure must not block startup")
	if c, ok := store.(io.Closer); ok {
		t.Cleanup(func() { _ = c.Close() })
	}

	// Verify the fallback actually engaged via behaviour, not a concrete-type assertion
	// (test files must not import pkg/storage/providers/*). The SQLitePath is configured,
	// so the fallback yields the durable SQLite store, never MemStore.
	_, isMem := store.(*session.MemStore)
	assert.False(t, isMem, "cluster-mode Postgres failure with a configured SQLitePath must fall back to SQLite, not MemStore")

	// The decisive proof that the unreachable DSN was NOT accepted: a store backed by the
	// broken Postgres connection would fail every operation. A working round-trip through
	// the session.Store contract confirms the store is the functional SQLite fallback.
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	sess := &session.Session{
		ID:                "sess-baddsn-2775",
		ConnectionName:    "conn-baddsn",
		PrincipalID:       "admin-baddsn",
		TenantID:          "root",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, store.Set(ctx, "hash-baddsn-2775", sess),
		"fallback store must be operational; a broken-Postgres store would fail Set")
	got, err := store.Get(ctx, "hash-baddsn-2775")
	require.NoError(t, err, "fallback store must serve reads; a broken-Postgres store would fail Get")
	assert.Equal(t, sess.ID, got.ID)
}
