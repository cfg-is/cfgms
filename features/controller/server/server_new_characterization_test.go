// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Characterization tests for the storage, RBAC, audit, tenant, service and
// certificate region of New (Issue #5862). They pin the observable behavior of
// that region (error text, check order, what the returned Server holds, and
// the Issue #4058 close-once contract) so the region can be split into helpers
// without changing it. Every helper, type and test here carries the
// servernewChar prefix so sibling cleanup stories can add files to this
// package without name clashes.

// servernewCharConfig returns a single-node OSS-composite config whose data
// lives entirely under t.TempDir().
func servernewCharConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: filepath.Join(dir, "flatfile"),
			SQLitePath:   filepath.Join(dir, "cfgms.db"),
		},
	}
}

// servernewCharCertConfig enables certificate management against a CA that was
// initialized under t.TempDir() with the same helper the other server tests use.
func servernewCharCertConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := servernewCharConfig(t)
	certDir := t.TempDir()
	caPath := filepath.Join(certDir, "ca")
	PreInitControllerForTest(t, certDir, caPath)
	cfg.Certificate = &config.CertificateConfig{
		EnableCertManagement:   true,
		ClientCertValidityDays: 30,
		ServerCertValidityDays: 90,
		RenewalThresholdDays:   7,
		CAPath:                 caPath,
		Server: &config.ServerCertificateConfig{
			CommonName:   "servernew-char-controller",
			DNSNames:     []string{"localhost"},
			IPAddresses:  []string{"127.0.0.1"},
			Organization: "Test Org",
		},
	}
	return cfg
}

// servernewCharNewServer builds a Server and stops it when the test ends.
func servernewCharNewServer(t *testing.T, cfg *config.Config, logger logging.Logger) *Server {
	t.Helper()
	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })
	return srv
}

// servernewCharCloseCountingProvider wraps a real registered StorageProvider
// and counts the closes of the audit store it hands out. Embedding
// the interface also hides any optional bundle-opener interface, which is
// irrelevant for the flatfile provider (its stores are created one by one).
type servernewCharCloseCountingProvider struct {
	interfaces.StorageProvider
	auditCloses int
}

type servernewCharCountedAuditStore struct {
	business.AuditStore
	p *servernewCharCloseCountingProvider
}

func (s servernewCharCountedAuditStore) Close() error {
	s.p.auditCloses++
	return s.AuditStore.Close()
}

func (p *servernewCharCloseCountingProvider) CreateAuditStore(c map[string]interface{}) (business.AuditStore, error) {
	store, err := p.StorageProvider.CreateAuditStore(c)
	if err != nil {
		return store, err
	}
	return servernewCharCountedAuditStore{AuditStore: store, p: p}, nil
}

// servernewCharInstallCountingFlatfile swaps the registered flatfile provider
// for a counting wrapper around it and restores the original on cleanup.
func servernewCharInstallCountingFlatfile(t *testing.T) *servernewCharCloseCountingProvider {
	t.Helper()
	original, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err, "the flatfile provider must be registered for this test")
	counting := &servernewCharCloseCountingProvider{StorageProvider: original}
	interfaces.RegisterStorageProvider(counting)
	t.Cleanup(func() { interfaces.RegisterStorageProvider(original) })
	return counting
}

func TestServernewChar_PreconditionErrors(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		srv, err := New(nil, logging.NewNoopLogger())
		assert.Nil(t, srv)
		assert.ErrorIs(t, err, ErrNilConfig)
	})

	t.Run("storage section required", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Storage = nil
		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "storage configuration is required for CFGMS operation")
	})
}

// TestServernewChar_StorageSelection pins which backend each configuration
// shape selects, and the error each unusable shape returns.
func TestServernewChar_StorageSelection(t *testing.T) {
	t.Run("single node flatfile root selects the OSS composite backend", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, cfg, logger)

		require.NotNil(t, srv.storageManager)
		assert.NotNil(t, srv.storageManager.GetTenantStore())
		assert.NotNil(t, srv.storageManager.GetAuditStore())
		assert.NotNil(t, srv.storageManager.GetRBACStore())
		assert.True(t, logger.containsAny("OSS composite storage backend initialized"))
		assert.False(t, logger.containsAny("Cluster storage backend initialized"))
		assert.DirExists(t, cfg.Storage.FlatfileRoot)
		assert.FileExists(t, cfg.Storage.SQLitePath)
	})

	t.Run("cluster mode selects the cluster backend and fails without a reachable Postgres", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.HA = &config.HAConfig{Mode: "cluster"}
		cfg.Storage.Cluster = &config.ClusterStorageConfig{PostgresDSN: "", SessionHMACKey: "servernew-char-hmac-key"}
		logger := &recordingLogger{}

		srv, err := New(cfg, logger)
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize cluster storage")
		assert.True(t, logger.containsAny("Cluster mode: initializing Postgres business store backend..."))
		assert.False(t, logger.containsAny("OSS composite"), "cluster mode must not fall through to the OSS composite branch")
	})

	t.Run("cluster mode without a cluster block still takes the cluster branch", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.HA = &config.HAConfig{Mode: "cluster"}
		cfg.Storage.Cluster = nil

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize cluster storage")
	})

	t.Run("database provider without connection parameters fails with the remedy text", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Storage.FlatfileRoot = ""
		cfg.Storage.Provider = "database"
		cfg.Storage.Config = map[string]interface{}{}

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize database storage provider")
		assert.Contains(t, err.Error(), "Verify storage.config contains valid database connection parameters")
	})

	t.Run("no flatfile root and no database provider is refused", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Storage.FlatfileRoot = ""
		cfg.Storage.Provider = "git"

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "storage.flatfile_root is required for OSS composite storage")
		assert.Contains(t, err.Error(), "'git' storage provider has been removed")
	})
}

// TestServernewChar_AuditSink pins the audit sink resolution order and errors.
func TestServernewChar_AuditSink(t *testing.T) {
	t.Run("default sink is local and installs no WORM store", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, cfg, logger)

		assert.Nil(t, srv.wormAuditStore)
		assert.True(t, logger.containsAny("Audit sink selected"))
	})

	t.Run("explicit local sink installs no WORM store", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Audit = &config.AuditSinkConfig{Sink: config.AuditSinkLocal}
		srv := servernewCharNewServer(t, cfg, logging.NewNoopLogger())

		assert.Nil(t, srv.wormAuditStore)
	})

	t.Run("unknown sink is refused", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Audit = &config.AuditSinkConfig{Sink: "carrier-pigeon"}

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unknown audit sink "carrier-pigeon"`)
		assert.Contains(t, err.Error(), `valid values: "local", "worm"`)
	})

	t.Run("worm sink without a usable blob target is refused", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Audit = &config.AuditSinkConfig{Sink: config.AuditSinkWORM, WORM: map[string]interface{}{}}

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize worm audit sink blob store")
	})
}

// TestServernewChar_TenantAndServiceValidation pins the validation checks of
// the region and the values they wire into the returned Server.
func TestServernewChar_TenantAndServiceValidation(t *testing.T) {
	t.Run("a valid realm id reaches the tenant manager", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.RealmID = "cell-one"
		srv := servernewCharNewServer(t, cfg, logging.NewNoopLogger())

		require.NotNil(t, srv.tenantManager)
		assert.Equal(t, "cell-one", srv.tenantManager.RealmID)
		assert.NotNil(t, srv.rbacManager)
		assert.NotNil(t, srv.rbacService)
	})

	t.Run("a malformed realm id is refused", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.RealmID = "root/msp-a"

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "configured realm is not a valid realm identifier")
	})

	t.Run("invalid deployment rings are refused", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.DeploymentRings = &config.DeploymentRingConfig{Rings: []config.RingSpec{{Name: "Not A Ring"}}}

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid deployment_rings config:")
	})

	t.Run("invalid module trust is refused", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.ModuleTrust = &config.ModuleTrustConfig{Publishers: []config.ModuleTrustPublisher{{Name: ""}}}

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid module config:")
	})

	t.Run("services built by the region are wired into the Server", func(t *testing.T) {
		srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())

		assert.NotNil(t, srv.dnaStorageManager, "single-node DNA storage is durable")
		assert.NotNil(t, srv.tagStore, "SQLite path is configured, so the tag store is opened")
		assert.NotNil(t, srv.configSyncService)
		assert.NotNil(t, srv.routerSecretStore)
		assert.NotNil(t, srv.directoryManager)
	})

	t.Run("without a SQLite path the entity graph provider refuses to start", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Storage.SQLitePath = ""

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize entity graph provider:")
		assert.Contains(t, err.Error(), "storage.sqlite_path is required for the entity graph provider")
	})
}

// TestServernewChar_CertificateManager pins the certificate manager block: the
// disabled shape builds none of the three certificate services, the enabled
// shape builds all of them, and the init guard refuses an uninitialized CA.
func TestServernewChar_CertificateManager(t *testing.T) {
	t.Run("disabled builds no certificate services", func(t *testing.T) {
		srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())

		assert.Nil(t, srv.certManager)
		assert.Nil(t, srv.certProvisioningService)
		assert.Nil(t, srv.signingMigrationSvc)
	})

	t.Run("nil certificate section behaves as disabled", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Certificate = nil
		srv := servernewCharNewServer(t, cfg, logging.NewNoopLogger())

		assert.Nil(t, srv.certManager)
		assert.Nil(t, srv.certProvisioningService)
	})

	t.Run("enabled on an initialized CA builds the certificate services", func(t *testing.T) {
		cfg := servernewCharCertConfig(t)
		srv := servernewCharNewServer(t, cfg, logging.NewNoopLogger())

		require.NotNil(t, srv.certManager)
		assert.NotNil(t, srv.certProvisioningService)
		assert.NotNil(t, srv.signingMigrationSvc)
	})

	t.Run("enabled with custom validity days and common names", func(t *testing.T) {
		cfg := servernewCharCertConfig(t)
		cfg.Certificate.InternalCertValidityDays = 30
		cfg.Certificate.SigningCertValidityDays = 365
		cfg.Certificate.Internal = &config.InternalCertConfig{CommonName: "servernew-char-internal"}
		cfg.Certificate.Signing = &config.SigningCertificateConfig{CommonName: "servernew-char-signer", Organization: "Test Org"}
		srv := servernewCharNewServer(t, cfg, logging.NewNoopLogger())

		require.NotNil(t, srv.certManager)
		assert.NotNil(t, srv.certProvisioningService)
	})

	t.Run("an uninitialized CA is refused with ErrNotInitialized", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Certificate = &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               filepath.Join(t.TempDir(), "never-initialized"),
		}

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		assert.True(t, errors.Is(err, ErrNotInitialized), "got %v", err)
	})

	t.Run("a legacy CA without an init marker gets one created", func(t *testing.T) {
		cfg := servernewCharCertConfig(t)
		caPath := cfg.Certificate.CAPath
		require.True(t, initialization.IsInitialized(caPath))
		require.NoError(t, os.Remove(filepath.Join(caPath, ".cfgms-initialized")))
		require.False(t, initialization.IsInitialized(caPath))
		logger := &recordingLogger{}

		servernewCharNewServer(t, cfg, logger)

		assert.True(t, initialization.IsInitialized(caPath), "New must recreate the marker for a legacy CA")
		assert.True(t, logger.containsAny("Legacy CA detected without init marker"))
	})
}

// TestServernewChar_FailureClosesOpenedStoresOnce pins the Issue #4058
// contract across the region: every store opened before a failure is closed
// exactly once, and a successful New closes nothing. The failing stages are
// real: an uninitialized CA inside the region, and an invalid ha.mode in the
// stage that follows it.
func TestServernewChar_FailureClosesOpenedStoresOnce(t *testing.T) {
	t.Run("failure inside the region after storage creation", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		cfg := servernewCharConfig(t)
		cfg.Certificate = &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               filepath.Join(t.TempDir(), "never-initialized"),
		}

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		assert.True(t, errors.Is(err, ErrNotInitialized), "got %v", err)

		assert.Equal(t, 1, counting.auditCloses, "the audit store opened by New must be closed exactly once")
	})

	t.Run("failure in a later stage than the region", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		cfg := servernewCharConfig(t)
		cfg.HA = &config.HAConfig{Mode: "not-a-real-mode"}

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize HA manager")

		assert.Equal(t, 1, counting.auditCloses, "stores opened by the region must be closed when a later stage fails")
	})

	t.Run("failure before any store is opened closes nothing", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		cfg := servernewCharConfig(t)
		cfg.Storage.FlatfileRoot = ""
		cfg.Storage.Provider = "git"

		_, err := New(cfg, logging.NewNoopLogger())
		require.Error(t, err)

		assert.Zero(t, counting.auditCloses)
	})

	t.Run("a successful New leaves the stores open until Stop", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		srv, err := New(servernewCharConfig(t), logging.NewNoopLogger())
		require.NoError(t, err)

		assert.Zero(t, counting.auditCloses)
		require.NoError(t, srv.Stop())
	})
}

// TestServernewChar_RegionFailures pins the error text of failure paths that
// need no external service: they sit before, inside and just after the region
// and each must return no Server and the exact wrapped message.
func TestServernewChar_RegionFailures(t *testing.T) {
	t.Run("0.0.0.0 bind without an external address is refused before storage opens", func(t *testing.T) {
		t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
		cfg := servernewCharConfig(t)
		cfg.Transport = &config.TransportConfig{ListenAddr: "0.0.0.0:4433"}
		logger := &recordingLogger{}

		srv, err := New(cfg, logger)
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "transport.listen_addr binds 0.0.0.0 but no external address is configured")
		assert.False(t, logger.containsAny("Config validated, proceeding with storage initialization"))
	})

	t.Run("an unknown security profile is refused", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.SecurityProfile = "wide-open"

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "execution security validation failed:")
	})

	t.Run("an OSS composite backend that cannot be created is refused", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		blocker := filepath.Join(t.TempDir(), "blocker")
		require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o600))
		cfg.Storage.FlatfileRoot = filepath.Join(blocker, "flatfile")

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize OSS composite storage:")
	})

	t.Run("a config git work directory that cannot be created is refused", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		cfg := servernewCharConfig(t)
		dataRoot := filepath.Dir(cfg.Storage.SQLitePath)
		require.NoError(t, os.MkdirAll(dataRoot, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dataRoot, "config-git-sources"), []byte("file"), 0o600))

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create config git work directory:")
		assert.Equal(t, 1, counting.auditCloses, "stores opened before the failure are closed exactly once")
	})

	t.Run("the removed unified certificate architecture is refused", func(t *testing.T) {
		cfg := servernewCharCertConfig(t)
		cfg.Certificate.Architecture = "unified"

		srv, err := New(cfg, logging.NewNoopLogger())
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `certificate architecture "unified" is no longer supported`)
	})
}
