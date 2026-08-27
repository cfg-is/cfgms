// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestServer_New_WiresEntityGraphProviderIntoAPIServer is the regression guard
// for Issue #3253: the entity graph provider and its ConfigStore writer were
// constructed as library code (Issues #2871–#2880) but never instantiated in a
// running controller — every /api/v1/entities* request returned 503 "entity
// graph unavailable" unconditionally because s.egProvider was always nil.
// This asserts New() wires all four into the API server the REST handlers
// read from: the read provider and ConfigStore writer (Issue #3253), the
// write provider for operator-asserted edge assertions (Issue #3374), and the
// watch provider for the cockpit WebSocket fan-out (Issue #3613) — all wired
// from the same egProvider instance.
func TestServer_New_WiresEntityGraphProviderIntoAPIServer(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir := t.TempDir()
	// cert.NewManager with StoragePath=tempDir stores the CA at tempDir/ca/;
	// CAPath is tempDir+"/ca" so loadExistingCertificateManager derives StoragePath=tempDir.
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "EG Wiring Test",
			Country:      "US",
			ValidityDays: 3650,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "failed to create test CA")

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "eg-wiring-controller",
				Organization: "EG Wiring Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		// createTestStorageConfig sets FlatfileRoot and SQLitePath, putting the
		// controller into OSS composite mode so initializeEntityGraphProvider
		// opens a dedicated entitygraph.db alongside the main SQLite file.
		Storage: createTestStorageConfig(tempDir, "eg-wiring"),
	}

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })

	require.NotNil(t, srv.httpServer, "API server must be initialized")

	// All four must be wired into the API server the REST handlers read.
	assert.NotNil(t, srv.httpServer.EntityGraphProvider(),
		"entity graph provider must be wired into the API server (else /api/v1/entities* 503s)")
	assert.NotNil(t, srv.httpServer.ConfigStoreWriter(),
		"entity graph configstore writer must be wired into the API server (else GetDesiredState has no writer)")
	assert.NotNil(t, srv.httpServer.EntityGraphWriteProvider(),
		"entity graph write provider must be wired into the API server (else POST /api/v1/entities/edges 503s)")
	assert.NotNil(t, srv.httpServer.EntityGraphWatchProvider(),
		"entity graph watch provider must be wired into the API server (else GET /api/v1/cases/{id}/watch 503s)")
}

// TestInitializeEntityGraphProvider covers the error paths of
// initializeEntityGraphProvider so that misconfiguration is caught at startup.
func TestInitializeEntityGraphProvider(t *testing.T) {
	logger := logging.NewNoopLogger()

	t.Run("nil_storage_returns_error", func(t *testing.T) {
		cfg := &config.Config{Storage: nil}
		p, err := initializeEntityGraphProvider(cfg, logger)
		require.Error(t, err, "nil storage must return an error")
		assert.Nil(t, p)
	})

	t.Run("oss_composite_no_sqlite_path_returns_error", func(t *testing.T) {
		// FlatfileRoot set → OSS composite mode, but SQLitePath missing.
		cfg := &config.Config{
			Storage: &config.StorageConfig{
				FlatfileRoot: t.TempDir(),
				SQLitePath:   "",
			},
		}
		p, err := initializeEntityGraphProvider(cfg, logger)
		require.Error(t, err, "OSS composite mode without sqlite_path must return an error")
		assert.Nil(t, p)
	})

	t.Run("oss_composite_bad_sqlite_path_returns_error", func(t *testing.T) {
		// SQLitePath points into a non-existent directory so the open fails.
		cfg := &config.Config{
			Storage: &config.StorageConfig{
				FlatfileRoot: t.TempDir(),
				SQLitePath:   "/nonexistent/dir/cfgms.db",
			},
		}
		p, err := initializeEntityGraphProvider(cfg, logger)
		require.Error(t, err, "bad sqlite path must return an error")
		assert.Nil(t, p)
	})

	t.Run("database_mode_bad_dsn_returns_error", func(t *testing.T) {
		// Provider == "database" with a DSN pointing at a port that is never
		// a Postgres instance (port 1 is privileged and unbound). lib/pq
		// defers connection until first use (sql.Open is lazy), so the error
		// surfaces during initializeSchema — guaranteed regardless of whether
		// a local Postgres socket happens to be present.
		cfg := &config.Config{
			Storage: &config.StorageConfig{
				Provider: "database",
				Config: map[string]interface{}{
					"dsn": "host=127.0.0.1 port=1 dbname=nonexistent user=nobody password=none sslmode=disable",
				},
			},
		}
		p, err := initializeEntityGraphProvider(cfg, logger)
		require.Error(t, err, "unreachable DSN must return an error")
		assert.Nil(t, p)
	})

	t.Run("cluster_mode_bad_dsn_returns_error", func(t *testing.T) {
		// Cluster mode takes the Postgres branch regardless of the composite
		// settings below; the DSN points at an unbound privileged port so
		// initializeSchema fails deterministically on any host.
		cfg := &config.Config{
			HA: &config.HAConfig{Mode: "cluster"},
			Storage: &config.StorageConfig{
				FlatfileRoot: t.TempDir(),
				Cluster: &config.ClusterStorageConfig{
					PostgresDSN: "host=127.0.0.1 port=1 dbname=nonexistent user=nobody password=none sslmode=disable",
				},
			},
		}
		p, err := initializeEntityGraphProvider(cfg, logger)
		require.Error(t, err, "cluster mode with an unreachable Postgres DSN must return an error")
		assert.Nil(t, p)
	})

	t.Run("oss_composite_happy_path", func(t *testing.T) {
		// SQLitePath points to a tempdir so the provider opens successfully.
		dir := t.TempDir()
		cfg := &config.Config{
			Storage: &config.StorageConfig{
				FlatfileRoot: dir,
				SQLitePath:   dir + "/cfgms.db",
			},
		}
		p, err := initializeEntityGraphProvider(cfg, logger)
		require.NoError(t, err)
		require.NotNil(t, p)
		assert.NoError(t, p.Close())
	})

	t.Run("database_mode_individual_fields_no_dsn_key_attempts_configured_host", func(t *testing.T) {
		// PR #3392 merge-queue regression: createDockerTestStorageConfig (and the
		// docker-compose.test.yml HA fixtures) configure the "database" provider
		// with discrete host/port/database/username/password/sslmode keys, never a
		// "dsn" key — matching pkg/storage/providers/database/plugin.go's getDSN
		// contract, which falls back to those fields when "dsn" is absent. Before
		// this fix, initializeEntityGraphProvider read only Config["dsn"], got an
		// empty string, and lib/pq's sql.Open("postgres", "") silently defaulted to
		// dialing localhost:5432 instead of the configured host — failing startup
		// with a misleading "connection refused" against the wrong address. Port 1
		// here is privileged and unbound, so a connection attempt against the
		// *configured* host is guaranteed to fail; the failure must reference this
		// DSN's target, proving the individual fields were actually used.
		cfg := &config.Config{
			Storage: &config.StorageConfig{
				Provider: "database",
				Config: map[string]interface{}{
					"host":     "127.0.0.1",
					"port":     1,
					"database": "cfgms_test",
					"username": "cfgms_test",
					"password": "test-password",
					"sslmode":  "disable",
				},
			},
		}
		p, err := initializeEntityGraphProvider(cfg, logger)
		require.Error(t, err, "unreachable configured host must fail, not silently default to localhost")
		assert.Nil(t, p)
	})
}

// TestEntityGraphDatabaseDSN unit-tests the DSN extraction used by
// initializeEntityGraphProvider's "database" single-provider branch. It must
// mirror pkg/storage/providers/database/plugin.go's getDSN fallback exactly —
// preferring an explicit "dsn" key, otherwise building one from discrete
// host/port/database/username/password/sslmode keys — so the entity graph
// provider connects to the same database the rest of the controller uses
// (Issue #3253 merge-queue fix).
func TestEntityGraphDatabaseDSN(t *testing.T) {
	t.Run("prefers_explicit_dsn", func(t *testing.T) {
		dsn, err := entityGraphDatabaseDSN(map[string]interface{}{
			"dsn":      "host=explicit-host port=5432 dbname=x user=y password=z sslmode=disable",
			"host":     "ignored-host",
			"password": "ignored",
		})
		require.NoError(t, err)
		assert.Equal(t, "host=explicit-host port=5432 dbname=x user=y password=z sslmode=disable", dsn)
	})

	t.Run("builds_dsn_from_individual_fields", func(t *testing.T) {
		dsn, err := entityGraphDatabaseDSN(map[string]interface{}{
			"host":     "timescaledb-test",
			"port":     5433,
			"database": "cfgms_test",
			"username": "cfgms_test",
			"password": "test-password",
			"sslmode":  "disable",
		})
		require.NoError(t, err)
		assert.Equal(t, "host=timescaledb-test port=5433 dbname=cfgms_test user=cfgms_test password=test-password sslmode=disable", dsn)
	})

	t.Run("accepts_float64_port_from_decoded_config", func(t *testing.T) {
		// Config maps decoded from JSON/YAML frequently carry numeric values as
		// float64 rather than int.
		dsn, err := entityGraphDatabaseDSN(map[string]interface{}{
			"host":     "db-host",
			"port":     float64(5433),
			"password": "test-password",
		})
		require.NoError(t, err)
		assert.Contains(t, dsn, "port=5433")
	})

	t.Run("applies_defaults_when_fields_missing", func(t *testing.T) {
		dsn, err := entityGraphDatabaseDSN(map[string]interface{}{
			"password": "only-password-set",
		})
		require.NoError(t, err)
		assert.Equal(t, "host=localhost port=5432 dbname=cfgms user=cfgms password=only-password-set sslmode=require", dsn)
	})

	t.Run("requires_password_when_no_dsn", func(t *testing.T) {
		_, err := entityGraphDatabaseDSN(map[string]interface{}{
			"host": "localhost",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password")
	})
}
