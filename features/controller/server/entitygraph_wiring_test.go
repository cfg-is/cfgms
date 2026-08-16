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
// This asserts New() wires BOTH into the API server the REST handlers read from.
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

	// Both must be wired into the API server the REST handlers read.
	assert.NotNil(t, srv.httpServer.EntityGraphProvider(),
		"entity graph provider must be wired into the API server (else /api/v1/entities* 503s)")
	assert.NotNil(t, srv.httpServer.ConfigStoreWriter(),
		"entity graph configstore writer must be wired into the API server (else GetDesiredState has no writer)")
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
}
