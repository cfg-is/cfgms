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

// TestServer_New_WiresTagAndRoleConfigStoresIntoAPIServer is the regression guard
// for Issue #2548: the durable tag store (#2545) and role-config store (#2543)
// were initialized in New() and wired into the *service* layer, but never wired
// into the HTTP API server — so every `/api/v1/stewards/{id}/tags` and
// `/api/v1/roles` request returned 503 (TAG_STORE_UNAVAILABLE /
// "Role config store not available") in production even though the stores existed
// and the feature's unit tests (which call SetTagStore/SetRoleConfigStore
// directly) passed. This asserts New() wires BOTH stores into the API server the
// REST handlers actually read from.
func TestServer_New_WiresTagAndRoleConfigStoresIntoAPIServer(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir := t.TempDir()
	// cert.NewManager with StoragePath=tempDir stores the CA at tempDir/ca/;
	// CAPath is tempDir+"/ca" so loadExistingCertificateManager derives StoragePath=tempDir.
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Store Wiring Test",
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
				CommonName:   "store-wiring-controller",
				Organization: "Store Wiring Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		// createTestStorageConfig sets SQLitePath, which initializeTagStore
		// requires — without it the tag store is deliberately nil and this test
		// would not distinguish "unconfigured" from "unwired".
		Storage: createTestStorageConfig(tempDir, "store-wiring"),
	}

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	require.NotNil(t, srv.httpServer, "API server must be initialized")

	// Both stores must be wired into the API server the REST handlers read.
	assert.NotNil(t, srv.httpServer.TagStore(),
		"tag store must be wired into the API server (else /stewards/{id}/tags 503s)")
	assert.NotNil(t, srv.httpServer.RoleConfigStore(),
		"role-config store must be wired into the API server (else /roles 503s)")
	assert.NotNil(t, srv.httpServer.HypervProfileConfigStore(),
		"hyperv-profile store must be wired into the API server (else /hyperv/profiles 503s, Issue #3785)")
}
