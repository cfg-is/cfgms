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

// TestServer_New_WiresScriptLibrary is the composition-root wiring test for the
// script library (Issue #5422): New must give the execution queue and the API
// server the tenant script library, and the API server its privilege store.
func TestServer_New_WiresScriptLibrary(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir := t.TempDir()
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Script Library Wiring Test",
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
				CommonName:   "script-library-wiring-controller",
				Organization: "Script Library Wiring Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		// SQLitePath causes CreateOSSStorageManager to open the SQLite bundle,
		// which always includes a CaseStore (SQLiteCaseStore). Without SQLitePath
		// the bundle is absent and GetCaseStore returns nil, which would make this
		// test a false positive.
		Storage: createTestStorageConfig(tempDir, "script-library-wiring"),
	}

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })

	require.NotNil(t, srv.httpServer, "API server must be initialized")
	require.NotNil(t, srv.executionQueue, "execution queue must be initialized")

	assert.NotNil(t, srv.executionQueue.ScriptRepository(),
		"the execution queue needs the script library (else a library run resolves no content)")
	assert.NotNil(t, srv.httpServer.ScriptRepository(),
		"the script library must be wired into the API server (else /api/v1/scripts 503s)")
	assert.NotNil(t, srv.httpServer.PrivilegeStore(),
		"the privilege store must be wired into the API server (else PUT .../privilege 503s)")
}
