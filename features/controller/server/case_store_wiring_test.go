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

// TestServer_New_WiresCasesStoreIntoAPIServer is the REQUIRED COMPOSITION-ROOT
// WIRING TEST from Issue #3605 AC #7: the real startup path in
// features/controller/server/server.go (New) must result in a non-nil
// Server.casesStore when storageManager.GetCaseStore() returns a store.
// Without this test, the same gap that caused /registration/ip-trust to 503
// indefinitely (Issue #3096) can silently occur for /api/v1/cases.
func TestServer_New_WiresCasesStoreIntoAPIServer(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir := t.TempDir()
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Cases Store Wiring Test",
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
				CommonName:   "cases-wiring-controller",
				Organization: "Cases Store Wiring Test",
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
		Storage: createTestStorageConfig(tempDir, "cases-wiring"),
	}

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })

	require.NotNil(t, srv.httpServer, "API server must be initialized")

	assert.NotNil(t, srv.httpServer.CasesStore(),
		"cases store must be wired into the API server (else /api/v1/cases 503s at runtime)")
}
