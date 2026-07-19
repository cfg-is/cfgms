// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestServer_New_WiresTerminalWebSocketRoute is the regression guard for the
// production defect where New() constructed the terminal SessionManager from a
// bare &terminal.Config{RecordSessions: true, RecordingStoragePath: ...} that
// omitted SessionTimeout and MaxSessions. NewSessionManager validates both are
// positive, so the call always errored, the terminal relay block was skipped,
// and the /api/v1/terminal/ws route was never registered — silently disabling
// the terminal feature in every transport-enabled deployment (Issue #2761).
//
// This exercises the full New() terminal wiring path (which requires a running
// control plane: commandPublisher + connRegistry, both created only when
// transport is configured) and asserts the terminal WebSocket route is present.
// A GET against the route returns a non-404 status only when SetTerminalHandler
// registered it — a bare 404 means the session manager failed to initialize.
func TestServer_New_WiresTerminalWebSocketRoute(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir := t.TempDir()
	certDir := tempDir + "/ca"

	// Create the CA up front so EnableCertManagement startup succeeds.
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certDir,
		CAConfig: &cert.CAConfig{
			Organization: "Terminal Wiring Test",
			Country:      "US",
			ValidityDays: 3650,
			StoragePath:  certDir,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "failed to create test CA")

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		CertPath:   certDir,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               certDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "terminal-wiring-controller",
				Organization: "Terminal Wiring Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		Storage: createTestStorageConfig(tempDir, "terminal-wiring"),
	}

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	// Transport is configured, so the terminal relay block must have run and the
	// session manager must have initialized successfully.
	require.NotNil(t, srv.httpServer, "API server must be initialized")

	// A GET to the terminal WS route must be matched by the router. Without the
	// fix the route is absent and the router returns 404; with it, the request
	// reaches the permission middleware (401/403) — anything but 404 proves the
	// route was registered.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/ws/steward-123", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.GetRouter().ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusNotFound, rec.Code,
		"terminal WebSocket route must be registered when transport is configured; "+
			"a 404 means the terminal session manager failed to initialize (Issue #2761)")
}
