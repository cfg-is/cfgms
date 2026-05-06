// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/commercial/ha"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTLSTestCertManager creates a real cert.Manager backed by a temp dir.
func newTLSTestCertManager(t *testing.T) *cert.Manager {
	t.Helper()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cert.CAConfig{
			Organization: "Test CFGMS",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)
	return mgr
}

// newMinimalTLSServer creates a minimal Server with only the fields needed by setupManagedTLS.
func newMinimalTLSServer(t *testing.T, certMgr *cert.Manager, haManager *ha.Manager) *Server {
	t.Helper()
	cfg := config.DefaultConfig()
	return &Server{
		cfg:         cfg,
		certManager: certMgr,
		haManager:   haManager,
		logger:      logging.NewNoopLogger(),
	}
}

// TestSetupManagedTLS_NilHAManager_NoClientAuth verifies that when haManager is nil,
// setupManagedTLS returns a tls.Config with no client auth — non-HA API consumers
// must not be required or requested to present client certificates.
func TestSetupManagedTLS_NilHAManager_NoClientAuth(t *testing.T) {
	certMgr := newTLSTestCertManager(t)
	server := newMinimalTLSServer(t, certMgr, nil)

	tlsConfig, err := server.setupManagedTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, tls.NoClientCert, tlsConfig.ClientAuth,
		"nil haManager must not request or require client certificates")
}
