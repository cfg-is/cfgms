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

// TestSetupManagedTLS_SingleServerMode_NoClientAuth verifies that when haManager is
// non-nil but configured in SingleServerMode, setupManagedTLS returns a tls.Config
// with no client auth. This exercises the GetDeploymentMode() != ClusterMode branch
// (distinct from the nil haManager short-circuit path), ensuring a bug in the mode
// comparison cannot hide behind the nil check.
func TestSetupManagedTLS_SingleServerMode_NoClientAuth(t *testing.T) {
	certMgr := newTLSTestCertManager(t)

	haManager, err := ha.NewManager(ha.DefaultConfig(), logging.NewNoopLogger(), nil)
	require.NoError(t, err)

	server := newMinimalTLSServer(t, certMgr, haManager)

	tlsConfig, err := server.setupManagedTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, tls.NoClientCert, tlsConfig.ClientAuth,
		"SingleServerMode manager must not request or require client certificates")
}
