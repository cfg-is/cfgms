// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ha"
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

// TestSetupManagedTLS_RequestsClientCertWhenCertManagerSet verifies that when certManager
// is non-nil (regardless of HA mode), setupManagedTLS sets ClientAuth = VerifyClientCertIfGiven
// and populates ClientCAs from the controller CA. This enables mTLS admin cert auth while
// allowing clients without certs to fall through to API-key auth.
func TestSetupManagedTLS_RequestsClientCertWhenCertManagerSet(t *testing.T) {
	certMgr := newTLSTestCertManager(t)
	server := newMinimalTLSServer(t, certMgr, nil)

	tlsConfig, err := server.setupManagedTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, tls.VerifyClientCertIfGiven, tlsConfig.ClientAuth,
		"certManager != nil must set ClientAuth = VerifyClientCertIfGiven: "+
			"presented certs are chain-verified; missing cert falls through to API-key auth")
	assert.NotNil(t, tlsConfig.ClientCAs,
		"ClientCAs must be populated from the controller CA when certManager is set")
}

// TestSetupManagedTLS_SingleServerMode_VerifyClientCertIfGiven verifies that when haManager
// is non-nil but configured in SingleServerMode, setupManagedTLS still sets
// ClientAuth = VerifyClientCertIfGiven because cert management (not HA mode) is the
// determining factor. This exercises the GetDeploymentMode() != ClusterMode branch.
func TestSetupManagedTLS_SingleServerMode_VerifyClientCertIfGiven(t *testing.T) {
	certMgr := newTLSTestCertManager(t)

	haManager, err := ha.NewManager(ha.DefaultConfig(), logging.NewNoopLogger(), nil)
	require.NoError(t, err)

	server := newMinimalTLSServer(t, certMgr, haManager)

	tlsConfig, err := server.setupManagedTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, tls.VerifyClientCertIfGiven, tlsConfig.ClientAuth,
		"SingleServerMode manager must set VerifyClientCertIfGiven (certManager drives the policy)")
	assert.NotNil(t, tlsConfig.ClientCAs,
		"ClientCAs must be populated from the controller CA")
}
