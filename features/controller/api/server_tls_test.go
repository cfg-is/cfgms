// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto/tls"
	"os"
	"path/filepath"
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

	haManager, err := ha.NewManager(ha.DefaultConfig(), logging.NewNoopLogger(), nil, nil, "")
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

// writeLegacyCertFiles generates a server cert via a real cert.Manager and writes
// server.crt / server.key into dir so setupLegacyTLS can load them.
func writeLegacyCertFiles(t *testing.T, dir string) {
	t.Helper()
	mgr := newTLSTestCertManager(t)
	serverCert, err := mgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "test-legacy-tls",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "server.crt"), serverCert.CertificatePEM, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "server.key"), serverCert.PrivateKeyPEM, 0600))
}

// TestSetupLegacyTLS_CWDIndependent verifies that setupLegacyTLS resolves server.crt
// and server.key from an absolute cfg.CertPath even when the process working directory
// is a completely different location (Issue #3197).
func TestSetupLegacyTLS_CWDIndependent(t *testing.T) {
	certDir := t.TempDir()
	writeLegacyCertFiles(t, certDir)

	// Move CWD to a directory that has no cert files.
	otherDir := t.TempDir()
	origWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(otherDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(origWD)) })

	cfg := config.DefaultConfig()
	cfg.CertPath = certDir // absolute path — must win regardless of CWD
	s := &Server{cfg: cfg, logger: logging.NewNoopLogger()}

	tlsConfig, err := s.setupLegacyTLS()
	require.NoError(t, err,
		"setupLegacyTLS must succeed when CertPath is absolute, even when CWD != cert dir")
	require.NotNil(t, tlsConfig)
}

// TestSetupLegacyTLS_ExplicitAbsolutePathHonoured verifies that an explicitly
// configured absolute CertPath is resolved correctly for server.crt/server.key
// (Issue #3197).
func TestSetupLegacyTLS_ExplicitAbsolutePathHonoured(t *testing.T) {
	certDir := t.TempDir()
	writeLegacyCertFiles(t, certDir)

	cfg := config.DefaultConfig()
	cfg.CertPath = certDir
	s := &Server{cfg: cfg, logger: logging.NewNoopLogger()}

	tlsConfig, err := s.setupLegacyTLS()
	require.NoError(t, err, "explicit absolute CertPath must be honoured by setupLegacyTLS")
	require.NotNil(t, tlsConfig)
}
