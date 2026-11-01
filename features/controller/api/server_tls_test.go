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
	return newSharedTestCertManager(t)
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

// TestSetupLegacyTLS_ConfigFileRelativeCertPath_CWDIndependent is the regression guard for
// Issue #3197. It exercises the actual defect and the actual fix: a *relative* cert_path in
// a config file, loaded through config.LoadWithPath, must resolve against the config file's
// directory rather than the process working directory.
//
// This test goes through LoadWithPath deliberately. Before the fix, LoadWithPath left
// cfg.CertPath as the literal relative string, so setupLegacyTLS resolved "certs/server.crt"
// against whatever CWD the process happened to have and failed here. Asserting on an
// already-absolute CertPath cannot detect that regression, because an absolute path is
// CWD-independent whether or not the fix is present — see
// TestSetupLegacyTLS_CWDIndependent below, which covers a different property.
func TestSetupLegacyTLS_ConfigFileRelativeCertPath_CWDIndependent(t *testing.T) {
	// Layout: <configDir>/controller.cfg declares `cert_path: certs/`, and the certs live
	// at <configDir>/certs. Nothing is placed under the working directory.
	configDir := t.TempDir()
	certDir := filepath.Join(configDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	writeLegacyCertFiles(t, certDir)

	configPath := filepath.Join(configDir, "controller.cfg")
	require.NoError(t, os.WriteFile(configPath, []byte("cert_path: certs/\n"), 0600))

	// Run from a directory that contains no config and no certs.
	otherDir := t.TempDir()
	origWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(otherDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(origWD)) })

	// Guard the guard: if CWD ever did contain certs/server.crt this test would pass for
	// the wrong reason, so assert the CWD-relative path genuinely does not exist.
	_, statErr := os.Stat(filepath.Join(otherDir, "certs", "server.crt"))
	require.True(t, os.IsNotExist(statErr),
		"test setup is invalid: CWD must not contain certs/server.crt")

	cfg, err := config.LoadWithPath(configPath)
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(cfg.CertPath),
		"LoadWithPath must anchor a relative cert_path to the config file directory")

	s := &Server{cfg: cfg, logger: logging.NewNoopLogger()}
	tlsConfig, err := s.setupLegacyTLS()
	require.NoError(t, err,
		"setupLegacyTLS must load server.crt/server.key relative to the config file "+
			"directory, not the process working directory")
	require.NotNil(t, tlsConfig)
	require.NotEmpty(t, tlsConfig.Certificates)
}

// TestSetupLegacyTLS_CWDIndependent verifies that setupLegacyTLS honours an
// already-absolute cfg.CertPath regardless of the process working directory.
//
// NOTE: this is not the Issue #3197 regression guard. It hand-assigns an absolute
// CertPath and never calls config.LoadWithPath, so it passes with or without the fix.
// The guard is TestSetupLegacyTLS_ConfigFileRelativeCertPath_CWDIndependent above.
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

// TestSetupLegacyTLS_MissingCertFile verifies the first error branch: when
// server.crt is absent from CertPath, setupLegacyTLS returns a read error and no
// TLS config rather than silently serving an unconfigured listener.
func TestSetupLegacyTLS_MissingCertFile(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.CertPath = t.TempDir() // empty dir — no server.crt
	s := &Server{cfg: cfg, logger: logging.NewNoopLogger()}

	tlsConfig, err := s.setupLegacyTLS()
	require.Error(t, err, "missing server.crt must be reported, never ignored")
	assert.Nil(t, tlsConfig, "no TLS config may be returned when the certificate cannot be read")
	assert.Contains(t, err.Error(), "failed to read certificate file",
		"error must identify the certificate file as the failing input")
	assert.ErrorIs(t, err, os.ErrNotExist,
		"underlying os error must be wrapped, not flattened into a string")
}

// TestSetupLegacyTLS_MissingKeyFile verifies the second error branch: server.crt
// exists but server.key does not, so the key read fails after a successful cert read.
func TestSetupLegacyTLS_MissingKeyFile(t *testing.T) {
	certDir := t.TempDir()
	writeLegacyCertFiles(t, certDir)
	require.NoError(t, os.Remove(filepath.Join(certDir, "server.key")))

	cfg := config.DefaultConfig()
	cfg.CertPath = certDir
	s := &Server{cfg: cfg, logger: logging.NewNoopLogger()}

	tlsConfig, err := s.setupLegacyTLS()
	require.Error(t, err, "missing server.key must be reported even when server.crt is readable")
	assert.Nil(t, tlsConfig, "no TLS config may be returned when the key cannot be read")
	assert.Contains(t, err.Error(), "failed to read key file",
		"error must identify the key file, not the certificate, as the failing input")
	assert.ErrorIs(t, err, os.ErrNotExist,
		"underlying os error must be wrapped, not flattened into a string")
}

// TestSetupLegacyTLS_InvalidPEM verifies the third error branch: both files are
// readable but contain data that is not a valid certificate/key pair, so
// cert.CreateBasicTLSConfig rejects them.
func TestSetupLegacyTLS_InvalidPEM(t *testing.T) {
	certDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(certDir, "server.crt"), []byte("not a pem certificate"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(certDir, "server.key"), []byte("not a pem key"), 0600))

	cfg := config.DefaultConfig()
	cfg.CertPath = certDir
	s := &Server{cfg: cfg, logger: logging.NewNoopLogger()}

	tlsConfig, err := s.setupLegacyTLS()
	require.Error(t, err, "unparseable PEM data must fail TLS setup")
	assert.Nil(t, tlsConfig, "no TLS config may be returned when the key pair is invalid")
	assert.Contains(t, err.Error(), "failed to create TLS config",
		"error must attribute the failure to TLS config construction, not to file I/O")
}
