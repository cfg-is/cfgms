// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package testutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/cert"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	testpkg "github.com/cfgis/cfgms/pkg/testing"
)

// TestEnv provides a test environment for integration testing.
// Controller-connected tests use TransportClient directly (production-mirroring pattern).
// For steward convergence-loop testing, build a *steward.Steward via steward.NewStandalone().
type TestEnv struct {
	T                    *testing.T
	TempDir              string
	Logger               *testpkg.MockLogger
	Controller           *controller.Controller
	ControllerCfg        *config.Config
	TransportClient      *client.TransportClient
	CertManager          *cert.Manager
	ctx                  context.Context
	cancel               context.CancelFunc
	useDockerController  bool   // If true, connect to Docker controller instead of in-process
	dockerControllerAddr string // Address of Docker controller (e.g., "localhost:50054")
	registrationToken    string // Registration token for testing
	certStoragePath      string // Certificate storage path used for TransportClient TLS
}

// NewTestEnvWithDocker creates a test environment that connects to Docker controller
// This is used to test against the standalone controller in docker-compose.test.yml
func NewTestEnvWithDocker(t *testing.T, dockerAddr string) *TestEnv {
	tempDir, err := os.MkdirTemp("", "cfgms-test-")
	require.NoError(t, err)

	logger := testpkg.NewMockLogger(false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	env := createTestEnv(t, tempDir, logger, ctx, cancel, false, "")
	env.useDockerController = true
	env.dockerControllerAddr = dockerAddr
	return env
}

// NewTestEnvWithTimeout creates a test environment with custom context timeout
func NewTestEnvWithTimeout(t *testing.T, timeout time.Duration) *TestEnv {
	tempDir, err := os.MkdirTemp("", "cfgms-test-")
	require.NoError(t, err)

	logger := testpkg.NewMockLogger(false)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	return createTestEnv(t, tempDir, logger, ctx, cancel, false, "")
}

// NewTestEnvWithSharedCerts creates a test environment that reuses existing certificates
// from a shared certificate storage path. This simulates a controller reboot scenario
// where certificates are already present on disk.
//
// Use this for test suites where you want to:
// - Test certificate persistence across restarts
// - Optimize test performance by generating certs once
// - Validate LoadExistingCA code path
//
// Example usage in a test suite:
//
//	func (s *MySuite) SetupSuite() {
//	    s.sharedCertPath = s.T().TempDir()
//	    // First test will generate certs
//	    s.env = NewTestEnvWithSharedCerts(s.T(), s.sharedCertPath)
//	}
//
//	func (s *MySuite) SetupTest() {
//	    // Subsequent tests reuse certs (simulates reboot)
//	    s.env = NewTestEnvWithSharedCerts(s.T(), s.sharedCertPath)
//	}
func NewTestEnvWithSharedCerts(t *testing.T, sharedCertPath string) *TestEnv {
	tempDir, err := os.MkdirTemp("", "cfgms-test-")
	require.NoError(t, err)

	logger := testpkg.NewMockLogger(false)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	return createTestEnv(t, tempDir, logger, ctx, cancel, true, sharedCertPath)
}

// NewTestEnv creates a new test environment
func NewTestEnv(t *testing.T) *TestEnv {
	return NewTestEnvWithTimeout(t, 30*time.Second)
}

func createTestEnv(t *testing.T, tempDir string, logger *testpkg.MockLogger, ctx context.Context, cancel context.CancelFunc, useSharedCerts bool, sharedCertPath string) *TestEnv {
	// Determine certificate storage path
	var certStoragePath string

	if useSharedCerts && sharedCertPath != "" {
		// Use shared certificate storage (simulates controller reboot)
		certStoragePath = sharedCertPath

		// Check if CA already exists to log appropriate message
		caPath := filepath.Join(certStoragePath, "ca", "ca.crt")
		if _, err := os.Stat(caPath); err == nil {
			t.Logf("Controller will load existing certificates from shared storage (simulates reboot)")
		} else {
			t.Logf("Controller will generate new certificates in shared storage (first test in suite)")
		}
	} else {
		// Isolated test environment (fresh deployment scenario)
		certStoragePath = filepath.Join(tempDir, "certs")
		t.Logf("Controller will generate fresh certificates (isolated test)")
	}

	// Create cert storage directory
	err := os.MkdirAll(certStoragePath, 0755)
	require.NoError(t, err)

	controllerCfg := &config.Config{
		ListenAddr: "127.0.0.1:0",   // Use random port
		CertPath:   certStoragePath, // Legacy cert path for backward compatibility
		DataDir:    filepath.Join(tempDir, "controller-data"),
		LogLevel:   "debug",
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: filepath.Join(tempDir, "storage-flatfile"),
			SQLitePath:   filepath.Join(tempDir, "cfgms.db"),
		},
		Certificate: &config.CertificateConfig{
			EnableCertManagement:   true, // Enable full certificate lifecycle management
			CAPath:                 filepath.Join(certStoragePath, "ca"),
			RenewalThresholdDays:   30,
			ServerCertValidityDays: 365,
			ClientCertValidityDays: 365,
			Server: &config.ServerCertificateConfig{
				CommonName:   "cfgms-controller",
				DNSNames:     []string{"localhost", "cfgms-controller"},
				IPAddresses:  []string{"127.0.0.1"},
				Organization: "CFGMS Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
		},
	}

	// Create controller data directory
	err = os.MkdirAll(controllerCfg.DataDir, 0755)
	require.NoError(t, err)

	// Create storage directory
	storageDir := filepath.Join(tempDir, "storage-git")
	err = os.MkdirAll(storageDir, 0755)
	require.NoError(t, err)

	// Pre-initialize if not already initialized (Story #410: first-run init guard)
	caPath := controllerCfg.Certificate.CAPath
	if !initialization.IsInitialized(caPath) && !initialization.CAFilesExist(caPath) {
		t.Logf("Pre-initializing controller for test (Story #410 init guard)")
		initResult, initErr := initialization.Run(controllerCfg, logger)
		require.NoError(t, initErr, "Failed to pre-initialize controller for test")
		t.Logf("Controller pre-initialized, CA fingerprint: %s", initResult.CAFingerprint)
	}

	// Create controller - loads existing CA from pre-initialization
	ctrl, err := controller.New(controllerCfg, logger)
	require.NoError(t, err)

	// Get the cert manager that the controller created and initialized
	// This contains either newly generated certs or loaded existing certs
	certManager := ctrl.GetCertificateManager()
	require.NotNil(t, certManager, "Controller should have initialized cert manager")

	// The controller has already generated/loaded CA and server certificates.
	// For tests that need client certificates before steward registration, generate one now.
	// This simulates having a client certificate available for testing mTLS scenarios.
	_, err = certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: "test-steward",
	})
	if err != nil {
		t.Logf("Note: Client certificate generation failed: %v (may already exist)", err)
	}

	// Create simple registration token for testing
	// Format: cfgms_reg_{tenant_id}_{steward_id}_{random}
	regToken := "cfgms_reg_test_tenant_test_steward_12345"

	return &TestEnv{
		T:                 t,
		TempDir:           tempDir,
		Logger:            logger,
		Controller:        ctrl,
		ControllerCfg:     controllerCfg,
		CertManager:       certManager,
		ctx:               ctx,
		cancel:            cancel,
		registrationToken: regToken,
		certStoragePath:   certStoragePath,
	}
}

// Start starts the controller and creates the transport client.
// Mirrors the production pattern in cmd/steward/main.go: controller-connected
// operation uses client.NewTransportClient directly.
func (e *TestEnv) Start() {
	var quicAddr string

	if e.useDockerController {
		// Using Docker controller - use docker gRPC transport address (port 4436)
		quicAddr = "localhost:4436"
	} else {
		// Start the in-process controller
		if err := e.Controller.Start(e.ctx); err != nil {
			e.T.Fatalf("Failed to start controller: %v", err)
		}

		// Get actual QUIC transport address (may be OS-assigned if port 0 is configured)
		quicAddr = e.Controller.GetTransportListenAddr()
	}

	// Get CA cert PEM from cert manager so the transport client can verify the
	// controller's server certificate (issued by the same CA).
	caCertPEM, caErr := e.CertManager.GetCACertificate()
	if caErr != nil {
		e.T.Logf("Warning: Could not get CA cert for transport client TLS: %v", caErr)
	}

	// Create transport client — mirrors cmd/steward/main.go production pattern.
	// Pass the CertManager from the test environment so on-demand cert loading is
	// exercised in integration tests (Issue #920).
	transportClient, err := client.NewTransportClient(&client.TransportConfig{
		ControllerURL:     quicAddr,
		RegistrationToken: e.registrationToken,
		TLSCertPath:       e.certStoragePath,
		CACertPEM:         string(caCertPEM),
		CertManager:       e.CertManager,
		Logger:            e.Logger,
	})
	if err != nil {
		e.T.Fatalf("Failed to create transport client: %v", err)
	}
	e.TransportClient = transportClient

	// Set steward ID before connecting — Connect() requires this to subscribe to commands.
	// In production this is set after HTTP registration; for integration tests we use the
	// test steward ID derived from the registration token (format: cfgms_reg_{tenant}_{steward}_{rand}).
	transportClient.SetStewardID("test-steward")

	// Attempt to connect — failure is expected in some test configurations where
	// the QUIC transport listener is not yet accepting (logged as warning, not fatal).
	if err := transportClient.Connect(e.ctx); err != nil {
		e.T.Logf("Warning: Transport connect returned error (may be expected for testing): %v", err)
	}

	// Wait for components to initialize
	if e.useDockerController {
		time.Sleep(500 * time.Millisecond)
	} else {
		time.Sleep(100 * time.Millisecond)
	}
}

// Stop stops the transport client and controller in the test environment
func (e *TestEnv) Stop() {
	// Disconnect transport client if started
	if e.TransportClient != nil {
		_ = e.TransportClient.Disconnect(e.ctx)
		e.TransportClient = nil
	}

	// Stop global data plane provider to allow subsequent Connect() calls in the same process.
	// The gRPC data plane provider is a process-level singleton; Disconnect() closes the session
	// but leaves the provider in "started" state — Stop() resets it for re-use.
	if dpProvider := dataplaneInterfaces.GetProvider("grpc"); dpProvider != nil {
		_ = dpProvider.Stop(e.ctx)
	}

	// Only stop controller if it's in-process (not Docker)
	if !e.useDockerController && e.Controller != nil {
		_ = e.Controller.Stop(e.ctx)
	}
}

// Cleanup cleans up the test environment
func (e *TestEnv) Cleanup() {
	e.cancel()

	// Remove temporary directory
	if e.TempDir != "" {
		if err := os.RemoveAll(e.TempDir); err != nil {
			// Log error but continue cleanup
			_ = err // Explicitly ignore cleanup errors for temp directory
		}
	}
}

// Reset resets the test environment for a new test
func (e *TestEnv) Reset() {
	e.Logger.Reset()
}

// GetContext returns the context for the test environment
func (e *TestEnv) GetContext() context.Context {
	return e.ctx
}

// GetCertificateManager returns the certificate manager for testing
func (e *TestEnv) GetCertificateManager() *cert.Manager {
	return e.CertManager
}

// ValidateCertificateSetup validates that certificates are properly configured
func (e *TestEnv) ValidateCertificateSetup() error {
	// Check that CA is initialized
	caCerts, err := e.CertManager.GetCertificatesByType(cert.CertificateTypeCA)
	if err != nil {
		return err
	}
	if len(caCerts) == 0 {
		return fmt.Errorf("no CA certificates found")
	}

	// Check that server certificate exists
	serverCerts, err := e.CertManager.GetCertificatesByType(cert.CertificateTypeServer)
	if err != nil {
		return err
	}
	if len(serverCerts) == 0 {
		return fmt.Errorf("no server certificates found")
	}

	// Check that client certificate exists
	clientCerts, err := e.CertManager.GetCertificatesByType(cert.CertificateTypeClient)
	if err != nil {
		return err
	}
	if len(clientCerts) == 0 {
		return fmt.Errorf("no client certificates found")
	}

	return nil
}

// GenerateNewClientCertificate generates a new client certificate for testing
func (e *TestEnv) GenerateNewClientCertificate(clientID string) (*cert.Certificate, error) {
	return e.CertManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:         clientID,
		Organization:       "CFGMS Test Stewards",
		OrganizationalUnit: "Integration Tests",
		ValidityDays:       365,
		KeySize:            2048,
		ClientID:           clientID,
	})
}

// GetCertificateInfo returns certificate information for testing
func (e *TestEnv) GetCertificateInfo(certType cert.CertificateType) ([]*cert.CertificateInfo, error) {
	return e.CertManager.GetCertificatesByType(certType)
}
