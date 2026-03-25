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
	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/cert"
	testpkg "github.com/cfgis/cfgms/pkg/testing"
)

// TestEnv provides a test environment for integration testing
type TestEnv struct {
	T                    *testing.T
	TempDir              string
	Logger               *testpkg.MockLogger
	Controller           *controller.Controller
	ControllerCfg        *config.Config
	Steward              *steward.Steward
	StewardCfg           *steward.Config
	CertManager          *cert.Manager
	ctx                  context.Context
	cancel               context.CancelFunc
	useDockerController  bool   // If true, connect to Docker controller instead of in-process
	dockerControllerAddr string // Address of Docker controller (e.g., "localhost:50054")
	registrationToken    string // Registration token for testing
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
			Provider: "git",
			Config: map[string]interface{}{
				"repository_path": filepath.Join(tempDir, "storage-git"),
				"encryption": map[string]interface{}{
					"enabled": false, // Disable encryption for tests
				},
			},
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

	stewardCfg := &steward.Config{
		ControllerAddr: controllerCfg.ListenAddr,
		CertPath:       certStoragePath, // Legacy cert path for backward compatibility
		DataDir:        filepath.Join(tempDir, "steward-data"),
		LogLevel:       "debug",
		ID:             "test-steward",
		Certificate: &steward.CertificateConfig{
			EnableCertManagement: false, // Disable cert management for steward in tests - uses controller's certs
			CertStoragePath:      certStoragePath,
			RenewalThresholdDays: 30,
			Provisioning: &steward.ProvisioningConfig{
				EnableAutoProvisioning: false, // Disable for tests
				ProvisioningEndpoint:   "/api/v1/certificates/provision",
				ValidityDays:           365,
				Organization:           "CFGMS Test Stewards",
			},
		},
	}

	// Create steward data directory
	err = os.MkdirAll(stewardCfg.DataDir, 0755)
	require.NoError(t, err)

	// Create steward using gRPC transport testing mode
	s, err := steward.NewForControllerTesting(stewardCfg, logger)
	require.NoError(t, err)

	// Create simple registration token for testing
	// Format: cfgms_reg_{tenant_id}_{steward_id}_{random}
	regToken := "cfgms_reg_test_tenant_test_steward_12345"

	// Transport client for steward will be set up during Start()
	// once we have the actual controller address

	return &TestEnv{
		T:                 t,
		TempDir:           tempDir,
		Logger:            logger,
		Controller:        ctrl,
		ControllerCfg:     controllerCfg,
		Steward:           s,
		StewardCfg:        stewardCfg,
		CertManager:       certManager,
		ctx:               ctx,
		cancel:            cancel,
		registrationToken: regToken,
	}
}

// Start starts the controller and steward in the test environment
func (e *TestEnv) Start() {
	var quicAddr string

	if e.useDockerController {
		// Using Docker controller - use docker gRPC transport address (port 4436)
		quicAddr = "localhost:4436"
		e.StewardCfg.ControllerAddr = e.dockerControllerAddr
	} else {
		// Start the in-process controller
		_ = e.Controller.Start(e.ctx)

		// Get actual controller addresses
		controllerAddr := e.Controller.GetListenAddr()
		e.StewardCfg.ControllerAddr = controllerAddr

		// gRPC transport address (controller listens on fixed port 4433)
		quicAddr = "localhost:4433"
	}

	// Create transport client for steward — uses gRPC-over-QUIC transport address
	transportClient, err := client.NewTransportClient(&client.TransportConfig{
		ControllerURL:     quicAddr,
		RegistrationToken: e.registrationToken,
		TLSCertPath:       e.StewardCfg.CertPath,
		Logger:            e.Logger,
	})
	if err != nil {
		e.T.Fatalf("Failed to create transport client: %v", err)
	}

	// For integration tests, skip registration and directly set steward ID
	// This avoids needing the full registration service to be running
	// The client will be configured when we call Connect() in the steward Start() method

	// Inject transport client into steward for testing
	e.Steward.SetTransportClientForTesting(transportClient)

	// Start the steward (will use injected transport client)
	if err := e.Steward.Start(e.ctx); err != nil {
		e.T.Logf("Warning: Steward start returned error (may be expected for testing): %v", err)
	}

	// Wait for components to initialize
	if e.useDockerController {
		time.Sleep(500 * time.Millisecond)
	} else {
		time.Sleep(100 * time.Millisecond)
	}
}

// Stop stops the controller and steward in the test environment
func (e *TestEnv) Stop() {
	// Stop the steward
	_ = e.Steward.Stop(e.ctx)

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

// CreateStewardClient is OBSOLETE - removed as part of Story #198 (MQTT+QUIC migration)
// The old gRPC client.Client no longer exists. Use client.NewTransportClient() instead.
// Tests using this method need to be updated for gRPC transport architecture.
// func (e *TestEnv) CreateStewardClient() (*client.Client, error) {
// 	actualAddr := e.Controller.GetListenAddr()
// 	return client.New(actualAddr, e.CertManager.GetStoragePath(), e.Logger)
// }
