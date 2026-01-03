// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
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
	registrationToken    string // MQTT registration token for testing
}

// NewTestEnvWithDocker creates a test environment that connects to Docker controller
// This is used to test against the standalone controller in docker-compose.test.yml
func NewTestEnvWithDocker(t *testing.T, dockerAddr string) *TestEnv {
	env := NewTestEnv(t)
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

	return createTestEnv(t, tempDir, logger, ctx, cancel)
}

// NewTestEnv creates a new test environment
func NewTestEnv(t *testing.T) *TestEnv {
	return NewTestEnvWithTimeout(t, 30*time.Second)
}

func createTestEnv(t *testing.T, tempDir string, logger *testpkg.MockLogger, ctx context.Context, cancel context.CancelFunc) *TestEnv {
	// Initialize production certificate manager for testing
	certStoragePath := filepath.Join(tempDir, "certs")
	err := os.MkdirAll(certStoragePath, 0755)
	require.NoError(t, err)

	certManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certStoragePath,
		CAConfig: &cert.CAConfig{
			Organization:       "CFGMS Test CA",
			Country:            "US",
			State:              "Test",
			City:               "Test",
			OrganizationalUnit: "Integration Tests",
			ValidityDays:       365,
			KeySize:            2048,
		},
		LoadExistingCA:       false, // Create new CA for each test
		RenewalThresholdDays: 30,
		EnableAutoRenewal:    false, // Disable for tests
	})
	require.NoError(t, err)

	// Generate server certificate for controller
	serverCert, err := certManager.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "cfgms-controller",
		DNSNames:     []string{"localhost", "cfgms-controller"},
		IPAddresses:  []string{"127.0.0.1"},
		Organization: "CFGMS Test",
		ValidityDays: 365,
		KeySize:      2048,
	})
	require.NoError(t, err)
	t.Logf("Generated server certificate: %s", serverCert.SerialNumber)

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
			EnableCertManagement:   true,
			CAPath:                 filepath.Join(certStoragePath, "ca"),
			AutoGenerate:           true,
			RenewalThresholdDays:   30,
			ServerCertValidityDays: 365,
			ClientCertValidityDays: 365,
			EnableAutoRenewal:      false, // Disable for tests
			Server: &config.ServerCertificateConfig{
				CommonName:   "cfgms-controller",
				DNSNames:     []string{"localhost", "cfgms-controller"},
				IPAddresses:  []string{"127.0.0.1"},
				Organization: "CFGMS Test",
			},
		},
		MQTT: &config.MQTTConfig{
			Enabled:        true,
			ListenAddr:     "127.0.0.1:1883",
			EnableTLS:      false,
			UseCertManager: true,
		},
		QUIC: &config.QUICConfig{
			Enabled:        true,
			ListenAddr:     "127.0.0.1:4433",
			SessionTimeout: 300,
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

	ctrl, err := controller.New(controllerCfg, logger)
	require.NoError(t, err)

	// Generate client certificate for steward
	clientCert, err := certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:         "test-steward",
		Organization:       "CFGMS Test Stewards",
		OrganizationalUnit: "Integration Tests",
		ValidityDays:       365,
		KeySize:            2048,
		ClientID:           "test-steward",
	})
	require.NoError(t, err)
	t.Logf("Generated client certificate: %s", clientCert.SerialNumber)

	// Save certificates to files for backward compatibility with legacy client
	err = certManager.SaveCertificateFiles(serverCert.SerialNumber,
		filepath.Join(certStoragePath, "server.crt"),
		filepath.Join(certStoragePath, "server.key"))
	require.NoError(t, err)

	err = certManager.SaveCertificateFiles(clientCert.SerialNumber,
		filepath.Join(certStoragePath, "client.crt"),
		filepath.Join(certStoragePath, "client.key"))
	require.NoError(t, err)

	// Save CA certificate
	caCertPEM, err := certManager.GetCACertificate()
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(certStoragePath, "ca.crt"), caCertPEM, 0644)
	require.NoError(t, err)

	stewardCfg := &steward.Config{
		ControllerAddr: controllerCfg.ListenAddr,
		CertPath:       certStoragePath, // Legacy cert path for backward compatibility
		DataDir:        filepath.Join(tempDir, "steward-data"),
		LogLevel:       "debug",
		ID:             "test-steward",
		Certificate: &steward.CertificateConfig{
			EnableCertManagement: false, // Disable cert management for steward in tests
			CertStoragePath:      certStoragePath,
			EnableAutoRenewal:    false, // Disable for tests
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

	// Create steward using new MQTT+QUIC testing mode
	s, err := steward.NewForControllerTesting(stewardCfg, logger)
	require.NoError(t, err)

	// Create simple registration token for testing
	// Format: cfgms_reg_{tenant_id}_{steward_id}_{random}
	regToken := "cfgms_reg_test_tenant_test_steward_12345"

	// Create MQTT client for steward (will be set up during Start())
	// Note: We'll create this in Start() since we need the actual controller address
	// For now, just create the steward with the testing constructor

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
	var mqttBrokerAddr string
	var quicAddr string

	if e.useDockerController {
		// Using Docker controller - use docker addresses
		// Docker standalone controller uses ports 1886 (MQTT) and 4436 (QUIC)
		mqttBrokerAddr = "tcp://localhost:1886"
		quicAddr = "localhost:4436"
		e.StewardCfg.ControllerAddr = e.dockerControllerAddr
	} else {
		// Start the in-process controller
		_ = e.Controller.Start(e.ctx)

		// Get actual controller addresses
		controllerAddr := e.Controller.GetListenAddr()
		e.StewardCfg.ControllerAddr = controllerAddr

		// Extract host for MQTT/QUIC (controller provides these on fixed ports)
		mqttBrokerAddr = "tcp://localhost:1883" // Controller MQTT broker
		quicAddr = "localhost:4433"             // Controller QUIC server
	}

	// Create MQTT client for steward
	mqttClient, err := client.NewMQTTClient(&client.MQTTConfig{
		ControllerURL:     mqttBrokerAddr,
		QUICAddress:       quicAddr,
		RegistrationToken: e.registrationToken,
		TLSCertPath:       e.StewardCfg.CertPath,
		Logger:            e.Logger,
	})
	if err != nil {
		e.T.Fatalf("Failed to create MQTT client: %v", err)
	}

	// For integration tests, skip registration and directly set steward ID
	// This avoids needing the full registration service to be running
	// The client will be configured when we call Connect() in the steward Start() method

	// Inject MQTT client into steward for testing
	e.Steward.SetMQTTClientForTesting(mqttClient)

	// Start the steward (will use injected MQTT client)
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
// The old gRPC client.Client no longer exists. Use client.NewMQTTClient() instead.
// Tests using this method need to be updated for MQTT+QUIC architecture.
// func (e *TestEnv) CreateStewardClient() (*client.Client, error) {
// 	actualAddr := e.Controller.GetListenAddr()
// 	return client.New(actualAddr, e.CertManager.GetStoragePath(), e.Logger)
// }
