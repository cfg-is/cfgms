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
	T             *testing.T
	TempDir       string
	Logger        *testpkg.MockLogger
	Controller    *controller.Controller
	ControllerCfg *config.Config
	Steward       *steward.Steward
	StewardCfg    *steward.Config
	CertManager   *cert.Manager
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewTestEnv creates a new test environment
func NewTestEnv(t *testing.T) *TestEnv {
	tempDir, err := os.MkdirTemp("", "cfgms-test-")
	require.NoError(t, err)

	logger := testpkg.NewMockLogger(false)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	// Initialize production certificate manager for testing
	certStoragePath := filepath.Join(tempDir, "certs")
	err = os.MkdirAll(certStoragePath, 0755)
	require.NoError(t, err)

	certManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certStoragePath,
		CAConfig: &cert.CAConfig{
			Organization:       "CFGMS Test CA",
			Country:           "US",
			State:             "Test",
			City:              "Test",
			OrganizationalUnit: "Integration Tests",
			ValidityDays:      365,
			KeySize:           2048,
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
		ListenAddr: "127.0.0.1:0", // Use random port
		CertPath:   certStoragePath, // Legacy cert path for backward compatibility
		DataDir:    filepath.Join(tempDir, "controller-data"),
		LogLevel:   "debug",
		Certificate: &config.CertificateConfig{
			EnableCertManagement:   true,
			CAPath:                filepath.Join(certStoragePath, "ca"),
			AutoGenerate:          true,
			RenewalThresholdDays:  30,
			ServerCertValidityDays: 365,
			ClientCertValidityDays: 365,
			EnableAutoRenewal:     false, // Disable for tests
			Server: &config.ServerCertificateConfig{
				CommonName:   "cfgms-controller",
				DNSNames:     []string{"localhost", "cfgms-controller"},
				IPAddresses:  []string{"127.0.0.1"},
				Organization: "CFGMS Test",
			},
		},
	}

	// Create controller data directory
	err = os.MkdirAll(controllerCfg.DataDir, 0755)
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
			EnableCertManagement:  false, // Disable cert management for steward in tests
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

	s, err := steward.New(stewardCfg, logger)
	require.NoError(t, err)

	return &TestEnv{
		T:             t,
		TempDir:       tempDir,
		Logger:        logger,
		Controller:    ctrl,
		ControllerCfg: controllerCfg,
		Steward:       s,
		StewardCfg:    stewardCfg,
		CertManager:   certManager,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start starts the controller and steward in the test environment
func (e *TestEnv) Start() {
	// Start the controller
	_ = e.Controller.Start(e.ctx)

	// Update steward config with actual controller address
	e.StewardCfg.ControllerAddr = e.Controller.GetListenAddr()

	// Start the steward
	_ = e.Steward.Start(e.ctx)

	// Wait for components to initialize
	time.Sleep(100 * time.Millisecond)
}

// Stop stops the controller and steward in the test environment
func (e *TestEnv) Stop() {
	// Stop the steward
	_ = e.Steward.Stop(e.ctx)

	// Stop the controller
	_ = e.Controller.Stop(e.ctx)
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

// CreateStewardClient creates a new steward client for testing
func (e *TestEnv) CreateStewardClient() (*client.Client, error) {
	// Use actual server address after binding (important for :0 ports)
	actualAddr := e.Controller.GetListenAddr()
	return client.New(actualAddr, e.CertManager.GetStoragePath(), e.Logger)
}
