// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cert

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name        string
		config      *ManagerConfig
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "missing storage path",
			config: &ManagerConfig{
				CAConfig: &CAConfig{
					Organization: "Test",
					Country:      "US",
				},
			},
			expectError: true,
		},
		{
			name: "missing CA config for new CA",
			config: &ManagerConfig{
				StoragePath:    "test_storage",
				LoadExistingCA: false,
			},
			expectError: true,
		},
		{
			name: "valid config for new CA",
			config: &ManagerConfig{
				StoragePath: "test_storage",
				CAConfig: &CAConfig{
					Organization: "Test",
					Country:      "US",
					ValidityDays: 365,
				},
				LoadExistingCA: false,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for storage
			if tt.config != nil && tt.config.StoragePath != "" {
				tempDir, err := os.MkdirTemp("", "cert-test-")
				require.NoError(t, err)
				defer func() {
					if err := os.RemoveAll(tempDir); err != nil {
						t.Logf("Failed to remove temp directory: %v", err)
					}
				}()

				tt.config.StoragePath = tempDir
			}

			manager, err := NewManager(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
			}
		})
	}
}

func TestManager_GenerateServerCertificate(t *testing.T) {
	// Setup
	tempDir, err := os.MkdirTemp("", "cert-test-")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to clean up temp directory: %v", err)
		}
	}()

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Test certificate generation
	serverConfig := &ServerCertConfig{
		CommonName:   "test-server",
		DNSNames:     []string{"localhost", "test.local"},
		IPAddresses:  []string{"127.0.0.1"},
		Organization: "Test Org",
		ValidityDays: 365,
	}

	cert, err := manager.GenerateServerCertificate(serverConfig)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate properties
	assert.Equal(t, CertificateTypeServer, cert.Type)
	assert.Equal(t, "test-server", cert.CommonName)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotEmpty(t, cert.CertificatePEM)
	assert.NotEmpty(t, cert.PrivateKeyPEM)
	assert.True(t, cert.IsValid)

	// Verify certificate is stored
	storedCert, err := manager.GetCertificate(cert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, cert.CommonName, storedCert.CommonName)
}

func TestManager_GenerateClientCertificate(t *testing.T) {
	// Setup
	tempDir, err := os.MkdirTemp("", "cert-test-")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to clean up temp directory: %v", err)
		}
	}()

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Test certificate generation
	clientConfig := &ClientCertConfig{
		CommonName:   "test-client",
		Organization: "Test Org",
		ClientID:     "client-001",
		ValidityDays: 365,
	}

	cert, err := manager.GenerateClientCertificate(clientConfig)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate properties
	assert.Equal(t, CertificateTypeClient, cert.Type)
	assert.Equal(t, "test-client", cert.CommonName)
	assert.Equal(t, "client-001", cert.ClientID)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotEmpty(t, cert.CertificatePEM)
	assert.NotEmpty(t, cert.PrivateKeyPEM)
	assert.True(t, cert.IsValid)

	// Verify certificate is stored
	storedCert, err := manager.GetCertificate(cert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, cert.CommonName, storedCert.CommonName)
}

func TestManager_CertificateValidation(t *testing.T) {
	// Setup
	tempDir, err := os.MkdirTemp("", "cert-test-")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to clean up temp directory: %v", err)
		}
	}()

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Generate a certificate
	serverConfig := &ServerCertConfig{
		CommonName:   "test-server",
		ValidityDays: 365,
	}

	cert, err := manager.GenerateServerCertificate(serverConfig)
	require.NoError(t, err)

	// Validate the certificate
	validationResult, err := manager.ValidateCertificate(cert.CertificatePEM)
	require.NoError(t, err)
	require.NotNil(t, validationResult)

	assert.True(t, validationResult.IsValid)
	assert.Empty(t, validationResult.Errors)
	assert.False(t, validationResult.IsExpired)
	assert.Greater(t, validationResult.DaysUntilExpiration, 0)
}

func TestManager_CertificateRenewal(t *testing.T) {
	// Setup
	tempDir, err := os.MkdirTemp("", "cert-test-")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to clean up temp directory: %v", err)
		}
	}()

	manager, err := NewManager(&ManagerConfig{
		StoragePath:       tempDir,
		EnableAutoRenewal: true,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Generate a certificate with short validity for testing
	serverConfig := &ServerCertConfig{
		CommonName:   "test-server",
		ValidityDays: 1, // Very short validity for testing
	}

	originalCert, err := manager.GenerateServerCertificate(serverConfig)
	require.NoError(t, err)

	// Wait a moment to ensure different timestamps
	time.Sleep(100 * time.Millisecond)

	// Renew the certificate
	renewalConfig := &ServerCertConfig{
		CommonName:   "test-server",
		ValidityDays: 365,
	}

	renewedCert, err := manager.RenewCertificate(originalCert.SerialNumber, renewalConfig)
	require.NoError(t, err)
	require.NotNil(t, renewedCert)

	// Verify renewed certificate properties
	assert.Equal(t, CertificateTypeServer, renewedCert.Type)
	assert.Equal(t, "test-server", renewedCert.CommonName)
	assert.NotEqual(t, originalCert.SerialNumber, renewedCert.SerialNumber)
	assert.True(t, renewedCert.CreatedAt.After(originalCert.CreatedAt))
	assert.True(t, renewedCert.ExpiresAt.After(originalCert.ExpiresAt))
}

func TestManager_ListCertificates(t *testing.T) {
	// Setup
	tempDir, err := os.MkdirTemp("", "cert-test-")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to clean up temp directory: %v", err)
		}
	}()

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Generate multiple certificates
	serverConfig := &ServerCertConfig{
		CommonName:   "server-1",
		ValidityDays: 365,
	}
	_, err = manager.GenerateServerCertificate(serverConfig)
	require.NoError(t, err)

	clientConfig := &ClientCertConfig{
		CommonName:   "client-1",
		ClientID:     "client-001",
		ValidityDays: 365,
	}
	_, err = manager.GenerateClientCertificate(clientConfig)
	require.NoError(t, err)

	// List all certificates
	certs, err := manager.ListCertificates()
	require.NoError(t, err)
	assert.Len(t, certs, 2)

	// Verify certificate types
	serverCerts, err := manager.GetCertificatesByType(CertificateTypeServer)
	require.NoError(t, err)
	assert.Len(t, serverCerts, 1)

	clientCerts, err := manager.GetCertificatesByType(CertificateTypeClient)
	require.NoError(t, err)
	assert.Len(t, clientCerts, 1)
}

func TestManager_GetManagerStats(t *testing.T) {
	// Setup
	tempDir, err := os.MkdirTemp("", "cert-test-")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to clean up temp directory: %v", err)
		}
	}()

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Generate certificates
	_, err = manager.GenerateServerCertificate(&ServerCertConfig{
		CommonName:   "server-1",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	_, err = manager.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "client-1",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Get manager statistics
	stats, err := manager.GetManagerStats()
	require.NoError(t, err)
	require.NotNil(t, stats)

	assert.Equal(t, 2, stats.TotalCertificates)
	assert.Equal(t, 1, stats.CertificatesByType[CertificateTypeServer])
	assert.Equal(t, 1, stats.CertificatesByType[CertificateTypeClient])
	assert.NotNil(t, stats.CAInfo)
	assert.Equal(t, CertificateTypeCA, stats.CAInfo.Type)
}

func TestManager_ImportExportCertificate(t *testing.T) {
	// Setup
	tempDir, err := os.MkdirTemp("", "cert-test-")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to clean up temp directory: %v", err)
		}
	}()

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Generate a certificate
	serverConfig := &ServerCertConfig{
		CommonName:   "test-server",
		ValidityDays: 365,
	}

	originalCert, err := manager.GenerateServerCertificate(serverConfig)
	require.NoError(t, err)

	// Export the certificate
	certPEM, keyPEM, err := manager.ExportCertificate(originalCert.SerialNumber, true)
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM)
	assert.NotEmpty(t, keyPEM)

	// Delete the original certificate
	err = manager.DeleteCertificate(originalCert.SerialNumber)
	require.NoError(t, err)

	// Verify it's deleted
	_, err = manager.GetCertificate(originalCert.SerialNumber)
	assert.Error(t, err)

	// Import the certificate back
	importedCert, err := manager.ImportCertificate(certPEM, keyPEM, CertificateTypeServer)
	require.NoError(t, err)
	require.NotNil(t, importedCert)

	// Verify imported certificate
	assert.Equal(t, originalCert.CommonName, importedCert.CommonName)
	assert.Equal(t, originalCert.SerialNumber, importedCert.SerialNumber)
	assert.Equal(t, CertificateTypeServer, importedCert.Type)
}

func TestManager_SaveCertificateFiles(t *testing.T) {
	// Setup
	tempDir, err := os.MkdirTemp("", "cert-test-")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to clean up temp directory: %v", err)
		}
	}()

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Generate a certificate
	serverConfig := &ServerCertConfig{
		CommonName:   "test-server",
		ValidityDays: 365,
	}

	cert, err := manager.GenerateServerCertificate(serverConfig)
	require.NoError(t, err)

	// Save certificate files
	certPath := filepath.Join(tempDir, "server.crt")
	keyPath := filepath.Join(tempDir, "server.key")

	err = manager.SaveCertificateFiles(cert.SerialNumber, certPath, keyPath)
	require.NoError(t, err)

	// Verify files exist
	assert.FileExists(t, certPath)
	assert.FileExists(t, keyPath)

	// Verify file contents
	savedCertPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, cert.CertificatePEM, savedCertPEM)

	savedKeyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, cert.PrivateKeyPEM, savedKeyPEM)
}
