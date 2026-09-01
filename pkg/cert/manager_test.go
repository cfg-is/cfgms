// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
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
			if tt.config != nil && tt.config.StoragePath != "" {
				tt.config.StoragePath = t.TempDir()
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
	tempDir := t.TempDir()
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
	assert.Equal(t, CertificateTypePublicAPI, cert.Type)
	assert.Equal(t, "test-server", cert.CommonName)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotEmpty(t, cert.CertificatePEM)
	assert.NotEmpty(t, cert.PrivateKeyPEM)

	serverResult, err := manager.ValidateCertificate(cert.CertificatePEM)
	require.NoError(t, err)
	assert.True(t, serverResult.IsValid)

	// Verify certificate is stored
	storedCert, err := manager.GetCertificate(cert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, cert.CommonName, storedCert.CommonName)
}

func TestManager_SignClientCertificateRequest(t *testing.T) {
	tempDir := t.TempDir()
	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Caller generates its own keypair locally; the manager never sees the private key.
	callerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientConfig := &ClientCertConfig{
		CommonName:   "payload-signer",
		Organization: "Test Org",
		ClientID:     "payload-signer-001",
		ValidityDays: 365,
	}

	cert, err := manager.SignClientCertificateRequest(&callerKey.PublicKey, clientConfig)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate properties
	assert.Equal(t, CertificateTypeClient, cert.Type)
	assert.Equal(t, "payload-signer", cert.CommonName)
	assert.Equal(t, "payload-signer-001", cert.ClientID)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotEmpty(t, cert.CertificatePEM)

	// [REQUIRED TEST] no private key is returned or persisted for a CSR-issued cert.
	assert.Empty(t, cert.PrivateKeyPEM)

	clientResult, err := manager.ValidateCertificate(cert.CertificatePEM)
	require.NoError(t, err)
	assert.True(t, clientResult.IsValid)

	// Verify certificate is stored (metadata + cert.pem)
	storedCert, err := manager.GetCertificate(cert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, cert.CommonName, storedCert.CommonName)

	// [REQUIRED TEST] FileStore must not write a key.pem file for a CSR-issued
	// certificate — there is no private key to persist.
	keyPath := filepath.Join(tempDir, cert.SerialNumber, "key.pem")
	_, statErr := os.Stat(keyPath)
	assert.True(t, os.IsNotExist(statErr), "key.pem must not be written for a CSR-issued certificate")

	// cert.pem must still be written.
	certPath := filepath.Join(tempDir, cert.SerialNumber, "cert.pem")
	_, statErr = os.Stat(certPath)
	assert.NoError(t, statErr)
}

// TestManager_SignSubordinateCA verifies Manager.SignSubordinateCA delegates
// to CA.SignSubordinateCA with the same error and result shape as
// Manager.SignClientCertificateRequest.
func TestManager_SignSubordinateCA(t *testing.T) {
	tempDir := t.TempDir()
	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization:  "Test",
			Country:       "US",
			ValidityDays:  365,
			PathLength:    1,
			PathLengthSet: true,
		},
	})
	require.NoError(t, err)

	// Caller generates its own keypair locally; the manager never sees the private key.
	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	subConfig := &SubordinateCAConfig{
		CommonName:   "Test Intermediate CA",
		Organization: "Test Org",
		ValidityDays: 365,
		PathLength:   0,
	}

	cert, err := manager.SignSubordinateCA(&subKey.PublicKey, subConfig)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate properties
	assert.Equal(t, CertificateTypeCA, cert.Type)
	assert.Equal(t, "Test Intermediate CA", cert.CommonName)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotEmpty(t, cert.CertificatePEM)

	// No private key is returned or persisted for a subordinate CA signed
	// from a caller-supplied public key.
	assert.Empty(t, cert.PrivateKeyPEM)

	x509Cert, err := ParseCertificateFromPEM(cert.CertificatePEM)
	require.NoError(t, err)
	assert.True(t, x509Cert.IsCA)
	assert.Equal(t, 0, x509Cert.MaxPathLen)
	assert.True(t, x509Cert.MaxPathLenZero)

	// Verify certificate is stored (metadata + cert.pem)
	storedCert, err := manager.GetCertificate(cert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, cert.CommonName, storedCert.CommonName)

	// key.pem must not be written — there is no private key to persist.
	keyPath := filepath.Join(tempDir, cert.SerialNumber, "key.pem")
	_, statErr := os.Stat(keyPath)
	assert.True(t, os.IsNotExist(statErr), "key.pem must not be written for a subordinate CA signed from a caller-supplied public key")

	// cert.pem must still be written.
	certPath := filepath.Join(tempDir, cert.SerialNumber, "cert.pem")
	_, statErr = os.Stat(certPath)
	assert.NoError(t, statErr)
}

// TestManager_SignSubordinateCA_RejectsPathLengthZeroSigner verifies the
// manager wrapper surfaces the same rejection as CA.SignSubordinateCA when
// the signing CA is path-length-zero (today's default), and stores nothing.
func TestManager_SignSubordinateCA_RejectsPathLengthZeroSigner(t *testing.T) {
	tempDir := t.TempDir()
	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert, err := manager.SignSubordinateCA(&subKey.PublicKey, &SubordinateCAConfig{
		CommonName:   "Test Intermediate CA",
		Organization: "Test Org",
		ValidityDays: 365,
	})
	require.Error(t, err)
	assert.Nil(t, cert)
}

func TestManager_GenerateClientCertificate(t *testing.T) {
	tempDir := t.TempDir()
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

	clientResult, err := manager.ValidateCertificate(cert.CertificatePEM)
	require.NoError(t, err)
	assert.True(t, clientResult.IsValid)

	// Verify certificate is stored
	storedCert, err := manager.GetCertificate(cert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, cert.CommonName, storedCert.CommonName)
}

func TestManager_CertificateValidation(t *testing.T) {
	tempDir := t.TempDir()
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
	tempDir := t.TempDir()
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

	// Renew the certificate
	renewalConfig := &ServerCertConfig{
		CommonName:   "test-server",
		ValidityDays: 365,
	}

	renewedCert, err := manager.RenewCertificate(originalCert.SerialNumber, renewalConfig)
	require.NoError(t, err)
	require.NotNil(t, renewedCert)

	// Verify renewed certificate properties
	assert.Equal(t, CertificateTypePublicAPI, renewedCert.Type)
	assert.Equal(t, "test-server", renewedCert.CommonName)
	assert.NotEqual(t, originalCert.SerialNumber, renewedCert.SerialNumber)
	assert.True(t, renewedCert.ExpiresAt.After(originalCert.ExpiresAt))
}

func TestManager_ListCertificates(t *testing.T) {
	tempDir := t.TempDir()
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
	serverCerts, err := manager.GetAllValidCertificatesForPurpose(PurposeAPI)
	require.NoError(t, err)
	assert.Len(t, serverCerts, 1)

	clientCerts, err := manager.GetAllValidCertificatesForPurpose(PurposeClient)
	require.NoError(t, err)
	assert.Len(t, clientCerts, 1)
}

func TestManager_GetManagerStats(t *testing.T) {
	tempDir := t.TempDir()
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
	assert.Equal(t, 1, stats.CertificatesByType[CertificateTypePublicAPI])
	assert.Equal(t, 1, stats.CertificatesByType[CertificateTypeClient])
	assert.NotNil(t, stats.CAInfo)
	assert.Equal(t, CertificateTypeCA, stats.CAInfo.Type)
}

func TestManager_ImportExportCertificate(t *testing.T) {
	tempDir := t.TempDir()
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
	certPEM, keyPEM, err := manager.ExportCertificate(originalCert.SerialNumber, true, false)
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
	importedCert, err := manager.ImportCertificate(certPEM, keyPEM, CertificateTypePublicAPI)
	require.NoError(t, err)
	require.NotNil(t, importedCert)

	// Verify imported certificate
	assert.Equal(t, originalCert.CommonName, importedCert.CommonName)
	assert.Equal(t, originalCert.SerialNumber, importedCert.SerialNumber)
	assert.Equal(t, CertificateTypePublicAPI, importedCert.Type)
}

func TestManager_SaveCertificateFiles(t *testing.T) {
	tempDir := t.TempDir()
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

func TestManager_GetClientCertificate(t *testing.T) {
	tempDir := t.TempDir()
	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// No client cert in store yet — must return an error.
	_, err = manager.GetClientCertificate(ctx)
	assert.Error(t, err, "should error when no client cert exists")

	// Generate the first client certificate.
	cert1, err := manager.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-001",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// GetClientCertificate must return the cert successfully.
	tlsCert1, err := manager.GetClientCertificate(ctx)
	require.NoError(t, err)
	require.NotNil(t, tlsCert1)
	assert.NotEmpty(t, tlsCert1.Certificate, "TLS cert must contain the leaf certificate bytes")

	// Generate a second client certificate (simulates rotation).
	cert2, err := manager.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-001-renewed",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// GetClientCertificate must now return the newest cert — leaf bytes differ.
	tlsCert2, err := manager.GetClientCertificate(ctx)
	require.NoError(t, err)
	require.NotNil(t, tlsCert2)
	assert.NotEqual(t, cert1.SerialNumber, cert2.SerialNumber,
		"rotation must produce a cert with a different serial")
	// The leaf DER bytes are different between the two generated certs.
	assert.NotEqual(t, tlsCert1.Certificate[0], tlsCert2.Certificate[0],
		"second call must return the newer cert after rotation")
}

func TestManager_ValidateCertificate_SignedByDifferentCA(t *testing.T) {
	tempDir1 := t.TempDir()
	tempDir2 := t.TempDir()

	manager1, err := NewManager(&ManagerConfig{
		StoragePath: tempDir1,
		CAConfig:    &CAConfig{Organization: "TestOrg1", Country: "US", ValidityDays: 365},
	})
	require.NoError(t, err)

	manager2, err := NewManager(&ManagerConfig{
		StoragePath: tempDir2,
		CAConfig:    &CAConfig{Organization: "TestOrg2", Country: "US", ValidityDays: 365},
	})
	require.NoError(t, err)

	// Cert issued by manager2's CA — manager1 should reject it.
	cert, err := manager2.GenerateServerCertificate(&ServerCertConfig{
		CommonName:   "cross-ca-server",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	result, err := manager1.ValidateCertificate(cert.CertificatePEM)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.IsValid, "cert signed by a different CA must not be valid")
	require.NotEmpty(t, result.Errors, "expected at least one error")
	foundSig := false
	for _, e := range result.Errors {
		if strings.Contains(e, "signature") {
			foundSig = true
			break
		}
	}
	assert.True(t, foundSig, "expected a signature error; got: %v", result.Errors)
}

func TestManager_ValidateCertificate_Expired(t *testing.T) {
	tempDir := t.TempDir()
	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig:    &CAConfig{Organization: "Test", Country: "US", ValidityDays: 365},
	})
	require.NoError(t, err)

	expiredPEM := generateExpiredCertPEM(t, manager.ca)

	result, err := manager.ValidateCertificate(expiredPEM)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.IsValid, "expired cert must not be valid")
	assert.True(t, result.IsExpired, "IsExpired must be true for expired cert")
}

// generateExpiredCertPEM creates a cert signed by ca with NotAfter in the past.
func generateExpiredCertPEM(t *testing.T, ca *CA) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "expired-test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.privateKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// TestNewManagerFromSecretStore_InputValidation covers the error paths for missing
// required arguments.
func TestNewManagerFromSecretStore_InputValidation(t *testing.T) {
	ctx := context.Background()
	store := newInMemSecretStore()
	validConfig := &ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &CAConfig{Organization: "Test", Country: "US", ValidityDays: 365},
	}

	tests := []struct {
		name      string
		store     secretsinterfaces.SecretStore
		tenantID  string
		caKeyPath string
		config    *ManagerConfig
		wantErr   string
	}{
		{"nil store", nil, "root", "ca", validConfig, "secret store is required"},
		{"empty tenantID", store, "", "ca", validConfig, "tenantID and caKeyPath are required"},
		{"empty caKeyPath", store, "root", "", validConfig, "tenantID and caKeyPath are required"},
		{"nil config", store, "root", "ca", nil, "manager config is required"},
		{"empty StoragePath", store, "root", "ca", &ManagerConfig{
			CAConfig: &CAConfig{Organization: "Test"},
		}, "storage path is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewManagerFromSecretStore(ctx, tt.store, tt.tenantID, tt.caKeyPath, tt.config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestClusterCA_CrossInstanceValidation is the REQUIRED test for Issue #2018.
// It verifies that two Manager instances initialized from the same SecretStore-held CA
// produce leaf certificates that validate against each other's CA, and that no ca.key
// file exists in any controller-accessible path.
func TestClusterCA_CrossInstanceValidation(t *testing.T) {
	ctx := context.Background()
	store := newInMemSecretStore()

	dir1 := t.TempDir()
	dir2 := t.TempDir()

	caConfig := &CAConfig{
		Organization: "CFGMS Test Cluster",
		Country:      "US",
		ValidityDays: 3650,
	}

	// First Manager: bootstraps the CA and stores it in the secret store.
	mgr1, err := NewManagerFromSecretStore(ctx, store, "root", "cluster-ca", &ManagerConfig{
		StoragePath: dir1,
		CAConfig:    caConfig,
	})
	require.NoError(t, err, "first manager must initialise successfully")

	// Second Manager: loads the SAME CA from the secret store.
	mgr2, err := NewManagerFromSecretStore(ctx, store, "root", "cluster-ca", &ManagerConfig{
		StoragePath: dir2,
		CAConfig:    caConfig,
	})
	require.NoError(t, err, "second manager must load the CA from the store")

	// Verify both managers have the SAME CA (fingerprints must match).
	ca1Info, err := mgr1.GetCAInfo()
	require.NoError(t, err)
	ca2Info, err := mgr2.GetCAInfo()
	require.NoError(t, err)
	assert.Equal(t, ca1Info.Fingerprint, ca2Info.Fingerprint,
		"both managers must share the same CA fingerprint")

	// Issue a leaf cert from manager 1.
	leaf1, err := mgr1.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-node1",
		Organization: "CFGMS",
		ValidityDays: 30,
	})
	require.NoError(t, err)

	// Issue a leaf cert from manager 2.
	leaf2, err := mgr2.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-node2",
		Organization: "CFGMS",
		ValidityDays: 30,
	})
	require.NoError(t, err)

	// Leaf cert issued by mgr1 must validate against mgr2's CA (cross-instance trust).
	result1, err := mgr2.ValidateCertificate(leaf1.CertificatePEM)
	require.NoError(t, err)
	assert.True(t, result1.IsValid,
		"cert issued by node1 must be valid according to node2's CA")

	// Leaf cert issued by mgr2 must validate against mgr1's CA.
	result2, err := mgr1.ValidateCertificate(leaf2.CertificatePEM)
	require.NoError(t, err)
	assert.True(t, result2.IsValid,
		"cert issued by node2 must be valid according to node1's CA")

	// SECURITY: the CA private key must NOT be written to any node disk.
	for _, dir := range []string{dir1, dir2} {
		keyPaths := []string{
			filepath.Join(dir, "ca.key"),
			filepath.Join(dir, "ca", "ca.key"),
		}
		for _, kp := range keyPaths {
			_, statErr := os.Stat(kp)
			assert.True(t, os.IsNotExist(statErr),
				"ca.key must not exist at %s (CA key must remain in-process only)", kp)
		}
	}

	// SECURITY: the CA public cert MUST be present (required for TLS config).
	for _, dir := range []string{dir1, dir2} {
		assert.FileExists(t, filepath.Join(dir, "ca", "ca.crt"),
			"ca.crt must be written to disk for TLS config")
	}
}

// TestNewManagerFromSecretStore_NoCAConfigFails verifies that NewManagerFromSecretStore
// returns an error when the CA is absent from the store and no CAConfig is provided.
func TestNewManagerFromSecretStore_NoCAConfigFails(t *testing.T) {
	ctx := context.Background()
	store := newInMemSecretStore()

	_, err := NewManagerFromSecretStore(ctx, store, "root", "cluster-ca", &ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    nil,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA config required")
}

// buildIntermediateManagerForTest builds a root manager, signs a one-level-deep
// subordinate CA from it, and returns a Manager whose active CA identity is that
// subordinate — the Issue #3778 shape a controller cell backed by an imported
// regional intermediate has once S3's ImportSubordinateCA lands. Also returns the
// root CA certificate PEM (what the steward pins as its trust anchor).
func buildIntermediateManagerForTest(t *testing.T) (intermediate *Manager, rootCertPEM []byte) {
	t.Helper()

	rootMgr, err := NewManager(&ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &CAConfig{
			Organization:  "Test Root",
			Country:       "US",
			ValidityDays:  3650,
			PathLength:    1,
			PathLengthSet: true,
		},
	})
	require.NoError(t, err)

	rootCertPEM, err = rootMgr.GetCACertificate()
	require.NoError(t, err)

	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	subCert, err := rootMgr.SignSubordinateCA(&subKey.PublicKey, &SubordinateCAConfig{
		CommonName:   "Test Regional Intermediate",
		Organization: "Test Org",
		ValidityDays: 3650,
		PathLength:   0,
	})
	require.NoError(t, err)

	subKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(subKey),
	})

	intermediate, err = NewManagerFromCAMaterial(&ManagerConfig{
		StoragePath: t.TempDir(),
	}, subCert.CertificatePEM, subKeyPEM, rootCertPEM)
	require.NoError(t, err)

	return intermediate, rootCertPEM
}

// TestManager_GenerateClientCertificate_IntermediateCA_PopulatesIssuerChain
// proves the chain population plumbs all the way through the Manager, not just
// the underlying CA (ca_test.go covers the CA-level behavior directly).
// [REQUIRED TEST]
func TestManager_GenerateClientCertificate_IntermediateCA_PopulatesIssuerChain(t *testing.T) {
	intermediate, rootCertPEM := buildIntermediateManagerForTest(t)

	leaf, err := intermediate.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-001",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-001",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, leaf.IssuerChainPEM, "leaf issued by an intermediate-backed Manager must carry a non-empty issuer chain")

	// The trust anchor returned to callers must be the root, never the
	// intermediate's own currently-active certificate.
	anchorPEM, err := intermediate.GetCACertificate()
	require.NoError(t, err)
	assert.Equal(t, rootCertPEM, anchorPEM)
}

// TestManager_GenerateClientCertificate_RootCA_EmptyIssuerChain proves the
// self-hosted, root-only default is unaffected: a Manager backed by a plain root
// CA issues certificates with an empty IssuerChainPEM. [REQUIRED TEST]
func TestManager_GenerateClientCertificate_RootCA_EmptyIssuerChain(t *testing.T) {
	mgr, err := NewManager(&ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &CAConfig{
			Organization: "Test CFGMS",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	leaf, err := mgr.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-001",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-001",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	assert.Empty(t, leaf.IssuerChainPEM, "leaf issued by a root-only Manager must carry no issuer chain")
}

// TestManager_ExportCertificate_IncludeChain verifies the includeChain parameter
// appends IssuerChainPEM to the exported PEM only when requested.
func TestManager_ExportCertificate_IncludeChain(t *testing.T) {
	intermediate, _ := buildIntermediateManagerForTest(t)

	leaf, err := intermediate.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-001",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-001",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	require.NotEmpty(t, leaf.IssuerChainPEM)

	withoutChain, _, err := intermediate.ExportCertificate(leaf.SerialNumber, false, false)
	require.NoError(t, err)
	assert.Equal(t, leaf.CertificatePEM, withoutChain)

	withChain, _, err := intermediate.ExportCertificate(leaf.SerialNumber, false, true)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte{}, leaf.CertificatePEM...), leaf.IssuerChainPEM...), withChain)
}

// twoLevelChainMaterial is a root -> intermediate A -> intermediate B hierarchy,
// deep enough that chain ORDER is observable: a one-entry chain reads the same
// forwards and backwards, a two-entry chain does not.
type twoLevelChainMaterial struct {
	rootCertPEM []byte // self-signed root, path length 2
	interACert  []byte // signed by root, path length 1
	interBCert  []byte // signed by intermediate A, path length 0
	interBKey   []byte // intermediate B's private key
}

// buildTwoLevelChainMaterial signs a two-deep subordinate hierarchy off a fresh
// root and returns the raw PEM material for it, so issuer-chain validation can be
// exercised with correctly-ordered, reversed, and non-linking chains for the same
// certificate.
func buildTwoLevelChainMaterial(t *testing.T) twoLevelChainMaterial {
	t.Helper()

	rootMgr, err := NewManager(&ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &CAConfig{
			Organization:  "Test Root",
			Country:       "US",
			ValidityDays:  3650,
			PathLength:    2,
			PathLengthSet: true,
		},
	})
	require.NoError(t, err)

	rootCertPEM, err := rootMgr.GetCACertificate()
	require.NoError(t, err)

	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certA, err := rootMgr.SignSubordinateCA(&keyA.PublicKey, &SubordinateCAConfig{
		CommonName:   "Test Intermediate A",
		Organization: "Test Org",
		ValidityDays: 3650,
		PathLength:   1,
	})
	require.NoError(t, err)
	keyAPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyA),
	})

	mgrA, err := NewManagerFromCAMaterial(&ManagerConfig{
		StoragePath: t.TempDir(),
	}, certA.CertificatePEM, keyAPEM, rootCertPEM)
	require.NoError(t, err)

	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certB, err := mgrA.SignSubordinateCA(&keyB.PublicKey, &SubordinateCAConfig{
		CommonName:   "Test Intermediate B",
		Organization: "Test Org",
		ValidityDays: 3650,
		PathLength:   0,
	})
	require.NoError(t, err)
	keyBPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyB),
	})

	return twoLevelChainMaterial{
		rootCertPEM: rootCertPEM,
		interACert:  certA.CertificatePEM,
		interBCert:  certB.CertificatePEM,
		interBKey:   keyBPEM,
	}
}

// TestNewManagerFromCAMaterial_AcceptsCorrectlyOrderedChain is the positive
// control for the chain validation below: a genuine nearest-issuer-first /
// root-last chain two levels deep is accepted, and the trust anchor it publishes
// is the root.
func TestNewManagerFromCAMaterial_AcceptsCorrectlyOrderedChain(t *testing.T) {
	m := buildTwoLevelChainMaterial(t)

	mgr, err := NewManagerFromCAMaterial(&ManagerConfig{
		StoragePath: t.TempDir(),
	}, m.interBCert, m.interBKey, append(append([]byte{}, m.interACert...), m.rootCertPEM...))
	require.NoError(t, err)

	anchor, err := mgr.GetCACertificate()
	require.NoError(t, err)
	assert.Equal(t, m.rootCertPEM, anchor)
}

// TestNewManagerFromCAMaterial_RejectsReversedChain covers the fail-open case the
// security review found: the chain convention is root-LAST, the reverse of the
// conventional PEM bundle order an operator reaches for. Supplied root-first, the
// terminal entry is the INTERMEDIATE, which every steward would then TOFU-pin
// permanently as its root. Construction must fail closed instead.
func TestNewManagerFromCAMaterial_RejectsReversedChain(t *testing.T) {
	m := buildTwoLevelChainMaterial(t)

	reversed := append(append([]byte{}, m.rootCertPEM...), m.interACert...)

	mgr, err := NewManagerFromCAMaterial(&ManagerConfig{
		StoragePath: t.TempDir(),
	}, m.interBCert, m.interBKey, reversed)

	require.Error(t, err, "a root-first (reversed) issuer chain must be rejected, not pinned as the fleet trust anchor")
	assert.Nil(t, mgr)
	assert.Contains(t, err.Error(), "issuer chain")
}

// TestNewManagerFromCAMaterial_RejectsNonLinkingChain proves a chain with a gap
// is rejected: intermediate B's chain jumps straight to the root, skipping the
// intermediate A that actually issued it, so the chain does not link even though
// its terminal entry is a genuine self-signed root.
func TestNewManagerFromCAMaterial_RejectsNonLinkingChain(t *testing.T) {
	m := buildTwoLevelChainMaterial(t)

	mgr, err := NewManagerFromCAMaterial(&ManagerConfig{
		StoragePath: t.TempDir(),
	}, m.interBCert, m.interBKey, m.rootCertPEM)

	require.Error(t, err, "an issuer chain whose first entry did not issue the CA certificate must be rejected")
	assert.Nil(t, mgr)
	assert.Contains(t, err.Error(), "did not issue the CA certificate")
}

// TestNewManagerFromCAMaterial_RejectsChainTerminatingInIntermediate proves a
// chain that links correctly but stops short of the root is rejected: its
// terminal entry is intermediate A, which is not self-signed and must never
// become the pinned anchor.
func TestNewManagerFromCAMaterial_RejectsChainTerminatingInIntermediate(t *testing.T) {
	m := buildTwoLevelChainMaterial(t)

	mgr, err := NewManagerFromCAMaterial(&ManagerConfig{
		StoragePath: t.TempDir(),
	}, m.interBCert, m.interBKey, m.interACert)

	require.Error(t, err, "an issuer chain terminating in an intermediate must be rejected")
	assert.Nil(t, mgr)
	assert.Contains(t, err.Error(), "not a self-signed root")
}

// TestNewManagerFromCAMaterial_RejectsUnrelatedChain proves a chain from an
// entirely different hierarchy — a well-formed, self-signed root that simply did
// not issue this CA — cannot be substituted in as the trust anchor.
func TestNewManagerFromCAMaterial_RejectsUnrelatedChain(t *testing.T) {
	m := buildTwoLevelChainMaterial(t)

	foreignMgr, err := NewManager(&ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &CAConfig{
			Organization: "Foreign Root",
			Country:      "US",
			ValidityDays: 3650,
		},
	})
	require.NoError(t, err)
	foreignRootPEM, err := foreignMgr.GetCACertificate()
	require.NoError(t, err)

	mgr, err := NewManagerFromCAMaterial(&ManagerConfig{
		StoragePath: t.TempDir(),
	}, m.interBCert, m.interBKey, foreignRootPEM)

	require.Error(t, err, "an issuer chain from an unrelated hierarchy must be rejected")
	assert.Nil(t, mgr)
	assert.Contains(t, err.Error(), "did not issue the CA certificate")
}

// TestNewManagerFromCAMaterial_RejectsSubordinateWithEmptyChain proves the
// omitted-chain case fails closed too: an empty chain declares the supplied
// certificate to be the trust anchor itself, which is only true of a self-signed
// root. A subordinate passed with no chain would otherwise publish itself as the
// fleet anchor.
func TestNewManagerFromCAMaterial_RejectsSubordinateWithEmptyChain(t *testing.T) {
	m := buildTwoLevelChainMaterial(t)

	mgr, err := NewManagerFromCAMaterial(&ManagerConfig{
		StoragePath: t.TempDir(),
	}, m.interBCert, m.interBKey, nil)

	require.Error(t, err, "a subordinate CA supplied without an issuer chain must be rejected")
	assert.Nil(t, mgr)
	assert.Contains(t, err.Error(), "not self-signed")
}

// TestNewManagerFromCAMaterial_AcceptsSelfSignedRootWithEmptyChain is the
// positive control for the empty-chain rule: the root-only, self-hosted default
// still constructs and publishes its own certificate as the anchor.
func TestNewManagerFromCAMaterial_AcceptsSelfSignedRootWithEmptyChain(t *testing.T) {
	rootDir := t.TempDir()
	rootMgr, err := NewManager(&ManagerConfig{
		StoragePath: rootDir,
		CAConfig: &CAConfig{
			Organization: "Test Root",
			Country:      "US",
			ValidityDays: 3650,
		},
	})
	require.NoError(t, err)
	rootCertPEM, err := rootMgr.GetCACertificate()
	require.NoError(t, err)

	rootKeyPEM, err := os.ReadFile(filepath.Join(rootDir, "ca", "ca.key"))
	require.NoError(t, err)

	mgr, err := NewManagerFromCAMaterial(&ManagerConfig{
		StoragePath: t.TempDir(),
	}, rootCertPEM, rootKeyPEM, nil)
	require.NoError(t, err)

	anchor, err := mgr.GetCACertificate()
	require.NoError(t, err)
	assert.Equal(t, rootCertPEM, anchor)
}
