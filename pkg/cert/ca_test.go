// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

func TestNewCA(t *testing.T) {
	tests := []struct {
		name        string
		config      *CAConfig
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "valid config",
			config: &CAConfig{
				Organization: "Test CA",
				Country:      "US",
				ValidityDays: 365,
				KeySize:      2048,
			},
			expectError: false,
		},
		{
			name:   "config with defaults",
			config: &CAConfig{
				// Only required fields, others should use defaults
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca, err := NewCA(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, ca)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ca)
				assert.False(t, ca.IsInitialized())
			}
		})
	}
}

func TestCA_Initialize(t *testing.T) {
	config := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		State:        "CA",
		City:         "San Francisco",
		ValidityDays: 365,
		KeySize:      2048,
	}

	ca, err := NewCA(config)
	require.NoError(t, err)

	err = ca.Initialize(config)
	require.NoError(t, err)

	assert.True(t, ca.IsInitialized())

	// Test CA certificate properties
	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	assert.NotEmpty(t, caCertPEM)

	// Parse and verify the CA certificate
	caCert, err := ParseCertificateFromPEM(caCertPEM)
	require.NoError(t, err)

	assert.True(t, caCert.IsCA)
	assert.Equal(t, "Test CA Root CA", caCert.Subject.CommonName)
	assert.Contains(t, caCert.Subject.Organization, "Test CA")
	assert.Contains(t, caCert.Subject.Country, "US")
	assert.Contains(t, caCert.Subject.Province, "CA")
	assert.Contains(t, caCert.Subject.Locality, "San Francisco")
}

func TestCA_GenerateServerCertificate(t *testing.T) {
	// Setup CA
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	// Test server certificate generation
	serverConfig := &ServerCertConfig{
		CommonName:   "test-server.local",
		DNSNames:     []string{"localhost", "test-server.local", "*.test.local"},
		IPAddresses:  []string{"127.0.0.1", "192.168.1.1"},
		Organization: "Test Server Org",
		ValidityDays: 365,
		KeySize:      2048,
	}

	cert, err := ca.GenerateServerCertificate(serverConfig)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate properties
	assert.Equal(t, CertificateTypePublicAPI, cert.Type)
	assert.Equal(t, "test-server.local", cert.CommonName)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotEmpty(t, cert.CertificatePEM)
	assert.NotEmpty(t, cert.PrivateKeyPEM)
	assert.NotEmpty(t, cert.Fingerprint)

	serverResult, err := ca.ValidateCertificate(cert.CertificatePEM)
	require.NoError(t, err)
	assert.True(t, serverResult.IsValid)

	// Parse and verify the generated certificate
	x509Cert, err := ParseCertificateFromPEM(cert.CertificatePEM)
	require.NoError(t, err)

	assert.False(t, x509Cert.IsCA)
	assert.Equal(t, "test-server.local", x509Cert.Subject.CommonName)
	assert.Contains(t, x509Cert.Subject.Organization, "Test Server Org")
	assert.Contains(t, x509Cert.DNSNames, "localhost")
	assert.Contains(t, x509Cert.DNSNames, "test-server.local")
	assert.Contains(t, x509Cert.DNSNames, "*.test.local")
	assert.Len(t, x509Cert.IPAddresses, 2) // 127.0.0.1, 192.168.1.1 (127.0.0.1 already present)

	// Verify extended key usage
	assert.Contains(t, x509Cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	// Verify the certificate is signed by the CA
	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	caCert, err := ParseCertificateFromPEM(caCertPEM)
	require.NoError(t, err)

	err = x509Cert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)
}

func TestCA_SignClientCertificateRequest(t *testing.T) {
	// Setup CA
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	// Caller generates its own keypair locally; the CA never sees the private key.
	callerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := &ClientCertConfig{
		CommonName:         "payload-signer-001",
		Organization:       "Test Client Org",
		OrganizationalUnit: "Engineering",
		ClientID:           "payload-signer-001",
		ValidityDays:       365,
	}

	cert, err := ca.SignClientCertificateRequest(&callerKey.PublicKey, config)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate properties
	assert.Equal(t, CertificateTypeClient, cert.Type)
	assert.Equal(t, "payload-signer-001", cert.CommonName)
	assert.Equal(t, "payload-signer-001", cert.ClientID)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotEmpty(t, cert.CertificatePEM)
	assert.NotEmpty(t, cert.Fingerprint)

	// [REQUIRED TEST] no private key ever exists for a CSR-issued certificate.
	assert.Empty(t, cert.PrivateKeyPEM, "CA must never generate or return a private key for a caller-supplied public key")

	// Parse and verify the generated certificate
	x509Cert, err := ParseCertificateFromPEM(cert.CertificatePEM)
	require.NoError(t, err)

	assert.False(t, x509Cert.IsCA)
	assert.Equal(t, "payload-signer-001", x509Cert.Subject.CommonName)
	assert.Contains(t, x509Cert.Subject.Organization, "Test Client Org")
	assert.Contains(t, x509Cert.Subject.OrganizationalUnit, "Engineering")

	// Verify extended key usage
	assert.Contains(t, x509Cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)

	// [REQUIRED TEST] the issued certificate's public key equals the exact pubKey
	// passed in — proves no substitution/regeneration happened.
	issuedPubKey, ok := x509Cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "issued certificate public key must be the ECDSA key supplied by the caller")
	assert.True(t, issuedPubKey.Equal(&callerKey.PublicKey), "issued certificate public key must equal the caller-supplied public key")

	// Verify the certificate is signed by the CA
	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	caCert, err := ParseCertificateFromPEM(caCertPEM)
	require.NoError(t, err)

	err = x509Cert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)

	// [REQUIRED TEST] a certificate issued via SignClientCertificateRequest passes
	// the same x509.Verify chain check used by verifyOperatorCert /
	// validatePublicBetaCommandSignature — drop-in compatible with existing
	// verification, no changes needed there.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err = x509Cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	assert.NoError(t, err)
}

func TestCA_SignClientCertificateRequest_PayloadSigningMarker(t *testing.T) {
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	callerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := &ClientCertConfig{
		CommonName:       "payload-signer-002",
		TemplateModifier: SetPayloadSigningMarker,
	}

	cert, err := ca.SignClientCertificateRequest(&callerKey.PublicKey, config)
	require.NoError(t, err)

	x509Cert, err := ParseCertificateFromPEM(cert.CertificatePEM)
	require.NoError(t, err)

	assert.True(t, HasPayloadSigningMarker(x509Cert))
}

// TestAdminCertificate_DoesNotCarryPayloadSigningMarker proves an ordinary admin
// transport bundle (AdminMarkerOID only) is not usable as a payload-signing
// credential — [REQUIRED TEST].
func TestAdminCertificate_DoesNotCarryPayloadSigningMarker(t *testing.T) {
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	config := &ClientCertConfig{
		CommonName:       "admin-001",
		ValidityDays:     365,
		TemplateModifier: SetAdminMarker,
	}

	cert, err := ca.GenerateClientCertificate(config)
	require.NoError(t, err)

	x509Cert, err := ParseCertificateFromPEM(cert.CertificatePEM)
	require.NoError(t, err)

	assert.True(t, HasAdminMarker(x509Cert))
	assert.False(t, HasPayloadSigningMarker(x509Cert), "an admin transport bundle must not be usable as a payload-signing credential")
}

func TestCA_GenerateClientCertificate(t *testing.T) {
	// Setup CA
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	// Test client certificate generation
	clientConfig := &ClientCertConfig{
		CommonName:         "test-client-001",
		Organization:       "Test Client Org",
		OrganizationalUnit: "Engineering",
		ClientID:           "client-001",
		ValidityDays:       365,
		KeySize:            2048,
	}

	cert, err := ca.GenerateClientCertificate(clientConfig)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate properties
	assert.Equal(t, CertificateTypeClient, cert.Type)
	assert.Equal(t, "test-client-001", cert.CommonName)
	assert.Equal(t, "client-001", cert.ClientID)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotEmpty(t, cert.CertificatePEM)
	assert.NotEmpty(t, cert.PrivateKeyPEM)
	assert.NotEmpty(t, cert.Fingerprint)

	clientResult, err := ca.ValidateCertificate(cert.CertificatePEM)
	require.NoError(t, err)
	assert.True(t, clientResult.IsValid)

	// Parse and verify the generated certificate
	x509Cert, err := ParseCertificateFromPEM(cert.CertificatePEM)
	require.NoError(t, err)

	assert.False(t, x509Cert.IsCA)
	assert.Equal(t, "test-client-001", x509Cert.Subject.CommonName)
	assert.Contains(t, x509Cert.Subject.Organization, "Test Client Org")
	assert.Contains(t, x509Cert.Subject.OrganizationalUnit, "Engineering")

	// Verify extended key usage
	assert.Contains(t, x509Cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)

	// Verify the certificate is signed by the CA
	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	caCert, err := ParseCertificateFromPEM(caCertPEM)
	require.NoError(t, err)

	err = x509Cert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)
}

func TestCA_ValidateCertificate(t *testing.T) {
	// Setup CA
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	// Generate a valid certificate
	serverConfig := &ServerCertConfig{
		CommonName:   "test-server",
		ValidityDays: 365,
	}

	cert, err := ca.GenerateServerCertificate(serverConfig)
	require.NoError(t, err)

	// Test validation of valid certificate
	result, err := ca.ValidateCertificate(cert.CertificatePEM)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.IsValid)
	assert.Empty(t, result.Errors)
	assert.False(t, result.IsExpired)
	assert.Greater(t, result.DaysUntilExpiration, 0)

	// Test validation of invalid PEM
	invalidPEM := []byte("invalid pem data")
	result, err = ca.ValidateCertificate(invalidPEM)
	require.NoError(t, err)
	assert.False(t, result.IsValid)
	assert.NotEmpty(t, result.Errors)
}

func TestCA_LoadCA(t *testing.T) {
	tempDir := t.TempDir()

	// Create and initialize CA
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
		StoragePath:  tempDir,
	}

	originalCA, err := NewCA(caConfig)
	require.NoError(t, err)
	err = originalCA.Initialize(caConfig)
	require.NoError(t, err)

	// Get original CA info
	originalInfo, err := originalCA.GetCAInfo()
	require.NoError(t, err)

	// Create a new CA instance and load from storage
	loadedCA := &CA{}
	err = loadedCA.LoadCA(tempDir)
	require.NoError(t, err)

	assert.True(t, loadedCA.IsInitialized())

	// Verify loaded CA has same properties
	loadedInfo, err := loadedCA.GetCAInfo()
	require.NoError(t, err)

	assert.Equal(t, originalInfo.CommonName, loadedInfo.CommonName)
	assert.Equal(t, originalInfo.SerialNumber, loadedInfo.SerialNumber)
	assert.Equal(t, originalInfo.Fingerprint, loadedInfo.Fingerprint)

	// Verify loaded CA can generate certificates
	serverConfig := &ServerCertConfig{
		CommonName:   "test-server",
		ValidityDays: 365,
	}

	cert, err := loadedCA.GenerateServerCertificate(serverConfig)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestCA_GetCAInfo(t *testing.T) {
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	info, err := ca.GetCAInfo()
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, CertificateTypeCA, info.Type)
	assert.Equal(t, "Test CA Root CA", info.CommonName)
	assert.NotEmpty(t, info.SerialNumber)
	assert.NotEmpty(t, info.Fingerprint)
	assert.Greater(t, info.DaysUntilExpiration, 0)
	assert.Equal(t, info.CommonName, info.Issuer) // Self-signed
}

func TestCA_SerialNumberUniqueness(t *testing.T) {
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	// Generate multiple certificates and verify unique serial numbers
	serialNumbers := make(map[string]bool)

	for i := 0; i < 10; i++ {
		cert, err := ca.GenerateServerCertificate(&ServerCertConfig{
			CommonName:   "test-server-" + string(rune(i)),
			ValidityDays: 365,
		})
		require.NoError(t, err)

		// Verify serial number is unique
		assert.False(t, serialNumbers[cert.SerialNumber], "Serial number %s is not unique", cert.SerialNumber)
		serialNumbers[cert.SerialNumber] = true
	}
}

func TestCA_LoadCA_PKCS8Key(t *testing.T) {
	dir := t.TempDir()

	cfg := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
		KeySize:      2048,
		StoragePath:  dir,
	}
	ca, err := NewCA(cfg)
	require.NoError(t, err)
	err = ca.Initialize(cfg)
	require.NoError(t, err)

	// Read the saved PKCS1 key and re-encode as PKCS8
	keyPath := filepath.Join(dir, "ca.key")
	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock)

	rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)

	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	require.NoError(t, os.WriteFile(keyPath, pkcs8PEM, 0600))

	// LoadCA must succeed with a PKCS8-wrapped RSA key
	loaded := &CA{}
	require.NoError(t, loaded.LoadCA(dir))
	assert.True(t, loaded.IsInitialized())

	cert, err := loaded.GenerateServerCertificate(&ServerCertConfig{
		CommonName:   "test-server",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestCA_LoadCA_MismatchedKeyPair(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	cfg1 := &CAConfig{Organization: "Test CA 1", Country: "US", ValidityDays: 365, KeySize: 2048, StoragePath: dir1}
	ca1, err := NewCA(cfg1)
	require.NoError(t, err)
	require.NoError(t, ca1.Initialize(cfg1))

	cfg2 := &CAConfig{Organization: "Test CA 2", Country: "US", ValidityDays: 365, KeySize: 2048, StoragePath: dir2}
	ca2, err := NewCA(cfg2)
	require.NoError(t, err)
	require.NoError(t, ca2.Initialize(cfg2))

	// Write CA1's cert alongside CA2's key to a new dir to create a mismatch
	mismatchDir := t.TempDir()

	ca1Cert, err := os.ReadFile(filepath.Join(dir1, "ca.crt"))
	require.NoError(t, err)
	ca2Key, err := os.ReadFile(filepath.Join(dir2, "ca.key"))
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(mismatchDir, "ca.crt"), ca1Cert, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(mismatchDir, "ca.key"), ca2Key, 0600))

	loaded := &CA{}
	err = loaded.LoadCA(mismatchDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key does not match certificate")
}

func TestCA_LoadCA_ECKeyRejected(t *testing.T) {
	dir := t.TempDir()

	cfg := &CAConfig{Organization: "Test CA", Country: "US", ValidityDays: 365, KeySize: 2048, StoragePath: dir}
	ca, err := NewCA(cfg)
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(cfg))

	// Replace the RSA key file with an EC key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecKeyBytes, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)

	ecKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecKeyBytes})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.key"), ecKeyPEM, 0600))

	loaded := &CA{}
	err = loaded.LoadCA(dir)
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "unsupported") || strings.Contains(err.Error(), "RSA"),
		"expected error about unsupported key type or RSA requirement, got: %s", err.Error(),
	)
}

func TestCA_CertificateValidityPeriods(t *testing.T) {
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	tests := []struct {
		name         string
		validityDays int
	}{
		{"1 day", 1},
		{"30 days", 30},
		{"365 days", 365},
		{"3650 days", 3650},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ca.GenerateServerCertificate(&ServerCertConfig{
				CommonName:   "test-server",
				ValidityDays: tt.validityDays,
			})
			require.NoError(t, err)

			// Parse certificate to check validity period
			x509Cert, err := ParseCertificateFromPEM(cert.CertificatePEM)
			require.NoError(t, err)

			expectedDuration := time.Duration(tt.validityDays) * 24 * time.Hour
			actualDuration := x509Cert.NotAfter.Sub(x509Cert.NotBefore)

			// Allow some tolerance for processing time (1 minute)
			tolerance := time.Minute
			assert.InDelta(t, expectedDuration.Seconds(), actualDuration.Seconds(), tolerance.Seconds())
		})
	}
}

// TestLoadCAFromSecretStore_RoundTrip stores a CA in an in-memory secret store then
// loads it back and verifies the loaded CA can sign certs and the fingerprint matches.
func TestLoadCAFromSecretStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newInMemSecretStore()

	// Create and initialize a CA.
	ca, err := NewCA(&CAConfig{Organization: "Test", Country: "US", ValidityDays: 365})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	origCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	origInfo, err := ca.GetCAInfo()
	require.NoError(t, err)

	// Store in secret store.
	require.NoError(t, ca.StoreCAToSecretStore(ctx, store, "root", "cluster-ca"))

	// Load into a new CA instance.
	loaded := &CA{}
	require.NoError(t, loaded.LoadCAFromSecretStore(ctx, store, "root", "cluster-ca"))

	assert.True(t, loaded.IsInitialized())

	loadedCertPEM, err := loaded.GetCACertificate()
	require.NoError(t, err)
	assert.Equal(t, origCertPEM, loadedCertPEM)

	loadedInfo, err := loaded.GetCAInfo()
	require.NoError(t, err)
	assert.Equal(t, origInfo.Fingerprint, loadedInfo.Fingerprint)
	assert.Equal(t, origInfo.CommonName, loadedInfo.CommonName)

	// Loaded CA must be able to sign a leaf cert.
	leafCert, err := loaded.GenerateServerCertificate(&ServerCertConfig{
		CommonName:   "test-server",
		ValidityDays: 30,
	})
	require.NoError(t, err)
	result, err := loaded.ValidateCertificate(leafCert.CertificatePEM)
	require.NoError(t, err)
	assert.True(t, result.IsValid)
}

// TestStoreCAToSecretStore_UninitializedReturnsError ensures StoreCAToSecretStore
// rejects an uninitialized CA rather than storing empty/nil data.
func TestStoreCAToSecretStore_UninitializedReturnsError(t *testing.T) {
	ctx := context.Background()
	store := newInMemSecretStore()
	ca := &CA{}
	err := ca.StoreCAToSecretStore(ctx, store, "root", "cluster-ca")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// TestLoadCAFromSecretStore_MissingCertReturnsError verifies that LoadCAFromSecretStore
// returns a descriptive error when the CA cert secret does not exist.
func TestLoadCAFromSecretStore_MissingCertReturnsError(t *testing.T) {
	ctx := context.Background()
	store := newInMemSecretStore()
	ca := &CA{}
	err := ca.LoadCAFromSecretStore(ctx, store, "root", "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CA certificate")
}

// TestLoadCAFromSecretStore_MissingKeyReturnsError verifies that LoadCAFromSecretStore
// returns an error when the cert secret exists but the key secret does not.
func TestLoadCAFromSecretStore_MissingKeyReturnsError(t *testing.T) {
	ctx := context.Background()
	store := newInMemSecretStore()

	// Store only the cert, omit the key.
	ca, err := NewCA(&CAConfig{Organization: "Test", Country: "US", ValidityDays: 365})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	certPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	require.NoError(t, store.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
		Key: "cluster-ca", TenantID: "root", Value: string(certPEM),
	}))

	loaded := &CA{}
	err = loaded.LoadCAFromSecretStore(ctx, store, "root", "cluster-ca")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CA private key")
}

// TestLoadCAFromSecretStore_MissingCertIsReportedAbsent pins the one failure a
// caller may answer by generating a new fleet CA: a genuinely absent secret,
// signalled by the store as ErrSecretNotFound.
func TestLoadCAFromSecretStore_MissingCertIsReportedAbsent(t *testing.T) {
	ctx := context.Background()
	store := newInMemSecretStore()

	err := (&CA{}).LoadCAFromSecretStore(ctx, store, "root", "cluster-ca")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCAMaterialAbsent)
}

// TestLoadCAFromSecretStore_UnreadableCertIsNotReportedAbsent is the REQUIRED
// security test for the re-rooting finding: a vault read that fails for any
// reason other than "the secret does not exist" must NOT be reported as absent
// CA material. ErrCAMaterialAbsent is the caller's licence to generate and
// publish a new fleet root, and every failure below leaves the real CA sitting
// intact at the key path — a policy granting create/update but not read, an
// expired token, a KV mount misconfiguration, a read timeout during a vault
// blip. Misclassifying any of them re-roots the fleet on a single controller
// boot: every steward certificate already issued stops chaining.
func TestLoadCAFromSecretStore_UnreadableCertIsNotReportedAbsent(t *testing.T) {
	ctx := context.Background()

	ca, err := NewCA(&CAConfig{Organization: "Established", Country: "US", ValidityDays: 3650})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	readFailures := map[string]error{
		"permission denied": fmt.Errorf("failed to get secret root/cluster-ca: Error making API request. Code: 403. Errors: * permission denied"),
		"token expired":     fmt.Errorf("failed to get secret root/cluster-ca: Error making API request. Code: 403. Errors: * permission denied (token expired)"),
		"mount misconfigured": fmt.Errorf("failed to get secret root/cluster-ca: Error making API request. Code: 400. Errors: " +
			"* preflight capability check returned 403, no KV v2 engine at this mount"),
		"read timeout": context.DeadlineExceeded,
	}

	for name, readErr := range readFailures {
		t.Run(name, func(t *testing.T) {
			inner := newInMemSecretStore()
			require.NoError(t, ca.StoreCAToSecretStore(ctx, inner, "root", "cluster-ca"))

			store := newFaultySecretStore(inner)
			store.failReads("root/cluster-ca", readErr)

			loadErr := (&CA{}).LoadCAFromSecretStore(ctx, store, "root", "cluster-ca")
			require.Error(t, loadErr)
			assert.NotErrorIs(t, loadErr, ErrCAMaterialAbsent,
				"a read failure that is not a genuine absence must never license a bootstrap over published CA material")
			assert.ErrorIs(t, loadErr, readErr, "the underlying vault failure must reach the operator")
		})
	}
}

// TestLoadCAFromSecretStore_UnreadableChainFailsClosed covers the same
// misclassification on the issuer-chain read. A chain that exists but cannot be
// read must not be silently treated as "no chain": this node would then publish
// its own certificate as the fleet trust anchor while peers that did read the
// chain publish the root, diverging anchors inside one cluster.
func TestLoadCAFromSecretStore_UnreadableChainFailsClosed(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, chainPEM, _ := importableIntermediateMaterial(t)

	inner := newInMemSecretStore()
	for key, value := range map[string]string{
		"cluster-ca":       string(certPEM),
		"cluster-ca-key":   string(keyPEM),
		"cluster-ca-chain": string(chainPEM),
	} {
		require.NoError(t, inner.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
			Key: key, Value: value, TenantID: "root", CreatedBy: "test",
		}))
	}

	store := newFaultySecretStore(inner)
	store.failReads("root/cluster-ca-chain", fmt.Errorf("Error making API request. Code: 403. Errors: * permission denied"))

	ca := &CA{}
	err := ca.LoadCAFromSecretStore(ctx, store, "root", "cluster-ca")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA issuer chain")
	assert.False(t, ca.initialized, "a CA that cannot read its published issuer chain must not become usable")
}

// TestStoreCAToSecretStore_RefusesToReplaceDifferentPublishedIdentity proves the
// second half of the fix: even a caller that wrongly believes the key path is
// unclaimed cannot destroy published CA material through this function. The
// write is create-if-absent and a different identity already there fails closed.
func TestStoreCAToSecretStore_RefusesToReplaceDifferentPublishedIdentity(t *testing.T) {
	ctx := context.Background()
	store := newInMemSecretStore()

	established, err := NewCA(&CAConfig{Organization: "Established", Country: "US", ValidityDays: 3650})
	require.NoError(t, err)
	require.NoError(t, established.Initialize(nil))
	require.NoError(t, established.StoreCAToSecretStore(ctx, store, "root", "cluster-ca"))

	replacement, err := NewCA(&CAConfig{Organization: "Replacement", Country: "US", ValidityDays: 3650})
	require.NoError(t, err)
	require.NoError(t, replacement.Initialize(nil))

	err = replacement.StoreCAToSecretStore(ctx, store, "root", "cluster-ca")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to overwrite")

	storedCert, err := store.GetSecret(ctx, "root/cluster-ca")
	require.NoError(t, err)
	assert.Equal(t, string(established.ownCertificatePEM()), storedCert.Value, "the published CA certificate must be untouched")

	storedKey, err := store.GetSecret(ctx, "root/cluster-ca-key")
	require.NoError(t, err)
	assert.Equal(t, string(established.privateKeyPEM()), storedKey.Value, "the published CA private key must be untouched")
}

// TestStoreCAToSecretStore_RepublishingSameMaterialIsIdempotent keeps the
// create-if-absent write usable on the paths that legitimately re-run it (the
// disk-to-vault migration, a re-boot that republishes what it loaded).
func TestStoreCAToSecretStore_RepublishingSameMaterialIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := newInMemSecretStore()

	ca, err := NewCA(&CAConfig{Organization: "Established", Country: "US", ValidityDays: 3650})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	require.NoError(t, ca.StoreCAToSecretStore(ctx, store, "root", "cluster-ca"))
	require.NoError(t, ca.StoreCAToSecretStore(ctx, store, "root", "cluster-ca"),
		"republishing identical CA material must converge, not fail")

	loaded := &CA{}
	require.NoError(t, loaded.LoadCAFromSecretStore(ctx, store, "root", "cluster-ca"))
	assert.Equal(t, ca.ownCertificatePEM(), loaded.ownCertificatePEM())
}

// TestCA_Initialize_UnsetPathLengthPreservesLeafOnlyBehavior verifies that a
// CAConfig with no PathLength override produces byte-identical
// MaxPathLen/MaxPathLenZero behavior to today's hardcoded leaf-only CA.
// [REQUIRED TEST]
func TestCA_Initialize_UnsetPathLengthPreservesLeafOnlyBehavior(t *testing.T) {
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	caCert, err := ParseCertificateFromPEM(caCertPEM)
	require.NoError(t, err)

	assert.Equal(t, 0, caCert.MaxPathLen)
	assert.True(t, caCert.MaxPathLenZero)
}

// TestCA_Initialize_CustomPathLength verifies that a CAConfig with
// PathLength: 1 (PathLengthSet: true) produces a certificate capable of
// signing a subordinate CA. [REQUIRED TEST]
func TestCA_Initialize_CustomPathLength(t *testing.T) {
	caConfig := &CAConfig{
		Organization:  "Test Intermediate-Capable CA",
		Country:       "US",
		ValidityDays:  365,
		PathLength:    1,
		PathLengthSet: true,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	caCert, err := ParseCertificateFromPEM(caCertPEM)
	require.NoError(t, err)

	assert.Equal(t, 1, caCert.MaxPathLen)
	assert.False(t, caCert.MaxPathLenZero)

	// Prove the chain-capable CA can actually sign a subordinate.
	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	subCert, err := ca.SignSubordinateCA(&subKey.PublicKey, &SubordinateCAConfig{
		CommonName:   "Test Intermediate CA",
		Organization: "Test Org",
		ValidityDays: 365,
		PathLength:   0,
	})
	require.NoError(t, err)
	require.NotNil(t, subCert)

	subX509Cert, err := ParseCertificateFromPEM(subCert.CertificatePEM)
	require.NoError(t, err)

	assert.True(t, subX509Cert.IsCA)
	assert.Equal(t, 0, subX509Cert.MaxPathLen)
	assert.True(t, subX509Cert.MaxPathLenZero)
	assert.Empty(t, subCert.PrivateKeyPEM, "CA must never generate or return a private key for a caller-supplied public key")

	err = subX509Cert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)
}

// TestCA_Initialize_InvalidPathLengthRejected verifies out-of-range
// PathLength values are rejected rather than silently clamped.
func TestCA_Initialize_InvalidPathLengthRejected(t *testing.T) {
	caConfig := &CAConfig{
		Organization:  "Test CA",
		Country:       "US",
		ValidityDays:  365,
		PathLength:    7,
		PathLengthSet: true,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	assert.Error(t, err)
}

// TestCA_SignSubordinateCA_RejectsPathLengthZeroSigner verifies that
// SignSubordinateCA against a path-length-zero CA (today's default) returns
// an error and signs nothing. [REQUIRED TEST]
func TestCA_SignSubordinateCA_RejectsPathLengthZeroSigner(t *testing.T) {
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	subCert, err := ca.SignSubordinateCA(&subKey.PublicKey, &SubordinateCAConfig{
		CommonName:   "Test Intermediate CA",
		Organization: "Test Org",
		ValidityDays: 365,
		PathLength:   0,
	})
	require.Error(t, err)
	assert.Nil(t, subCert)
}

// TestCA_SignSubordinateCA_RejectsPathLengthNotLessThanSigner verifies a
// subordinate's requested path length must leave room within the signer's
// own path-length constraint (RFC 5280 4.2.1.9).
func TestCA_SignSubordinateCA_RejectsPathLengthNotLessThanSigner(t *testing.T) {
	caConfig := &CAConfig{
		Organization:  "Test CA",
		Country:       "US",
		ValidityDays:  365,
		PathLength:    1,
		PathLengthSet: true,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// PathLength 1 does not leave room under a signer whose own path
	// length is also 1 — must be strictly less.
	subCert, err := ca.SignSubordinateCA(&subKey.PublicKey, &SubordinateCAConfig{
		CommonName:   "Test Intermediate CA",
		Organization: "Test Org",
		ValidityDays: 365,
		PathLength:   1,
	})
	require.Error(t, err)
	assert.Nil(t, subCert)
}

// TestCA_SignSubordinateCA_UninitializedReturnsError ensures SignSubordinateCA
// rejects an uninitialized CA rather than signing against a nil certificate.
func TestCA_SignSubordinateCA_UninitializedReturnsError(t *testing.T) {
	ca := &CA{}
	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	subCert, err := ca.SignSubordinateCA(&subKey.PublicKey, &SubordinateCAConfig{
		CommonName: "Test Intermediate CA",
	})
	assert.Error(t, err)
	assert.Nil(t, subCert)
}

// newRootCAForChainTests builds a self-signed root CA with a path length that
// permits signing subordinate CAs, for use by the Issue #3778 chain-identity
// tests below.
func newRootCAForChainTests(t *testing.T, pathLength int) (*CA, []byte) {
	t.Helper()
	caConfig := &CAConfig{
		Organization:  "Test Root CA",
		Country:       "US",
		ValidityDays:  3650,
		PathLength:    pathLength,
		PathLengthSet: true,
	}
	root, err := NewCA(caConfig)
	require.NoError(t, err)
	require.NoError(t, root.Initialize(caConfig))

	rootCertPEM, err := root.GetCACertificate()
	require.NoError(t, err)
	return root, rootCertPEM
}

// signIntermediateForChainTests signs a caller-generated key into a subordinate
// CA certificate under root, and returns a fully-populated *CA wrapping it —
// exactly the shape ImportSubordinateCA (S3) will eventually produce by re-loading
// a previously-signed subordinate's working cert+key, minus the vault plumbing.
func signIntermediateForChainTests(t *testing.T, root *CA, rootCertPEM []byte, commonName string, pathLength int) *CA {
	t.Helper()
	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	subCert, err := root.SignSubordinateCA(&subKey.PublicKey, &SubordinateCAConfig{
		CommonName:   commonName,
		Organization: "Test Org",
		ValidityDays: 3650,
		PathLength:   pathLength,
	})
	require.NoError(t, err)

	subX509Cert, err := ParseCertificateFromPEM(subCert.CertificatePEM)
	require.NoError(t, err)

	return &CA{
		certificate: subX509Cert,
		privateKey:  subKey,
		config:      &CAConfig{Organization: "Test Org"},
		initialized: true,
		// The intermediate's direct issuer chain, up to and including the root:
		// a single hop away, so it is exactly the root's own certificate.
		issuerChainPEM: rootCertPEM,
	}
}

// TestCA_GetCACertificate_WithIssuerChain_ReturnsTerminalRoot is the direct
// regression test for the trust-anchor identity bug the security review found:
// GetCACertificate() must return the ultimate trust root, not ca.certificate's
// own PEM, once ca.issuerChainPEM is non-empty. [REQUIRED TEST]
func TestCA_GetCACertificate_WithIssuerChain_ReturnsTerminalRoot(t *testing.T) {
	root, rootCertPEM := newRootCAForChainTests(t, 1)
	intermediate := signIntermediateForChainTests(t, root, rootCertPEM, "Test Intermediate CA", 0)

	intermediateOwnCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: intermediate.certificate.Raw,
	})

	got, err := intermediate.GetCACertificate()
	require.NoError(t, err)

	assert.Equal(t, rootCertPEM, got, "GetCACertificate() on a subordinate CA must return the root, not its own active cert")
	assert.NotEqual(t, intermediateOwnCertPEM, got, "GetCACertificate() must never return the intermediate's own certificate as the trust anchor")
}

// TestCA_SignSubordinateCA_IssuedLeafCarriesIntermediateInIssuerChain proves a CA
// initialized as a subordinate (re-loaded working cert+key, mirroring how S3's
// ImportSubordinateCA will populate a *CA) signs a leaf whose IssuerChainPEM
// contains exactly the intermediate's own PEM — not the root, not empty.
// [REQUIRED TEST]
func TestCA_SignSubordinateCA_IssuedLeafCarriesIntermediateInIssuerChain(t *testing.T) {
	root, rootCertPEM := newRootCAForChainTests(t, 1)
	intermediate := signIntermediateForChainTests(t, root, rootCertPEM, "Test Intermediate CA", 0)

	intermediateOwnCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: intermediate.certificate.Raw,
	})

	leaf, err := intermediate.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-001",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-001",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	assert.Equal(t, intermediateOwnCertPEM, leaf.IssuerChainPEM,
		"leaf issued by a subordinate CA must carry exactly the intermediate's own PEM as its issuer chain")

	leafX509, err := ParseCertificateFromPEM(leaf.CertificatePEM)
	require.NoError(t, err)
	require.NoError(t, leafX509.CheckSignatureFrom(intermediate.certificate))
}

// TestCA_IntermediateRotationSurvival is the property ADR-032 actually promises:
// rotating a region's active intermediate never requires wiping and re-enrolling
// its already-registered stewards. Two independent sibling intermediates, A and
// B, are signed from the same root. A leaf is issued from A (the steward's
// original enrollment) and the steward's trust pool is built from the root
// alone — exactly what GetCACertificate() now returns — and never touched again.
// A second, independent leaf is then issued from B (the region rotating its
// active intermediate for a different device) and must still verify against
// that untouched root-only pool, using only its own freshly-delivered
// IssuerChainPEM to bridge to the root. [REQUIRED TEST]
func TestCA_IntermediateRotationSurvival(t *testing.T) {
	root, rootCertPEM := newRootCAForChainTests(t, 1)
	intermediateA := signIntermediateForChainTests(t, root, rootCertPEM, "Region Intermediate A", 0)
	intermediateB := signIntermediateForChainTests(t, root, rootCertPEM, "Region Intermediate B", 0)

	// Simulate the steward's original enrollment: pin the root-only trust pool
	// exactly as this story's GetCACertificate() fix delivers it, and never touch
	// it again for the rest of the test.
	stewardPool := x509.NewCertPool()
	require.True(t, stewardPool.AppendCertsFromPEM(rootCertPEM))

	// Original enrollment leaf, issued from intermediate A.
	leafA, err := intermediateA.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-original",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-original",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Region rotates its active intermediate: a second, independent device
	// enrolls and is issued a leaf from intermediate B instead.
	leafB, err := intermediateB.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-post-rotation",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-post-rotation",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// leafA still verifies against the untouched root-only pool using its own
	// delivered chain (intermediate A) — rotation of B does not disturb A.
	leafAX509, err := ParseCertificateFromPEM(leafA.CertificatePEM)
	require.NoError(t, err)
	intermediatesA := x509.NewCertPool()
	require.True(t, intermediatesA.AppendCertsFromPEM(leafA.IssuerChainPEM))
	_, err = leafAX509.Verify(x509.VerifyOptions{
		Roots:         stewardPool,
		Intermediates: intermediatesA,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err)

	// leafB — presented with its own IssuerChainPEM (intermediate B) — verifies
	// against the SAME untouched root-only pool. No reference to A or B's
	// identity was ever added to stewardPool, and no re-enrollment occurred.
	leafBX509, err := ParseCertificateFromPEM(leafB.CertificatePEM)
	require.NoError(t, err)
	intermediatesB := x509.NewCertPool()
	require.True(t, intermediatesB.AppendCertsFromPEM(leafB.IssuerChainPEM))
	_, err = leafBX509.Verify(x509.VerifyOptions{
		Roots:         stewardPool,
		Intermediates: intermediatesB,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err, "rotating the region's active intermediate must not require wiping and re-enrolling already-registered stewards")
}

// TestCA_GetCACertificate_ReversedChainFailsClosed proves the trust-anchor
// selection itself fails closed, independent of the constructor-level validation
// in NewManagerFromCAMaterial: a *CA assembled inside the package with a
// root-FIRST (reversed) issuer chain must return an error rather than publish its
// terminal entry — an intermediate — as the fleet's permanently-pinned anchor.
func TestCA_GetCACertificate_ReversedChainFailsClosed(t *testing.T) {
	root, rootCertPEM := newRootCAForChainTests(t, 1)
	intermediate := signIntermediateForChainTests(t, root, rootCertPEM, "Test Intermediate CA", 0)

	intermediateOwnCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: intermediate.certificate.Raw,
	})

	// Root-first ordering: the terminal entry is the intermediate, not the root.
	reversed := &CA{
		certificate:    intermediate.certificate,
		privateKey:     intermediate.privateKey,
		config:         intermediate.config,
		initialized:    true,
		issuerChainPEM: append(append([]byte{}, rootCertPEM...), intermediateOwnCertPEM...),
	}

	got, err := reversed.GetCACertificate()
	require.Error(t, err, "a reversed issuer chain must not yield a trust anchor")
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "not a self-signed root")
}

// TestValidateIssuerChain_RejectsGarbagePEM proves non-certificate material
// supplied as an issuer chain is rejected outright rather than partially parsed.
func TestValidateIssuerChain_RejectsGarbagePEM(t *testing.T) {
	root, _ := newRootCAForChainTests(t, 1)

	err := validateIssuerChain(root.certificate, []byte("not a pem block at all"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse issuer chain")
}

// externalIntermediateMaterial builds a real root CA and a regional
// intermediate signed under it (mirroring an offline root ceremony's output),
// and returns the PEM bytes ImportSubordinateCA consumes: the intermediate's
// own certificate, its private key, and the root-terminal issuer chain.
func externalIntermediateMaterial(t *testing.T) (certPEM, keyPEM, chainPEM, rootCertPEM []byte) {
	t.Helper()

	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	root, rootCertPEM := newRootCAForChainTests(t, 1)
	subCert, err := root.SignSubordinateCA(&subKey.PublicKey, &SubordinateCAConfig{
		CommonName:   "Regional Intermediate",
		Organization: "Test Org",
		ValidityDays: 3650,
		PathLength:   0,
	})
	require.NoError(t, err)

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(subKey),
	})

	return subCert.CertificatePEM, keyPEM, rootCertPEM, rootCertPEM
}

// TestCA_ImportSubordinateCA_TrustAnchorIsRootNotIntermediate is the
// trust-anchor-identity check: GetCACertificate() on an imported subordinate
// must return the offline root's own certificate PEM, byte-for-byte, and must
// NOT equal the imported intermediate's own certificate PEM. Chain validity
// alone would pass whether the pinned anchor is the root or the intermediate,
// so this asserts identity. A freshly issued leaf's IssuerChainPEM must carry
// the intermediate, proving the two fields hold deliberately different
// material. [REQUIRED TEST]
func TestCA_ImportSubordinateCA_TrustAnchorIsRootNotIntermediate(t *testing.T) {
	certPEM, keyPEM, chainPEM, rootCertPEM := externalIntermediateMaterial(t)

	ca := &CA{}
	require.NoError(t, ca.ImportSubordinateCA(certPEM, keyPEM, chainPEM))
	assert.True(t, ca.IsInitialized())

	got, err := ca.GetCACertificate()
	require.NoError(t, err)
	assert.Equal(t, rootCertPEM, got, "GetCACertificate() must return the root, not the imported intermediate")
	assert.NotEqual(t, certPEM, got, "GetCACertificate() must never return the imported intermediate's own certificate as the trust anchor")

	leaf, err := ca.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "steward-001",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-001",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	assert.Equal(t, certPEM, leaf.IssuerChainPEM,
		"a leaf issued by the imported CA must carry the intermediate's own PEM as its issuer chain, for handshake chain assembly")
}

// TestCA_ImportSubordinateCA_RejectsNonCACertificate ensures a leaf
// certificate (IsCA: false) cannot be imported as a CA's active identity.
func TestCA_ImportSubordinateCA_RejectsNonCACertificate(t *testing.T) {
	root, _ := newRootCAForChainTests(t, 1)
	leaf, err := root.GenerateServerCertificate(&ServerCertConfig{CommonName: "not-a-ca", ValidityDays: 30})
	require.NoError(t, err)

	ca := &CA{}
	err = ca.ImportSubordinateCA(leaf.CertificatePEM, leaf.PrivateKeyPEM, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a CA certificate")
	assert.False(t, ca.IsInitialized())
}

// TestCA_ImportSubordinateCA_RejectsMismatchedKeyPair ensures a cert/key pair
// that do not belong together is rejected rather than silently imported.
func TestCA_ImportSubordinateCA_RejectsMismatchedKeyPair(t *testing.T) {
	certPEM, _, chainPEM, _ := externalIntermediateMaterial(t)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrongKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(otherKey),
	})

	ca := &CA{}
	err = ca.ImportSubordinateCA(certPEM, wrongKeyPEM, chainPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
	assert.False(t, ca.IsInitialized())
}

// TestCA_ImportSubordinateCA_RejectsBrokenIssuerChain proves a chain that does
// not actually link to the imported certificate is rejected, not silently
// recorded — the same fail-closed rule validateIssuerChain enforces elsewhere.
func TestCA_ImportSubordinateCA_RejectsBrokenIssuerChain(t *testing.T) {
	certPEM, keyPEM, _, _ := externalIntermediateMaterial(t)

	unrelatedRoot, unrelatedRootPEM := newRootCAForChainTests(t, 1)
	_ = unrelatedRoot

	ca := &CA{}
	err := ca.ImportSubordinateCA(certPEM, keyPEM, unrelatedRootPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CA issuer chain")
	assert.False(t, ca.IsInitialized())
}
