package cert

import (
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name: "config with defaults",
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
	assert.Equal(t, CertificateTypeServer, cert.Type)
	assert.Equal(t, "test-server.local", cert.CommonName)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotEmpty(t, cert.CertificatePEM)
	assert.NotEmpty(t, cert.PrivateKeyPEM)
	assert.True(t, cert.IsValid)
	assert.NotEmpty(t, cert.Fingerprint)

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
	assert.True(t, cert.IsValid)
	assert.NotEmpty(t, cert.Fingerprint)

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
	// Create temporary directory for CA storage
	tempDir, err := os.MkdirTemp("", "ca-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

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
	assert.True(t, info.IsValid)
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