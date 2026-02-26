// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateSigningCertificate_Properties verifies the signing certificate has the correct
// cryptographic properties: CodeSigning EKU, DigitalSignature-only KeyUsage, 4096-bit key, 3-year validity.
func TestGenerateSigningCertificate_Properties(t *testing.T) {
	ca := setupTestCA(t)

	cert, err := ca.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		Organization: "CFGMS Test",
		ValidityDays: 1095,
		KeySize:      4096,
	})
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate metadata
	assert.Equal(t, CertificateTypeConfigSigning, cert.Type)
	assert.Equal(t, "cfgms-config-signer", cert.CommonName)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotEmpty(t, cert.CertificatePEM)
	assert.NotEmpty(t, cert.PrivateKeyPEM)
	assert.True(t, cert.IsValid)
	assert.NotEmpty(t, cert.Fingerprint)

	// Parse and verify x509 properties
	x509Cert, err := ParseCertificateFromPEM(cert.CertificatePEM)
	require.NoError(t, err)

	// Must have CodeSigning EKU only (NOT ServerAuth)
	assert.Contains(t, x509Cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning,
		"signing cert must have CodeSigning EKU")
	assert.NotContains(t, x509Cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth,
		"signing cert must NOT have ServerAuth EKU")

	// Must have DigitalSignature key usage only (no KeyEncipherment)
	assert.True(t, x509Cert.KeyUsage&x509.KeyUsageDigitalSignature != 0,
		"signing cert must have DigitalSignature key usage")
	assert.True(t, x509Cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0,
		"signing cert must NOT have KeyEncipherment key usage")

	// Verify 4096-bit RSA key
	assert.Equal(t, 4096, x509Cert.PublicKey.(*rsa.PublicKey).N.BitLen(),
		"signing cert must use 4096-bit RSA key")

	// Verify 3-year validity (1095 days)
	duration := x509Cert.NotAfter.Sub(x509Cert.NotBefore)
	expectedDays := 1095
	actualDays := int(duration.Hours() / 24)
	assert.InDelta(t, expectedDays, actualDays, 1, "signing cert should be valid for ~1095 days")

	// Verify organization
	assert.Contains(t, x509Cert.Subject.Organization, "CFGMS Test")

	// Verify signed by CA
	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	caCert, err := ParseCertificateFromPEM(caCertPEM)
	require.NoError(t, err)
	err = x509Cert.CheckSignatureFrom(caCert)
	assert.NoError(t, err, "signing cert must be signed by the CA")
}

// TestGenerateSigningCertificate_Defaults verifies default values are applied
func TestGenerateSigningCertificate_Defaults(t *testing.T) {
	ca := setupTestCA(t)

	cert, err := ca.GenerateSigningCertificate(&SigningCertConfig{})
	require.NoError(t, err)
	require.NotNil(t, cert)

	assert.Equal(t, CertificateTypeConfigSigning, cert.Type)
	assert.Equal(t, "cfgms-config-signer", cert.CommonName)

	x509Cert, err := ParseCertificateFromPEM(cert.CertificatePEM)
	require.NoError(t, err)

	// Default 4096-bit key
	assert.Equal(t, 4096, x509Cert.PublicKey.(*rsa.PublicKey).N.BitLen())

	// Default 1095-day validity
	duration := x509Cert.NotAfter.Sub(x509Cert.NotBefore)
	actualDays := int(duration.Hours() / 24)
	assert.InDelta(t, 1095, actualDays, 1)
}

// TestGenerateSigningCertificate_NilConfig returns error
func TestGenerateSigningCertificate_NilConfig(t *testing.T) {
	ca := setupTestCA(t)

	cert, err := ca.GenerateSigningCertificate(nil)
	assert.Error(t, err)
	assert.Nil(t, cert)
}

// TestGenerateSigningCertificate_UninitializedCA returns error
func TestGenerateSigningCertificate_UninitializedCA(t *testing.T) {
	ca, err := NewCA(&CAConfig{Organization: "Test"})
	require.NoError(t, err)

	cert, err := ca.GenerateSigningCertificate(&SigningCertConfig{CommonName: "test"})
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "CA is not initialized")
}

// TestGenerateInternalServerCertificate verifies internal server cert has correct type and properties
func TestGenerateInternalServerCertificate(t *testing.T) {
	ca := setupTestCA(t)

	cert, err := ca.GenerateInternalServerCertificate(&ServerCertConfig{
		CommonName:   "cfgms-internal",
		DNSNames:     []string{"localhost", "cfgms-internal"},
		IPAddresses:  []string{"127.0.0.1"},
		Organization: "CFGMS Test",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Must be InternalServer type
	assert.Equal(t, CertificateTypeInternalServer, cert.Type)
	assert.Equal(t, "cfgms-internal", cert.CommonName)

	// Parse and verify x509 properties
	x509Cert, err := ParseCertificateFromPEM(cert.CertificatePEM)
	require.NoError(t, err)

	// Must have ServerAuth EKU (for mTLS)
	assert.Contains(t, x509Cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	// Must have proper SANs
	assert.Contains(t, x509Cert.DNSNames, "localhost")
	assert.Contains(t, x509Cert.DNSNames, "cfgms-internal")

	// Verify signed by CA
	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	caCert, err := ParseCertificateFromPEM(caCertPEM)
	require.NoError(t, err)
	err = x509Cert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)
}

// TestCertificateTypeEnumStability ensures explicit type values never change
// (prevents metadata.json corruption from iota reordering)
func TestCertificateTypeEnumStability(t *testing.T) {
	assert.Equal(t, CertificateType(0), CertificateTypeCA, "CA must be 0")
	assert.Equal(t, CertificateType(1), CertificateTypeServer, "Server must be 1")
	assert.Equal(t, CertificateType(2), CertificateTypeClient, "Client must be 2")
	assert.Equal(t, CertificateType(3), CertificateTypePublicAPI, "PublicAPI must be 3")
	assert.Equal(t, CertificateType(4), CertificateTypeInternalServer, "InternalServer must be 4")
	assert.Equal(t, CertificateType(5), CertificateTypeConfigSigning, "ConfigSigning must be 5")
}

// TestCertificateTypeString verifies String() for all types
func TestCertificateTypeString(t *testing.T) {
	tests := []struct {
		certType CertificateType
		expected string
	}{
		{CertificateTypeCA, "CA"},
		{CertificateTypeServer, "Server"},
		{CertificateTypeClient, "Client"},
		{CertificateTypePublicAPI, "PublicAPI"},
		{CertificateTypeInternalServer, "InternalServer"},
		{CertificateTypeConfigSigning, "ConfigSigning"},
		{CertificateType(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.certType.String())
		})
	}
}

// setupTestCA creates and initializes a CA for testing
func setupTestCA(t *testing.T) *CA {
	t.Helper()
	caConfig := &CAConfig{
		Organization: "Test CA",
		Country:      "US",
		ValidityDays: 365,
		KeySize:      2048,
	}

	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	err = ca.Initialize(caConfig)
	require.NoError(t, err)

	return ca
}
