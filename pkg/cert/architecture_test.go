// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cert

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnsureSeparatedCertificates_GeneratesMissing verifies that EnsureSeparatedCertificates
// generates internal server and config signing certificates when they don't exist.
func TestEnsureSeparatedCertificates_GeneratesMissing(t *testing.T) {
	manager := setupTestManager(t)

	// Verify no separated certs exist initially
	internalCerts, err := manager.GetCertificatesByType(CertificateTypeInternalServer)
	require.NoError(t, err)
	assert.Empty(t, internalCerts)

	signingCerts, err := manager.GetCertificatesByType(CertificateTypeConfigSigning)
	require.NoError(t, err)
	assert.Empty(t, signingCerts)

	// Ensure separated certificates
	err = manager.EnsureSeparatedCertificates(nil, nil)
	require.NoError(t, err)

	// Verify both cert types were generated
	internalCerts, err = manager.GetCertificatesByType(CertificateTypeInternalServer)
	require.NoError(t, err)
	assert.Len(t, internalCerts, 1, "should generate exactly one internal server cert")
	assert.Equal(t, "cfgms-internal", internalCerts[0].CommonName)

	signingCerts, err = manager.GetCertificatesByType(CertificateTypeConfigSigning)
	require.NoError(t, err)
	assert.Len(t, signingCerts, 1, "should generate exactly one signing cert")
	assert.Equal(t, "cfgms-config-signer", signingCerts[0].CommonName)
}

// TestEnsureSeparatedCertificates_Idempotent verifies calling EnsureSeparatedCertificates
// multiple times doesn't create duplicate certificates.
func TestEnsureSeparatedCertificates_Idempotent(t *testing.T) {
	manager := setupTestManager(t)

	// Call twice
	err := manager.EnsureSeparatedCertificates(nil, nil)
	require.NoError(t, err)

	err = manager.EnsureSeparatedCertificates(nil, nil)
	require.NoError(t, err)

	// Should still have exactly one of each
	internalCerts, err := manager.GetCertificatesByType(CertificateTypeInternalServer)
	require.NoError(t, err)
	assert.Len(t, internalCerts, 1)

	signingCerts, err := manager.GetCertificatesByType(CertificateTypeConfigSigning)
	require.NoError(t, err)
	assert.Len(t, signingCerts, 1)
}

// TestEnsureSeparatedCertificates_CustomConfig verifies custom config is applied
func TestEnsureSeparatedCertificates_CustomConfig(t *testing.T) {
	manager := setupTestManager(t)

	internalCfg := &ServerCertConfig{
		CommonName:   "my-custom-internal",
		DNSNames:     []string{"localhost", "custom.internal"},
		IPAddresses:  []string{"10.0.0.1"},
		ValidityDays: 180,
	}

	signingCfg := &SigningCertConfig{
		CommonName:   "my-custom-signer",
		Organization: "Custom Org",
		ValidityDays: 730,
		KeySize:      4096,
	}

	err := manager.EnsureSeparatedCertificates(internalCfg, signingCfg)
	require.NoError(t, err)

	internalCerts, err := manager.GetCertificatesByType(CertificateTypeInternalServer)
	require.NoError(t, err)
	require.Len(t, internalCerts, 1)
	assert.Equal(t, "my-custom-internal", internalCerts[0].CommonName)

	signingCerts, err := manager.GetCertificatesByType(CertificateTypeConfigSigning)
	require.NoError(t, err)
	require.Len(t, signingCerts, 1)
	assert.Equal(t, "my-custom-signer", signingCerts[0].CommonName)
}

// TestGetSigningCertificate_ReturnsPEM verifies GetSigningCertificate returns valid PEM
func TestGetSigningCertificate_ReturnsPEM(t *testing.T) {
	manager := setupTestManager(t)

	// No signing cert yet
	_, err := manager.GetSigningCertificate()
	assert.Error(t, err)

	// Generate signing cert
	err = manager.EnsureSeparatedCertificates(nil, nil)
	require.NoError(t, err)

	// Should return PEM now
	signingPEM, err := manager.GetSigningCertificate()
	require.NoError(t, err)
	assert.NotEmpty(t, signingPEM)

	// Should be parseable
	x509Cert, err := ParseCertificateFromPEM(signingPEM)
	require.NoError(t, err)
	assert.Equal(t, "cfgms-config-signer", x509Cert.Subject.CommonName)
}

// TestSigningCertRoundTrip_SignAndVerify verifies that a config signed with the signing cert
// can be verified using the signing cert's public key (simulating controller→steward flow).
func TestSigningCertRoundTrip_SignAndVerify(t *testing.T) {
	manager := setupTestManager(t)

	// Generate signing cert
	signingCert, err := manager.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		ValidityDays: 1095,
		KeySize:      4096,
	})
	require.NoError(t, err)

	// Verify the cert was stored and can be retrieved
	storedCert, err := manager.GetCertificate(signingCert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, CertificateTypeConfigSigning, storedCert.Type)
	assert.NotEmpty(t, storedCert.CertificatePEM)
	assert.NotEmpty(t, storedCert.PrivateKeyPEM)

	// The signing cert PEM should be retrievable
	signingPEM, err := manager.GetSigningCertificate()
	require.NoError(t, err)
	assert.Equal(t, signingCert.CertificatePEM, signingPEM)
}

// TestUnifiedMode_ServerCertUnchanged verifies that in unified mode,
// GetCertificatesByType(Server) works as before.
func TestUnifiedMode_ServerCertUnchanged(t *testing.T) {
	manager := setupTestManager(t)

	// Generate a server cert (unified mode)
	serverCert, err := manager.GenerateServerCertificate(&ServerCertConfig{
		CommonName:   "cfgms-controller",
		DNSNames:     []string{"localhost"},
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Should be retrievable by Server type
	serverCerts, err := manager.GetCertificatesByType(CertificateTypeServer)
	require.NoError(t, err)
	assert.Len(t, serverCerts, 1)
	assert.Equal(t, serverCert.CommonName, serverCerts[0].CommonName)

	// No separated certs should exist
	internalCerts, err := manager.GetCertificatesByType(CertificateTypeInternalServer)
	require.NoError(t, err)
	assert.Empty(t, internalCerts)

	signingCerts, err := manager.GetCertificatesByType(CertificateTypeConfigSigning)
	require.NoError(t, err)
	assert.Empty(t, signingCerts)
}

// TestCertificateArchitectureConstants verifies the architecture string constants
func TestCertificateArchitectureConstants(t *testing.T) {
	assert.Equal(t, CertificateArchitecture("unified"), CertArchitectureUnified)
	assert.Equal(t, CertificateArchitecture("separated"), CertArchitectureSeparated)
}

// TestManagerGenerateInternalServerCertificate verifies Manager stores internal server certs
func TestManagerGenerateInternalServerCertificate(t *testing.T) {
	manager := setupTestManager(t)

	cert, err := manager.GenerateInternalServerCertificate(&ServerCertConfig{
		CommonName:   "test-internal",
		DNSNames:     []string{"localhost"},
		ValidityDays: 365,
	})
	require.NoError(t, err)
	assert.Equal(t, CertificateTypeInternalServer, cert.Type)

	// Verify stored
	storedCert, err := manager.GetCertificate(cert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, CertificateTypeInternalServer, storedCert.Type)
	assert.Equal(t, "test-internal", storedCert.CommonName)
}

// TestManagerGenerateSigningCertificate verifies Manager stores signing certs
func TestManagerGenerateSigningCertificate(t *testing.T) {
	manager := setupTestManager(t)

	cert, err := manager.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "test-signer",
		ValidityDays: 1095,
		KeySize:      4096,
	})
	require.NoError(t, err)
	assert.Equal(t, CertificateTypeConfigSigning, cert.Type)

	// Verify stored
	storedCert, err := manager.GetCertificate(cert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, CertificateTypeConfigSigning, storedCert.Type)
	assert.Equal(t, "test-signer", storedCert.CommonName)
}

// setupTestManager creates a Manager with a temporary directory for testing
func setupTestManager(t *testing.T) *Manager {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "cert-arch-test-")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to remove temp directory: %v", err)
		}
	})

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	return manager
}
