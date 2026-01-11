// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper functions for generating test keys and certificates

func generateRSAKeyPair(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode private key to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Generate self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test-signer",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return privateKeyPEM, certPEM, certPEM // cert is self-signed, so it's also the CA
}

func generateECDSAKeyPair(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()

	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Encode private key to PEM
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Generate self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test-signer-ecdsa",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return privateKeyPEM, certPEM, certPEM
}

func TestRSASHA256SignAndVerify(t *testing.T) {
	privateKeyPEM, certPEM, _ := generateRSAKeyPair(t)

	// Create signer
	signer, err := NewSigner(&SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)
	assert.Equal(t, AlgorithmRSASHA256, signer.Algorithm())
	assert.NotEmpty(t, signer.KeyFingerprint())

	// Create verifier
	verifier, err := NewVerifier(&VerifierConfig{
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)
	assert.True(t, verifier.SupportsAlgorithm(AlgorithmRSASHA256))
	assert.False(t, verifier.SupportsAlgorithm(AlgorithmECDSASHA256))

	// Test data
	testData := []byte("test configuration data")

	// Sign
	sig, err := signer.Sign(testData)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmRSASHA256, sig.Algorithm)
	assert.NotEmpty(t, sig.Signature)
	assert.Greater(t, sig.Timestamp, int64(0))

	// Verify
	err = verifier.Verify(testData, sig)
	assert.NoError(t, err)

	// Verify with tampered data should fail
	tamperedData := []byte("tampered configuration data")
	err = verifier.Verify(tamperedData, sig)
	assert.Error(t, err)
	assert.Equal(t, ErrSignatureMismatch, err)
}

func TestECDSASHA256SignAndVerify(t *testing.T) {
	privateKeyPEM, certPEM, _ := generateECDSAKeyPair(t)

	// Create signer
	signer, err := NewSigner(&SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)
	assert.Equal(t, AlgorithmECDSASHA256, signer.Algorithm())

	// Create verifier
	verifier, err := NewVerifier(&VerifierConfig{
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)
	assert.True(t, verifier.SupportsAlgorithm(AlgorithmECDSASHA256))
	assert.False(t, verifier.SupportsAlgorithm(AlgorithmRSASHA256))

	// Test data
	testData := []byte("test configuration data for ecdsa")

	// Sign
	sig, err := signer.Sign(testData)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmECDSASHA256, sig.Algorithm)

	// Verify
	err = verifier.Verify(testData, sig)
	assert.NoError(t, err)

	// Verify with tampered data should fail
	tamperedData := []byte("tampered data")
	err = verifier.Verify(tamperedData, sig)
	assert.Error(t, err)
}

func TestSignAndEmbedYAML(t *testing.T) {
	privateKeyPEM, certPEM, _ := generateRSAKeyPair(t)

	// Create signer
	signer, err := NewSigner(&SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	// Create verifier
	verifier, err := NewVerifier(&VerifierConfig{
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	// Test YAML configuration
	configData := []byte(`version: "1.0"
modules:
  file:
    - name: test-file
      resource_id: /etc/test.conf
      state: present
      config:
        content: "test content"
`)

	// Sign and embed
	signedData, err := SignAndEmbed(signer, configData)
	require.NoError(t, err)
	assert.True(t, HasSignature(signedData))

	// Extract and verify
	verifiedData, err := ExtractAndVerify(verifier, signedData)
	require.NoError(t, err)
	assert.NotEmpty(t, verifiedData)

	// Verify the original content is preserved (should have same keys)
	assert.Contains(t, string(verifiedData), "version:")
	assert.Contains(t, string(verifiedData), "modules:")
	assert.NotContains(t, string(verifiedData), "_signature")
}

func TestExtractSignature(t *testing.T) {
	privateKeyPEM, certPEM, _ := generateRSAKeyPair(t)

	// Create signer
	signer, err := NewSigner(&SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	// Test data
	configData := []byte(`key: value
nested:
  item: test
`)

	// Sign and embed
	signedData, err := SignAndEmbed(signer, configData)
	require.NoError(t, err)

	// Extract signature without verification
	sig, originalData, err := ExtractSignature(signedData)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.Equal(t, AlgorithmRSASHA256, sig.Algorithm)
	assert.NotEmpty(t, sig.Signature)
	assert.NotEmpty(t, originalData)
}

func TestMissingSignature(t *testing.T) {
	_, certPEM, _ := generateRSAKeyPair(t)

	// Create verifier
	verifier, err := NewVerifier(&VerifierConfig{
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	// Unsigned data
	unsignedData := []byte(`key: value`)

	// HasSignature should return false
	assert.False(t, HasSignature(unsignedData))

	// ExtractAndVerify should fail
	_, err = ExtractAndVerify(verifier, unsignedData)
	assert.Error(t, err)

	// ExtractSignature should fail
	_, _, err = ExtractSignature(unsignedData)
	assert.Error(t, err)
}

func TestInvalidSignature(t *testing.T) {
	privateKeyPEM1, certPEM1, _ := generateRSAKeyPair(t)
	_, certPEM2, _ := generateRSAKeyPair(t)

	// Create signer with key 1
	signer, err := NewSigner(&SignerConfig{
		PrivateKeyPEM:  privateKeyPEM1,
		CertificatePEM: certPEM1,
	})
	require.NoError(t, err)

	// Create verifier with key 2 (different key)
	verifier, err := NewVerifier(&VerifierConfig{
		CertificatePEM: certPEM2,
	})
	require.NoError(t, err)

	// Test data
	configData := []byte(`key: value`)

	// Sign with key 1
	signedData, err := SignAndEmbed(signer, configData)
	require.NoError(t, err)

	// Verify with key 2 should fail
	_, err = ExtractAndVerify(verifier, signedData)
	assert.Error(t, err)
}

func TestSignerErrors(t *testing.T) {
	t.Run("missing private key", func(t *testing.T) {
		_, err := NewSigner(&SignerConfig{})
		assert.ErrorIs(t, err, ErrMissingPrivateKey)
	})

	t.Run("invalid private key", func(t *testing.T) {
		_, err := NewSigner(&SignerConfig{
			PrivateKeyPEM: []byte("invalid pem data"),
		})
		assert.Error(t, err)
	})

	t.Run("wrong algorithm for key type", func(t *testing.T) {
		privateKeyPEM, certPEM, _ := generateRSAKeyPair(t)
		_, err := NewSigner(&SignerConfig{
			PrivateKeyPEM:  privateKeyPEM,
			CertificatePEM: certPEM,
			Algorithm:      AlgorithmECDSASHA256, // Wrong algorithm for RSA key
		})
		assert.Error(t, err)
	})
}

func TestVerifierErrors(t *testing.T) {
	t.Run("missing public key", func(t *testing.T) {
		_, err := NewVerifier(&VerifierConfig{})
		assert.ErrorIs(t, err, ErrMissingPublicKey)
	})

	t.Run("invalid certificate", func(t *testing.T) {
		_, err := NewVerifier(&VerifierConfig{
			CertificatePEM: []byte("invalid pem data"),
		})
		assert.Error(t, err)
	})

	t.Run("verify with nil signature", func(t *testing.T) {
		_, certPEM, _ := generateRSAKeyPair(t)
		verifier, err := NewVerifier(&VerifierConfig{
			CertificatePEM: certPEM,
		})
		require.NoError(t, err)

		err = verifier.Verify([]byte("data"), nil)
		assert.ErrorIs(t, err, ErrMissingSignature)
	})

	t.Run("verify with unsupported algorithm", func(t *testing.T) {
		_, certPEM, _ := generateRSAKeyPair(t)
		verifier, err := NewVerifier(&VerifierConfig{
			CertificatePEM: certPEM,
		})
		require.NoError(t, err)

		sig := &ConfigSignature{
			Algorithm: "UNKNOWN-ALG",
			Signature: "invalid",
		}
		err = verifier.Verify([]byte("data"), sig)
		assert.Error(t, err)
	})
}

func TestAlgorithmIsValid(t *testing.T) {
	assert.True(t, AlgorithmRSASHA256.IsValid())
	assert.True(t, AlgorithmECDSASHA256.IsValid())
	assert.False(t, Algorithm("INVALID").IsValid())
}

func TestNewVerifierFromCertificate(t *testing.T) {
	_, certPEM, _ := generateRSAKeyPair(t)

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)

	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Create verifier from certificate
	verifier, err := NewVerifierFromCertificate(certificate)
	require.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.True(t, verifier.SupportsAlgorithm(AlgorithmRSASHA256))
}

func TestComplexYAMLConfig(t *testing.T) {
	privateKeyPEM, certPEM, _ := generateRSAKeyPair(t)

	signer, err := NewSigner(&SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	verifier, err := NewVerifier(&VerifierConfig{
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	// Complex YAML with nested structures
	configData := []byte(`version: "1.0"
tenant_id: "test-tenant"
modules:
  file:
    - name: ssh-config
      resource_id: /etc/ssh/sshd_config
      state: present
      config:
        content: |
          PermitRootLogin no
          PasswordAuthentication no
        permissions: 600
        owner: root
        group: root
  directory:
    - name: log-dir
      resource_id: /var/log/cfgms
      state: present
      config:
        permissions: 755
  script:
    - name: cleanup
      resource_id: cleanup-script-v1
      state: present
      config:
        shell: bash
        timeout: 60
`)

	// Sign, embed, extract, and verify
	signedData, err := SignAndEmbed(signer, configData)
	require.NoError(t, err)

	verifiedData, err := ExtractAndVerify(verifier, signedData)
	require.NoError(t, err)

	// Verify content structure is preserved
	assert.Contains(t, string(verifiedData), "version:")
	assert.Contains(t, string(verifiedData), "tenant_id:")
	assert.Contains(t, string(verifiedData), "PermitRootLogin no")
	assert.Contains(t, string(verifiedData), "cleanup-script-v1")
}

func TestDeterministicSigning(t *testing.T) {
	// RSA signing should be deterministic (same input = same output)
	privateKeyPEM, certPEM, _ := generateRSAKeyPair(t)

	signer, err := NewSigner(&SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	testData := []byte("deterministic test data")

	// Sign twice
	sig1, err := signer.Sign(testData)
	require.NoError(t, err)

	sig2, err := signer.Sign(testData)
	require.NoError(t, err)

	// RSA PKCS1v15 signatures should be deterministic
	assert.Equal(t, sig1.Signature, sig2.Signature)
}
