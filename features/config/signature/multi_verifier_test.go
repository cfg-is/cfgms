// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeCertAndSigner generates a fresh ECDSA cert+signer pair for testing.
func makeCertAndSigner(t *testing.T) (*x509.Certificate, *ConfigSigner, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "test-signer",
		},
		NotBefore:             time.Now().Add(-time.Hour),
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

	x509Cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	signer, err := NewSigner(&SignerConfig{
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	return x509Cert, signer, certPEM
}

// TestMultiVerifierAcceptsAny verifies that a MultiVerifier accepts data signed
// by any certificate in the set.
//
// (a) old cert only — verifier holds old cert, data signed with old cert -> passes
// (b) new cert only — verifier holds new cert, data signed with new cert -> passes
// (c) both certs, old-signed data -> passes
// (d) both certs, new-signed data -> passes
func TestMultiVerifierAcceptsAny(t *testing.T) {
	oldCert, oldSigner, _ := makeCertAndSigner(t)
	newCert, newSigner, _ := makeCertAndSigner(t)

	data := []byte("config data payload")

	oldSig, err := oldSigner.Sign(data)
	require.NoError(t, err)

	newSig, err := newSigner.Sign(data)
	require.NoError(t, err)

	t.Run("old_cert_only", func(t *testing.T) {
		mv, err := NewMultiVerifier([]*x509.Certificate{oldCert})
		require.NoError(t, err)
		assert.NoError(t, mv.Verify(data, oldSig))
	})

	t.Run("new_cert_only", func(t *testing.T) {
		mv, err := NewMultiVerifier([]*x509.Certificate{newCert})
		require.NoError(t, err)
		assert.NoError(t, mv.Verify(data, newSig))
	})

	t.Run("both_certs_old_signed_data", func(t *testing.T) {
		mv, err := NewMultiVerifier([]*x509.Certificate{oldCert, newCert})
		require.NoError(t, err)
		assert.NoError(t, mv.Verify(data, oldSig))
	})

	t.Run("both_certs_new_signed_data", func(t *testing.T) {
		mv, err := NewMultiVerifier([]*x509.Certificate{oldCert, newCert})
		require.NoError(t, err)
		assert.NoError(t, mv.Verify(data, newSig))
	})
}

// TestMultiVerifierRejectsRetiredOnly verifies that a MultiVerifier holding only
// a "retired" certificate rejects data signed with a different (new) certificate.
func TestMultiVerifierRejectsRetiredOnly(t *testing.T) {
	retiredCert, _, _ := makeCertAndSigner(t)
	_, newSigner, _ := makeCertAndSigner(t)

	data := []byte("config data payload")

	newSig, err := newSigner.Sign(data)
	require.NoError(t, err)

	// Verifier holds only the retired cert
	mv, err := NewMultiVerifier([]*x509.Certificate{retiredCert})
	require.NoError(t, err)

	// Verification of new-cert-signed data must fail
	err = mv.Verify(data, newSig)
	assert.Error(t, err, "retired-only verifier must reject new-cert-signed data")
}

// TestMultiVerifierNilOrEmptyCerts verifies that NewMultiVerifier returns an
// error when given a nil or empty certificate slice.
func TestMultiVerifierNilOrEmptyCerts(t *testing.T) {
	t.Run("nil_slice", func(t *testing.T) {
		_, err := NewMultiVerifier(nil)
		assert.ErrorIs(t, err, ErrMissingPublicKey)
	})

	t.Run("empty_slice", func(t *testing.T) {
		_, err := NewMultiVerifier([]*x509.Certificate{})
		assert.ErrorIs(t, err, ErrMissingPublicKey)
	})

	t.Run("nil_certificate_in_slice", func(t *testing.T) {
		_, err := NewMultiVerifier([]*x509.Certificate{nil})
		assert.Error(t, err)
	})
}

// TestMultiVerifierVerifyNilSignature verifies that Verify returns ErrMissingSignature
// when sig is nil.
func TestMultiVerifierVerifyNilSignature(t *testing.T) {
	cert, _, _ := makeCertAndSigner(t)

	mv, err := NewMultiVerifier([]*x509.Certificate{cert})
	require.NoError(t, err)

	err = mv.Verify([]byte("data"), nil)
	assert.ErrorIs(t, err, ErrMissingSignature)
}

// TestMultiVerifierSupportsAlgorithm verifies that SupportsAlgorithm returns true
// if any member supports the given algorithm.
func TestMultiVerifierSupportsAlgorithm(t *testing.T) {
	ecdsaCert, _, _ := makeCertAndSigner(t) // ECDSA cert

	mv, err := NewMultiVerifier([]*x509.Certificate{ecdsaCert})
	require.NoError(t, err)

	assert.True(t, mv.SupportsAlgorithm(AlgorithmECDSASHA256))
	assert.False(t, mv.SupportsAlgorithm(AlgorithmRSASHA256))
}

// TestMultiVerifierKeyFingerprint verifies that KeyFingerprint returns a
// comma-separated list of member fingerprints.
func TestMultiVerifierKeyFingerprint(t *testing.T) {
	cert1, _, _ := makeCertAndSigner(t)
	cert2, _, _ := makeCertAndSigner(t)

	mv1, err := NewMultiVerifier([]*x509.Certificate{cert1})
	require.NoError(t, err)

	mv2, err := NewMultiVerifier([]*x509.Certificate{cert1, cert2})
	require.NoError(t, err)

	fp1 := mv1.KeyFingerprint()
	fp2 := mv2.KeyFingerprint()

	assert.NotEmpty(t, fp1)
	assert.NotEmpty(t, fp2)
	// Two certs should produce a different (longer) fingerprint string
	assert.NotEqual(t, fp1, fp2)
	assert.Contains(t, fp2, fp1, "combined fingerprint should contain the individual cert fingerprint")
}

// TestMultiVerifierImplementsVerifier verifies that *MultiVerifier satisfies
// the signature.Verifier interface.
func TestMultiVerifierImplementsVerifier(t *testing.T) {
	cert, _, _ := makeCertAndSigner(t)

	mv, err := NewMultiVerifier([]*x509.Certificate{cert})
	require.NoError(t, err)

	// Compile-time check via interface assignment
	var _ Verifier = mv
}

// TestMultiVerifierRejectsTamperedData verifies that Verify returns an error when
// the data does not match the signature (data was tampered after signing).
func TestMultiVerifierRejectsTamperedData(t *testing.T) {
	cert, signer, _ := makeCertAndSigner(t)

	original := []byte("original payload")
	sig, err := signer.Sign(original)
	require.NoError(t, err)

	mv, err := NewMultiVerifier([]*x509.Certificate{cert})
	require.NoError(t, err)

	// Tampered data must be rejected
	tampered := []byte("tampered payload")
	err = mv.Verify(tampered, sig)
	assert.Error(t, err, "tampered data must be rejected by MultiVerifier")
}

// TestMultiVerifierConcurrentVerify verifies that concurrent Verify calls are
// safe under the race detector.
// Run with: go test -race ./features/config/signature/...
func TestMultiVerifierConcurrentVerify(t *testing.T) {
	cert1, signer1, _ := makeCertAndSigner(t)
	cert2, signer2, _ := makeCertAndSigner(t)

	mv, err := NewMultiVerifier([]*x509.Certificate{cert1, cert2})
	require.NoError(t, err)

	data := []byte("concurrent verify payload")

	sig1, err := signer1.Sign(data)
	require.NoError(t, err)

	sig2, err := signer2.Sign(data)
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			assert.NoError(t, mv.Verify(data, sig1))
		}()
		go func() {
			defer wg.Done()
			assert.NoError(t, mv.Verify(data, sig2))
		}()
	}
	wg.Wait()
}
