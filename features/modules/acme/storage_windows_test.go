//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWinCertStoreBackend_NewCertBackend_CertStorePath(t *testing.T) {
	// On Windows, cert:\ paths should create a winCertStoreBackend
	backend, err := newCertBackend(`cert:\LocalMachine\My`)
	require.NoError(t, err)
	require.NotNil(t, backend)

	_, ok := backend.(*winCertStoreBackend)
	assert.True(t, ok, "expected winCertStoreBackend for cert:\\ path")
}

func TestWinCertStoreBackend_NewCertBackend_FilesystemPath(t *testing.T) {
	// On Windows, non-cert:\ paths should create a fsCertBackend
	tmpDir := t.TempDir()
	backend, err := newCertBackend(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, backend)

	_, ok := backend.(*fsCertBackend)
	assert.True(t, ok, "expected fsCertBackend for filesystem path")
}

func TestWinCertStoreBackend_StoreAndDelete_RoundTrip(t *testing.T) {
	// This test requires administrator privileges to access LocalMachine cert store.
	// Use CurrentUser for non-admin testing.
	backend, err := newWinCertStoreBackend("CurrentUser", "My")
	require.NoError(t, err)

	domain := "acme-test.cfgms.local"
	certPEM, keyPEM := generateTestCertAndKey(t, domain)
	meta := &CertificateMetadata{
		Domain:   domain,
		Email:    "test@cfgms.local",
		IssuedAt: time.Now(),
		KeyType:  "ec256",
	}

	// Store
	err = backend.StoreCertificate(domain, certPEM, keyPEM, nil, meta)
	require.NoError(t, err)

	// Exists
	assert.True(t, backend.CertificateExists(domain))

	// Load (from filesystem backup)
	loadedCert, loadedKey, err := backend.LoadCertificate(domain)
	require.NoError(t, err)
	assert.Equal(t, certPEM, loadedCert)
	assert.Equal(t, keyPEM, loadedKey)

	// Load metadata
	loadedMeta, err := backend.LoadCertificateMetadata(domain)
	require.NoError(t, err)
	assert.Equal(t, domain, loadedMeta.Domain)

	// Delete (from both cert store and filesystem)
	err = backend.DeleteCertificate(domain)
	require.NoError(t, err)
	assert.False(t, backend.CertificateExists(domain))
}

func TestWinCertStoreBackend_ParsePrivateKeyDER(t *testing.T) {
	// EC key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)

	parsed, err := parsePrivateKeyDER(ecDER)
	require.NoError(t, err)
	assert.NotNil(t, parsed)
}

// generateTestCertAndKey creates a self-signed cert and key PEM for testing.
func generateTestCertAndKey(t *testing.T, domain string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}
