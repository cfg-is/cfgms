// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCACert creates a self-signed CA cert for testing.
// Returns the PEM-encoded cert string and its SHA-256 fingerprint as lowercase hex.
func generateTestCACert(t *testing.T) (certPEM, fingerprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"CFGMS Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	hash := sha256.Sum256(cert.Raw)
	fingerprint = hex.EncodeToString(hash[:])
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return
}

func TestVerifyCACertFingerprintMatch(t *testing.T) {
	certPEM, fingerprint := generateTestCACert(t)
	require.NoError(t, verifyCACertFingerprint(certPEM, fingerprint))
}

func TestVerifyCACertFingerprintMatchCaseInsensitive(t *testing.T) {
	certPEM, fingerprint := generateTestCACert(t)
	require.NoError(t, verifyCACertFingerprint(certPEM, strings.ToUpper(fingerprint)))
}

func TestVerifyCACertFingerprintMismatch(t *testing.T) {
	certPEM, _ := generateTestCACert(t)
	err := verifyCACertFingerprint(certPEM, "deadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")
	assert.Contains(t, err.Error(), "deadbeef")
}

func TestVerifyCACertFingerprintInvalidPEM(t *testing.T) {
	err := verifyCACertFingerprint("not-valid-pem", "deadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode CA certificate PEM")
}

func TestWriteCACertMode(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "etc", "cfgms", "controller-ca.crt")
	certPEM, _ := generateTestCACert(t)

	require.NoError(t, writeCACert(certPEM, destPath))

	info, err := os.Stat(destPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}

func TestWriteCACertContent(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "controller-ca.crt")
	certPEM, _ := generateTestCACert(t)

	require.NoError(t, writeCACert(certPEM, destPath))

	got, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, certPEM, string(got))
}

func TestWriteCACertCreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "deeply", "nested", "dir", "controller-ca.crt")
	certPEM, _ := generateTestCACert(t)

	require.NoError(t, writeCACert(certPEM, destPath))

	_, err := os.Stat(destPath)
	require.NoError(t, err)
}
