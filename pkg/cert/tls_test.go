// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCertPoolFromPEM_RealCACertificate verifies that CertPoolFromPEM builds a
// usable verification pool from a real CA certificate produced by cert.Manager,
// and that a certificate issued by that CA verifies against the pool.
func TestCertPoolFromPEM_RealCACertificate(t *testing.T) {
	manager := setupTestManager(t)

	caCertPEM, err := manager.GetCACertificate()
	require.NoError(t, err)
	require.NotEmpty(t, caCertPEM)

	pool, err := CertPoolFromPEM(caCertPEM)
	require.NoError(t, err)
	require.NotNil(t, pool)

	// The pool must actually verify a certificate issued by that CA, proving the
	// PEM was appended as a trusted root and not silently dropped.
	serverCert, err := manager.GenerateServerCertificate(&ServerCertConfig{
		CommonName: "pool-test.cfgms.local",
		DNSNames:   []string{"pool-test.cfgms.local"},
	})
	require.NoError(t, err)

	leaf, err := ParseCertificateFromPEM(serverCert.CertificatePEM)
	require.NoError(t, err)

	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err, "certificate issued by the CA must verify against the pool")
	assert.NotEmpty(t, chains)
}

// TestCertPoolFromPEM_EmptyInput verifies that empty input is reported as an error
// rather than returning an empty pool that would silently trust nothing.
func TestCertPoolFromPEM_EmptyInput(t *testing.T) {
	for name, input := range map[string][]byte{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			pool, err := CertPoolFromPEM(input)
			require.Error(t, err)
			assert.Nil(t, pool)
			assert.Contains(t, err.Error(), "no CA certificate PEM provided")
		})
	}
}

// TestCertPoolFromPEM_UnparseablePEM verifies that non-certificate input is
// rejected instead of yielding a pool with no roots.
func TestCertPoolFromPEM_UnparseablePEM(t *testing.T) {
	for name, input := range map[string]string{
		"not pem at all":     "this is not a certificate",
		"wrong pem block":    "-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----\n",
		"truncated cert pem": "-----BEGIN CERTIFICATE-----\nZm9v\n",
	} {
		t.Run(name, func(t *testing.T) {
			pool, err := CertPoolFromPEM([]byte(input))
			require.Error(t, err)
			assert.Nil(t, pool)
			assert.Contains(t, err.Error(), "failed to parse CA certificate PEM")
		})
	}
}
