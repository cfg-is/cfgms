// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateSelfSignedRSA creates a minimal self-signed RSA cert with the given key size.
func generateSelfSignedRSA(t *testing.T, bits int) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)
	return cert
}

// generateSelfSignedEC creates a minimal self-signed EC P-256 cert.
func generateSelfSignedEC(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)
	return cert
}

func hasRSAKeySizeWarning(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "RSA key size") {
			return true
		}
	}
	return false
}

func TestValidateBasicConstraints_RSAKeySize(t *testing.T) {
	tests := []struct {
		name        string
		cert        func() *x509.Certificate
		wantWarning bool
	}{
		{
			name:        "2048-bit RSA cert emits no warning",
			cert:        func() *x509.Certificate { return generateSelfSignedRSA(t, 2048) },
			wantWarning: false,
		},
		{
			name:        "4096-bit RSA cert emits no warning",
			cert:        func() *x509.Certificate { return generateSelfSignedRSA(t, 4096) },
			wantWarning: false,
		},
		{
			name:        "1024-bit RSA cert emits warning",
			cert:        func() *x509.Certificate { return generateSelfSignedRSA(t, 1024) },
			wantWarning: true,
		},
		{
			name:        "EC P-256 cert emits no RSA warning",
			cert:        func() *x509.Certificate { return generateSelfSignedEC(t) },
			wantWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewValidator(nil)
			result, err := v.ValidateCertificate(tt.cert())
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.True(t, result.IsValid, "cert should be valid regardless of key size; warnings: %v", result.Warnings)

			gotWarning := hasRSAKeySizeWarning(result.Warnings)
			if tt.wantWarning {
				assert.True(t, gotWarning, "expected RSA key-size warning but got none; warnings: %v", result.Warnings)
			} else {
				assert.False(t, gotWarning, "unexpected RSA key-size warning; warnings: %v", result.Warnings)
			}
		})
	}
}

func TestValidateBasicConstraints_RSAWarningSaysActualBitLen(t *testing.T) {
	v := NewValidator(nil)
	cert := generateSelfSignedRSA(t, 1024)
	result, err := v.ValidateCertificate(cert)
	require.NoError(t, err)

	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "1024") {
			found = true
		}
	}
	assert.True(t, found, "warning should include actual bit length 1024; warnings: %v", result.Warnings)
}
