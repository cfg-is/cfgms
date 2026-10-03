// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIssuedCertificateVerifiesOnATrailingClock guards Issue #4536: a steward
// whose clock trails the controller's must accept a certificate it was just
// issued. Before the allowance, NotBefore was the controller's "now", so a
// verifier two minutes behind rejected both the leaf and the CA as not yet valid.
func TestIssuedCertificateVerifiesOnATrailingClock(t *testing.T) {
	caConfig := &CAConfig{Organization: "Test CA", Country: "US", ValidityDays: 365}
	ca, err := NewCA(caConfig)
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(caConfig))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issued, err := ca.SignClientCertificateRequest(&key.PublicKey, &ClientCertConfig{
		CommonName: "steward-skew-test", ClientID: "steward-skew-test", ValidityDays: 365,
	})
	require.NoError(t, err)

	leaf, err := ParseCertificateFromPEM(issued.CertificatePEM)
	require.NoError(t, err)
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	root, err := ParseCertificateFromPEM(caPEM)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now().Add(-2 * time.Minute), // a steward two minutes behind
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err, "a freshly issued certificate must verify on a clock that trails the issuer's")
}
