// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPoolTestCA builds a real, initialized CA — no static test fixtures.
func newPoolTestCA(t *testing.T) *CA {
	t.Helper()
	cfg := &CAConfig{
		Organization: "CFGMS Pool Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	}
	ca, err := NewCA(cfg)
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(cfg))
	return ca
}

// TestNewCertPoolFromPEM_BuildsUsableVerificationPool proves the helper produces a
// pool that actually verifies a chain, not just a non-nil value. This is the single
// construction point callers outside pkg/cert must use instead of x509.NewCertPool
// (enforced by `make check-architecture`).
func TestNewCertPoolFromPEM_BuildsUsableVerificationPool(t *testing.T) {
	ca := newPoolTestCA(t)
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	pool, err := NewCertPoolFromPEM(caPEM)
	require.NoError(t, err)
	require.NotNil(t, pool)

	leaf, err := ca.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "pool-test-steward",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	leafCert, err := ParseCertificateFromPEM(leaf.CertificatePEM)
	require.NoError(t, err)

	chains, err := leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err, "a cert issued by the CA must chain to the pool built from that CA's PEM")
	assert.NotEmpty(t, chains)

	// An unrelated CA's leaf must NOT verify — the pool is not permissive.
	other := newPoolTestCA(t)
	otherLeaf, err := other.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "foreign-steward",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	otherCert, err := ParseCertificateFromPEM(otherLeaf.CertificatePEM)
	require.NoError(t, err)
	_, err = otherCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	assert.Error(t, err, "a cert from a different CA must not chain to this pool")
}

// TestNewCertPoolFromPEM_RejectsUnusablePEM: the helper never hands back an empty
// pool. An empty pool silently rejects every chain, which is indistinguishable at
// the call site from "verification is disabled" — so it must be an error instead.
func TestNewCertPoolFromPEM_RejectsUnusablePEM(t *testing.T) {
	for name, input := range map[string][]byte{
		"nil":          nil,
		"empty":        {},
		"not PEM":      []byte("this is not a certificate"),
		"PEM-ish junk": []byte("-----BEGIN CERTIFICATE-----\nnot-base64!!\n-----END CERTIFICATE-----\n"),
	} {
		t.Run(name, func(t *testing.T) {
			pool, err := NewCertPoolFromPEM(input)
			require.Error(t, err)
			assert.Nil(t, pool, "no pool may be returned when the PEM is unusable")
		})
	}
}
