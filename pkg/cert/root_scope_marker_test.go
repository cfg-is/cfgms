// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetRootScopeMarker_AddsExtension(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	SetRootScopeMarker(template)

	found := false
	for _, ext := range template.ExtraExtensions {
		if ext.Id.Equal(RootScopeMarkerOID) {
			found = true
			assert.False(t, ext.Critical, "root-scope marker must not be critical")
			assert.Equal(t, []byte{0x01, 0x01, 0xff}, ext.Value, "root-scope marker value must be ASN.1 DER boolean TRUE")
			break
		}
	}
	assert.True(t, found, "SetRootScopeMarker must add the root-scope marker OID extension")
}

func TestHasRootScopeMarker_TrueForMarkedCert(t *testing.T) {
	cert := makeRootScopeSignedCert(t, true)
	assert.True(t, HasRootScopeMarker(cert), "HasRootScopeMarker must return true for a cert with the root-scope marker")
}

func TestHasRootScopeMarker_FalseForUnmarkedCert(t *testing.T) {
	cert := makeRootScopeSignedCert(t, false)
	assert.False(t, HasRootScopeMarker(cert), "HasRootScopeMarker must return false for a cert without the root-scope marker")
}

// TestHasRootScopeMarker_IndependentOfAdminMarker verifies the two markers are
// distinct signals: a cert can carry the admin marker without the root-scope marker
// (an ordinary unscoped superadmin cert, today's only shape) and HasRootScopeMarker
// must not be satisfied by AdminMarkerOID alone.
func TestHasRootScopeMarker_IndependentOfAdminMarker(t *testing.T) {
	caKey, caCert := makeTestCA(t)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "admin-only"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	SetAdminMarker(template)

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	assert.True(t, HasAdminMarker(leafCert))
	assert.False(t, HasRootScopeMarker(leafCert), "admin marker alone must not imply root scope")
}

// makeRootScopeSignedCert builds a CA-signed leaf cert carrying both the admin and
// root-scope markers (or neither), mirroring admin_marker_test.go's makeSignedCert.
func makeRootScopeSignedCert(t *testing.T, withMarker bool) *x509.Certificate {
	t.Helper()
	caKey, caCert := makeTestCA(t)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-leaf-root-scoped"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	SetAdminMarker(template)
	if withMarker {
		SetRootScopeMarker(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return leafCert
}
