// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetAdminMarker_AddsExtension(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	SetAdminMarker(template)

	found := false
	for _, ext := range template.ExtraExtensions {
		if ext.Id.Equal(AdminMarkerOID) {
			found = true
			assert.False(t, ext.Critical, "admin marker must not be critical")
			assert.Equal(t, []byte{0x01, 0x01, 0xff}, ext.Value, "admin marker value must be ASN.1 DER boolean TRUE")
			break
		}
	}
	assert.True(t, found, "SetAdminMarker must add the admin marker OID extension")
}

func TestSetAdminMarker_PreservesExistingExtensions(t *testing.T) {
	otherOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: otherOID, Value: []byte{0x00}},
		},
	}

	SetAdminMarker(template)

	assert.Len(t, template.ExtraExtensions, 2, "must preserve existing extension")
	assert.True(t, template.ExtraExtensions[0].Id.Equal(otherOID), "existing extension must remain first")
}

func TestHasAdminMarker_TrueForMarkedCert(t *testing.T) {
	cert := makeSignedCert(t, true)
	assert.True(t, HasAdminMarker(cert), "HasAdminMarker must return true for a cert with admin marker")
}

func TestHasAdminMarker_FalseForUnmarkedCert(t *testing.T) {
	cert := makeSignedCert(t, false)
	assert.False(t, HasAdminMarker(cert), "HasAdminMarker must return false for a cert without admin marker")
}

func TestHasAdminMarker_FalseForWrongOID(t *testing.T) {
	wrongOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2} // sibling OID
	caKey, caCert := makeTestCA(t)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "wrong-oid"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: wrongOID, Value: []byte{0x01, 0x01, 0xff}},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	assert.False(t, HasAdminMarker(leafCert), "HasAdminMarker must return false for cert with wrong OID")
}

// makeTestCA generates an in-memory CA key and self-signed certificate for tests.
func makeTestCA(t *testing.T) (caKey *rsa.PrivateKey, caCert *x509.Certificate) {
	t.Helper()
	var err error
	caKey, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)
	return
}

// makeSignedCert creates a CA-signed leaf cert optionally carrying the admin marker.
func makeSignedCert(t *testing.T, withMarker bool) *x509.Certificate {
	t.Helper()
	caKey, caCert := makeTestCA(t)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if withMarker {
		SetAdminMarker(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return leafCert
}
