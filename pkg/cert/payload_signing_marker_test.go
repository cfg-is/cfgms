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

func TestPayloadSigningMarkerOID_DistinctFromAdminMarkerOID(t *testing.T) {
	assert.False(t, PayloadSigningMarkerOID.Equal(AdminMarkerOID),
		"PayloadSigningMarkerOID must be a distinct arc from AdminMarkerOID")
	assert.False(t, PayloadSigningMarkerOID.Equal(RootScopeMarkerOID),
		"PayloadSigningMarkerOID must be a distinct arc from RootScopeMarkerOID")
}

func TestSetPayloadSigningMarker_AddsExtension(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	SetPayloadSigningMarker(template)

	found := false
	for _, ext := range template.ExtraExtensions {
		if ext.Id.Equal(PayloadSigningMarkerOID) {
			found = true
			assert.False(t, ext.Critical, "payload signing marker must not be critical")
			assert.Equal(t, []byte{0x01, 0x01, 0xff}, ext.Value, "payload signing marker value must be ASN.1 DER boolean TRUE")
			break
		}
	}
	assert.True(t, found, "SetPayloadSigningMarker must add the payload signing marker OID extension")
}

func TestSetPayloadSigningMarker_PreservesExistingExtensions(t *testing.T) {
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

	SetPayloadSigningMarker(template)

	assert.Len(t, template.ExtraExtensions, 2, "must preserve existing extension")
	assert.True(t, template.ExtraExtensions[0].Id.Equal(otherOID), "existing extension must remain first")
}

func TestHasPayloadSigningMarker_TrueForMarkedCert(t *testing.T) {
	cert := makePayloadSigningTestCert(t, true, false)
	assert.True(t, HasPayloadSigningMarker(cert), "HasPayloadSigningMarker must return true for a cert with the marker")
}

func TestHasPayloadSigningMarker_FalseForUnmarkedCert(t *testing.T) {
	cert := makePayloadSigningTestCert(t, false, false)
	assert.False(t, HasPayloadSigningMarker(cert), "HasPayloadSigningMarker must return false for a cert without the marker")
}

// TestHasPayloadSigningMarker_AdminMarkerAloneIsNotSufficient proves an ordinary
// admin transport bundle (AdminMarkerOID only) cannot be mistaken for a
// payload-signing credential — [REQUIRED TEST].
func TestHasPayloadSigningMarker_AdminMarkerAloneIsNotSufficient(t *testing.T) {
	cert := makePayloadSigningTestCert(t, false, true)
	assert.True(t, HasAdminMarker(cert))
	assert.False(t, HasPayloadSigningMarker(cert), "an admin-marked cert without the payload signing marker must not pass HasPayloadSigningMarker")
}

// makePayloadSigningTestCert creates a CA-signed leaf cert optionally carrying the
// payload signing marker and/or the admin marker.
func makePayloadSigningTestCert(t *testing.T, withPayloadSigningMarker, withAdminMarker bool) *x509.Certificate {
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
	if withPayloadSigningMarker {
		SetPayloadSigningMarker(template)
	}
	if withAdminMarker {
		SetAdminMarker(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return leafCert
}
