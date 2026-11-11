// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountBindingOID_DistinctFromOtherMarkers(t *testing.T) {
	for name, other := range map[string]asn1.ObjectIdentifier{
		"admin": AdminMarkerOID, "root-scope": RootScopeMarkerOID, "payload-signing": PayloadSigningMarkerOID,
	} {
		assert.False(t, AccountBindingOID.Equal(other), "AccountBindingOID must be a distinct arc from the %s marker", name)
	}
}

// issueWithExtension signs a leaf carrying the given raw extensions with a throwaway CA, so the
// parsed certificate has the extension exactly as x509.ParseCertificate reports it.
func issueWithExtension(t *testing.T, exts ...[]byte) *x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
	}
	for _, v := range exts {
		leafTpl.ExtraExtensions = append(leafTpl.ExtraExtensions, pkix.Extension{Id: AccountBindingOID, Value: v})
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf
}

func TestSetAccountBinding_RoundTripsThroughACertificate(t *testing.T) {
	tpl := &x509.Certificate{}
	require.NoError(t, SetAccountBinding(tpl, "acct-1234"))
	require.Len(t, tpl.ExtraExtensions, 1)
	assert.False(t, tpl.ExtraExtensions[0].Critical, "the binding must not be critical")

	leaf := issueWithExtension(t, tpl.ExtraExtensions[0].Value)
	id, ok := AccountBindingFromCertificate(leaf)
	assert.True(t, ok)
	assert.Equal(t, "acct-1234", id)
}

func TestSetAccountBinding_PreservesExistingExtensions(t *testing.T) {
	tpl := &x509.Certificate{ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{0}}}}
	require.NoError(t, SetAccountBinding(tpl, "acct-1"))
	require.Len(t, tpl.ExtraExtensions, 2)
	assert.True(t, tpl.ExtraExtensions[0].Id.Equal(asn1.ObjectIdentifier{1, 2, 3, 4}))
}

func TestSetAccountBinding_RejectsUnusableAccountIDs(t *testing.T) {
	for name, id := range map[string]string{
		"empty":        "",
		"control char": "acct\x00id",
		"too long":     strings.Repeat("a", MaxAccountBindingLen+1),
		"not utf-8":    "acct\xffid",
	} {
		t.Run(name, func(t *testing.T) {
			tpl := &x509.Certificate{}
			require.Error(t, SetAccountBinding(tpl, id))
			assert.Empty(t, tpl.ExtraExtensions, "a refused binding must not leave an extension behind")
		})
	}
}

func TestValidateAccountBindingID(t *testing.T) {
	require.NoError(t, ValidateAccountBindingID("acct-123"))
	require.NoError(t, ValidateAccountBindingID(strings.Repeat("a", MaxAccountBindingLen)))
	for name, id := range map[string]string{
		"empty":        "",
		"control char": "acct\x00id",
		"too long":     strings.Repeat("a", MaxAccountBindingLen+1),
		"not utf-8":    "acct\xffid",
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, ValidateAccountBindingID(id))
		})
	}
}

func TestAccountBindingFromCertificate_Absent(t *testing.T) {
	id, ok := AccountBindingFromCertificate(issueWithExtension(t))
	assert.False(t, ok)
	assert.Empty(t, id)
}

func TestAccountBindingFromCertificate_MalformedValueIsNotABinding(t *testing.T) {
	valid, err := asn1.MarshalWithParams("acct-1", "utf8")
	require.NoError(t, err)
	intValue, err := asn1.Marshal(42)
	require.NoError(t, err)
	emptyValue, err := asn1.MarshalWithParams("", "utf8")
	require.NoError(t, err)

	for name, value := range map[string][]byte{
		"not a string":       intValue,
		"empty string":       emptyValue,
		"trailing bytes":     append(append([]byte{}, valid...), 0x00),
		"garbage":            {0xff, 0xff},
		"empty extension":    {},
		"oversized":          mustUTF8(t, strings.Repeat("a", MaxAccountBindingLen+1)),
		"control characters": mustUTF8(t, "a\nb"),
	} {
		t.Run(name, func(t *testing.T) {
			id, ok := AccountBindingFromCertificate(issueWithExtension(t, value))
			assert.False(t, ok)
			assert.Empty(t, id)
		})
	}
}

// A certificate repeating the extension is refused outright: x509.CreateCertificate refuses it,
// so a duplicate can only arrive in a hand-built certificate, where "first wins" would let a
// verifier and a relying party disagree about the owner.
func TestAccountBindingFromCertificate_DuplicateExtensionIsNotABinding(t *testing.T) {
	a, b := mustUTF8(t, "acct-a"), mustUTF8(t, "acct-b")
	cert := &x509.Certificate{Extensions: []pkix.Extension{
		{Id: AccountBindingOID, Value: a}, {Id: AccountBindingOID, Value: b},
	}}
	id, ok := AccountBindingFromCertificate(cert)
	assert.False(t, ok)
	assert.Empty(t, id)
}

func mustUTF8(t *testing.T, s string) []byte {
	t.Helper()
	v, err := asn1.MarshalWithParams(s, "utf8")
	require.NoError(t, err)
	return v
}
