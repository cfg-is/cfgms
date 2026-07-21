// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust_test

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// testContentHash is a well-formed hex SHA-256 (the digest of the empty input).
const testContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// stewardBinaryStore returns a trust store holding pub under the "cfgms" publisher.
func stewardBinaryStore(t *testing.T, pub ed25519.PublicKey) trust.TrustStore {
	t.Helper()
	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: []byte(pub),
		Algorithm: "ed25519",
	}))
	return store
}

// signStewardBinary signs the canonical composite message for the given coordinates.
func signStewardBinary(t *testing.T, priv ed25519.PrivateKey, contentHash, version, platform, arch string) bundle.BundleSignature {
	t.Helper()
	msg, err := trust.StewardBinaryMessage(contentHash, version, platform, arch)
	require.NoError(t, err)
	return bundle.BundleSignature{
		Publisher: "cfgms",
		Algorithm: "ed25519",
		Signature: ed25519.Sign(priv, []byte(msg)),
	}
}

// TestStewardBinaryMessage_BindsAllCoordinates proves the signed message covers the
// release coordinates, not just the content hash — the basis of the rollback defense.
func TestStewardBinaryMessage_BindsAllCoordinates(t *testing.T) {
	msg, err := trust.StewardBinaryMessage(testContentHash, "v0.9.41", "windows", "amd64")
	require.NoError(t, err)

	assert.Contains(t, msg, testContentHash)
	assert.Contains(t, msg, "v0.9.41")
	assert.Contains(t, msg, "windows")
	assert.Contains(t, msg, "amd64")

	// Changing any single coordinate must change the message.
	for _, other := range []struct{ hash, version, platform, arch string }{
		{"aaaa", "v0.9.41", "windows", "amd64"},
		{testContentHash, "v0.9.42", "windows", "amd64"},
		{testContentHash, "v0.9.41", "linux", "amd64"},
		{testContentHash, "v0.9.41", "windows", "arm64"},
	} {
		got, err := trust.StewardBinaryMessage(other.hash, other.version, other.platform, other.arch)
		require.NoError(t, err)
		assert.NotEqual(t, msg, got)
	}
}

// TestStewardBinaryMessage_CanonicalizesLeadingV proves the only permitted
// normalization — a missing "v" prefix — yields a byte-identical message.
func TestStewardBinaryMessage_CanonicalizesLeadingV(t *testing.T) {
	withV, err := trust.StewardBinaryMessage(testContentHash, "v0.9.41", "windows", "amd64")
	require.NoError(t, err)
	withoutV, err := trust.StewardBinaryMessage(testContentHash, "0.9.41", "windows", "amd64")
	require.NoError(t, err)

	assert.Equal(t, withV, withoutV, "v-prefix normalization must produce an identical message")
}

// TestStewardBinaryMessage_DoesNotCollapseDistinctVersions proves normalization is
// strictly limited to the leading "v". Collapsing pre-release or build metadata would
// let one signature cover two releases and partially reopen the rollback gap.
func TestStewardBinaryMessage_DoesNotCollapseDistinctVersions(t *testing.T) {
	base, err := trust.StewardBinaryMessage(testContentHash, "v1.2.3", "windows", "amd64")
	require.NoError(t, err)

	for _, distinct := range []string{"v1.2.3-rc1", "v1.2.3+build5", "v1.2.30", "v1.2.3-RC1"} {
		got, err := trust.StewardBinaryMessage(testContentHash, distinct, "windows", "amd64")
		require.NoError(t, err)
		assert.NotEqual(t, base, got, "%q must not collapse to v1.2.3", distinct)
	}
}

// TestStewardBinaryMessage_RejectsSeparatorInField proves the separator is hard-rejected
// rather than sanitized — stripping it would let two distinct inputs collide.
func TestStewardBinaryMessage_RejectsSeparatorInField(t *testing.T) {
	cases := map[string][4]string{
		"content hash": {"abc|def", "v0.9.41", "windows", "amd64"},
		"version":      {testContentHash, "v0.9|41", "windows", "amd64"},
		"platform":     {testContentHash, "v0.9.41", "win|dows", "amd64"},
		"arch":         {testContentHash, "v0.9.41", "windows", "amd|64"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := trust.StewardBinaryMessage(c[0], c[1], c[2], c[3])
			require.Error(t, err)
			assert.ErrorIs(t, err, trust.ErrInvalidSignatureMessage)
		})
	}
}

// TestStewardBinaryMessage_RejectsEmptyField proves an unbound coordinate cannot be
// signed — an empty version would defeat the binding entirely.
func TestStewardBinaryMessage_RejectsEmptyField(t *testing.T) {
	cases := map[string][4]string{
		"content hash": {"", "v0.9.41", "windows", "amd64"},
		"version":      {testContentHash, "", "windows", "amd64"},
		"platform":     {testContentHash, "v0.9.41", "", "amd64"},
		"arch":         {testContentHash, "v0.9.41", "windows", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := trust.StewardBinaryMessage(c[0], c[1], c[2], c[3])
			require.Error(t, err)
			assert.ErrorIs(t, err, trust.ErrInvalidSignatureMessage)
		})
	}
}

// TestVerifyStewardBinarySignature_ValidRoundTrip proves signer and verifier agree
// byte-for-byte on the canonical message.
func TestVerifyStewardBinarySignature_ValidRoundTrip(t *testing.T) {
	pub, priv := makeKeypair(t)
	store := stewardBinaryStore(t, pub)
	sig := signStewardBinary(t, priv, testContentHash, "v0.9.41", "windows", "amd64")

	err := trust.VerifyStewardBinarySignature(testContentHash, "v0.9.41", "windows", "amd64", sig, store)
	assert.NoError(t, err)
}

// TestVerifyStewardBinarySignature_RejectsRollback is the core security test: a binary
// validly signed for an OLDER version, served at a NEWER version's coordinates, must be
// rejected. Without version binding the signature would verify and the downgrade guard
// would be bypassed, because the version is controller-attested rather than signed.
func TestVerifyStewardBinarySignature_RejectsRollback(t *testing.T) {
	pub, priv := makeKeypair(t)
	store := stewardBinaryStore(t, pub)

	// Authentic signature over the OLD version.
	sig := signStewardBinary(t, priv, testContentHash, "v0.9.40", "windows", "amd64")

	// Presented as the NEW version, with its genuine content hash and signature.
	err := trust.VerifyStewardBinarySignature(testContentHash, "v0.9.41", "windows", "amd64", sig, store)
	require.Error(t, err)
	assert.ErrorIs(t, err, trust.ErrInvalidSignature)
}

// TestVerifyStewardBinarySignature_RejectsCoordinateMismatch proves platform/arch and
// content-hash substitution are rejected alongside version.
func TestVerifyStewardBinarySignature_RejectsCoordinateMismatch(t *testing.T) {
	pub, priv := makeKeypair(t)
	store := stewardBinaryStore(t, pub)
	sig := signStewardBinary(t, priv, testContentHash, "v0.9.41", "windows", "amd64")

	cases := map[string][4]string{
		"tampered binary": {strings.Repeat("a", 64), "v0.9.41", "windows", "amd64"},
		"platform swap":   {testContentHash, "v0.9.41", "linux", "amd64"},
		"arch swap":       {testContentHash, "v0.9.41", "windows", "arm64"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := trust.VerifyStewardBinarySignature(c[0], c[1], c[2], c[3], sig, store)
			require.Error(t, err)
			assert.ErrorIs(t, err, trust.ErrInvalidSignature)
		})
	}
}

// TestVerifyStewardBinarySignature_RejectsUntrustedPublisher proves a controller-supplied
// publisher name cannot select a key outside the store.
func TestVerifyStewardBinarySignature_RejectsUntrustedPublisher(t *testing.T) {
	pub, priv := makeKeypair(t)
	store := stewardBinaryStore(t, pub)

	sig := signStewardBinary(t, priv, testContentHash, "v0.9.41", "windows", "amd64")
	sig.Publisher = "attacker"

	err := trust.VerifyStewardBinarySignature(testContentHash, "v0.9.41", "windows", "amd64", sig, store)
	require.Error(t, err)
	assert.ErrorIs(t, err, trust.ErrPublisherNotTrusted)
}

// TestVerifyStewardBinarySignature_PlaceholderKeyFailsClosed proves an unconfigured
// (all-zero identity) build rejects every binary rather than accepting forgeries.
func TestVerifyStewardBinarySignature_PlaceholderKeyFailsClosed(t *testing.T) {
	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: make([]byte, ed25519.PublicKeySize), // all-zero placeholder
		Algorithm: "ed25519",
	}))

	_, priv := makeKeypair(t)
	sig := signStewardBinary(t, priv, testContentHash, "v0.9.41", "windows", "amd64")

	err := trust.VerifyStewardBinarySignature(testContentHash, "v0.9.41", "windows", "amd64", sig, store)
	require.Error(t, err)
	assert.ErrorIs(t, err, trust.ErrUntrustedPublisherKey)
}

// TestVerifyStewardBinarySignature_RejectsMalformedCoordinates proves message-construction
// failures surface as verification failures rather than being silently signed over.
func TestVerifyStewardBinarySignature_RejectsMalformedCoordinates(t *testing.T) {
	pub, priv := makeKeypair(t)
	store := stewardBinaryStore(t, pub)
	sig := signStewardBinary(t, priv, testContentHash, "v0.9.41", "windows", "amd64")

	err := trust.VerifyStewardBinarySignature(testContentHash, "v0.9|41", "windows", "amd64", sig, store)
	require.Error(t, err)
	assert.ErrorIs(t, err, trust.ErrInvalidSignatureMessage)
}

// TestVerifyBundleSignature_ModuleBundlePathUnaffected is a regression guard for the
// #2834 constraint: module-bundle verification still signs the bare content hash, so
// already-published module bundles keep verifying. If this breaks, the shared primitive
// was altered and module auto-approval / steward module trust would fail fleet-wide.
func TestVerifyBundleSignature_ModuleBundlePathUnaffected(t *testing.T) {
	pub, priv := makeKeypair(t)
	store := stewardBinaryStore(t, pub)

	b := makeBundle("modulebundlecontenthash")
	sig := bundle.BundleSignature{
		Publisher: "cfgms",
		Algorithm: "ed25519",
		Signature: signHash(t, priv, b.ContentHash),
	}

	assert.NoError(t, trust.VerifyBundleSignature(b, sig, store))
}
