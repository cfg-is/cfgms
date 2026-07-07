// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

func makeKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func makeBundle(contentHash string) *bundle.Bundle {
	return &bundle.Bundle{
		ContentHash: contentHash,
	}
}

func signHash(t *testing.T, priv ed25519.PrivateKey, contentHash string) []byte {
	t.Helper()
	sig := ed25519.Sign(priv, []byte(contentHash))
	return sig
}

// TestVerifyBundleSignature_ValidSignature verifies that a valid Ed25519 signature
// from a trusted publisher passes verification.
func TestVerifyBundleSignature_ValidSignature(t *testing.T) {
	pub, priv := makeKeypair(t)

	store := trust.NewInMemoryTrustStore()
	err := store.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: []byte(pub),
		Algorithm: "ed25519",
	})
	require.NoError(t, err)

	b := makeBundle("abc123contenthash")
	sig := bundle.BundleSignature{
		Publisher: "cfgms",
		Algorithm: "ed25519",
		Signature: signHash(t, priv, b.ContentHash),
	}

	err = trust.VerifyBundleSignature(b, sig, store)
	assert.NoError(t, err)
}

// TestVerifyBundleSignature_TamperedBundle verifies that a tampered bundle
// (content hash bytes changed) fails verification.
func TestVerifyBundleSignature_TamperedBundle(t *testing.T) {
	pub, priv := makeKeypair(t)

	store := trust.NewInMemoryTrustStore()
	err := store.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: []byte(pub),
		Algorithm: "ed25519",
	})
	require.NoError(t, err)

	originalHash := "original-content-hash"
	tamperedHash := "tampered-content-hash"

	// Sign the original hash
	sig := bundle.BundleSignature{
		Publisher: "cfgms",
		Algorithm: "ed25519",
		Signature: signHash(t, priv, originalHash),
	}

	// But verify against a bundle with a different hash
	b := makeBundle(tamperedHash)
	err = trust.VerifyBundleSignature(b, sig, store)
	require.Error(t, err)
	assert.True(t, errors.Is(err, trust.ErrInvalidSignature), "expected ErrInvalidSignature, got: %v", err)
}

// TestVerifyBundleSignature_UnknownPublisher verifies that a signature from an
// unknown publisher (not in the trust store) returns ErrPublisherNotTrusted.
func TestVerifyBundleSignature_UnknownPublisher(t *testing.T) {
	_, priv := makeKeypair(t)

	store := trust.NewInMemoryTrustStore()
	// No publishers added to the store

	b := makeBundle("some-content-hash")
	sig := bundle.BundleSignature{
		Publisher: "unknown-publisher",
		Algorithm: "ed25519",
		Signature: signHash(t, priv, b.ContentHash),
	}

	err := trust.VerifyBundleSignature(b, sig, store)
	require.Error(t, err)
	assert.True(t, errors.Is(err, trust.ErrPublisherNotTrusted), "expected ErrPublisherNotTrusted, got: %v", err)
}

// TestVerifyBundleSignature_WrongKey verifies that a known publisher signed with a
// different private key returns ErrInvalidSignature (the stored key is valid length
// but verification fails cryptographically).
func TestVerifyBundleSignature_WrongKey(t *testing.T) {
	pub1, _ := makeKeypair(t)
	_, priv2 := makeKeypair(t) // Different keypair — priv2 doesn't pair with pub1

	store := trust.NewInMemoryTrustStore()
	err := store.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: []byte(pub1),
		Algorithm: "ed25519",
	})
	require.NoError(t, err)

	b := makeBundle("some-content-hash")
	sig := bundle.BundleSignature{
		Publisher: "cfgms",
		Algorithm: "ed25519",
		Signature: signHash(t, priv2, b.ContentHash),
	}

	err = trust.VerifyBundleSignature(b, sig, store)
	require.Error(t, err)
	assert.True(t, errors.Is(err, trust.ErrInvalidSignature),
		"expected ErrInvalidSignature for wrong keypair, got: %v", err)
}

// TestVerifyBundleSignature_MalformedStoredKey verifies that a publisher registered
// with a malformed (short) public key returns ErrKeyMismatch.
func TestVerifyBundleSignature_MalformedStoredKey(t *testing.T) {
	_, priv := makeKeypair(t)

	store := trust.NewInMemoryTrustStore()
	// Register a short (malformed) public key — less than 32 bytes
	err := store.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: []byte("short"),
		Algorithm: "ed25519",
	})
	require.NoError(t, err)

	b := makeBundle("some-content-hash")
	sig := bundle.BundleSignature{
		Publisher: "cfgms",
		Algorithm: "ed25519",
		Signature: signHash(t, priv, b.ContentHash),
	}

	err = trust.VerifyBundleSignature(b, sig, store)
	require.Error(t, err)
	assert.True(t, errors.Is(err, trust.ErrKeyMismatch),
		"expected ErrKeyMismatch for malformed stored key, got: %v", err)
}

// forgedSigOverAnyMessage builds an Ed25519 signature (R || S) that ed25519.Verify
// accepts against the all-zero public key for an arbitrary message: R is a small-order
// point (the p-1 / order-2 encoding) and S is the zero scalar. No private key is used.
func forgedSigOverAnyMessage() []byte {
	r := make([]byte, ed25519.PublicKeySize)
	r[0] = 0xec
	for i := 1; i < ed25519.PublicKeySize-1; i++ {
		r[i] = 0xff
	}
	r[ed25519.PublicKeySize-1] = 0x7f
	s := make([]byte, ed25519.PublicKeySize) // zero scalar
	return append(append([]byte{}, r...), s...)
}

// TestVerifyBundleSignature_AllZeroPlaceholderKeyRejected proves the placeholder-key
// footgun is closed. The all-zero key is a small-order Ed25519 point: raw ed25519.Verify
// ACCEPTS an attacker-forged signature over an attacker-chosen message against it. A
// trust store holding that key must therefore refuse the bundle, not accept the forgery.
func TestVerifyBundleSignature_AllZeroPlaceholderKeyRejected(t *testing.T) {
	allZeroKey := make([]byte, ed25519.PublicKeySize)
	forged := forgedSigOverAnyMessage()

	// Whether the primitive accepts this fixed small-order R || S=0 forgery depends on
	// the hash of (R, A, message) landing on the right residue, so search for a content
	// hash the raw primitive accepts. This makes the footgun concrete and deterministic.
	var message string
	var accepted bool
	for i := 0; i < 4096; i++ {
		candidate := fmt.Sprintf("attacker-chosen-content-hash-%d", i)
		if ed25519.Verify(ed25519.PublicKey(allZeroKey), []byte(candidate), forged) {
			message = candidate
			accepted = true
			break
		}
	}
	require.True(t, accepted,
		"precondition: ed25519.Verify must accept the forgery against the all-zero key for some message")

	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: allZeroKey,
		Algorithm: "ed25519",
	}))

	b := makeBundle(message)
	sig := bundle.BundleSignature{Publisher: "cfgms", Algorithm: "ed25519", Signature: forged}

	err := trust.VerifyBundleSignature(b, sig, store)
	require.Error(t, err)
	assert.True(t, errors.Is(err, trust.ErrUntrustedPublisherKey),
		"placeholder all-zero key must be rejected as ErrUntrustedPublisherKey, got: %v", err)
}

// TestVerifyBundleSignature_SmallOrderKeyRejected verifies that a non-zero small-order
// public key (an order-8 point) is also rejected, independent of the signature bytes.
func TestVerifyBundleSignature_SmallOrderKeyRejected(t *testing.T) {
	// An order-8 small-order point encoding.
	smallOrderKey := []byte{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
		0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
		0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	}
	require.Len(t, smallOrderKey, ed25519.PublicKeySize)

	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: smallOrderKey,
		Algorithm: "ed25519",
	}))

	b := makeBundle("some-content-hash")
	sig := bundle.BundleSignature{
		Publisher: "cfgms",
		Algorithm: "ed25519",
		Signature: make([]byte, ed25519.SignatureSize),
	}

	err := trust.VerifyBundleSignature(b, sig, store)
	require.Error(t, err)
	assert.True(t, errors.Is(err, trust.ErrUntrustedPublisherKey),
		"small-order key must be rejected as ErrUntrustedPublisherKey, got: %v", err)
}

// TestVerifyBundleSignature_CFGMSPlaceholderIdentityRejectsBundles verifies that a build
// carrying the unconfigured placeholder identity (all-zero key) refuses bundles rather
// than accepting forgeries, exercising the exact runtime trust anchor.
func TestVerifyBundleSignature_CFGMSPlaceholderIdentityRejectsBundles(t *testing.T) {
	id := trust.CFGMSPublisherIdentity() // default build: all-zero placeholder key

	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(id))

	message := "attacker-chosen-content-hash"
	b := makeBundle(message)
	sig := bundle.BundleSignature{
		Publisher: id.Name,
		Algorithm: "ed25519",
		Signature: forgedSigOverAnyMessage(),
	}

	err := trust.VerifyBundleSignature(b, sig, store)
	require.Error(t, err)
	assert.True(t, errors.Is(err, trust.ErrUntrustedPublisherKey),
		"placeholder CFGMS identity must refuse all bundles, got: %v", err)
}

// TestInMemoryTrustStore_Operations tests the basic operations of InMemoryTrustStore.
func TestInMemoryTrustStore_Operations(t *testing.T) {
	store := trust.NewInMemoryTrustStore()

	pub, _ := makeKeypair(t)
	id := trust.PublisherIdentity{
		Name:      "test-publisher",
		PublicKey: []byte(pub),
		Algorithm: "ed25519",
	}

	// Not trusted initially
	assert.False(t, store.IsTrusted("test-publisher", []byte(pub)))

	err := store.AddPublisher(id)
	require.NoError(t, err)

	// Now trusted
	assert.True(t, store.IsTrusted("test-publisher", []byte(pub)))

	// GetPublisher returns the identity
	got, ok := store.GetPublisher("test-publisher")
	assert.True(t, ok)
	assert.Equal(t, id.Name, got.Name)
	assert.Equal(t, id.Algorithm, got.Algorithm)

	// ListPublishers returns it
	list := store.ListPublishers()
	assert.Len(t, list, 1)
	assert.Equal(t, "test-publisher", list[0].Name)

	// Unknown publisher
	_, ok = store.GetPublisher("nonexistent")
	assert.False(t, ok)
}

// TestCFGMSPublisherIdentity verifies that CFGMSPublisherIdentity returns a well-formed
// identity with the ed25519 algorithm set.
func TestCFGMSPublisherIdentity(t *testing.T) {
	id := trust.CFGMSPublisherIdentity()
	assert.Equal(t, "cfgms", id.Name)
	assert.Equal(t, "ed25519", id.Algorithm)
	assert.Len(t, id.PublicKey, 32) // Ed25519 public key is 32 bytes
}
