// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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
