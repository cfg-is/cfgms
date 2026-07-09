// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

var (
	// ErrPublisherNotTrusted is returned when the bundle's signing publisher is not
	// registered in the TrustStore.
	ErrPublisherNotTrusted = errors.New("publisher not trusted")

	// ErrKeyMismatch is returned when the publisher is known but the stored public
	// key does not match the key that produced the signature.
	ErrKeyMismatch = errors.New("publisher key mismatch")

	// ErrInvalidSignature is returned when the Ed25519 signature does not verify
	// against the bundle's ContentHash and the publisher's public key.
	ErrInvalidSignature = errors.New("invalid bundle signature")

	// ErrUntrustedPublisherKey is returned when the stored publisher public key is not
	// a safe, prime-order Ed25519 point — specifically the all-zero placeholder key
	// baked into unconfigured builds or any known small-order point. Such keys must
	// never be treated as a trust anchor: a small-order public key lets an attacker
	// forge a signature over an arbitrary message with no private key (ed25519.Verify
	// accepts a signature with S=0 and a small-order R against it). A build carrying
	// such a key therefore refuses ALL bundles instead of failing open.
	ErrUntrustedPublisherKey = errors.New("publisher public key is not a valid prime-order Ed25519 key")
)

// smallOrderEncodings is the set of Ed25519 public-key encodings (sign bit cleared)
// that decode to a point of small order — order 1, 2, 4, or 8. It includes the
// all-zero placeholder key used by unconfigured builds (which encodes an order-4
// point). Any public key matching one of these, ignoring the sign bit, permits
// signature forgery and must be rejected as a trust anchor. This is the canonical
// small-order point set (equivalent to libsodium's ed25519 small-order blocklist).
var smallOrderEncodings = buildSmallOrderEncodings()

func buildSmallOrderEncodings() [][ed25519.PublicKeySize]byte {
	set := [][ed25519.PublicKeySize]byte{
		// 0 — order 4 (also the all-zero placeholder key of unconfigured builds)
		{},
		// 1 — order 1 (identity)
		{0x01},
		// order-8 point
		{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
			0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
			0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
		// order-8 point
		{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
			0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
			0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	}
	// p-1 (order 2), p (order 4), p+1 (order 1): first byte varies, then 0xff…, 0x7f.
	for _, first := range []byte{0xec, 0xed, 0xee} {
		var e [ed25519.PublicKeySize]byte
		e[0] = first
		for i := 1; i < ed25519.PublicKeySize-1; i++ {
			e[i] = 0xff
		}
		e[ed25519.PublicKeySize-1] = 0x7f
		set = append(set, e)
	}
	return set
}

// isUnsafePublisherKey reports whether pub is a small-order Ed25519 point (including
// the all-zero placeholder key). Such a key cannot serve as a trust anchor because it
// permits signature forgery. The sign bit (high bit of the last byte) is masked before
// comparison so both sign variants of each small-order point are caught.
func isUnsafePublisherKey(pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	var masked [ed25519.PublicKeySize]byte
	copy(masked[:], pub)
	masked[ed25519.PublicKeySize-1] &= 0x7f
	for i := range smallOrderEncodings {
		if masked == smallOrderEncodings[i] {
			return true
		}
	}
	return false
}

// VerifyBundleSignature verifies that sig is a valid Ed25519 signature over the
// bundle's ContentHash bytes, produced by a publisher known to store.
//
// Error precedence:
//  1. ErrPublisherNotTrusted — publisher name not in store
//  2. ErrKeyMismatch — publisher known but stored key != key in store (defensive; the
//     store only holds one key per publisher so the verification catches this implicitly)
//  3. ErrInvalidSignature — signature bytes do not verify
func VerifyBundleSignature(b *bundle.Bundle, sig bundle.BundleSignature, store TrustStore) error {
	id, ok := store.GetPublisher(sig.Publisher)
	if !ok {
		return fmt.Errorf("%w: %q", ErrPublisherNotTrusted, sig.Publisher)
	}

	if len(id.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: stored key for %q has wrong length %d (expected %d)",
			ErrKeyMismatch, sig.Publisher, len(id.PublicKey), ed25519.PublicKeySize)
	}

	// Reject small-order/placeholder public keys before calling ed25519.Verify. The
	// all-zero placeholder baked into unconfigured builds is a small-order point, and
	// ed25519.Verify does NOT fail closed against it — it accepts an attacker-forged
	// signature (S=0, small-order R) over any message. Refusing the key here makes a
	// placeholder-key build reject every bundle instead of accepting forgeries.
	if isUnsafePublisherKey(id.PublicKey) {
		return fmt.Errorf("%w: stored key for %q is a small-order/placeholder point and cannot anchor trust",
			ErrUntrustedPublisherKey, sig.Publisher)
	}

	message := []byte(b.ContentHash)
	if !ed25519.Verify(ed25519.PublicKey(id.PublicKey), message, sig.Signature) {
		return fmt.Errorf("%w: signature by %q over content hash %q is not valid",
			ErrInvalidSignature, sig.Publisher, b.ContentHash)
	}

	return nil
}
