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
)

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

	message := []byte(b.ContentHash)
	if !ed25519.Verify(ed25519.PublicKey(id.PublicKey), message, sig.Signature) {
		return fmt.Errorf("%w: signature by %q over content hash %q is not valid",
			ErrInvalidSignature, sig.Publisher, b.ContentHash)
	}

	return nil
}
