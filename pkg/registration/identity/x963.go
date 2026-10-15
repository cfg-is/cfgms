// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
)

// parseX963P256 converts an uncompressed X9.63 point (0x04 || X || Y), the form
// the macOS Security framework exports for an EC public key, into a P-256 key.
// It rejects any other length, a compressed point and a point not on the curve.
func parseX963P256(point []byte) (*ecdsa.PublicKey, error) {
	if len(point) != 65 || point[0] != 0x04 {
		return nil, errors.New("public key is not an uncompressed P-256 point")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("public key point is not on curve P-256: %w", err)
	}
	return pub, nil
}
