// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

// KeyAlgorithm names a device identity key algorithm (ADR-011 Amendment 3).
type KeyAlgorithm string

const (
	// KeyAlgorithmEd25519 is the file-backed device key. identity_key_pub is the
	// raw 32-byte public key and the DeviceID is SHA-256 of those bytes.
	KeyAlgorithmEd25519 KeyAlgorithm = "ed25519"
	// KeyAlgorithmECDSAP256 is the hardware-backed device key. identity_key_pub is
	// the PKIX (SubjectPublicKeyInfo) DER encoding and the DeviceID is SHA-256 of
	// that DER.
	KeyAlgorithmECDSAP256 KeyAlgorithm = "ecdsa-p256"
)

var errInvalidDeviceKey = errors.New("invalid device identity key")

// normalizeKeyAlgorithm maps the wire/stored value to a KeyAlgorithm. An empty
// value means ed25519 (stewards and records that predate Amendment 3). ok is
// false for any other unknown value.
func normalizeKeyAlgorithm(v string) (KeyAlgorithm, bool) {
	switch KeyAlgorithm(v) {
	case "", KeyAlgorithmEd25519:
		return KeyAlgorithmEd25519, true
	case KeyAlgorithmECDSAP256:
		return KeyAlgorithmECDSAP256, true
	default:
		return "", false
	}
}

// parseDevicePublicKey decodes the stored/wire public key bytes for alg. For
// ecdsa-p256 it requires a PKIX-encoded *ecdsa.PublicKey on P-256 and rejects
// trailing data.
func parseDevicePublicKey(alg KeyAlgorithm, keyBytes []byte) (crypto.PublicKey, error) {
	switch alg {
	case KeyAlgorithmEd25519:
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, errInvalidDeviceKey
		}
		return ed25519.PublicKey(keyBytes), nil
	case KeyAlgorithmECDSAP256:
		parsed, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil, errInvalidDeviceKey
		}
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errInvalidDeviceKey
		}
		return pub, nil
	default:
		return nil, errInvalidDeviceKey
	}
}

// deviceIDForKey returns the DeviceID for the key bytes of alg: lowercase hex
// SHA-256 of the raw key (ed25519) or of the PKIX DER (ecdsa-p256). Both are
// SHA-256 over the stored bytes.
func deviceIDForKey(keyBytes []byte) string {
	sum := sha256.Sum256(keyBytes)
	return hex.EncodeToString(sum[:])
}

// PoPVerifier verifies a proof-of-possession signature over the 32-byte PoP
// digest for the given algorithm (ADR-011 Amendment 3). Injected on the Server so
// tests can assert it is never called for revoked devices or on an algorithm
// change.
type PoPVerifier interface {
	Verify(alg KeyAlgorithm, pub crypto.PublicKey, digest, sig []byte) bool
}

// defaultPoPVerifier is the stdlib-backed PoPVerifier. Ed25519 signs the digest as
// its message; ECDSA P-256 uses the digest directly as the hash input (no second
// hash) with an ASN.1 DER signature.
type defaultPoPVerifier struct{}

func (defaultPoPVerifier) Verify(alg KeyAlgorithm, pub crypto.PublicKey, digest, sig []byte) bool {
	switch alg {
	case KeyAlgorithmEd25519:
		k, ok := pub.(ed25519.PublicKey)
		if !ok || len(k) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(k, digest, sig)
	case KeyAlgorithmECDSAP256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k == nil || k.Curve != elliptic.P256() {
			return false
		}
		return ecdsa.VerifyASN1(k, digest, sig)
	default:
		return false
	}
}
