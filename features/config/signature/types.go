// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

// Package signature provides cryptographic signing and verification for CFGMS configurations.
//
// This package implements configuration signing to ensure integrity and authenticity of
// configurations sent from the controller to stewards. It prevents MITM attacks by
// cryptographically signing configurations with the controller's private key and verifying
// them with the controller's public key on the steward side.
package signature

import (
	"crypto"
	"errors"
)

// Algorithm represents a cryptographic signing algorithm.
type Algorithm string

const (
	// AlgorithmRSASHA256 uses RSA with SHA-256 for signing.
	AlgorithmRSASHA256 Algorithm = "RSA-SHA256"

	// AlgorithmECDSASHA256 uses ECDSA with SHA-256 for signing.
	AlgorithmECDSASHA256 Algorithm = "ECDSA-SHA256"
)

// Hash returns the crypto.Hash for this algorithm.
func (a Algorithm) Hash() crypto.Hash {
	switch a {
	case AlgorithmRSASHA256, AlgorithmECDSASHA256:
		return crypto.SHA256
	default:
		return crypto.SHA256
	}
}

// IsValid checks if the algorithm is supported.
func (a Algorithm) IsValid() bool {
	switch a {
	case AlgorithmRSASHA256, AlgorithmECDSASHA256:
		return true
	default:
		return false
	}
}

// ConfigSignature contains the cryptographic signature for a configuration.
type ConfigSignature struct {
	// Algorithm used to create the signature.
	Algorithm Algorithm `yaml:"algorithm" json:"algorithm"`

	// Signature is the base64-encoded signature bytes.
	Signature string `yaml:"signature" json:"signature"`

	// Timestamp is the Unix timestamp when the signature was created.
	Timestamp int64 `yaml:"timestamp" json:"timestamp"`

	// KeyFingerprint is the SHA256 fingerprint of the signing certificate (for verification).
	KeyFingerprint string `yaml:"key_fingerprint,omitempty" json:"key_fingerprint,omitempty"`
}

// SignedConfig wraps configuration data with its signature.
type SignedConfig struct {
	// Data is the raw configuration data (YAML).
	Data []byte

	// Signature is the cryptographic signature.
	Signature *ConfigSignature
}

// Signer signs configuration data.
type Signer interface {
	// Sign creates a cryptographic signature for the given data.
	Sign(data []byte) (*ConfigSignature, error)

	// Algorithm returns the signing algorithm used.
	Algorithm() Algorithm

	// KeyFingerprint returns the fingerprint of the signing key.
	KeyFingerprint() string
}

// Verifier verifies configuration signatures.
type Verifier interface {
	// Verify checks if the signature is valid for the given data.
	Verify(data []byte, sig *ConfigSignature) error

	// SupportsAlgorithm checks if the verifier supports the given algorithm.
	SupportsAlgorithm(alg Algorithm) bool
}

// Common errors for signature operations.
var (
	// ErrInvalidSignature indicates the signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrUnsupportedAlgorithm indicates the signing algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("unsupported signing algorithm")

	// ErrMissingSignature indicates no signature was provided.
	ErrMissingSignature = errors.New("missing signature")

	// ErrMissingPrivateKey indicates no private key was provided for signing.
	ErrMissingPrivateKey = errors.New("missing private key")

	// ErrMissingPublicKey indicates no public key was provided for verification.
	ErrMissingPublicKey = errors.New("missing public key")

	// ErrInvalidKey indicates the key is invalid or wrong type.
	ErrInvalidKey = errors.New("invalid key")

	// ErrSignatureMismatch indicates the signature doesn't match the data.
	ErrSignatureMismatch = errors.New("signature does not match data")
)

// SignatureMetadataKey is the YAML key used for embedding signatures in configs.
const SignatureMetadataKey = "_signature"
