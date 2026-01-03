// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/cfgis/cfgms/pkg/cert"
)

// ConfigVerifier implements the Verifier interface for configuration signature verification.
type ConfigVerifier struct {
	publicKey      crypto.PublicKey
	keyFingerprint string
}

// VerifierConfig holds configuration for creating a new verifier.
type VerifierConfig struct {
	// PublicKeyPEM is the PEM-encoded public key for verification.
	// Can be extracted from a certificate.
	PublicKeyPEM []byte

	// CertificatePEM is the PEM-encoded certificate containing the public key.
	// If provided, the public key is extracted from this certificate.
	CertificatePEM []byte
}

// NewVerifier creates a new configuration verifier.
func NewVerifier(cfg *VerifierConfig) (*ConfigVerifier, error) {
	var publicKey crypto.PublicKey
	var fingerprint string

	// Prefer certificate if provided
	if len(cfg.CertificatePEM) > 0 {
		certificate, err := cert.ParseCertificateFromPEM(cfg.CertificatePEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		publicKey = certificate.PublicKey
		fingerprint = calculateFingerprint(certificate.Raw)
	} else if len(cfg.PublicKeyPEM) > 0 {
		// Parse raw public key
		key, err := parsePublicKeyFromPEM(cfg.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		publicKey = key

		// Calculate fingerprint from public key bytes
		pubKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
		if len(pubKeyBytes) > 0 {
			fingerprint = calculateFingerprint(pubKeyBytes)
		}
	} else {
		return nil, ErrMissingPublicKey
	}

	// Validate key type
	switch publicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		// Valid key types
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrInvalidKey, publicKey)
	}

	return &ConfigVerifier{
		publicKey:      publicKey,
		keyFingerprint: fingerprint,
	}, nil
}

// NewVerifierFromCertificate creates a verifier from an x509 certificate.
func NewVerifierFromCertificate(certificate *x509.Certificate) (*ConfigVerifier, error) {
	if certificate == nil {
		return nil, ErrMissingPublicKey
	}

	// Validate key type
	switch certificate.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		// Valid key types
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrInvalidKey, certificate.PublicKey)
	}

	return &ConfigVerifier{
		publicKey:      certificate.PublicKey,
		keyFingerprint: calculateFingerprint(certificate.Raw),
	}, nil
}

// Verify checks if the signature is valid for the given data.
func (v *ConfigVerifier) Verify(data []byte, sig *ConfigSignature) error {
	if sig == nil {
		return ErrMissingSignature
	}

	if !sig.Algorithm.IsValid() {
		return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, sig.Algorithm)
	}

	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// Verify based on algorithm
	switch sig.Algorithm {
	case AlgorithmRSASHA256:
		rsaKey, ok := v.publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected RSA public key for RSA-SHA256", ErrInvalidKey)
		}
		err = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash[:], signatureBytes)
		if err != nil {
			return ErrSignatureMismatch
		}

	case AlgorithmECDSASHA256:
		ecdsaKey, ok := v.publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected ECDSA public key for ECDSA-SHA256", ErrInvalidKey)
		}
		if !ecdsa.VerifyASN1(ecdsaKey, hash[:], signatureBytes) {
			return ErrSignatureMismatch
		}

	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, sig.Algorithm)
	}

	return nil
}

// SupportsAlgorithm checks if the verifier supports the given algorithm.
func (v *ConfigVerifier) SupportsAlgorithm(alg Algorithm) bool {
	switch v.publicKey.(type) {
	case *rsa.PublicKey:
		return alg == AlgorithmRSASHA256
	case *ecdsa.PublicKey:
		return alg == AlgorithmECDSASHA256
	default:
		return false
	}
}

// KeyFingerprint returns the fingerprint of the verification key.
func (v *ConfigVerifier) KeyFingerprint() string {
	return v.keyFingerprint
}

// parsePublicKeyFromPEM parses a public key from PEM data.
func parsePublicKeyFromPEM(keyPEM []byte) (crypto.PublicKey, error) {
	// Try to parse as certificate first (common case)
	if certificate, err := cert.ParseCertificateFromPEM(keyPEM); err == nil {
		return certificate.PublicKey, nil
	}

	// Try to parse as raw public key
	block, rest := pemDecode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKIX format first
	if pub, err := x509.ParsePKIXPublicKey(block); err == nil {
		return pub, nil
	}

	// Try PKCS1 RSA public key
	if pub, err := x509.ParsePKCS1PublicKey(block); err == nil {
		return pub, nil
	}

	// If there's more data, try the next block
	if len(rest) > 0 {
		return parsePublicKeyFromPEM(rest)
	}

	return nil, fmt.Errorf("failed to parse public key")
}

// pemDecode decodes a PEM block and returns the data and remainder.
func pemDecode(data []byte) ([]byte, []byte) {
	// Simple PEM decoder
	const pemBegin = "-----BEGIN "
	const pemEnd = "-----END "

	start := 0
	for i := 0; i <= len(data)-len(pemBegin); i++ {
		if string(data[i:i+len(pemBegin)]) == pemBegin {
			// Find end of header line
			for j := i; j < len(data); j++ {
				if data[j] == '\n' {
					start = j + 1
					break
				}
			}
			break
		}
	}

	if start == 0 {
		return nil, data
	}

	// Find end marker
	end := start
	for i := start; i <= len(data)-len(pemEnd); i++ {
		if string(data[i:i+len(pemEnd)]) == pemEnd {
			end = i
			break
		}
	}

	if end == start {
		return nil, data
	}

	// Decode base64
	encoded := data[start:end]
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil {
		return nil, data
	}

	// Find end of this PEM block
	rest := data
	for i := end; i < len(data); i++ {
		if data[i] == '\n' {
			rest = data[i+1:]
			break
		}
	}

	return decoded[:n], rest
}
