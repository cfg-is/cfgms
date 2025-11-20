// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors

package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
)

// ConfigSigner implements the Signer interface for configuration signing.
type ConfigSigner struct {
	privateKey     crypto.Signer
	algorithm      Algorithm
	keyFingerprint string
}

// SignerConfig holds configuration for creating a new signer.
type SignerConfig struct {
	// PrivateKeyPEM is the PEM-encoded private key for signing.
	PrivateKeyPEM []byte

	// CertificatePEM is the PEM-encoded certificate (optional, used for fingerprint).
	CertificatePEM []byte

	// Algorithm to use for signing (defaults to RSA-SHA256 for RSA keys, ECDSA-SHA256 for EC keys).
	Algorithm Algorithm
}

// NewSigner creates a new configuration signer.
func NewSigner(cfg *SignerConfig) (*ConfigSigner, error) {
	if len(cfg.PrivateKeyPEM) == 0 {
		return nil, ErrMissingPrivateKey
	}

	// Parse the private key
	privateKey, err := cert.ParsePrivateKeyFromPEM(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Determine algorithm based on key type if not specified
	algorithm := cfg.Algorithm
	var signer crypto.Signer

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		signer = key
		if algorithm == "" {
			algorithm = AlgorithmRSASHA256
		}
		if algorithm != AlgorithmRSASHA256 {
			return nil, fmt.Errorf("%w: RSA key requires RSA-SHA256 algorithm", ErrInvalidKey)
		}
	case *ecdsa.PrivateKey:
		signer = key
		if algorithm == "" {
			algorithm = AlgorithmECDSASHA256
		}
		if algorithm != AlgorithmECDSASHA256 {
			return nil, fmt.Errorf("%w: ECDSA key requires ECDSA-SHA256 algorithm", ErrInvalidKey)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported key type %T", ErrInvalidKey, privateKey)
	}

	// Calculate key fingerprint from certificate if provided
	var fingerprint string
	if len(cfg.CertificatePEM) > 0 {
		certificate, err := cert.ParseCertificateFromPEM(cfg.CertificatePEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		fingerprint = calculateFingerprint(certificate.Raw)
	} else {
		// Calculate fingerprint from public key
		var pubKeyBytes []byte
		switch key := privateKey.(type) {
		case *rsa.PrivateKey:
			pubKeyBytes, _ = x509.MarshalPKIXPublicKey(&key.PublicKey)
		case *ecdsa.PrivateKey:
			pubKeyBytes, _ = x509.MarshalPKIXPublicKey(&key.PublicKey)
		}
		if len(pubKeyBytes) > 0 {
			fingerprint = calculateFingerprint(pubKeyBytes)
		}
	}

	return &ConfigSigner{
		privateKey:     signer,
		algorithm:      algorithm,
		keyFingerprint: fingerprint,
	}, nil
}

// Sign creates a cryptographic signature for the given configuration data.
func (s *ConfigSigner) Sign(data []byte) (*ConfigSignature, error) {
	// Hash the data
	hash := sha256.Sum256(data)

	var signatureBytes []byte
	var err error

	switch s.algorithm {
	case AlgorithmRSASHA256:
		rsaKey, ok := s.privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected RSA key for RSA-SHA256", ErrInvalidKey)
		}
		signatureBytes, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
		if err != nil {
			return nil, fmt.Errorf("RSA signing failed: %w", err)
		}

	case AlgorithmECDSASHA256:
		ecdsaKey, ok := s.privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected ECDSA key for ECDSA-SHA256", ErrInvalidKey)
		}
		signatureBytes, err = ecdsa.SignASN1(rand.Reader, ecdsaKey, hash[:])
		if err != nil {
			return nil, fmt.Errorf("ECDSA signing failed: %w", err)
		}

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, s.algorithm)
	}

	return &ConfigSignature{
		Algorithm:      s.algorithm,
		Signature:      base64.StdEncoding.EncodeToString(signatureBytes),
		Timestamp:      time.Now().Unix(),
		KeyFingerprint: s.keyFingerprint,
	}, nil
}

// Algorithm returns the signing algorithm used.
func (s *ConfigSigner) Algorithm() Algorithm {
	return s.algorithm
}

// KeyFingerprint returns the fingerprint of the signing key.
func (s *ConfigSigner) KeyFingerprint() string {
	return s.keyFingerprint
}

// calculateFingerprint calculates SHA256 fingerprint of the given data.
func calculateFingerprint(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%X", hash)
}
