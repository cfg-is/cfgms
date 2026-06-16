// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// MultiVerifier accepts a signature verified by any certificate in a trusted set.
// Used during rotation overlap windows so stewards accept configs signed by either
// the current or the rotating (previous) signing certificate.
package signature

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// MultiVerifier holds a set of Verifier instances and accepts a signature that
// any one of them can successfully verify. It implements the signature.Verifier
// interface with OR semantics.
type MultiVerifier struct {
	verifiers []*ConfigVerifier
}

// NewMultiVerifier constructs a MultiVerifier from a slice of x509 certificates.
// Returns ErrMissingPublicKey if the slice is nil or empty.
func NewMultiVerifier(certs []*x509.Certificate) (*MultiVerifier, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("at least one certificate is required: %w", ErrMissingPublicKey)
	}

	verifiers := make([]*ConfigVerifier, 0, len(certs))
	for i, cert := range certs {
		v, err := NewVerifierFromCertificate(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier for certificate at index %d: %w", i, err)
		}
		verifiers = append(verifiers, v)
	}

	return &MultiVerifier{verifiers: verifiers}, nil
}

// Verify checks the signature against each verifier in the set.
// It applies a fingerprint-match optimisation: if sig.KeyFingerprint matches one
// of the member verifiers, that verifier is tried first. On the first successful
// verification the method returns nil immediately. If every verifier rejects the
// signature a composite error is returned.
func (mv *MultiVerifier) Verify(data []byte, sig *ConfigSignature) error {
	if sig == nil {
		return ErrMissingSignature
	}

	// Build an ordered trial list: fingerprint-matching verifier first, then the rest.
	var first *ConfigVerifier
	rest := make([]*ConfigVerifier, 0, len(mv.verifiers))
	for _, v := range mv.verifiers {
		if first == nil && sig.KeyFingerprint != "" && v.KeyFingerprint() == sig.KeyFingerprint {
			first = v
		} else {
			rest = append(rest, v)
		}
	}

	ordered := rest
	if first != nil {
		ordered = append([]*ConfigVerifier{first}, rest...)
	}

	errs := make([]error, 0, len(ordered))
	for _, v := range ordered {
		if err := v.Verify(data, sig); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}

	return fmt.Errorf("signature verification failed against all %d certificate(s): %w",
		len(mv.verifiers), errors.Join(errs...))
}

// SupportsAlgorithm returns true if any member verifier supports alg.
func (mv *MultiVerifier) SupportsAlgorithm(alg Algorithm) bool {
	for _, v := range mv.verifiers {
		if v.SupportsAlgorithm(alg) {
			return true
		}
	}
	return false
}

// KeyFingerprint returns a comma-separated list of fingerprints from all member
// verifiers — one fingerprint per certificate in the trusted set.
func (mv *MultiVerifier) KeyFingerprint() string {
	fps := make([]string, 0, len(mv.verifiers))
	for _, v := range mv.verifiers {
		fps = append(fps, v.KeyFingerprint())
	}
	return strings.Join(fps, ",")
}
