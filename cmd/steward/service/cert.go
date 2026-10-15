// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// parseSingleCACert accepts exactly one CERTIFICATE PEM block with no other
// non-whitespace data before or after it, so the fingerprint covers everything
// that is later written to the trust anchor path.
func parseSingleCACert(caCertPEM string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(caCertPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("CA PEM block must be of type CERTIFICATE")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("CA certificate PEM must contain exactly one certificate and no trailing data")
	}
	if prefix := strings.TrimSpace(caCertPEM[:strings.Index(caCertPEM, "-----BEGIN")]); prefix != "" {
		return nil, fmt.Errorf("CA certificate PEM must not contain data before the certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	return cert, nil
}

// verifyCACertFingerprint checks that the SHA-256 fingerprint of caCertPEM matches
// expectedFingerprint (case-insensitive hex). Returns an error if the PEM cannot
// be parsed or the fingerprints do not match.
func verifyCACertFingerprint(caCertPEM, expectedFingerprint string) error {
	cert, err := parseSingleCACert(caCertPEM)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(cert.Raw)
	actual := hex.EncodeToString(hash[:])
	if !strings.EqualFold(actual, expectedFingerprint) {
		return fmt.Errorf(
			"CA fingerprint mismatch: expected %s, got %s — verify the fingerprint from controller --init output before trusting this CA",
			expectedFingerprint, actual)
	}
	return nil
}

// writeCACert writes caCertPEM to destPath with mode 0444, creating any missing
// parent directories. ADR-013 §3: the pinned CA is public material; 0444 (immutable
// to non-root) makes it tamper-evident without hiding it.
func writeCACert(caCertPEM, destPath string) error {
	cert, err := parseSingleCACert(caCertPEM)
	if err != nil {
		return err
	}
	cleanPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	// #nosec G301 -- the service account must traverse /etc/cfgms to read the
	// public CA certificate; no private key is stored by this helper.
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create CA cert directory: %w", err)
	}
	return os.WriteFile(destPath, cleanPEM, 0444) // #nosec G306 -- CA cert is public material; 0444 per ADR-013 §3
}
