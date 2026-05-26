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

// verifyCACertFingerprint checks that the SHA-256 fingerprint of caCertPEM matches
// expectedFingerprint (case-insensitive hex). Returns an error if the PEM cannot
// be parsed or the fingerprints do not match.
func verifyCACertFingerprint(caCertPEM, expectedFingerprint string) error {
	block, _ := pem.Decode([]byte(caCertPEM))
	if block == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
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

// writeCACert writes caCertPEM to destPath with mode 0644, creating any missing
// parent directories. The CA cert is public material — 0644 is intentional.
func writeCACert(caCertPEM, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil { // #nosec G301 -- /etc/cfgms must be world-readable; CA cert is public material
		return fmt.Errorf("failed to create CA cert directory: %w", err)
	}
	return os.WriteFile(destPath, []byte(caCertPEM), 0644) // #nosec G306 -- CA cert is public material
}
