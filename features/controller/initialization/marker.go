// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package initialization

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cfgis/cfgms/pkg/version"
)

const markerFileName = ".cfgms-initialized"

// InitMarker records that first-run initialization has been performed.
// It is written to the CA directory so that if the CA mount is missing,
// both CA files and the marker are missing — the correct failure mode.
type InitMarker struct {
	// Version of the marker format (for future migration)
	Version int `json:"version"`

	// Timestamp when initialization was performed
	InitializedAt time.Time `json:"initialized_at"`

	// Controller version that performed initialization
	ControllerVersion string `json:"controller_version"`

	// Storage provider used during initialization
	StorageProvider string `json:"storage_provider"`

	// SHA-256 fingerprint of the CA certificate
	CAFingerprint string `json:"ca_fingerprint"`
}

// IsInitialized checks whether the controller has been initialized by looking
// for the marker file in the CA directory.
func IsInitialized(caPath string) bool {
	markerPath := filepath.Join(caPath, markerFileName)
	_, err := os.Stat(markerPath)
	return err == nil
}

// ReadInitMarker reads and parses the initialization marker from the CA directory.
func ReadInitMarker(caPath string) (*InitMarker, error) {
	markerPath := filepath.Join(caPath, markerFileName)
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read init marker: %w", err)
	}

	var marker InitMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return nil, fmt.Errorf("failed to parse init marker: %w", err)
	}

	return &marker, nil
}

// WriteInitMarker atomically writes the initialization marker to the CA directory.
// It uses a temp file + rename pattern to ensure the marker is either fully written
// or not present at all.
func WriteInitMarker(caPath string, marker *InitMarker) error {
	markerPath := filepath.Join(caPath, markerFileName)

	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal init marker: %w", err)
	}

	// Write to temp file first for atomic operation
	tmpPath := markerPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write init marker temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, markerPath); err != nil {
		// Clean up temp file on rename failure
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize init marker: %w", err)
	}

	return nil
}

// CreateLegacyMarker creates an initialization marker for an existing installation
// that was set up before the init guard was introduced. This provides backward
// compatibility — existing CA directories get a marker automatically on first startup.
func CreateLegacyMarker(caPath string) error {
	fingerprint, err := readCAFingerprint(caPath)
	if err != nil {
		fingerprint = "unknown-legacy"
	}

	marker := &InitMarker{
		Version:           1,
		InitializedAt:     time.Now().UTC(),
		ControllerVersion: version.Short(),
		StorageProvider:   "unknown-legacy",
		CAFingerprint:     fingerprint,
	}

	return WriteInitMarker(caPath, marker)
}

// readCAFingerprint computes the SHA-256 fingerprint of the CA certificate at the given path.
// Checks both direct placement (caPath/ca.crt) and subdirectory layout (caPath/ca/ca.crt).
func readCAFingerprint(caPath string) (string, error) {
	caCertPath := filepath.Join(caPath, "ca.crt")
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		// Try subdirectory layout used by cert.NewManager
		caCertPath = filepath.Join(caPath, "ca", "ca.crt")
		certPEM, err = os.ReadFile(caCertPath)
		if err != nil {
			return "", fmt.Errorf("failed to read CA certificate: %w", err)
		}
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", hash), nil
}
