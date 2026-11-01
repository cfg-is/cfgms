// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package initialization

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const bundleMarkerFileName = ".admin-bundle-issued"

// BundleMarker records that the admin bundle has been issued.
// Written atomically after bundle.Write succeeds.
type BundleMarker struct {
	Serial      string
	Fingerprint string
	IssuedAt    time.Time
	BundlePath  string
}

// defaultAdminBundlePath returns the platform default for the admin bundle file.
func defaultAdminBundlePath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "cfgms", "admin.bundle.yaml")
	}
	return "/etc/cfgms/admin.bundle.yaml"
}

// bundleMarkerPath returns the path for the bundle issuance marker,
// derived from the bundle file path (same directory, hidden file).
func bundleMarkerPath(bundlePath string) string {
	return filepath.Join(filepath.Dir(bundlePath), bundleMarkerFileName)
}

// isBundleMarkerPresent checks whether the admin bundle issuance marker exists.
func isBundleMarkerPresent(bundlePath string) bool {
	_, err := os.Stat(bundleMarkerPath(bundlePath))
	return err == nil
}

// readBundleMarker reads and parses the bundle issuance marker file.
func readBundleMarker(bundlePath string) (*BundleMarker, error) {
	markerPath := bundleMarkerPath(bundlePath)
	// #nosec G304 -- controlled path derived from operator-configured bundle path
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle marker: %w", err)
	}

	marker := &BundleMarker{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "serial":
			marker.Serial = value
		case "fingerprint":
			marker.Fingerprint = value
		case "issued_at":
			t, parseErr := time.Parse(time.RFC3339, value)
			if parseErr == nil {
				marker.IssuedAt = t
			}
		case "bundle_path":
			marker.BundlePath = value
		}
	}
	return marker, scanner.Err()
}

// writeBundleMarker atomically writes the bundle issuance marker file.
// The marker is written AFTER bundle.Write succeeds, so its presence implies
// the bundle was successfully created at BundlePath.
func writeBundleMarker(bundlePath string, marker *BundleMarker) error {
	markerPath := bundleMarkerPath(bundlePath)

	content := fmt.Sprintf("serial=%s\nfingerprint=%s\nissued_at=%s\nbundle_path=%s\n",
		marker.Serial,
		marker.Fingerprint,
		marker.IssuedAt.UTC().Format(time.RFC3339),
		marker.BundlePath,
	)

	tmpPath := markerPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write bundle marker temp file: %w", err)
	}

	if err := os.Rename(tmpPath, markerPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize bundle marker: %w", err)
	}

	return nil
}
