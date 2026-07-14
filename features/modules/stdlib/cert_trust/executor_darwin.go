// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

// macOS trust store implementation using the security(1) command-line tool.
//
// The macOS Keychain trust store is managed via the security command, which
// wraps the Security framework. Certificates are added to the System keychain
// (/Library/Keychains/System.keychain) so they are trusted system-wide.
// Administrator privileges are required for system keychain modifications.
//
// This executor shells out to:
//   - security  (declared in module.yaml behavioral_envelope via shells_out_to)

package cert_trust

import (
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// darwinExecutor manages the macOS system trust store via security(1).
type darwinExecutor struct {
	// tmpDir is used to stage cert files for security command operations.
	tmpDir string
}

func newExecutor() trustStoreExecutor {
	return &darwinExecutor{tmpDir: os.TempDir()}
}

// list returns all certificates in the System keychain via security find-certificate.
// The fingerprint is extracted from the SHA-256 hash reported by security.
func (e *darwinExecutor) list() ([]certEntry, error) {
	// security find-certificate -a -Z -p dumps all certs with their SHA-256 hashes.
	out, err := exec.Command("security", "find-certificate", "-a", "-Z", "-p", // #nosec G204 - no user input
		"/Library/Keychains/System.keychain").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("security find-certificate: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	var entries []certEntry
	lines := strings.Split(string(out), "\n")
	var currentFP string
	var pemLines []string
	inPEM := false

	for _, line := range lines {
		if strings.HasPrefix(line, "SHA-256 hash:") {
			raw := strings.TrimPrefix(line, "SHA-256 hash:")
			raw = strings.ReplaceAll(strings.TrimSpace(raw), " ", "")
			currentFP = strings.ToLower(strings.ReplaceAll(raw, ":", ""))
			continue
		}

		if strings.TrimSpace(line) == "-----BEGIN CERTIFICATE-----" {
			inPEM = true
			pemLines = []string{line}
			continue
		}
		if strings.TrimSpace(line) == "-----END CERTIFICATE-----" {
			inPEM = false
			pemLines = append(pemLines, line)
			pemBlock, _ := pem.Decode([]byte(strings.Join(pemLines, "\n")))
			if pemBlock != nil && currentFP != "" {
				entry, err := certEntryFromDER(pemBlock.Bytes)
				if err == nil {
					entry.Fingerprint = currentFP
					entries = append(entries, entry)
				}
			}
			pemLines = nil
			currentFP = ""
			continue
		}
		if inPEM {
			pemLines = append(pemLines, line)
		}
	}

	return entries, nil
}

// install adds the DER-encoded certificate to the System keychain and marks it
// as trusted for all purposes via security add-trusted-cert.
func (e *darwinExecutor) install(certDER []byte) error {
	fp := certFingerprint(certDER)
	tmpFile := filepath.Join(e.tmpDir, "cfgms-cert-install-"+fp+".pem")

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(tmpFile, pemData, 0600); err != nil {
		return fmt.Errorf("write temp cert file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile) }()

	// -d system stores in the System keychain; -r trustRoot trusts for all purposes.
	out, err := exec.Command("security", "add-trusted-cert", // #nosec G204 - tmpFile is an internal path
		"-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", tmpFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("security add-trusted-cert: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// remove deletes the certificate with the given fingerprint from the System keychain.
// If the certificate is not present, remove is a no-op.
func (e *darwinExecutor) remove(fingerprint string) error {
	// Verify the cert is present before attempting removal (idempotent).
	entries, err := e.list()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Fingerprint == fingerprint {
			out, err := exec.Command("security", "delete-certificate", // #nosec G204 - fingerprint validated by caller
				"-Z", strings.ToUpper(fingerprint), "-t",
				"/Library/Keychains/System.keychain").CombinedOutput()
			if err != nil {
				return fmt.Errorf("security delete-certificate %s: %w (output: %s)", fingerprint, err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	return nil // already absent
}
