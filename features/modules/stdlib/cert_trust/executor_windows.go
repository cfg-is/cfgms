// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

// Windows trust store implementation using certutil.exe.
//
// Prefers certutil.exe (in-process Windows crypto APIs via cgo are not used
// because the steward binary is built without cgo). certutil operates on the
// Local Machine "Root" store, which requires administrator privileges.
//
// This executor shells out to:
//   - certutil.exe  (declared in module.yaml behavioral_envelope via shells_out_to)

package cert_trust

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// windowsExecutor manages the Windows Local Machine "Root" trust store via
// certutil.exe. No cgo or Windows crypto API headers are required.
type windowsExecutor struct {
	// tmpDir is the directory used to stage PEM/CER files for certutil operations.
	// Defaults to os.TempDir(). Overridable for testing.
	tmpDir string
}

func newExecutor() trustStoreExecutor {
	return &windowsExecutor{tmpDir: os.TempDir()}
}

// list enumerates the Local Machine "Root" store certificates via certutil -store Root.
// Output is parsed line by line; each "Cert Hash(sha256):" line gives the fingerprint.
// Subject and issuer are parsed from the surrounding block.
func (e *windowsExecutor) list() ([]certEntry, error) {
	out, err := exec.Command("certutil", "-store", "Root").CombinedOutput() // #nosec G204 - no user input
	if err != nil {
		return nil, fmt.Errorf("certutil -store Root: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	var entries []certEntry
	var current certEntry
	inCert := false

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "================ Certificate") {
			if inCert && current.Fingerprint != "" {
				entries = append(entries, current)
			}
			current = certEntry{TrustedFor: "any"}
			inCert = true
			continue
		}

		if !inCert {
			continue
		}

		if strings.HasPrefix(line, "Cert Hash(sha256):") {
			raw := strings.TrimPrefix(line, "Cert Hash(sha256):")
			raw = strings.ReplaceAll(strings.TrimSpace(raw), " ", "")
			// certutil outputs uppercase hex; normalize to lowercase without colons
			decoded, err := hex.DecodeString(strings.ReplaceAll(raw, ":", ""))
			if err == nil {
				current.Fingerprint = hex.EncodeToString(decoded)
			}
		} else if strings.HasPrefix(line, "Subject:") {
			current.Subject = strings.TrimPrefix(line, "Subject:")
			current.Subject = strings.TrimSpace(current.Subject)
		} else if strings.HasPrefix(line, "Issuer:") {
			current.Issuer = strings.TrimPrefix(line, "Issuer:")
			current.Issuer = strings.TrimSpace(current.Issuer)
		} else if strings.HasPrefix(line, "NotAfter:") {
			current.NotAfter = strings.TrimPrefix(line, "NotAfter:")
			current.NotAfter = strings.TrimSpace(current.NotAfter)
		}
	}

	if inCert && current.Fingerprint != "" {
		entries = append(entries, current)
	}

	return entries, nil
}

// install adds the DER-encoded certificate to the Local Machine "Root" store
// using certutil -addstore Root <file>.
func (e *windowsExecutor) install(certDER []byte) error {
	// Stage as a PEM file in a temp location then install with certutil.
	fp := certFingerprint(certDER)
	tmpFile := filepath.Join(e.tmpDir, "cfgms-cert-install-"+fp+".cer")

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(tmpFile, pemData, 0600); err != nil {
		return fmt.Errorf("write temp cert file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile) }()

	out, err := exec.Command("certutil", "-addstore", "Root", tmpFile).CombinedOutput() // #nosec G204 - tmpFile is an internal path
	if err != nil {
		return fmt.Errorf("certutil -addstore Root: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// remove deletes the certificate with the given SHA-256 fingerprint from the
// Local Machine "Root" store using certutil -delstore Root <hash>.
// If the certificate is not present, remove is a no-op.
func (e *windowsExecutor) remove(fingerprint string) error {
	// certutil -delstore exits with an error if the cert is not found.
	// We check list first to make this idempotent.
	entries, err := e.list()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Fingerprint == fingerprint {
			out, err := exec.Command("certutil", "-delstore", "Root", fingerprint).CombinedOutput() // #nosec G204 - fingerprint validated by caller
			if err != nil {
				return fmt.Errorf("certutil -delstore Root %s: %w (output: %s)", fingerprint, err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	return nil // already absent
}
