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
	"time"

	"github.com/cfgis/cfgms/pkg/security"
)

// windowsExecutor manages the Windows Local Machine "Root" trust store via
// certutil.exe. No cgo or Windows crypto API headers are required.
type windowsExecutor struct {
	// tmpDir is the staging base directory for certutil operations. It is
	// secured with security.EnsureAdminOnlyDir before every stage. Overridable
	// for testing.
	tmpDir string

	// addStore adds the staged certificate file at path to the Root store and
	// returns the command output. newExecutor sets it to certutilAddStore;
	// tests replace it to observe the staged file without changing the
	// machine trust store.
	addStore func(path string) ([]byte, error)
}

func newExecutor() trustStoreExecutor {
	return &windowsExecutor{tmpDir: windowsStagingBase(), addStore: certutilAddStore}
}

// windowsStagingBase returns %ProgramData%\cfgms\staging, falling back to
// C:\ProgramData when the ProgramData environment variable is unset. It lies
// inside the %ProgramData%\cfgms tree that only SYSTEM and Administrators can
// write, unlike the system temporary directory.
func windowsStagingBase() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "cfgms", "staging")
}

// certutilAddStore runs certutil -addstore Root on the staged file at path.
func certutilAddStore(path string) ([]byte, error) {
	return exec.Command("certutil", "-addstore", "Root", path).CombinedOutput() // #nosec G204 - path is a file this executor just staged
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
			raw := strings.TrimPrefix(line, "NotAfter:")
			current.NotAfter = parseCertutilDate(raw)
		}
	}

	if inCert && current.Fingerprint != "" {
		entries = append(entries, current)
	}

	return entries, nil
}

// install adds the DER-encoded certificate to the Local Machine "Root" store
// using certutil -addstore Root <file>.
//
// The base directory is first secured so that only SYSTEM and Administrators
// can write it; when it cannot be secured (for example it is owned by another
// principal), nothing is staged and certutil does not run. The PEM is staged in
// a fresh private subdirectory and removed when certutil returns, on success
// and on failure.
func (e *windowsExecutor) install(certDER []byte) error {
	if err := security.EnsureAdminOnlyDir(e.tmpDir); err != nil {
		return fmt.Errorf("secure staging base directory: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tmpFile, cleanup, err := stageForTrustCommand(e.tmpDir, pemData)
	if err != nil {
		return fmt.Errorf("stage cert file: %w", err)
	}
	defer cleanup()

	addStore := e.addStore
	if addStore == nil {
		addStore = certutilAddStore
	}
	out, err := addStore(tmpFile)
	if err != nil {
		return fmt.Errorf("certutil -addstore Root: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// parseCertutilDate parses a date string from certutil -store Root output and
// returns it in RFC3339 format. Certutil output format is locale-dependent;
// common Windows locale formats are tried in order. Returns empty string when
// no known format matches, rather than propagating a locale-dependent value.
func parseCertutilDate(s string) string {
	s = strings.TrimSpace(s)
	// Try common certutil date formats. The en-US 12h format covers most server
	// deployments; additional entries handle 24h and European locales.
	formats := []string{
		"1/2/2006 3:04 PM",    // en-US 12h: "1/15/2035 12:00 AM"
		"1/2/2006 15:04",      // en-US 24h
		"2/1/2006 15:04",      // European day-first 24h
		"02/01/2006 15:04",    // European zero-padded
		"2006-01-02 15:04:05", // ISO-like (rare but possible)
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return "" // unknown format: omit rather than propagate locale-dependent value
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
