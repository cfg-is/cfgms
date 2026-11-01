// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

// Linux trust store implementation.
//
// This executor manages the Debian-family system trust store at
// /etc/ssl/certs. Each trusted CA is stored as an individual PEM file
// named cfgms-<fingerprint>.crt under /usr/local/share/ca-certificates/
// (the staging directory) and the system bundle is refreshed by running
// update-ca-certificates after each install or remove. A failed or missing
// refresh is returned as an error and the staged file change is rolled back.
//
// Assumed distro family: Debian/Ubuntu (and derivatives).
// On RPM-based distros (RHEL, Fedora) the staging dir and refresh command
// differ; those distros are not supported in this version.
//
// This executor shells out to:
//   - update-ca-certificates  (declared in module.yaml behavioral_envelope)

package cert_trust

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// defaultLinuxTrustStoreRoot is the directory where installed CA PEM files are
// stored. update-ca-certificates reads from this directory. Use
// /usr/local/share/ca-certificates as the staging area so removals are clean:
// the system bundle at /etc/ssl/certs/ca-certificates.crt is rebuilt on each
// update-ca-certificates run.
const defaultLinuxTrustStoreRoot = "/usr/local/share/ca-certificates"

// linuxExecutor manages the Debian-family system trust store.
type linuxExecutor struct {
	// trustStoreRoot is the staging directory where per-cert PEM files are written.
	// Default: /usr/local/share/ca-certificates. Overridable for testing via
	// newLinuxExecutorWithRoot so tests never touch the real system trust store.
	trustStoreRoot string

	// refresh rebuilds the system bundle after a staging change. newExecutor
	// wires update-ca-certificates; tests inject their own so nothing touches
	// the real trust store.
	refresh func() error
}

func newExecutor() trustStoreExecutor {
	return &linuxExecutor{trustStoreRoot: defaultLinuxTrustStoreRoot, refresh: runUpdateCACertificates}
}

// newLinuxExecutorWithRoot creates an executor with a custom trust store root.
// Used in tests to avoid touching the real system trust store: pass t.TempDir()
// as root. The refresh is a no-op that returns nil, so the real
// update-ca-certificates is never run.
func newLinuxExecutorWithRoot(root string) trustStoreExecutor {
	return &linuxExecutor{trustStoreRoot: root, refresh: func() error { return nil }}
}

// list reads all PEM files from trustStoreRoot and returns a certEntry per valid
// certificate block found. Files that cannot be parsed are silently skipped.
func (e *linuxExecutor) list() ([]certEntry, error) {
	entries, err := os.ReadDir(e.trustStoreRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read trust store root %s: %w", e.trustStoreRoot, err)
	}

	var result []certEntry
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") {
			continue
		}

		// #nosec G304 -- name comes from ReadDir of the fixed OS trust root and
		// only .crt/.pem entries are read; no caller supplies a path component.
		data, err := os.ReadFile(filepath.Join(e.trustStoreRoot, name))
		if err != nil {
			continue // skip unreadable files
		}

		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			entry, err := certEntryFromDER(block.Bytes)
			if err != nil {
				continue // skip malformed certs
			}
			result = append(result, entry)
		}
	}
	return result, nil
}

// install writes the DER-encoded certificate as a PEM file under trustStoreRoot,
// named cfgms-<fingerprint>.crt, then runs the refresh command to rebuild the
// system bundle. A failed or missing refresh is an error: the staged file is
// rolled back (removed only if it did not exist before the call) so the staging
// directory and the active bundle do not disagree.
func (e *linuxExecutor) install(certDER []byte) error {
	fp := certFingerprint(certDER)
	filename := "cfgms-" + fp + ".crt"
	destPath := filepath.Join(e.trustStoreRoot, filename)

	// #nosec G301 -- the OS CA trust directory must be traversable by all
	// processes that validate TLS; it contains public certificates only.
	if err := os.MkdirAll(e.trustStoreRoot, 0755); err != nil {
		return fmt.Errorf("create trust store root %s: %w", e.trustStoreRoot, err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	_, statErr := os.Stat(destPath)
	existed := statErr == nil

	// #nosec G306 -- CA certificates are public verification material and must
	// be readable by unprivileged TLS clients using the system trust store.
	if err := os.WriteFile(destPath, pemData, 0644); err != nil {
		return fmt.Errorf("write certificate %s: %w", destPath, err)
	}

	if err := e.refresh(); err != nil {
		if !existed {
			_ = os.Remove(destPath)
		}
		return fmt.Errorf("refresh trust store after install: %w", err)
	}

	return nil
}

// remove deletes the PEM file for the given fingerprint from trustStoreRoot, then
// runs the refresh command to rebuild the system bundle. If no file for the
// fingerprint exists, remove is a no-op that does not run the refresh. A failed
// refresh is an error and the removed file is written back with its previous
// bytes (mode 0644). The fingerprint is validated here, not only by the caller,
// so no input can make destPath name a file outside trustStoreRoot.
func (e *linuxExecutor) remove(fingerprint string) error {
	if !fingerprintPattern.MatchString(fingerprint) {
		return fmt.Errorf("%w: fingerprint must be 64 lowercase hex characters, got %q",
			modules.ErrInvalidResourceID, logging.SanitizeLogValue(fingerprint))
	}
	filename := "cfgms-" + fingerprint + ".crt"
	destPath := filepath.Join(e.trustStoreRoot, filename)

	// #nosec G304 -- fingerprint was checked against ^[0-9a-f]{64}$ above, so
	// destPath is the trust root joined with a fixed-form filename.
	previous, err := os.ReadFile(destPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already absent — idempotent no-op
		}
		return fmt.Errorf("read certificate %s: %w", destPath, err)
	}

	if err := os.Remove(destPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove certificate %s: %w", destPath, err)
	}

	if err := e.refresh(); err != nil {
		// #nosec G306 G703 -- CA certificates are public verification material and
		// must be world-readable (G306). destPath cannot traverse (G703): the
		// fingerprint is checked against ^[0-9a-f]{64}$ at the top of remove, so
		// the filename is cfgms-<64 hex>.crt directly under trustStoreRoot.
		if restoreErr := os.WriteFile(destPath, previous, 0644); restoreErr != nil {
			return fmt.Errorf("refresh trust store after remove: %w (restore %s failed: %s)",
				err, destPath, logging.SanitizeLogValue(restoreErr.Error()))
		}
		return fmt.Errorf("refresh trust store after remove: %w", err)
	}

	return nil
}

// runUpdateCACertificates runs update-ca-certificates and reports a missing
// tool or a failed run as an error.
func runUpdateCACertificates() error {
	out, err := exec.Command("update-ca-certificates").CombinedOutput() // #nosec G204 - no user input
	if err == nil {
		return nil
	}
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("update-ca-certificates not found: trust-store tooling on this host is unsupported (Debian-family only): %w", err)
	}
	return fmt.Errorf("update-ca-certificates failed: %s: %w",
		logging.SanitizeLogValue(strings.TrimSpace(string(out))), err)
}
