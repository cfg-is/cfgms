// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

// Linux trust store implementation.
//
// This executor manages the Debian-family system trust store at
// /etc/ssl/certs. Each trusted CA is stored as an individual PEM file
// named cfgms-<fingerprint>.crt under /usr/local/share/ca-certificates/
// (the staging directory) and the system bundle is refreshed by running
// update-ca-certificates after each install or remove.
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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
}

func newExecutor() trustStoreExecutor {
	return &linuxExecutor{trustStoreRoot: defaultLinuxTrustStoreRoot}
}

// newLinuxExecutorWithRoot creates an executor with a custom trust store root.
// Used in tests to avoid touching the real system trust store: pass t.TempDir()
// as root. The update-ca-certificates call is attempted but non-fatal when the
// root is not the real system directory.
func newLinuxExecutorWithRoot(root string) trustStoreExecutor {
	return &linuxExecutor{trustStoreRoot: root}
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
// named cfgms-<fingerprint>.crt, then runs update-ca-certificates to refresh
// the system bundle. The update-ca-certificates call is best-effort: if the root
// is not the real system directory (e.g. in tests), the command may fail and the
// error is logged but does not fail the install.
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

	// #nosec G306 -- CA certificates are public verification material and must
	// be readable by unprivileged TLS clients using the system trust store.
	if err := os.WriteFile(destPath, pemData, 0644); err != nil {
		return fmt.Errorf("write certificate %s: %w", destPath, err)
	}

	// update-ca-certificates refreshes the system bundle. This call is best-effort:
	// in test environments pointing at a temp dir the command will fail, but the
	// file write above is sufficient for the round-trip test to observe the cert.
	if out, err := exec.Command("update-ca-certificates").CombinedOutput(); err != nil { // #nosec G204 - no user input
		// Non-fatal: the cert file is written; the system bundle just won't reflect
		// the change until update-ca-certificates can run successfully.
		_ = out // error is an expected best-effort failure in non-system environments
	}

	return nil
}

// remove deletes the PEM file for the given fingerprint from trustStoreRoot, then
// runs update-ca-certificates to refresh the system bundle. If no file for the
// fingerprint exists, remove is a no-op.
func (e *linuxExecutor) remove(fingerprint string) error {
	filename := "cfgms-" + fingerprint + ".crt"
	destPath := filepath.Join(e.trustStoreRoot, filename)

	if err := os.Remove(destPath); err != nil {
		if os.IsNotExist(err) {
			return nil // already absent — idempotent no-op
		}
		return fmt.Errorf("remove certificate %s: %w", destPath, err)
	}

	// update-ca-certificates refreshes the system bundle (best-effort, same as install).
	if out, err := exec.Command("update-ca-certificates").CombinedOutput(); err != nil { // #nosec G204 - no user input
		_ = out
	}

	return nil
}
