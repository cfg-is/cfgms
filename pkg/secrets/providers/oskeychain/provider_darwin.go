// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package oskeychain

import (
	"bytes"
	"fmt"
	"os/exec"
)

// keychainBackend stores secrets in the macOS login Keychain via the `security`
// CLI (add/find/delete-generic-password against the Security framework).
type keychainBackend struct {
	bin string // resolved path to `security`, "" when unavailable
}

// platformNewBackend returns the macOS Keychain backend.
func platformNewBackend() (backend, error) {
	bin, err := exec.LookPath("security")
	if err != nil {
		return &keychainBackend{}, nil
	}
	return &keychainBackend{bin: bin}, nil
}

func (b *keychainBackend) name() string { return "macos-keychain" }

func (b *keychainBackend) available() bool { return b.bin != "" }

func (b *keychainBackend) set(key string, value []byte) error {
	// -U updates an existing generic-password item instead of failing.
	//
	// Security note: add-generic-password takes the secret via -w on argv, so
	// the token is briefly visible in the process table (`ps`) to other
	// processes of the SAME user for the sub-second lifetime of this exec. The
	// `security` CLI has no stdin-fed equivalent for add-generic-password
	// (unlike libsecret's secret-tool, which the Linux backend feeds via stdin).
	// Exposure is same-UID only — an attacker already at this UID can read the
	// Keychain directly — and momentary. Accepted, documented limitation; do not
	// assume this is leak-free.
	cmd := exec.Command(b.bin, "add-generic-password", //nolint:gosec // fixed binary + discrete args, no shell
		"-U", "-s", serviceName, "-a", key, "-w", string(value))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("security add-generic-password: %w: %s", err, stderr.String())
	}
	return nil
}

func (b *keychainBackend) get(key string) ([]byte, error) {
	cmd := exec.Command(b.bin, "find-generic-password", //nolint:gosec // fixed binary + discrete args, no shell
		"-s", serviceName, "-a", key, "-w")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// `security` exits non-zero with no stdout when the item is absent.
		if stdout.Len() == 0 {
			return nil, errSecretNotFound
		}
		return nil, fmt.Errorf("security find-generic-password: %w: %s", err, stderr.String())
	}
	// find-generic-password -w prints the password followed by a single newline.
	out := bytes.TrimSuffix(stdout.Bytes(), []byte("\n"))
	return out, nil
}

func (b *keychainBackend) del(key string) error {
	cmd := exec.Command(b.bin, "delete-generic-password", //nolint:gosec // fixed binary + discrete args, no shell
		"-s", serviceName, "-a", key)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Deleting an absent item is not an error.
		if bytes.Contains(stderr.Bytes(), []byte("could not be found")) {
			return nil
		}
		return fmt.Errorf("security delete-generic-password: %w: %s", err, stderr.String())
	}
	return nil
}
