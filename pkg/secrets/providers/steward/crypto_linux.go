// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package steward

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// machineIDPath is the standard Linux machine ID file.
const machineIDPath = "/etc/machine-id"

// fallbackMachineIDFile is stored in secretsDir when /etc/machine-id is absent
// or empty (common in containers without systemd). Generated once and reused across
// restarts to keep the key derivation stable for the lifetime of the installation.
const fallbackMachineIDFile = "machine-id"

// newPlatformEncryptor creates an AES-256-GCM encryptor using /etc/machine-id as the key source.
// When /etc/machine-id is unavailable or empty (common in containers without systemd),
// falls back to a per-directory stable identity stored at {secretsDir}/machine-id.
func newPlatformEncryptor(secretsDir string) (platformEncryptor, error) {
	machineID, err := readLinuxMachineID()
	if err != nil {
		// /etc/machine-id is absent or empty — generate or load a per-directory fallback.
		// This is the standard behaviour in containers without systemd/dbus.
		machineID, err = loadOrGenerateFallbackMachineID(secretsDir)
		if err != nil {
			return nil, fmt.Errorf("machine ID unavailable and fallback failed: %w", err)
		}
	}

	return newAesGcmEncryptor(machineID, secretsDir)
}

// readLinuxMachineID reads the machine ID from /etc/machine-id.
// This file contains a unique machine identifier that is stable across reboots.
func readLinuxMachineID() ([]byte, error) {
	data, err := os.ReadFile(machineIDPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", machineIDPath, err)
	}

	machineID := bytes.TrimSpace(data)
	if len(machineID) == 0 {
		return nil, fmt.Errorf("%s is empty", machineIDPath)
	}

	return machineID, nil
}

// loadOrGenerateFallbackMachineID loads {secretsDir}/machine-id, generating it on first call.
// The generated value is a random 32-hex-char string stored with 0600 permissions.
func loadOrGenerateFallbackMachineID(secretsDir string) ([]byte, error) {
	path := filepath.Join(secretsDir, fallbackMachineIDFile)
	data, err := os.ReadFile(path) //#nosec G304 -- path constructed from configured identity directory
	if err == nil {
		id := bytes.TrimSpace(data)
		if len(id) > 0 {
			return id, nil
		}
	}

	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, fmt.Errorf("generate fallback machine ID: %w", err)
	}
	id := []byte(hex.EncodeToString(raw))

	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return nil, fmt.Errorf("create dir for fallback machine ID: %w", err)
	}
	if err := os.WriteFile(path, id, 0600); err != nil {
		return nil, fmt.Errorf("write fallback machine ID: %w", err)
	}
	return id, nil
}
