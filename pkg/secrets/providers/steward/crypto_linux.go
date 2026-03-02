// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build linux

package steward

import (
	"bytes"
	"fmt"
	"os"
)

// machineIDPath is the standard Linux machine ID file.
const machineIDPath = "/etc/machine-id"

// newPlatformEncryptor creates an AES-256-GCM encryptor using /etc/machine-id as the key source.
func newPlatformEncryptor(secretsDir string) (platformEncryptor, error) {
	machineID, err := readLinuxMachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to read machine ID: %w", err)
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
