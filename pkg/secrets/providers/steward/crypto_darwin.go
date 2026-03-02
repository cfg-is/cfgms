// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build darwin

package steward

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
)

// ioregUUIDPattern matches the IOPlatformUUID value from ioreg output.
var ioregUUIDPattern = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

// newPlatformEncryptor creates an AES-256-GCM encryptor using IOPlatformUUID as the key source.
func newPlatformEncryptor(secretsDir string) (platformEncryptor, error) {
	machineID, err := readDarwinMachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to read machine ID: %w", err)
	}

	return newAesGcmEncryptor(machineID, secretsDir)
}

// readDarwinMachineID reads the machine UUID via ioreg on macOS.
func readDarwinMachineID() ([]byte, error) {
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice") //#nosec G204 -- fixed command, no user input
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute ioreg: %w", err)
	}

	matches := ioregUUIDPattern.FindSubmatch(output)
	if len(matches) < 2 {
		return nil, fmt.Errorf("IOPlatformUUID not found in ioreg output")
	}

	machineID := bytes.TrimSpace(matches[1])
	if len(machineID) == 0 {
		return nil, fmt.Errorf("IOPlatformUUID is empty")
	}

	return machineID, nil
}
