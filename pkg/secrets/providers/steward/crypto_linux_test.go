// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package steward

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlatformEncryptor_FallbackMachineID verifies that the Linux platform encryptor works
// when /etc/machine-id is absent or empty (the case in containers without systemd).
func TestPlatformEncryptor_FallbackMachineID(t *testing.T) {
	tmpDir := t.TempDir()

	enc, err := newPlatformEncryptor(tmpDir)
	require.NoError(t, err, "newPlatformEncryptor must succeed even without /etc/machine-id")
	require.NotNil(t, enc)

	// Verify round-trip works with the fallback key.
	plaintext := []byte("test secret for fallback key")
	ciphertext, err := enc.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	decrypted, err := enc.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// A second encryptor using the same dir must derive the same key (stable fallback).
	enc2, err := newPlatformEncryptor(tmpDir)
	require.NoError(t, err)
	decrypted2, err := enc2.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2, "second encryptor using same dir must decrypt ciphertext from first")
}

// TestLoadOrGenerateFallbackMachineID verifies that the fallback machine-id is stable
// across calls and persisted to disk.
func TestLoadOrGenerateFallbackMachineID(t *testing.T) {
	tmpDir := t.TempDir()

	id1, err := loadOrGenerateFallbackMachineID(tmpDir)
	require.NoError(t, err)
	require.NotEmpty(t, id1)

	// Second call must return the same value (loaded from disk).
	id2, err := loadOrGenerateFallbackMachineID(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, id1, id2, "fallback machine-id must be stable across calls")

	// Verify the file was created with restrictive permissions.
	info, err := os.Stat(filepath.Join(tmpDir, fallbackMachineIDFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
