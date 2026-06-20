// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package steward

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlatformEncryptor_RoundTrip(t *testing.T) {
	// newPlatformEncryptor falls back to a per-directory key when /etc/machine-id is
	// absent or empty, so this test runs in all environments without skipping.
	tmpDir := t.TempDir()

	enc, err := newPlatformEncryptor(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, enc)

	testCases := []struct {
		name      string
		plaintext string
	}{
		{"simple string", "hello world"},
		{"empty-ish", "x"},
		{"json payload", `{"key":"value","nested":{"array":[1,2,3]}}`},
		{"binary-like", string([]byte{0x00, 0x01, 0xFF, 0xFE, 0x80})},
		{"unicode", "secret: \u2603\u2764\U0001F600"},
		{"large payload", string(make([]byte, 64*1024))}, // 64KB
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt([]byte(tc.plaintext))
			require.NoError(t, err)
			assert.NotEmpty(t, ciphertext)

			// Ciphertext should differ from plaintext
			assert.NotEqual(t, []byte(tc.plaintext), ciphertext)

			decrypted, err := enc.Decrypt(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, string(decrypted))
		})
	}
}

func TestPlatformEncryptor_DifferentCiphertexts(t *testing.T) {
	tmpDir := t.TempDir()

	enc, err := newPlatformEncryptor(tmpDir)
	require.NoError(t, err)

	plaintext := []byte("same plaintext")

	ct1, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	ct2, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	// Each encryption should produce different ciphertext (random nonce/entropy)
	assert.NotEqual(t, ct1, ct2, "encrypting same plaintext should produce different ciphertexts")

	// Both should decrypt to the same value
	pt1, err := enc.Decrypt(ct1)
	require.NoError(t, err)

	pt2, err := enc.Decrypt(ct2)
	require.NoError(t, err)

	assert.Equal(t, plaintext, pt1)
	assert.Equal(t, plaintext, pt2)
}

func TestPlatformEncryptor_TamperedCiphertext(t *testing.T) {
	tmpDir := t.TempDir()

	enc, err := newPlatformEncryptor(tmpDir)
	require.NoError(t, err)

	ciphertext, err := enc.Encrypt([]byte("secret data"))
	require.NoError(t, err)

	// Tamper with the ciphertext
	if len(ciphertext) > 10 {
		ciphertext[len(ciphertext)-1] ^= 0xFF
	}

	_, err = enc.Decrypt(ciphertext)
	assert.Error(t, err, "decrypting tampered ciphertext should fail")
}

func TestPlatformEncryptor_Algorithm(t *testing.T) {
	tmpDir := t.TempDir()

	enc, err := newPlatformEncryptor(tmpDir)
	require.NoError(t, err)

	algo := enc.Algorithm()
	assert.NotEmpty(t, algo)
	// Should be "AES-256-GCM" on Linux/macOS or "DPAPI" on Windows
	assert.Contains(t, []string{"AES-256-GCM", "DPAPI"}, algo)
}

func TestLoadOrGenerateSalt_NewSalt(t *testing.T) {
	tmpDir := t.TempDir()

	salt, err := loadOrGenerateSalt(tmpDir)
	require.NoError(t, err)
	assert.Len(t, salt, saltSize)

	// Verify salt file was created
	saltPath := filepath.Join(tmpDir, saltFileName)
	info, err := os.Stat(saltPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
}

func TestLoadOrGenerateSalt_ExistingSalt(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate salt first time
	salt1, err := loadOrGenerateSalt(tmpDir)
	require.NoError(t, err)

	// Load same salt second time
	salt2, err := loadOrGenerateSalt(tmpDir)
	require.NoError(t, err)

	// Should return the same salt
	assert.Equal(t, salt1, salt2)
}

func TestAesGcmEncryptor_EmptyMachineID(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := newAesGcmEncryptor(nil, tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "machine ID cannot be empty")

	_, err = newAesGcmEncryptor([]byte{}, tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "machine ID cannot be empty")
}

func TestAesGcmEncryptor_ShortCiphertext(t *testing.T) {
	tmpDir := t.TempDir()

	enc, err := newAesGcmEncryptor([]byte("test-machine-id"), tmpDir)
	require.NoError(t, err)

	// Ciphertext shorter than nonce size should fail
	_, err = enc.Decrypt([]byte{0x01, 0x02})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

// TestPlatformEncryptor_FallbackMachineID verifies that the platform encryptor works
// when /etc/machine-id is absent or empty (the case in containers without systemd).
// This test only runs on Linux because the fallback is Linux-specific.
func TestPlatformEncryptor_FallbackMachineID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fallback machine-id is Linux-only")
	}
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
	if runtime.GOOS != "linux" {
		t.Skip("fallback machine-id is Linux-only")
	}
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
