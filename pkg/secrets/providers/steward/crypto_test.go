// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package steward

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlatformEncryptor_RoundTrip(t *testing.T) {
	// Platform behaviour: Linux uses /etc/machine-id with per-directory fallback;
	// macOS reads IOPlatformUUID via ioreg (available on all Apple hardware);
	// Windows uses DPAPI (no machine ID needed). All paths succeed on their native platform.
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

// TestUserEncryptor_RoundTrip is the cross-platform check that the CLI
// credential store's encryptor builds and round-trips on every platform, and
// that a second instance over the same directory (same salt) decrypts what the
// first wrote.
func TestUserEncryptor_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	enc, err := NewUserEncryptor(dir)
	require.NoError(t, err)

	ciphertext, err := enc.Encrypt([]byte("admin credential bundle"))
	require.NoError(t, err)

	again, err := NewUserEncryptor(dir)
	require.NoError(t, err)
	plaintext, err := again.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, []byte("admin credential bundle"), plaintext)
}

func TestLoadOrGenerateSalt_WrongLengthRefusedAndKept(t *testing.T) {
	tmpDir := t.TempDir()
	saltPath := filepath.Join(tmpDir, saltFileName)
	require.NoError(t, os.WriteFile(saltPath, []byte("short"), 0600))

	_, err := loadOrGenerateSalt(tmpDir)
	require.Error(t, err)

	got, rerr := os.ReadFile(saltPath)
	require.NoError(t, rerr)
	assert.Equal(t, "short", string(got))
}

// versionedAesGcm builds a versionedEncryptor over the AES-256-GCM encryptor for
// the given machine identity, so the header codec is testable on every platform.
func versionedAesGcm(t *testing.T, machineID, dir string) *versionedEncryptor {
	t.Helper()
	inner, err := newAesGcmEncryptor([]byte(machineID), dir)
	require.NoError(t, err)
	return &versionedEncryptor{inner: inner}
}

func TestVersionedEncryptor_RoundTripWritesHeader(t *testing.T) {
	enc := versionedAesGcm(t, "machine-a", t.TempDir())
	plaintext := []byte("admin credential bundle")

	blob, err := enc.Encrypt(plaintext)
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(blob, []byte(blobMagic)), "blob must start with the magic")
	assert.Equal(t, blobFormatVersion, blob[len(blobMagic)], "blob must carry the format version")
	assert.NotContains(t, string(blob), string(plaintext))

	got, err := enc.Decrypt(blob)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestNewUserEncryptor_WritesVersionedBlobs(t *testing.T) {
	enc, err := NewUserEncryptor(t.TempDir())
	require.NoError(t, err)
	blob, err := enc.Encrypt([]byte("bundle"))
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(blob, []byte(blobMagic)))

	got, err := enc.Decrypt(blob)
	require.NoError(t, err)
	assert.Equal(t, []byte("bundle"), got)
}

func TestVersionedEncryptor_HeaderlessBlobIsLegacyFormat(t *testing.T) {
	dir := t.TempDir()
	// The platform encryptor alone writes the pre-header format.
	legacy, err := newUserEncryptor(dir)
	require.NoError(t, err)
	blob, err := legacy.Encrypt([]byte("written by an older cfg"))
	require.NoError(t, err)

	enc, err := NewUserEncryptor(dir)
	require.NoError(t, err)
	_, err = enc.Decrypt(blob)
	require.ErrorIs(t, err, ErrLegacyFormat)
	assert.NotErrorIs(t, err, ErrCorrupt)
	assert.NotErrorIs(t, err, ErrWrongProtectionScope)
}

func TestVersionedEncryptor_WrongMachineIdentityIsWrongProtectionScope(t *testing.T) {
	dir := t.TempDir()
	blob, err := versionedAesGcm(t, "machine-a", dir).Encrypt([]byte("secret"))
	require.NoError(t, err)

	_, err = versionedAesGcm(t, "machine-b", dir).Decrypt(blob)
	require.ErrorIs(t, err, ErrWrongProtectionScope)
	assert.NotErrorIs(t, err, ErrCorrupt)
	assert.NotErrorIs(t, err, ErrLegacyFormat)
}

func TestVersionedEncryptor_CorruptBlobs(t *testing.T) {
	enc := versionedAesGcm(t, "machine-a", t.TempDir())
	good, err := enc.Encrypt([]byte("secret"))
	require.NoError(t, err)

	mutate := func(f func(b []byte) []byte) []byte {
		return f(append([]byte(nil), good...))
	}
	cases := map[string][]byte{
		"empty file":          {},
		"magic only":          []byte(blobMagic),
		"shorter than header": good[:blobHeaderSize-1],
		"header without body": good[:blobHeaderSize],
		"truncated body":      good[:len(good)-1],
		"flipped body byte":   mutate(func(b []byte) []byte { b[len(b)-1] ^= 0xFF; return b }),
		"flipped checksum":    mutate(func(b []byte) []byte { b[len(blobMagic)+1] ^= 0xFF; return b }),
		"unknown version":     mutate(func(b []byte) []byte { b[len(blobMagic)] = 2; return b }),
		"version zero":        mutate(func(b []byte) []byte { b[len(blobMagic)] = 0; return b }),
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := enc.Decrypt(blob)
			require.ErrorIs(t, err, ErrCorrupt)
			assert.NotErrorIs(t, err, ErrLegacyFormat)
			assert.NotErrorIs(t, err, ErrWrongProtectionScope)
		})
	}
}

// TestVersionedEncryptor_ErrorsCarryNoPlatformText checks the sentinel messages are
// fixed text: no platform error, key or entropy detail leaks through them.
func TestVersionedEncryptor_ErrorsCarryNoPlatformText(t *testing.T) {
	dir := t.TempDir()
	blob, err := versionedAesGcm(t, "machine-a", dir).Encrypt([]byte("secret"))
	require.NoError(t, err)

	_, err = versionedAesGcm(t, "machine-b", dir).Decrypt(blob)
	require.Error(t, err)
	assert.Equal(t, ErrWrongProtectionScope.Error(), err.Error())
	assert.NotContains(t, err.Error(), "decryption failed")
	assert.NotContains(t, err.Error(), "authentication")
}
