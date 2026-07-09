// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package credential_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/credential"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

// TestCredentialUnlockerInterfaceSatisfied verifies NewMachineUnlocker returns a non-nil
// CredentialUnlocker; the compiler enforces the interface satisfaction via the return type.
func TestCredentialUnlockerInterfaceSatisfied(t *testing.T) {
	unlocker, err := credential.NewMachineUnlocker(t.TempDir())
	if err != nil {
		t.Fatalf("NewMachineUnlocker must not fail: %v", err)
	}
	if unlocker == nil {
		t.Fatal("NewMachineUnlocker must return a non-nil CredentialUnlocker")
	}
}

// TestSentinelsAreDistinctErrors verifies ErrLocked and ErrNoUnlocker are separate sentinel values.
func TestSentinelsAreDistinctErrors(t *testing.T) {
	if credential.ErrLocked == nil {
		t.Fatal("ErrLocked must not be nil")
	}
	if credential.ErrNoUnlocker == nil {
		t.Fatal("ErrNoUnlocker must not be nil")
	}
	if errors.Is(credential.ErrLocked, credential.ErrNoUnlocker) {
		t.Fatal("ErrLocked and ErrNoUnlocker must be distinct error values")
	}
	if errors.Is(credential.ErrNoUnlocker, credential.ErrLocked) {
		t.Fatal("ErrNoUnlocker and ErrLocked must be distinct error values")
	}
}

// TestSentinelWrapping verifies sentinels are identifiable via errors.Is when wrapped.
func TestSentinelWrapping(t *testing.T) {
	wrapped := errors.Join(credential.ErrLocked, errors.New("additional context"))
	if !errors.Is(wrapped, credential.ErrLocked) {
		t.Fatal("wrapped ErrLocked must be identifiable via errors.Is")
	}
}

// TestMachineUnlocker_RoundTrip verifies that a credential encrypted by the platform
// encryptor for the same directory is correctly decrypted by machineUnlocker.Unlock.
func TestMachineUnlocker_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()

	// Pre-write an .enc file using the same dir (same salt → same HKDF key).
	enc, err := steward.NewPlatformEncryptor(tmpDir)
	require.NoError(t, err)

	plaintext := []byte("test-bundle-bytes")
	ciphertext, err := enc.Encrypt(plaintext)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "my-ctrl.enc"), ciphertext, 0600))

	unlocker, err := credential.NewMachineUnlocker(tmpDir)
	require.NoError(t, err)

	got, err := unlocker.Unlock(context.Background(), "my-ctrl")
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// TestMachineUnlocker_LockIsNoop verifies Lock returns nil without side effects.
func TestMachineUnlocker_LockIsNoop(t *testing.T) {
	tmpDir := t.TempDir()

	unlocker, err := credential.NewMachineUnlocker(tmpDir)
	require.NoError(t, err)

	assert.NoError(t, unlocker.Lock(context.Background(), "any-name"))
}

// TestMachineUnlocker_MissingFileReturnsErrLocked verifies Unlock wraps ErrLocked for absent credentials.
func TestMachineUnlocker_MissingFileReturnsErrLocked(t *testing.T) {
	tmpDir := t.TempDir()

	unlocker, err := credential.NewMachineUnlocker(tmpDir)
	require.NoError(t, err)

	_, err = unlocker.Unlock(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrLocked)
}

// TestMachineUnlocker_TamperedCiphertextReturnsErrLocked verifies Unlock wraps ErrLocked
// when decryption fails due to a corrupted .enc file.
func TestMachineUnlocker_TamperedCiphertextReturnsErrLocked(t *testing.T) {
	tmpDir := t.TempDir()

	enc, err := steward.NewPlatformEncryptor(tmpDir)
	require.NoError(t, err)
	ct, err := enc.Encrypt([]byte("original"))
	require.NoError(t, err)

	// Tamper: flip last byte.
	ct[len(ct)-1] ^= 0xFF
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "ctrl.enc"), ct, 0600))

	unlocker, err := credential.NewMachineUnlocker(tmpDir)
	require.NoError(t, err)

	_, err = unlocker.Unlock(context.Background(), "ctrl")
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrLocked)
}

// TestMachineUnlocker_PathTraversalRejected verifies Unlock rejects names containing
// path traversal sequences to prevent reading files outside the credentials directory.
func TestMachineUnlocker_PathTraversalRejected(t *testing.T) {
	tmpDir := t.TempDir()

	unlocker, err := credential.NewMachineUnlocker(tmpDir)
	require.NoError(t, err)

	traversalNames := []string{
		"../evil",
		"../../etc/passwd",
		"foo/../bar",
		"foo/bar",
		"",
		".",
		"..",
	}
	for _, name := range traversalNames {
		_, err := unlocker.Unlock(context.Background(), name)
		require.Error(t, err, "name %q should be rejected", name)
	}
}

// TestValidateCredentialName verifies the exported validator accepts valid names and
// rejects traversal attempts.
func TestValidateCredentialName(t *testing.T) {
	valid := []string{"my-ctrl", "controller.prod", "ctrl_1", "a"}
	for _, name := range valid {
		assert.NoError(t, credential.ValidateCredentialName(name), "name %q should be valid", name)
	}

	invalid := []string{"", "../evil", "foo/bar", "foo\\bar", "..", "."}
	for _, name := range invalid {
		assert.Error(t, credential.ValidateCredentialName(name), "name %q should be invalid", name)
	}
}

// TestMachineUnlocker_NonInteractive verifies Unlock completes with stdin closed —
// the machine-bound unlock requires no passphrase prompt or TTY.
func TestMachineUnlocker_NonInteractive(t *testing.T) {
	tmpDir := t.TempDir()

	enc, err := steward.NewPlatformEncryptor(tmpDir)
	require.NoError(t, err)
	ciphertext, err := enc.Encrypt([]byte("bundle-data"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "ctrl.enc"), ciphertext, 0600))

	origStdin := os.Stdin
	f, err := os.Open(os.DevNull)
	require.NoError(t, err)
	os.Stdin = f
	defer func() {
		os.Stdin = origStdin
		if closeErr := f.Close(); closeErr != nil {
			t.Logf("close devnull: %v", closeErr)
		}
	}()

	unlocker, err := credential.NewMachineUnlocker(tmpDir)
	require.NoError(t, err)

	got, err := unlocker.Unlock(context.Background(), "ctrl")
	require.NoError(t, err)
	assert.Equal(t, []byte("bundle-data"), got)
}
