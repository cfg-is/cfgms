// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package steward

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

func TestDPAPIEncryptor_RoundTrip(t *testing.T) {
	enc, err := newPlatformEncryptor("")
	require.NoError(t, err)
	require.NotNil(t, enc)

	assert.Equal(t, "DPAPI", enc.Algorithm())

	testData := []byte("DPAPI test secret data")
	encrypted, err := enc.Encrypt(testData)
	require.NoError(t, err)
	assert.NotEqual(t, testData, encrypted)

	decrypted, err := enc.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

func TestDPAPIEncryptor_EmptyInput(t *testing.T) {
	enc, err := newPlatformEncryptor("")
	require.NoError(t, err)

	_, err = enc.Encrypt(nil)
	assert.Error(t, err)

	_, err = enc.Encrypt([]byte{})
	assert.Error(t, err)

	_, err = enc.Decrypt(nil)
	assert.Error(t, err)

	_, err = enc.Decrypt([]byte{})
	assert.Error(t, err)
}

// secretTestSIDs returns the SID strings named by the ACEs of path's DACL.
func secretTestSIDs(t *testing.T, path string) []string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NotNil(t, acl)
	var sids []string
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, i, &ace))
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return sids
}

func TestCreateSecretStore_LocksDownSecretsDirOnWindows(t *testing.T) {
	secretsDir := filepath.Join(t.TempDir(), "secrets")
	p := &StewardProvider{}
	store, err := p.CreateSecretStore(map[string]interface{}{"secrets_dir": secretsDir})
	require.NoError(t, err)

	require.NoError(t, store.StoreSecret(context.Background(), &interfaces.SecretRequest{
		Key: "acl-test", Value: "s3cret",
	}))

	var blobs []string
	require.NoError(t, filepath.WalkDir(filepath.Join(secretsDir, "blobs"), func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			blobs = append(blobs, path)
		}
		return err
	}))
	require.NotEmpty(t, blobs, "stored secret must produce a blob file")

	paths := append([]string{secretsDir, filepath.Join(secretsDir, "blobs")}, blobs...)
	for _, path := range paths {
		sids := secretTestSIDs(t, path)
		for _, denied := range []string{"S-1-5-32-545", "S-1-5-11", "S-1-1-0"} {
			assert.NotContains(t, sids, denied, path)
		}
	}
}

// dpapiBlobFlags returns the dwFlags field of a DPAPI blob header. It follows
// dwVersion (4 bytes), guidProvider (16), dwMasterKeyVersion (4) and
// guidMasterKey (16).
func dpapiBlobFlags(t *testing.T, blob []byte) uint32 {
	t.Helper()
	const flagsOffset = 4 + 16 + 4 + 16
	require.GreaterOrEqual(t, len(blob), flagsOffset+4, "DPAPI blob too short for a header")
	return binary.LittleEndian.Uint32(blob[flagsOffset : flagsOffset+4])
}

// TestUserEncryptor_BlobIsUserScopedAndMachineBound proves the CLI credential
// store's blob is user-scope DPAPI (no CRYPTPROTECT_LOCAL_MACHINE), that the
// constant entropy the machine-scope encryptor uses does not open it, and that
// the entropy binds it to this machine's MachineGuid and the store's salt.
func TestUserEncryptor_BlobIsUserScopedAndMachineBound(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("admin credential bundle")

	enc, err := NewUserEncryptor(dir)
	require.NoError(t, err)
	blob, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	assert.Zero(t, dpapiBlobFlags(t, blob)&cryptprotectLocalMachine,
		"CLI credential blob must not be machine-scope DPAPI")

	// The header reading is meaningful: the steward's encryptor sets the flag.
	machine, err := newPlatformEncryptor("")
	require.NoError(t, err)
	machineBlob, err := machine.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotZero(t, dpapiBlobFlags(t, machineBlob)&cryptprotectLocalMachine,
		"steward blob must stay machine-scope DPAPI")

	constEntropy := sha256.Sum256([]byte(hkdfInfo))
	_, err = (&dpapiEncryptor{entropy: constEntropy[:]}).Decrypt(blob)
	assert.Error(t, err, "the old constant entropy must not decrypt the CLI blob")

	got, err := enc.Decrypt(blob)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	// Another machine (different MachineGuid, same copied salt) cannot open it.
	other, err := newUserDPAPIEncryptor([]byte("00000000-0000-0000-0000-000000000000"), dir)
	require.NoError(t, err)
	_, err = other.Decrypt(blob)
	assert.Error(t, err, "a blob must not decrypt under another machine's MachineGuid")
}
