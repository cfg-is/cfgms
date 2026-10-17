// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package steward

import (
	"context"
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
