// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/credential"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

// overrideCredentialsDir replaces credentialsDirFn for the duration of the test and
// restores it on cleanup.
func overrideCredentialsDir(t *testing.T, dir string) {
	t.Helper()
	orig := credentialsDirFn
	credentialsDirFn = func() (string, error) { return dir, nil }
	t.Cleanup(func() { credentialsDirFn = orig })
}

func TestCredentialStore_StoreAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	overrideCredentialsDir(t, tmpDir)

	store, err := newCredentialStore()
	require.NoError(t, err)

	ctx := context.Background()
	bundle := []byte("test-bundle-content")

	require.NoError(t, store.Store(ctx, "my-controller", bundle))

	got, err := store.Load(ctx, "my-controller")
	require.NoError(t, err)
	assert.Equal(t, bundle, got)
}

// TestCredentialStore_NoPlaintextOnDisk is a required acceptance test: it reads back
// the raw .enc file and asserts that no PEM header from the original bundle survives
// unencrypted on disk.
func TestCredentialStore_NoPlaintextOnDisk(t *testing.T) {
	tmpDir := t.TempDir()
	overrideCredentialsDir(t, tmpDir)

	store, err := newCredentialStore()
	require.NoError(t, err)

	bundle := []byte("-----BEGIN CERTIFICATE-----\nABCDEFGHIJKLMNOP\n-----END CERTIFICATE-----\n" +
		"-----BEGIN PRIVATE KEY-----\nXYZABCDEFG\n-----END PRIVATE KEY-----")

	ctx := context.Background()
	require.NoError(t, store.Store(ctx, "ctrl", bundle))

	raw, err := os.ReadFile(filepath.Join(tmpDir, "ctrl.enc"))
	require.NoError(t, err)

	assert.False(t, bytes.Contains(raw, []byte("-----BEGIN")),
		"raw .enc file must not contain plaintext PEM header '-----BEGIN'")
}

// TestCredentialStore_NoBespokeCrypto is a required acceptance test: it asserts that
// pkg/credential source files do not import any crypto packages directly.
// All encryption must be delegated to pkg/secrets/providers/steward.
func TestCredentialStore_NoBespokeCrypto(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)

	// cmd/cfg/cmd/ is 3 levels deep; pkg/credential is at workspace root.
	pkgCredDir := filepath.Join(wd, "..", "..", "..", "pkg", "credential")

	forbidden := []string{
		`"crypto/aes"`,
		`"crypto/cipher"`,
		`"crypto/des"`,
		`"crypto/rc4"`,
		`"golang.org/x/crypto/`,
	}

	entries, err := os.ReadDir(pkgCredDir)
	require.NoError(t, err)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(pkgCredDir, entry.Name()))
		require.NoError(t, err)

		for _, pkg := range forbidden {
			assert.False(t, bytes.Contains(content, []byte(pkg)),
				"pkg/credential/%s must not import forbidden crypto package %s",
				entry.Name(), pkg)
		}
	}
}

func TestCredentialStore_DirectoryCreatedAt0700(t *testing.T) {
	tmpDir := t.TempDir()
	credDir := filepath.Join(tmpDir, "credentials")
	overrideCredentialsDir(t, credDir)

	_, err := newCredentialStore()
	require.NoError(t, err)

	info, err := os.Stat(credDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	// POSIX permission bits are not meaningful on Windows (ACL-based); only
	// assert the mode where the underlying filesystem honors 0700.
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0700), info.Mode().Perm(),
			"credentials directory must be created at mode 0700")
	}
}

func TestCredentialStore_EncFileCreatedAt0600(t *testing.T) {
	tmpDir := t.TempDir()
	overrideCredentialsDir(t, tmpDir)

	store, err := newCredentialStore()
	require.NoError(t, err)

	require.NoError(t, store.Store(context.Background(), "ctrl", []byte("data")))

	info, err := os.Stat(filepath.Join(tmpDir, "ctrl.enc"))
	require.NoError(t, err)
	// POSIX permission bits are not meaningful on Windows (ACL-based); only
	// assert the mode where the underlying filesystem honors 0600.
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
			".enc file must be created at mode 0600")
	}
}

func TestCredentialStore_LoadMissingReturnsErrLocked(t *testing.T) {
	tmpDir := t.TempDir()
	overrideCredentialsDir(t, tmpDir)

	store, err := newCredentialStore()
	require.NoError(t, err)

	_, err = store.Load(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrLocked)
}

func TestCredentialStore_LockIsNoop(t *testing.T) {
	tmpDir := t.TempDir()
	overrideCredentialsDir(t, tmpDir)

	store, err := newCredentialStore()
	require.NoError(t, err)

	// Lock on a stored credential must not return an error.
	require.NoError(t, store.Store(context.Background(), "ctrl", []byte("data")))
	assert.NoError(t, store.Lock(context.Background(), "ctrl"))
}

func TestCredentialStore_MultipleCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	overrideCredentialsDir(t, tmpDir)

	store, err := newCredentialStore()
	require.NoError(t, err)

	ctx := context.Background()
	pairs := map[string][]byte{
		"controller-a": []byte("bundle-a"),
		"controller-b": []byte("bundle-b"),
		"controller-c": []byte("bundle-c"),
	}

	for name, data := range pairs {
		require.NoError(t, store.Store(ctx, name, data))
	}
	for name, want := range pairs {
		got, err := store.Load(ctx, name)
		require.NoError(t, err)
		assert.Equal(t, want, got, "credential %s round-trip mismatch", name)
	}
}

func TestCredentialStore_ConstructorErrorOnBadDir(t *testing.T) {
	orig := credentialsDirFn
	credentialsDirFn = func() (string, error) {
		return "", os.ErrPermission
	}
	t.Cleanup(func() { credentialsDirFn = orig })

	_, err := newCredentialStore()
	require.Error(t, err, "newCredentialStore must fail when credentialsDirFn returns an error")
}

func TestCredentialStore_StoreRejectsTraversalName(t *testing.T) {
	tmpDir := t.TempDir()
	overrideCredentialsDir(t, tmpDir)

	store, err := newCredentialStore()
	require.NoError(t, err)

	traversalNames := []string{"../evil", "foo/bar", "", "..", "."}
	for _, name := range traversalNames {
		err := store.Store(context.Background(), name, []byte("data"))
		require.Error(t, err, "Store should reject name %q", name)
	}
}

func TestCredentialStore_LoadRejectsTraversalName(t *testing.T) {
	tmpDir := t.TempDir()
	overrideCredentialsDir(t, tmpDir)

	store, err := newCredentialStore()
	require.NoError(t, err)

	traversalNames := []string{"../evil", "foo/bar", "", "..", "."}
	for _, name := range traversalNames {
		_, err := store.Load(context.Background(), name)
		require.Error(t, err, "Load should reject name %q", name)
	}
}

func TestCredentialStore_OverwriteExisting(t *testing.T) {
	tmpDir := t.TempDir()
	overrideCredentialsDir(t, tmpDir)

	store, err := newCredentialStore()
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, store.Store(ctx, "ctrl", []byte("first")))
	require.NoError(t, store.Store(ctx, "ctrl", []byte("second")))

	got, err := store.Load(ctx, "ctrl")
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), got)
}

// storeBlobCases writes one .enc file for each decrypt failure class into dir and
// returns the expected sentinel and message for the credential named name.
type storeBlobCase struct {
	name     string
	write    func(t *testing.T, dir, name string)
	sentinel error
	message  string
}

func storeBlobCases() []storeBlobCase {
	write := func(t *testing.T, dir, name string, blob []byte) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".enc"), blob, 0600))
	}
	return []storeBlobCase{
		{
			name: "older format (headerless)",
			write: func(t *testing.T, dir, name string) {
				old, err := steward.NewPlatformEncryptor(dir)
				require.NoError(t, err)
				ct, err := old.Encrypt([]byte("bundle stored by an older cfg"))
				require.NoError(t, err)
				write(t, dir, name, ct)
			},
			sentinel: steward.ErrLegacyFormat,
			message:  `credential store entry "ctrl" was written by an older cfg format and is not migrated; re-run cfg connect or cfg credential request-signing-cert`,
		},
		{
			name: "different user or machine",
			write: func(t *testing.T, dir, name string) {
				other, err := steward.NewUserEncryptor(t.TempDir())
				require.NoError(t, err)
				ct, err := other.Encrypt([]byte("bundle stored elsewhere"))
				require.NoError(t, err)
				write(t, dir, name, ct)
			},
			sentinel: steward.ErrWrongProtectionScope,
			message:  `credential store entry "ctrl" is protected for a different user or machine; run cfg as the user who stored it, or store it again here`,
		},
		{
			name: "corrupt",
			write: func(t *testing.T, dir, name string) {
				enc, err := steward.NewUserEncryptor(dir)
				require.NoError(t, err)
				ct, err := enc.Encrypt([]byte("bundle"))
				require.NoError(t, err)
				write(t, dir, name, ct[:len(ct)-1])
			},
			sentinel: steward.ErrCorrupt,
			message:  `credential store entry "ctrl" is corrupt or unreadable; remove it and store it again`,
		},
	}
}

func assertSpecificStoreError(t *testing.T, err error, c storeBlobCase) {
	t.Helper()
	require.Error(t, err)
	assert.ErrorIs(t, err, c.sentinel)
	assert.Contains(t, err.Error(), c.message)
	assert.NotContains(t, err.Error(), "credential is locked")
	assert.NotContains(t, err.Error(), "cfg credential enroll", "the generic hint must not be appended")
	for _, raw := range []string{"decryption failed", "message authentication", "CryptUnprotectData"} {
		assert.NotContains(t, err.Error(), raw)
	}
}

// TestCredentialStore_LoadReportsEachStoreFailureDistinctly covers the three cases
// the store tells apart: older format, different user or machine, corrupt.
func TestCredentialStore_LoadReportsEachStoreFailureDistinctly(t *testing.T) {
	for _, c := range storeBlobCases() {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			overrideCredentialsDir(t, dir)
			store, err := newCredentialStore()
			require.NoError(t, err)
			c.write(t, dir, "ctrl")

			_, err = store.Load(context.Background(), "ctrl")
			assertSpecificStoreError(t, err, c)
		})
	}
}

// TestCredentialStore_LoadMissingKeepsGenericHint keeps the missing-file path as it was.
func TestCredentialStore_LoadMissingKeepsGenericHint(t *testing.T) {
	overrideCredentialsDir(t, t.TempDir())
	store, err := newCredentialStore()
	require.NoError(t, err)

	_, err = store.Load(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cfg connect")
	assert.Contains(t, err.Error(), "cfg credential enroll")
}

// TestSignCommandContent_SurfacesStoreFailure runs the command path that loads the
// signing credential and checks the specific store message reaches the operator for
// each case, including a headerless .enc file on disk.
func TestSignCommandContent_SurfacesStoreFailure(t *testing.T) {
	for _, c := range storeBlobCases() {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			overrideCredentialsDir(t, dir)
			// Create the store first so the salt exists, then place the blob.
			_, err := newCredentialStore()
			require.NoError(t, err)
			signingCase := c
			signingCase.message = strings.ReplaceAll(c.message, `"ctrl"`, `"`+signingCredentialName+`"`)
			c.write(t, dir, signingCredentialName)

			_, err = signCommandContent([]byte("content"))
			assertSpecificStoreError(t, err, signingCase)
		})
	}
}
