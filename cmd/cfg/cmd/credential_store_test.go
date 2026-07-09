// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/credential"
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
	if os.Getenv("GOOS") != "windows" {
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
	if os.Getenv("GOOS") != "windows" {
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
