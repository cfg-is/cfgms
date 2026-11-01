// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCredentialStore_ExistingLooseDirIsRestricted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "creds")
	require.NoError(t, os.Mkdir(dir, 0700))
	require.NoError(t, os.Chmod(dir, 0777))
	overrideCredentialsDir(t, dir)

	_, err := newCredentialStore()
	require.NoError(t, err)

	fi, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), fi.Mode().Perm())
}

func TestCredentialStore_Store_ExistingLooseFileGets0600(t *testing.T) {
	dir := t.TempDir()
	overrideCredentialsDir(t, dir)
	path := filepath.Join(dir, "ctl.enc")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0600))
	require.NoError(t, os.Chmod(path, 0666))

	store, err := newCredentialStore()
	require.NoError(t, err)
	require.NoError(t, store.Store(context.Background(), "ctl", []byte("bundle")))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
}

func TestNewCredentialStore_SymlinkDirRefused(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	require.NoError(t, os.Mkdir(target, 0700))
	link := filepath.Join(base, "creds")
	require.NoError(t, os.Symlink(target, link))
	overrideCredentialsDir(t, link)

	_, err := newCredentialStore()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")
	entries, _ := os.ReadDir(target)
	assert.Empty(t, entries, "nothing may be written through the symlink")
}

func TestCredentialStore_Store_SymlinkFileRefused(t *testing.T) {
	dir := t.TempDir()
	overrideCredentialsDir(t, dir)
	store, err := newCredentialStore()
	require.NoError(t, err)

	victim := filepath.Join(t.TempDir(), "victim")
	require.NoError(t, os.WriteFile(victim, []byte("keep"), 0600))
	require.NoError(t, os.Symlink(victim, filepath.Join(dir, "ctl.enc")))

	err = store.Store(context.Background(), "ctl", []byte("bundle"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")
	got, _ := os.ReadFile(victim)
	assert.Equal(t, "keep", string(got))
}

func TestNewCredentialStore_BadLengthSaltRefused(t *testing.T) {
	dir := t.TempDir()
	overrideCredentialsDir(t, dir)
	saltPath := filepath.Join(dir, "salt")
	require.NoError(t, os.WriteFile(saltPath, []byte("short"), 0600))

	_, err := newCredentialStore()
	require.Error(t, err)

	got, rerr := os.ReadFile(saltPath)
	require.NoError(t, rerr)
	assert.Equal(t, "short", string(got), "salt must not be replaced")
}
