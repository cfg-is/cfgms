// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package service

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteTokenFileMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, tokenFileName)
	require.NoError(t, writeTokenFile(path, "tok_abc123"))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	got, err := ReadTokenFile(path)
	require.NoError(t, err)
	assert.Equal(t, "tok_abc123", got)

	// Overwrite keeps the mode and leaves no temp file behind.
	require.NoError(t, writeTokenFile(path, "tok_def456"))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	info, err = os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestWriteTokenFileTempModeBeforeRename(t *testing.T) {
	// A permissive umask must not widen the file, and O_EXCL must refuse a stale temp file.
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := t.TempDir()
	path := filepath.Join(dir, tokenFileName)
	require.NoError(t, writeTokenFile(path, "tok_abc123"))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// A stale temp file makes the write fail rather than reuse a wider-mode file.
	tmp := filepath.Join(dir, "."+tokenFileName+"."+strconv.Itoa(os.Getpid())+".tmp")
	require.NoError(t, os.WriteFile(tmp, []byte("x"), 0o644))
	assert.Error(t, writeTokenFile(path, "tok_def456"))
}

func TestWriteTokenFileRejectsInvalidToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), tokenFileName)
	assert.Error(t, writeTokenFile(path, "bad token"))
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestReadTokenFileRefusals(t *testing.T) {
	dir := t.TempDir()

	wide := filepath.Join(dir, "wide")
	require.NoError(t, os.WriteFile(wide, []byte("tok_secretvalue\n"), 0o600))
	require.NoError(t, os.Chmod(wide, 0o644))
	_, err := ReadTokenFile(wide)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "tok_secretvalue")

	good := filepath.Join(dir, "good")
	require.NoError(t, os.WriteFile(good, []byte("tok_secretvalue\n"), 0o600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(good, link))
	_, err = ReadTokenFile(link)
	require.Error(t, err, "a symlink must be refused")

	_, err = ReadTokenFile(dir)
	require.Error(t, err, "a directory must be refused")

	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, []byte("\n"), 0o600))
	_, err = ReadTokenFile(empty)
	require.Error(t, err)

	_, err = ReadTokenFile(filepath.Join(dir, "missing"))
	require.Error(t, err)
}

func TestReadTokenFileRefusesOtherOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires root")
	}
	path := filepath.Join(t.TempDir(), "owned")
	require.NoError(t, os.WriteFile(path, []byte("tok_abc123\n"), 0o600))
	require.NoError(t, os.Chown(path, 12345, 12345))
	_, err := ReadTokenFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not owned")
}

func TestTokenFileConfigured(t *testing.T) {
	dir := t.TempDir()

	ok, err := tokenFileConfigured(filepath.Join(dir, "missing"))
	require.NoError(t, err)
	assert.False(t, ok)

	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, nil, 0o600))
	ok, err = tokenFileConfigured(empty)
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = tokenFileConfigured(dir)
	require.NoError(t, err)
	assert.False(t, ok, "a directory is not a token file")

	full := filepath.Join(dir, "full")
	require.NoError(t, os.WriteFile(full, []byte("tok_abc123\n"), 0o600))
	ok, err = tokenFileConfigured(full)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestPlatformTokenFilePathHonoursInstallPrefix(t *testing.T) {
	prefix := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", prefix)
	assert.Equal(t, filepath.Join(filepath.Dir(platformCACertPath()), tokenFileName), platformTokenFilePath())
	assert.Contains(t, platformTokenFilePath(), prefix)
}

func TestReadTokenFile_ErrorKinds(t *testing.T) {
	dir := t.TempDir()
	kindOf := func(path string) TokenFileErrorKind {
		_, err := ReadTokenFile(path)
		require.Error(t, err)
		tfe, ok := AsTokenFileError(err)
		require.True(t, ok, "a refused file returns a *TokenFileError")
		return tfe.Kind
	}

	assert.Equal(t, TokenFileMissing, kindOf(filepath.Join(dir, "absent")))

	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, []byte(" \n"), 0o600))
	assert.Equal(t, TokenFileEmpty, kindOf(empty))

	open := filepath.Join(dir, "open")
	require.NoError(t, os.WriteFile(open, []byte("tok_open\n"), 0o600))
	require.NoError(t, os.Chmod(open, 0o644))
	assert.Equal(t, TokenFilePermissions, kindOf(open))

	spaced := filepath.Join(dir, "spaced")
	require.NoError(t, os.WriteFile(spaced, []byte("tok a b\n"), 0o600))
	assert.Equal(t, TokenFileInvalid, kindOf(spaced))
}

func TestReadTokenFile_ErrorNeverContainsToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "open")
	require.NoError(t, os.WriteFile(path, []byte("tok_secret_value\n"), 0o600))
	require.NoError(t, os.Chmod(path, 0o644))
	_, err := ReadTokenFile(path)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "tok_secret_value")
}
