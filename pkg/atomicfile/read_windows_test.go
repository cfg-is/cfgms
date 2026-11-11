// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package atomicfile

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// holdWithShareMode opens path through CreateFile with the given share mode
// and returns the handle as an *os.File, closed at test cleanup.
func holdWithShareMode(t *testing.T, path string, shareMode uint32) *os.File {
	t.Helper()
	pathW, err := syscall.UTF16PtrFromString(path)
	require.NoError(t, err)
	h, err := syscall.CreateFile(pathW, syscall.GENERIC_READ, shareMode,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	f := os.NewFile(uintptr(h), path)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestOpen_ReadsContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0o600))

	f, err := Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	got, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))
}

func TestOpen_AtomicReplaceSucceedsWhileOpenHandleHeld(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(dst, []byte("old"), 0o600))
	require.NoError(t, os.WriteFile(src, []byte("new"), 0o600))

	f, err := Open(dst)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	// The streaming handle carries FILE_SHARE_DELETE, so the replace must not
	// hit a sharing violation, and the open handle keeps reading the old data.
	require.NoError(t, AtomicReplace(src, dst))

	oldBytes, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "old", string(oldBytes))

	newBytes, err := ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "new", string(newBytes))
}

func TestOpen_MissingFileIsNotExist(t *testing.T) {
	f, err := Open(filepath.Join(t.TempDir(), "absent"))
	require.Error(t, err)
	assert.Nil(t, f)
	assert.True(t, os.IsNotExist(err), "want not-exist error, got %v", err)
}

func TestOpen_PersistentSharingViolationFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))

	// An exclusive handle (share mode 0) refuses every other open, including
	// ours, for the whole retry budget.
	holdWithShareMode(t, path, 0)

	f, err := Open(path)
	require.Error(t, err)
	assert.Nil(t, f)
	assert.True(t, IsSharingViolation(err), "want sharing violation, got %v", err)
}
