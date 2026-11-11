// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package atomicfile

import (
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

func TestRetryOnSharingViolation_SucceedsAfterTransientViolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	// Exclusive handle held until the second attempt, then released.
	held := holdWithShareMode(t, path, 0)

	attempts := 0
	err := RetryOnSharingViolation(func() error {
		attempts++
		if attempts == 2 {
			require.NoError(t, held.Close())
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			return openErr
		}
		return f.Close()
	})
	require.NoError(t, err)
	assert.Equal(t, 2, attempts, "attempt 1 hits the exclusive handle; attempt 2 releases it and succeeds")
}

func TestRetryOnSharingViolation_MissingFileReturnsAtOnce(t *testing.T) {
	attempts := 0
	err := RetryOnSharingViolation(func() error {
		attempts++
		f, openErr := os.Open(filepath.Join(t.TempDir(), "absent"))
		if openErr == nil {
			_ = f.Close()
		}
		return openErr
	})
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err), "want not-exist error, got %v", err)
	assert.Equal(t, 1, attempts, "a missing file is not a sharing violation and must not be retried")
}

func TestRetryOnSharingViolation_PersistentViolationFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	holdWithShareMode(t, path, 0)

	err := RetryOnSharingViolation(func() error {
		f, openErr := os.Open(path)
		if openErr == nil {
			_ = f.Close()
		}
		return openErr
	})
	require.Error(t, err)
	assert.True(t, IsSharingViolation(err), "want sharing violation, got %v", err)
}

func TestRetryOnSharingViolation_AtomicReplaceWaitsOutOpenReader(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(dst, []byte("old"), 0o600))
	require.NoError(t, os.WriteFile(src, []byte("new"), 0o600))

	// A plain os.Open reader omits FILE_SHARE_DELETE, so the replace is refused
	// until the reader closes; the retry wrapper rides that out.
	reader, err := os.Open(dst)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })

	attempts := 0
	err = RetryOnSharingViolation(func() error {
		attempts++
		if attempts == 2 {
			_ = reader.Close()
		}
		return AtomicReplace(src, dst)
	})
	require.NoError(t, err)

	got, err := ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
}

func TestReadFile_ReadsContentAndMissingIsNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0o600))
	got, err := ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))

	_, err = ReadFile(filepath.Join(t.TempDir(), "absent"))
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err), "want not-exist error, got %v", err)
}
