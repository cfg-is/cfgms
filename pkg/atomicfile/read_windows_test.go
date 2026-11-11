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

// sharingViolation returns the error Windows reports when another handle's
// share mode refuses an open: a *os.PathError wrapping ERROR_SHARING_VIOLATION.
func sharingViolation(path string) error {
	return &os.PathError{Op: "open", Path: path, Err: syscall.Errno(32)}
}

func TestRetryOnSharingViolation_SucceedsAfterTransientViolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))

	attempts := 0
	err := RetryOnSharingViolation(func() error {
		attempts++
		if attempts == 1 {
			return sharingViolation(path)
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			return openErr
		}
		return f.Close()
	})
	require.NoError(t, err)
	assert.Equal(t, 2, attempts, "attempt 1 reports a sharing violation; attempt 2 succeeds")
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

	attempts := 0
	err := RetryOnSharingViolation(func() error {
		attempts++
		return sharingViolation(path)
	})
	require.Error(t, err)
	assert.True(t, IsSharingViolation(err), "want sharing violation, got %v", err)
	assert.Greater(t, attempts, 1, "a persistent violation must be retried before failing")
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
