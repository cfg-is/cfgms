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

func TestAtomicReplace_ReplacesWhileDestinationHeldOpenWithShareDelete(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(dst, []byte("old"), 0o600))

	dstW, err := syscall.UTF16PtrFromString(dst)
	require.NoError(t, err)
	h, err := syscall.CreateFile(dstW, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	held := os.NewFile(uintptr(h), dst)
	defer func() { _ = held.Close() }()

	require.NoError(t, os.WriteFile(src, []byte("new"), 0o600))
	require.NoError(t, AtomicReplace(src, dst))

	oldBytes, err := io.ReadAll(held)
	require.NoError(t, err)
	assert.Equal(t, "old", string(oldBytes))

	got, err := ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
	_, err = os.Stat(src)
	assert.ErrorIs(t, err, os.ErrNotExist)
}
