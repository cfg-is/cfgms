// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package atomicfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadFile_MissingFileIsNotExist(t *testing.T) {
	_, err := ReadFile(filepath.Join(t.TempDir(), "absent"))
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestReadFile_ReturnsContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(p, []byte("hello"), 0o600))
	got, err := ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))
}

func TestAtomicReplace_CreatesDestinationWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(src, []byte("first"), 0o600))
	require.NoError(t, AtomicReplace(src, dst))
	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "first", string(got))
	_, err = os.Stat(src)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestAtomicReplace_OverwritesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(dst, []byte("old"), 0o600))
	require.NoError(t, os.WriteFile(src, []byte("new"), 0o600))
	require.NoError(t, AtomicReplace(src, dst))
	got, err := ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
}

func TestAtomicReplace_MissingSourceFails(t *testing.T) {
	dir := t.TempDir()
	assert.Error(t, AtomicReplace(filepath.Join(dir, "nosrc"), filepath.Join(dir, "dst")))
}
