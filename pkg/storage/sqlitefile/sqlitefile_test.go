//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlitefile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepare_NewFileOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "new.db")
	require.NoError(t, Prepare(p))
	fi, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestPrepare_ExistingFileKeepsMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "old.db")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o644))
	require.NoError(t, os.Chmod(p, 0o644))
	require.NoError(t, Prepare(p))
	fi, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
	b, _ := os.ReadFile(p)
	assert.Equal(t, "x", string(b))
}

func TestPrepare_MemoryCreatesNoFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for _, dsn := range []string{
		"", ":memory:", "file::memory:?cache=shared",
		"file:mem1?mode=memory&cache=shared", "file:" + filepath.Join(dir, "m.db") + "?mode=memory",
	} {
		require.NoError(t, Prepare(dsn), dsn)
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestPrepare_DSNResolution(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"file-prefix": "file:" + filepath.Join(dir, "a.db"),
		"file-triple": "file://" + filepath.Join(dir, "b.db") + "?x=y",
		"query":       filepath.Join(dir, "c.db") + "?_pragma=busy_timeout(1)",
	}
	want := map[string]string{
		"file-prefix": filepath.Join(dir, "a.db"),
		"file-triple": filepath.Join(dir, "b.db"),
		"query":       filepath.Join(dir, "c.db"),
	}
	for name, dsn := range cases {
		require.NoError(t, Prepare(dsn), name)
		fi, err := os.Stat(want[name])
		require.NoError(t, err, name)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), name)
	}
}

func TestPrepare_MissingDirectoryErrors(t *testing.T) {
	assert.Error(t, Prepare(filepath.Join(t.TempDir(), "nodir", "x.db")))
}
