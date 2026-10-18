// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoveCloneDir(t *testing.T) {
	workDir := t.TempDir()
	clone := filepath.Join(workDir, "tenant", "hash")
	require.NoError(t, os.MkdirAll(filepath.Join(clone, ".git"), 0750))

	require.NoError(t, RemoveCloneDir(workDir, clone))
	assert.NoDirExists(t, clone)
	assert.NoDirExists(t, filepath.Join(workDir, "tenant"), "empty tenant dir is dropped")
	assert.DirExists(t, workDir)
}

func TestRemoveCloneDir_KeepsTenantDirWithOtherClones(t *testing.T) {
	workDir := t.TempDir()
	a := filepath.Join(workDir, "tenant", "a")
	b := filepath.Join(workDir, "tenant", "b")
	require.NoError(t, os.MkdirAll(a, 0750))
	require.NoError(t, os.MkdirAll(b, 0750))

	require.NoError(t, RemoveCloneDir(workDir, a))
	assert.NoDirExists(t, a)
	assert.DirExists(t, b)
}

func TestRemoveCloneDir_RefusesOutsideAndWorkDir(t *testing.T) {
	workDir := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "keep"), []byte("x"), 0600))

	for name, target := range map[string]string{
		"outside":   outside,
		"traversal": filepath.Join(workDir, "..", filepath.Base(outside)),
		"workdir":   workDir,
		"empty":     "",
	} {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, RemoveCloneDir(workDir, target))
		})
	}
	assert.FileExists(t, filepath.Join(outside, "keep"))
	assert.FileExists(t, filepath.Join(workDir, "keep"))
}

// A store's repoDir is built from the symlink-resolved work directory, while callers
// hold the raw one (macOS /var -> /private/var, Windows short names). Removal must
// accept the resolved spelling.
func TestRemoveCloneDir_WorkDirReachedThroughSymlink(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	clone := filepath.Join(real, "tenant", "abc")
	require.NoError(t, os.MkdirAll(clone, 0750))

	require.NoError(t, RemoveCloneDir(link, clone))
	assert.NoDirExists(t, clone)
	assert.NoDirExists(t, filepath.Join(real, "tenant"))
	assert.DirExists(t, real)
}
