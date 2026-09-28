// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Coverage for RunPreCommitHooks: the configuration files it validates are named
// by the caller, so the read must stay inside the repository (Issue #4340), and
// the validation it performs on the files that are inside must still reject
// malformed configuration.
//
// Everything here runs against the real DefaultHookManager and real files on
// disk — no test doubles are involved.

// writeRepoFile writes content at repoPath/relPath, creating parent directories.
func writeRepoFile(t *testing.T, repoPath, relPath, content string) {
	t.Helper()

	full := filepath.Join(repoPath, relPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
}

func TestRunPreCommitHooks_AcceptsValidConfigurationInsideRepository(t *testing.T) {
	manager := NewHookManager()
	repoPath := t.TempDir()

	writeRepoFile(t, repoPath, "config.yaml", "version: \"1.0\"\nname: test\n")
	writeRepoFile(t, repoPath, "groups/servers/config.yaml", "version: \"1.0\"\n")
	writeRepoFile(t, repoPath, "settings.json", `{"enabled": true}`)

	err := manager.RunPreCommitHooks(context.Background(), repoPath,
		[]string{"config.yaml", "groups/servers/config.yaml", "settings.json"})

	require.NoError(t, err)
}

func TestRunPreCommitHooks_RejectsMalformedConfiguration(t *testing.T) {
	manager := NewHookManager()
	repoPath := t.TempDir()

	writeRepoFile(t, repoPath, "broken.yaml", "key: [unclosed\n")

	err := manager.RunPreCommitHooks(context.Background(), repoPath, []string{"broken.yaml"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed for broken.yaml")
}

func TestRunPreCommitHooks_SkipsNonConfigurationFiles(t *testing.T) {
	manager := NewHookManager()
	repoPath := t.TempDir()

	// The file does not exist at all: a non-configuration extension must never be
	// read, so a missing README is not an error.
	err := manager.RunPreCommitHooks(context.Background(), repoPath, []string{"README.md", "bin/steward"})

	require.NoError(t, err)
}

func TestRunPreCommitHooks_RejectsFileEscapingRepository(t *testing.T) {
	manager := NewHookManager()

	root := t.TempDir()
	repoPath := filepath.Join(root, "repo")
	require.NoError(t, os.MkdirAll(repoPath, 0o750))

	// A real, readable, valid YAML file outside the repository. It parses cleanly,
	// so if it were read the hook would succeed — the rejection therefore proves
	// containment rather than an incidental read or parse failure.
	outsidePath := filepath.Join(root, "outside.yaml")
	require.NoError(t, os.WriteFile(outsidePath, []byte("secret: value\n"), 0o600))

	for _, file := range []string{"../outside.yaml", "sub/../../outside.yaml", outsidePath} {
		t.Run(file, func(t *testing.T) {
			err := manager.RunPreCommitHooks(context.Background(), repoPath, []string{file})

			require.Error(t, err)
			assert.Contains(t, err.Error(), "path validation failed")
		})
	}
}

func TestRunPreCommitHooks_RejectsSymlinkEscapingRepository(t *testing.T) {
	manager := NewHookManager()

	root := t.TempDir()
	repoPath := filepath.Join(root, "repo")
	require.NoError(t, os.MkdirAll(repoPath, 0o750))

	outsidePath := filepath.Join(root, "outside.yaml")
	require.NoError(t, os.WriteFile(outsidePath, []byte("secret: value\n"), 0o600))

	// A path with no ".." in it that still resolves outside the repository: a
	// purely lexical check would accept it.
	require.NoError(t, os.Symlink(outsidePath, filepath.Join(repoPath, "linked.yaml")))

	err := manager.RunPreCommitHooks(context.Background(), repoPath, []string{"linked.yaml"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "path validation failed")
}
