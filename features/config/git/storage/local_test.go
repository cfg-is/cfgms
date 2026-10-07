// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gitstorage "github.com/cfgis/cfgms/features/config/git/storage"
)

// commitFile writes a file into the worktree and commits it, returning the commit SHA.
func commitFile(t *testing.T, worktree *gogit.Worktree, root, path, content, message string) string {
	t.Helper()

	full := filepath.Join(root, filepath.FromSlash(path))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o600))

	_, err := worktree.Add(path)
	require.NoError(t, err)

	sha, err := worktree.Commit(message, &gogit.CommitOptions{
		Author: &object.Signature{Name: "CFGMS", Email: "system@cfgms.local", When: time.Now()},
	})
	require.NoError(t, err)

	return sha.String()
}

// newSeededRepository creates a repository with one commit per configuration file.
func newSeededRepository(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "repo")
	repo, err := gogit.PlainInit(path, false)
	require.NoError(t, err)

	worktree, err := repo.Worktree()
	require.NoError(t, err)

	commitFile(t, worktree, path, "modules/firewall/config.yaml", "policy: baseline\n", "baseline firewall policy")
	commitFile(t, worktree, path, "modules/service/config.yaml", "state: running\n", "service configuration")

	return path
}

func TestLocalRepositoryStore_GetHistory(t *testing.T) {
	store := gitstorage.NewLocalRepositoryStore("", "")
	ctx := context.Background()
	path := newSeededRepository(t)

	t.Run("empty file path returns whole-repository history", func(t *testing.T) {
		// Repository-wide history is what the Git manager asks for when listing rollback
		// points and when resolving the current commit for a rollback preview. A file-name
		// filter of "" matches no commit, so it must not be applied.
		commits, err := store.GetHistory(ctx, path, "", 0)
		require.NoError(t, err)
		require.Len(t, commits, 2)
		assert.Equal(t, "service configuration", commits[0].Message)
		assert.Equal(t, "baseline firewall policy", commits[1].Message)
	})

	t.Run("file path scopes history to that file", func(t *testing.T) {
		commits, err := store.GetHistory(ctx, path, "modules/firewall/config.yaml", 0)
		require.NoError(t, err)
		require.Len(t, commits, 1)
		assert.Equal(t, "baseline firewall policy", commits[0].Message)
	})

	t.Run("limit caps the number of commits returned", func(t *testing.T) {
		commits, err := store.GetHistory(ctx, path, "", 1)
		require.NoError(t, err)
		require.Len(t, commits, 1)
		assert.Equal(t, "service configuration", commits[0].Message)
	})
}
