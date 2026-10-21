// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
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

func TestLocalRepositoryStore_ReadFile_RefusesSymlinks(t *testing.T) {
	repo := newSeededRepository(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o600))
	outsideDir := filepath.Dir(outside)

	require.NoError(t, os.Symlink(outside, filepath.Join(repo, "leak.yaml")))
	require.NoError(t, os.Symlink(outsideDir, filepath.Join(repo, "linkdir")))

	store := gitstorage.NewLocalRepositoryStore("", "")
	ctx := context.Background()

	data, err := store.ReadFile(ctx, repo, "leak.yaml")
	require.Error(t, err)
	assert.Nil(t, data)

	data, err = store.ReadFile(ctx, repo, "linkdir/secret.txt")
	require.Error(t, err)
	assert.Nil(t, data)

	data, err = store.ReadFile(ctx, repo, "modules/firewall/config.yaml")
	require.NoError(t, err)
	assert.Equal(t, "policy: baseline\n", string(data))

	_, err = store.ReadFile(ctx, repo, "missing.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file not found")
}

func TestLocalRepositoryStore_ReadFile_RefusesInCheckoutSymlinks(t *testing.T) {
	repo := newSeededRepository(t)
	require.NoError(t, os.Symlink("modules/firewall/config.yaml", filepath.Join(repo, "inl.yaml")))
	require.NoError(t, os.Symlink("modules/firewall", filepath.Join(repo, "inldir")))

	store := gitstorage.NewLocalRepositoryStore("", "")
	ctx := context.Background()

	data, err := store.ReadFile(ctx, repo, "inl.yaml")
	require.Error(t, err)
	assert.Nil(t, data)

	data, err = store.ReadFile(ctx, repo, "inldir/config.yaml")
	require.Error(t, err)
	assert.Nil(t, data)
}

func TestLocalRepositoryStore_WriteFile_RefusesLeafSymlinkInsideRepo(t *testing.T) {
	repo := newSeededRepository(t)
	sentinel := filepath.Join(repo, "other.yaml")
	require.NoError(t, os.WriteFile(sentinel, []byte("sentinel\n"), 0o600))
	leaf := filepath.Join(repo, "a.yaml")
	require.NoError(t, os.Symlink("other.yaml", leaf))

	store := gitstorage.NewLocalRepositoryStore("", "")
	err := store.WriteFile(context.Background(), repo, "a.yaml", []byte("pwned\n"))
	require.Error(t, err)

	got, rerr := os.ReadFile(sentinel) // #nosec G304 -- test path
	require.NoError(t, rerr)
	assert.Equal(t, "sentinel\n", string(got))
	fi, lerr := os.Lstat(leaf)
	require.NoError(t, lerr)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink)
}

func TestLocalRepositoryStore_WriteFile_RefusesLeafSymlinkOutsideRepo(t *testing.T) {
	repo := newSeededRepository(t)
	sentinel := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(sentinel, []byte("secret"), 0o600))
	leaf := filepath.Join(repo, "leak.yaml")
	require.NoError(t, os.Symlink(sentinel, leaf))

	store := gitstorage.NewLocalRepositoryStore("", "")
	err := store.WriteFile(context.Background(), repo, "leak.yaml", []byte("pwned"))
	require.Error(t, err)

	got, rerr := os.ReadFile(sentinel) // #nosec G304 -- test path
	require.NoError(t, rerr)
	assert.Equal(t, "secret", string(got))
}

func TestLocalRepositoryStore_WriteFile_WritesAndStages(t *testing.T) {
	repo := newSeededRepository(t)
	store := gitstorage.NewLocalRepositoryStore("", "")
	ctx := context.Background()

	require.NoError(t, store.WriteFile(ctx, repo, "plain.yaml", []byte("one\n")))
	require.NoError(t, store.WriteFile(ctx, repo, "new/nested/dir/f.yaml", []byte("two\n")))
	// Overwrite of an existing regular file.
	require.NoError(t, store.WriteFile(ctx, repo, "plain.yaml", []byte("three\n")))

	for path, want := range map[string]string{"plain.yaml": "three\n", "new/nested/dir/f.yaml": "two\n"} {
		full := filepath.Join(repo, filepath.FromSlash(path))
		got, err := os.ReadFile(full) // #nosec G304 -- test path
		require.NoError(t, err)
		assert.Equal(t, want, string(got))
		fi, err := os.Stat(full)
		require.NoError(t, err)
		if runtime.GOOS != "windows" { // Windows does not report POSIX permission bits
			assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
		}
	}

	r, err := gogit.PlainOpen(repo)
	require.NoError(t, err)
	w, err := r.Worktree()
	require.NoError(t, err)
	st, err := w.Status()
	require.NoError(t, err)
	assert.Equal(t, gogit.Added, st.File("plain.yaml").Staging)
	assert.Equal(t, gogit.Added, st.File("new/nested/dir/f.yaml").Staging)
}
