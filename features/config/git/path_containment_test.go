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

// Regression coverage for the cache-directory containment added to getLocalPath
// (Issue #4340). repoID reaches getLocalPath from caller-supplied identifiers —
// a rollback target ID is embedded verbatim in "device-<targetID>-repo" — so a
// repoID carrying "../" or an absolute path must be rejected instead of joined
// onto the cache directory and cloned into.
//
// Both call sites that propagate the new error are covered: ensureRepository
// (reached here through the exported GetCommitHistory, which is the path the
// rollback manager takes) and CreateRepository.

// staticGitProvider is a test implementation of GitProvider that returns a
// caller-chosen repository and records the repositories it was asked to delete.
// It is not a mock: it programs no per-call expectations and asserts nothing
// about how it was invoked. It stands in for a Git provider that answers
// CreateRepository with a repository ID containing path separators.
type staticGitProvider struct {
	repo    *Repository
	deleted []string
}

func (p *staticGitProvider) CreateRepository(_ context.Context, _ RepositoryConfig) (*Repository, error) {
	return p.repo, nil
}

func (p *staticGitProvider) GetRepository(_ context.Context, _, _ string) (*Repository, error) {
	return p.repo, nil
}

func (p *staticGitProvider) DeleteRepository(_ context.Context, _, name string) error {
	p.deleted = append(p.deleted, name)
	return nil
}

func (p *staticGitProvider) CreateBranch(_ context.Context, _, _, _, _ string) error { return nil }

func (p *staticGitProvider) DeleteBranch(_ context.Context, _, _, _ string) error { return nil }

func (p *staticGitProvider) GetDefaultBranch(_ context.Context, _, _ string) (string, error) {
	return "main", nil
}

func (p *staticGitProvider) CreatePullRequest(_ context.Context, _, _ string, _ PullRequestConfig) (string, error) {
	return "", nil
}

func (p *staticGitProvider) MergePullRequest(_ context.Context, _, _, _ string) error { return nil }

func (p *staticGitProvider) CreateWebhook(_ context.Context, _, _ string, _ WebhookConfig) (string, error) {
	return "", nil
}

func (p *staticGitProvider) DeleteWebhook(_ context.Context, _, _, _ string) error { return nil }

func (p *staticGitProvider) SetBranchProtection(_ context.Context, _, _ string, _ BranchProtectionRule) error {
	return nil
}

func (p *staticGitProvider) RemoveBranchProtection(_ context.Context, _, _, _ string) error {
	return nil
}

// newContainmentTestManager builds a manager whose cache directory is a fresh
// temporary directory. The repository store is nil on purpose: every case below
// must be rejected before any clone, pull or file access is attempted, so a nil
// store turns a missed rejection into a panic rather than a silent pass.
func newContainmentTestManager(t *testing.T, provider GitProvider) (*DefaultGitManager, string) {
	t.Helper()

	cacheDir := filepath.Join(t.TempDir(), "cache")
	manager := NewGitManager(provider, nil, GitManagerConfig{CacheDir: cacheDir}, nil)

	return manager, cacheDir
}

func TestGetLocalPath_RejectsRepoIDEscapingCacheDir(t *testing.T) {
	manager, cacheDir := newContainmentTestManager(t, nil)

	outside := t.TempDir()

	cases := map[string]string{
		"parent traversal":          "../escaped-repo",
		"repeated parent traversal": "../../../escaped-repo",
		"traversal after segment":   "device-123-repo/../../escaped-repo",
		"absolute path":             filepath.Join(outside, "escaped-repo"),
	}

	for name, repoID := range cases {
		t.Run(name, func(t *testing.T) {
			localPath, err := manager.getLocalPath(repoID)

			require.Error(t, err, "repoID %q must not resolve to a path outside the cache directory", repoID)
			assert.Empty(t, localPath)
		})
	}

	// The rejected IDs must not have left directories behind anywhere.
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a rejected repository ID must not create anything in the cache directory")
}

func TestGetLocalPath_RejectsSymlinkEscapingCacheDir(t *testing.T) {
	manager, cacheDir := newContainmentTestManager(t, nil)

	// Create the cache directory, then plant a symlink inside it that points out
	// of the cache. A purely lexical check would accept "escape-link" because it
	// contains no "..".
	require.NoError(t, os.MkdirAll(cacheDir, 0o750))
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(cacheDir, "escape-link")))

	localPath, err := manager.getLocalPath("escape-link")

	require.Error(t, err)
	assert.Empty(t, localPath)
}

func TestGetLocalPath_AcceptsRepoIDInsideCacheDir(t *testing.T) {
	manager, cacheDir := newContainmentTestManager(t, nil)

	localPath, err := manager.getLocalPath("device-123-repo")

	require.NoError(t, err)

	// The cache directory is created on demand and compared in canonical form,
	// since path validation resolves symlinks (on macOS the temp root is one).
	resolvedCacheDir, err := filepath.EvalSymlinks(cacheDir)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(resolvedCacheDir, "device-123-repo"), localPath)
}

func TestEnsureRepository_RejectsRepoIDEscapingCacheDir(t *testing.T) {
	manager, cacheDir := newContainmentTestManager(t, nil)

	cases := map[string]string{
		// What "device-<targetID>-repo" expands to when the rollback target ID is
		// "a/../../../escaped": the leading segment absorbs the first "..", so an
		// escape needs two more — which a caller is free to supply.
		"derived from a traversing target ID": "device-a/../../../escaped-repo",
		"bare traversal":                      "../../escaped-repo",
	}

	for name, repoID := range cases {
		t.Run(name, func(t *testing.T) {
			// A repository record has to exist for the ID under test, otherwise the
			// lookup fails before the containment check is reached and the test
			// would pass for the wrong reason.
			manager.repositories[repoID] = &Repository{
				ID:       repoID,
				Name:     "escaped-repo",
				CloneURL: "https://example.invalid/escaped-repo.git",
			}

			// GetCommitHistory is the entry point the rollback manager uses, and it
			// reaches ensureRepository with the untrusted ID.
			commits, err := manager.GetCommitHistory(context.Background(), repoID, "", 10)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid repository ID")
			assert.Nil(t, commits)

			// The clone must not have been recorded.
			_, cached := manager.localCache[repoID]
			assert.False(t, cached)
		})
	}

	// Nothing may have been written into or through the cache directory.
	entries, readErr := os.ReadDir(cacheDir)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
}

func TestCreateRepository_RejectsRepositoryIDEscapingCacheDir(t *testing.T) {
	provider := &staticGitProvider{
		repo: &Repository{
			ID:       "../../escaped-repo",
			Name:     "escaped-repo",
			CloneURL: "https://example.invalid/escaped-repo.git",
		},
	}
	manager, cacheDir := newContainmentTestManager(t, provider)

	repo, err := manager.CreateRepository(context.Background(), RepositoryConfig{
		Type:  RepositoryTypeClient,
		Name:  "escaped-repo",
		Owner: "client-1",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid repository ID")
	assert.Nil(t, repo)

	// The remote repository created before the rejection must be cleaned up, and
	// nothing may be cached or written locally.
	assert.Equal(t, []string{"escaped-repo"}, provider.deleted)
	assert.Empty(t, manager.repositories)
	assert.Empty(t, manager.localCache)
	entries, readErr := os.ReadDir(cacheDir)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
}
