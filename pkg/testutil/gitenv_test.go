// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snapshotRepo records config, index and hooks/ of a git dir byte for byte.
func snapshotRepo(t *testing.T, gitDir string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	for _, name := range []string{"config", "index"} {
		b, err := os.ReadFile(filepath.Join(gitDir, name))
		if err == nil {
			snap[name] = string(b)
		} else {
			snap[name] = "<absent>"
		}
	}
	require.NoError(t, filepath.Walk(filepath.Join(gitDir, "hooks"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		require.NoError(t, rerr)
		rel, _ := filepath.Rel(gitDir, p)
		snap[rel] = string(b)
		return nil
	}))
	return snap
}

// sentinelEnv points the process at a sentinel repository the way git does for a hook.
func sentinelEnv(t *testing.T) (gitDir string) {
	t.Helper()
	sentinel := t.TempDir()
	out, err := exec.Command("git", "init", "-q", sentinel).CombinedOutput() // #nosec G204 -- fixed args
	require.NoError(t, err, string(out))
	gitDir = filepath.Join(sentinel, ".git")
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "index"), []byte("sentinel-index"), 0o600))
	t.Setenv("GIT_DIR", gitDir)
	t.Setenv("GIT_INDEX_FILE", filepath.Join(gitDir, "index"))
	t.Setenv("GIT_WORK_TREE", sentinel)
	return gitDir
}

func TestGitEnv_DropsRepositoryVariablesAndIsolatesConfig(t *testing.T) {
	sentinelEnv(t)
	home := t.TempDir()
	env := strings.Join(GitEnv(home), "\n")
	for _, n := range []string{"GIT_DIR=", "GIT_INDEX_FILE=", "GIT_WORK_TREE="} {
		assert.NotContains(t, "\n"+env, "\n"+n)
	}
	assert.Contains(t, env, "GIT_CONFIG_NOSYSTEM=1")
	assert.Contains(t, env, "HOME="+home)
	assert.Contains(t, env, "GIT_CONFIG_GLOBAL="+filepath.Join(home, ".gitconfig"))
}

func TestGitCommand_DoesNotTouchCallingRepository(t *testing.T) {
	gitDir := sentinelEnv(t)
	before := snapshotRepo(t, gitDir)

	work := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "core.bare", "false"},
		{"commit", "-q", "--allow-empty", "-m", "x"},
	} {
		out, err := GitCommand(t, work, args...).CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	require.DirExists(t, filepath.Join(work, ".git"))
	assert.Equal(t, before, snapshotRepo(t, gitDir), "sentinel repository changed")
}

func TestIsolateGitEnv_ProtectsProductionGitCalls(t *testing.T) {
	gitDir := sentinelEnv(t)
	before := snapshotRepo(t, gitDir)

	IsolateGitEnv(t)
	assert.Empty(t, os.Getenv("GIT_DIR"))
	assert.Empty(t, os.Getenv("GIT_INDEX_FILE"))

	work := t.TempDir()
	// A bare command, as production code runs it: inherits the process environment.
	cmd := exec.Command("git", "init", "-q") // #nosec G204 -- fixed args
	cmd.Dir = work
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	cmd = exec.Command("git", "config", "--global", "user.name", "test") // #nosec G204 -- fixed args
	cmd.Dir = work
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, before, snapshotRepo(t, gitDir), "sentinel repository changed")
}

func TestGitFixtureHelpers_DoNotTouchCallingRepository(t *testing.T) {
	gitDir := sentinelEnv(t)
	before := snapshotRepo(t, gitDir)

	// The resolver test setup path: a signed bundle committed to a repo, plus a served repo.
	sb := NewSignedBundle(t, BundleOptions{Publisher: "cfgms", Name: "m", Version: "1.0.0"})
	repo := filepath.Join(t.TempDir(), "m")
	sb.CommitToRepo(t, repo)
	out, err := GitCommand(t, "", "-C", repo, "tag", "1.0.0").CombinedOutput()
	require.NoError(t, err, string(out))
	NewGitServer(t, filepath.Dir(repo))

	assert.Equal(t, before, snapshotRepo(t, gitDir), "sentinel repository changed")
}
