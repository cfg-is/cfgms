// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runGit runs git in dir with a fixed identity and fails the test on error.
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
		"-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Env = gitCleanEnv()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
}

// synthRepo creates a repo whose develop branch holds files, with a feature
// branch checked out.
func synthRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "-q", "-b", "develop")
	for n, b := range files {
		writeFile(t, root, n, b)
	}
	runGit(t, root, "add", "-A")
	runGit(t, root, "commit", "-q", "-m", "base")
	runGit(t, root, "checkout", "-q", "-b", "feature/x")
	return root
}

func TestTouchedFilesCoversCommittedStagedUnstagedUntracked(t *testing.T) {
	root := synthRepo(t, map[string]string{
		"pkg/a.go": "package pkg\n", "pkg/b.go": "package pkg\n", "pkg/c.go": "package pkg\n", "pkg/d.go": "package pkg\n",
	})
	mb, err := MergeBase(root)
	require.NoError(t, err)

	writeFile(t, root, "pkg/a.go", "package pkg\n\nfunc A() {}\n")
	runGit(t, root, "commit", "-q", "-am", "committed")
	writeFile(t, root, "pkg/b.go", "package pkg\n\nfunc B() {}\n")
	runGit(t, root, "add", "pkg/b.go")
	writeFile(t, root, "pkg/c.go", "package pkg\n\nfunc C() {}\n")
	writeFile(t, root, "pkg/new.go", "package pkg\n")

	got, err := TouchedFiles(root, mb)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"pkg/a.go", "pkg/b.go", "pkg/c.go", "pkg/new.go"}, got)
}

func TestMergeBaseFailsClosed(t *testing.T) {
	t.Run("no base ref", func(t *testing.T) {
		root := t.TempDir()
		runGit(t, root, "init", "-q", "-b", "main")
		writeFile(t, root, "a.go", "package a\n")
		runGit(t, root, "add", "-A")
		runGit(t, root, "commit", "-q", "-m", "x")
		_, err := MergeBase(root)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "origin/develop")
	})
	t.Run("shallow clone", func(t *testing.T) {
		src := synthRepo(t, map[string]string{"a.go": "package a\n"})
		writeFile(t, src, "b.go", "package a\n")
		runGit(t, src, "add", "-A")
		runGit(t, src, "commit", "-q", "-m", "more")
		clone := filepath.Join(t.TempDir(), "clone")
		runGit(t, src, "clone", "-q", "--depth", "1", "--branch", "develop", "file://"+src, clone)
		_, err := MergeBase(clone)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "history too shallow to compute merge-base")
	})
}

func TestMaterializeRefLeavesWorktreeAndIndexUnchanged(t *testing.T) {
	root := synthRepo(t, map[string]string{"pkg/a.go": "package pkg\n\nfunc Old() {}\n"})
	writeFile(t, root, "pkg/a.go", "package pkg\n\nfunc New() {}\n")
	writeFile(t, root, "untracked.txt", "u")
	runGit(t, root, "add", "pkg/a.go")
	beforeStatus := runGit(t, root, "status", "--porcelain")
	beforeIndex := runGit(t, root, "ls-files", "-s")

	fsys, cleanup, err := materializeRef(root, "develop")
	require.NoError(t, err)
	defer cleanup()
	b, err := fs.ReadFile(fsys, "pkg/a.go")
	require.NoError(t, err)
	assert.Contains(t, string(b), "Old")
	_, err = fs.Stat(fsys, "untracked.txt")
	assert.Error(t, err)

	assert.Equal(t, beforeStatus, runGit(t, root, "status", "--porcelain"))
	assert.Equal(t, beforeIndex, runGit(t, root, "ls-files", "-s"))
	cur, err := os.ReadFile(filepath.Join(root, "pkg", "a.go"))
	require.NoError(t, err)
	assert.Contains(t, string(cur), "New")
}

func TestMaterializeRefUnknownRef(t *testing.T) {
	root := synthRepo(t, map[string]string{"a.go": "package a\n"})
	_, _, err := materializeRef(root, "no-such-ref")
	assert.Error(t, err)
}

func TestMaterializeRefRejectsOptionLikeRef(t *testing.T) {
	root := synthRepo(t, map[string]string{"a.go": "package a\n"})
	_, _, err := materializeRef(root, "--output=x")
	assert.Error(t, err)
}

// TestGitCallsIgnoreHookEnvironment sets the variables git exports to a hook,
// pointing at a separate repository, and checks the fixtures and production
// helpers neither touch it nor read it.
func TestGitCallsIgnoreHookEnvironment(t *testing.T) {
	calling := t.TempDir()
	runGit(t, calling, "init", "-q", "-b", "main")
	gitDir := filepath.Join(calling, ".git")
	cfgBefore, err := os.ReadFile(filepath.Join(gitDir, "config"))
	require.NoError(t, err)
	t.Setenv("GIT_DIR", gitDir)
	t.Setenv("GIT_WORK_TREE", calling)
	t.Setenv("GIT_INDEX_FILE", filepath.Join(gitDir, "index"))
	t.Setenv("GIT_COMMON_DIR", gitDir)

	root := synthRepo(t, map[string]string{"pkg/a.go": "package pkg\n"})
	mb, err := MergeBase(root)
	require.NoError(t, err)
	assert.Equal(t, runGit(t, root, "rev-parse", "develop"), mb)
	_, err = TouchedFiles(root, mb)
	require.NoError(t, err)

	cfgAfter, err := os.ReadFile(filepath.Join(gitDir, "config"))
	require.NoError(t, err)
	assert.Equal(t, string(cfgBefore), string(cfgAfter))
	_, err = os.Stat(filepath.Join(gitDir, "index"))
	assert.True(t, os.IsNotExist(err), "calling repository index must not be created")
}
