// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runReplay(t *testing.T, root string, n string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	code = replayCmd([]string{"-root", root, "-n", n}, &so, &se)
	return code, so.String(), se.String()
}

func commitAll(t *testing.T, root, msg string) {
	t.Helper()
	runGit(t, root, "add", "-A")
	runGit(t, root, "commit", "-q", "-m", msg)
}

// replayRepo has three commits on develop: base, one adding a CC 12 function,
// and one adding a trivial function.
func replayRepo(t *testing.T) string {
	t.Helper()
	root := synthRepo(t, map[string]string{"pkg/a/a.go": "package a\n\nfunc A() {}\n"})
	runGit(t, root, "checkout", "-q", "develop")
	writeFile(t, root, "pkg/a/hot.go", hotFn)
	commitAll(t, root, "add hot (#101)")
	writeFile(t, root, "pkg/a/small.go", "package a\n\nfunc Small() {}\n")
	commitAll(t, root, "add small (#102)")
	return root
}

func TestReplayReportsOnlyHotCommit(t *testing.T) {
	root := replayRepo(t)
	code, stdout, stderr := runReplay(t, root, "2")
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "PRs replayed 2, rule 3 fires on 1, total rule 3 findings 1")
	var hot, small string
	for _, l := range strings.Split(stdout, "\n") {
		if strings.Contains(l, "#101") {
			hot = l
		}
		if strings.Contains(l, "#102") {
			small = l
		}
	}
	assert.Contains(t, hot, "fires")
	assert.Contains(t, small, "pass")
	assert.NotContains(t, small, "fires")
}

func TestReplayDoesNotApplyPartition(t *testing.T) {
	root := replayRepo(t)
	// A directory no manifest segment covers.
	writeFile(t, root, "uncovered/dir/x.go", hotFn)
	commitAll(t, root, "uncovered (#103)")
	code, stdout, stderr := runReplay(t, root, "1")
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "#103")
	assert.Contains(t, stdout, "rule 3 fires on 1")
	assert.NotContains(t, stdout, "unmeasurable:")
}

func TestReplayUnmeasurableNotPass(t *testing.T) {
	root := replayRepo(t)
	writeFile(t, root, "pkg/a/broken.go", "package a\n\nfunc {{{\n")
	commitAll(t, root, "broken (#104)")
	code, stdout, stderr := runReplay(t, root, "1")
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "unmeasurable: ")
	assert.Contains(t, stdout, "unmeasurable 1")
	assert.NotContains(t, stdout, " pass")
}

func TestReplayLeavesWorkingTreeUntouched(t *testing.T) {
	root := replayRepo(t)
	writeFile(t, root, "pkg/a/staged.go", "package a\n")
	runGit(t, root, "add", "pkg/a/staged.go")
	writeFile(t, root, "pkg/a/untracked.txt", "x")
	before := runGit(t, root, "status", "--porcelain=v1")
	head := runGit(t, root, "rev-parse", "HEAD")
	code, _, stderr := runReplay(t, root, "2")
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, before, runGit(t, root, "status", "--porcelain=v1"))
	assert.Equal(t, head, runGit(t, root, "rev-parse", "HEAD"))
}

func TestReplayShallowCloneExitsWithHistoryMessage(t *testing.T) {
	root := replayRepo(t)
	clone := t.TempDir()
	runGit(t, clone, "clone", "-q", "--depth", "1", "file://"+root, "c")
	code, stdout, stderr := runReplay(t, clone+"/c", "2")
	assert.Equal(t, 2, code, stdout)
	assert.Contains(t, stderr, "history too shallow")
}

func TestReplayTooFewCommits(t *testing.T) {
	root := replayRepo(t)
	code, _, stderr := runReplay(t, root, "30")
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "history too shallow")
}
