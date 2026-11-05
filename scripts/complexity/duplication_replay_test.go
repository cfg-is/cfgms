// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runDupReplay(t *testing.T, root string, n int, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{"replay", "-root", root, "-n", strconv.Itoa(n), "-threshold", dupCheckThreshold}, extra...)
	var so, se bytes.Buffer
	code := duplicationCmd(args, &so, &se)
	return code, so.String(), se.String()
}

func dupReplayRepo(t *testing.T) string {
	t.Helper()
	root := dupRepo(t, map[string]string{"pkg/a/a.go": stmtBody("Alpha", 12, false)})
	runGit(t, root, "checkout", "-q", "develop")
	writeFile(t, root, "pkg/b/b.go", stmtBody("Beta", 12, false))
	commitAll(t, root, "add copy (#201)")
	writeFile(t, root, "docs/note.md", "# note\n")
	commitAll(t, root, "docs only (#202)")
	return root
}

func lineWith(out, needle string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

func TestDuplicationReplayCopyFiresRules1And2DocsPass(t *testing.T) {
	root := dupReplayRepo(t)
	code, stdout, stderr := runDupReplay(t, root, 2)
	require.Equal(t, 0, code, stderr)
	copyLine := lineWith(stdout, "#201")
	assert.Contains(t, copyLine, "fires")
	assert.Contains(t, stdout, "rule 1 on 1, rule 2 on 1, rule 3 on 0")
	assert.Contains(t, stdout, "fires on 1 (50.0%)")
	assert.Contains(t, lineWith(stdout, "#202"), "pass")
	// Both copies of the firing are recorded as file:line ranges.
	assert.Contains(t, stdout, "pkg/a/a.go:")
	assert.Contains(t, stdout, "pkg/b/b.go:")
	assert.Contains(t, stdout, "copies")
}

func TestDuplicationReplayShallowFailsClosed(t *testing.T) {
	root := dupReplayRepo(t)
	clone := t.TempDir()
	runGit(t, clone, "clone", "-q", "--depth", "1", "file://"+root, "c")
	code, stdout, stderr := runDupReplay(t, clone+"/c", 2)
	assert.Equal(t, 2, code, stdout)
	assert.Contains(t, stderr, "history too shallow")
}

func TestDuplicationReplayTooFewCommits(t *testing.T) {
	code, _, stderr := runDupReplay(t, dupReplayRepo(t), 30)
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "history too shallow")
}

func TestDuplicationReplayBaseline(t *testing.T) {
	root := dupReplayRepo(t)
	head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	code, stdout, stderr := runDupReplay(t, root, 2, "-baseline", head)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "baseline "+head)
	assert.Contains(t, stdout, "pkg/a")
	assert.Contains(t, stdout, "pkg/b")

	code, _, stderr = runDupReplay(t, root, 2, "-baseline", "0000000000000000000000000000000000000000")
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "history too shallow")
}

func TestDuplicationReplayLeavesWorkingTreeUntouched(t *testing.T) {
	root := dupReplayRepo(t)
	writeFile(t, root, "pkg/a/untracked.txt", "x")
	before := runGit(t, root, "status", "--porcelain=v1")
	code, _, stderr := runDupReplay(t, root, 2)
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, before, runGit(t, root, "status", "--porcelain=v1"))
}
