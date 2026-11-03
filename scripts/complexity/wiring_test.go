// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoFile reads a file relative to the repository root (two levels above this package).
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	require.NoError(t, err, rel)
	return string(b)
}

// jobBlock returns the text of a top-level job in a workflow, from its key to the next job key.
func jobBlock(t *testing.T, workflow, job string) string {
	t.Helper()
	start := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(job) + `:\s*$`).FindStringIndex(workflow)
	require.NotNil(t, start, "job %s not found", job)
	rest := workflow[start[1]:]
	if next := regexp.MustCompile(`(?m)^  [A-Za-z0-9_-]+:\s*$`).FindStringIndex(rest); next != nil {
		rest = rest[:next[0]]
	}
	return rest
}

// The end-to-end failure output for a doctored baseline is covered by TestCheckExitFinding.

func TestWiringMakefileTestCommit(t *testing.T) {
	var line string
	for _, l := range strings.Split(repoFile(t, "Makefile"), "\n") {
		if strings.HasPrefix(l, "test-commit:") && !strings.Contains(l, "export") {
			line = l
		}
	}
	require.NotEmpty(t, line, "test-commit prerequisite line")
	assert.Contains(t, strings.Fields(line), "complexity-check")
}

func TestWiringWorkflowComplexityGate(t *testing.T) {
	wf := repoFile(t, ".github/workflows/test-suite.yml")
	job := jobBlock(t, wf, "complexity-gate")
	assert.Contains(t, job, "github.event_name == 'pull_request'")
	assert.Contains(t, job, "github.event_name == 'merge_group'")
	assert.Contains(t, job, "fetch-depth: 0")
	assert.Contains(t, job, "persist-credentials: false")
	assert.Contains(t, job, "run: make complexity-check")

	agg := jobBlock(t, wf, "unit-tests")
	nStart, nEnd := strings.Index(agg, "needs:"), strings.Index(agg, "if:")
	require.True(t, nStart >= 0 && nEnd > nStart, "unit-tests needs:/if: markers")
	needs := agg[nStart:nEnd]
	assert.Contains(t, needs, "- complexity-gate")

	check := strings.Index(agg, "needs.complexity-gate.result")
	docsOnly := strings.Index(agg, "docs-only PR")
	require.NotEqual(t, -1, check, "result check missing")
	require.NotEqual(t, -1, docsOnly)
	assert.Less(t, check, docsOnly, "result check must precede the docs-only exit")
	assert.Contains(t, agg, `needs.complexity-gate.result }}" != "success"`)
}

func TestWiringProtectedPaths(t *testing.T) {
	assert.Contains(t, repoFile(t, "CODEOWNERS"), "/scripts/complexity/")
	assert.Contains(t, repoFile(t, ".claude/agents/acceptance-reviewer.md"), "scripts/complexity/")
	claude := repoFile(t, "CLAUDE.md")
	assert.Contains(t, claude, "scripts/complexity/manifest.json")
	assert.Contains(t, claude, "scripts/complexity/analyzer/")
}
