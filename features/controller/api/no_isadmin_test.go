// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoIsAdminInGoSource verifies that Principal.IsAdmin has been fully deleted
// from all non-test Go source files. Any hit means a site was missed during the
// migration to principal.Assurance >= session.AssuranceBasic (Issue #2781).
//
// This runs as a CI-runnable check rather than a manual grep step.
func TestNoIsAdminInGoSource(t *testing.T) {
	repoRoot := findRepoRoot(t)

	// grep -rn '\.IsAdmin\b' --include=*.go, then filter out _test.go and docs/.
	cmd := exec.Command("grep", "-rn", `\.IsAdmin\b`, "--include=*.go", repoRoot)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		// grep exits 1 when no matches found — that is the success case.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return // zero hits — correct
		}
		require.NoError(t, err, "grep failed unexpectedly: %s", out.String())
	}

	// grep exited 0 → matches found. Filter out test files and docs/.
	lines := bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n"))
	var violations []string
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		s := string(line)
		if isTestFile(s) || isDocsPath(s) {
			continue
		}
		violations = append(violations, s)
	}

	assert.Empty(t, violations,
		"Principal.IsAdmin must be fully deleted from non-test Go source files (Issue #2781).\n"+
			"Found %d remaining site(s):\n%s",
		len(violations), bytes.Join(func() [][]byte {
			var bs [][]byte
			for _, v := range violations {
				bs = append(bs, []byte("  "+v))
			}
			return bs
		}(), []byte("\n")))
}

// findRepoRoot walks up from the current source file until it finds go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must succeed")

	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod found walking up from test file)")
		}
		dir = parent
	}
}

// isTestFile reports whether the grep output line references a _test.go file.
func isTestFile(line string) bool {
	// grep output format: path/to/file.go:line:match
	for i, c := range line {
		if c == ':' {
			return len(line) >= i && containsTestSuffix(line[:i])
		}
	}
	return false
}

func containsTestSuffix(path string) bool {
	base := filepath.Base(path)
	return len(base) > 8 && base[len(base)-8:] == "_test.go"
}

// isDocsPath reports whether the grep output line refers to a file under docs/.
func isDocsPath(line string) bool {
	for i, c := range line {
		if c == ':' {
			path := line[:i]
			rel := filepath.ToSlash(path)
			// Match both absolute paths containing /docs/ and relative paths starting with docs/
			for j := 0; j < len(rel)-5; j++ {
				if rel[j:j+5] == "/docs" {
					return true
				}
			}
			if len(rel) >= 5 && rel[:5] == "docs/" {
				return true
			}
			return false
		}
	}
	return false
}
