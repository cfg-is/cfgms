// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// dupCheckThreshold keeps the synthetic clones small.
const dupCheckThreshold = "20"

// stmtBody is a function of n token-bearing statements. With reflow every
// statement spans one line per term but yields the same tokens.
func stmtBody(name string, n int, reflow bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package p\n\nfunc %s(x int) int {\n", name)
	// Operators come from a fixed-seed generator, so a body never duplicates
	// itself and every call yields the same prefix of statements.
	rng := rand.New(rand.NewSource(1)) // #nosec G404 -- deterministic test fixture
	ops := []string{"+", "-", "*", "&", "|", "^"}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\tx = x")
		for j := 0; j < 6; j++ {
			op := ops[rng.Intn(len(ops))]
			if reflow {
				fmt.Fprintf(&b, " %s\n\t\tx", op)
			} else {
				fmt.Fprintf(&b, " %s x", op)
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("\treturn x\n}\n")
	return b.String()
}

// dupRepo is a synthetic repo whose develop base holds the given files.
func dupRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	return synthRepo(t, files)
}

func commitDupChange(t *testing.T, root string) {
	t.Helper()
	runGit(t, root, "add", "-A")
	runGit(t, root, "commit", "-q", "-m", "change")
}

func runDupCheck(t *testing.T, root string) (int, string, string) {
	t.Helper()
	var so, se bytes.Buffer
	code := duplicationCmd([]string{"check", "-root", root, "-threshold", dupCheckThreshold}, &so, &se)
	return code, so.String(), se.String()
}

func findingLines(stdout string, substr string) int {
	n := 0
	for _, l := range strings.Split(stdout, "\n") {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

func TestDuplicationCheckNewCopyFiresRules1And2(t *testing.T) {
	root := dupRepo(t, map[string]string{"pkg/a/a.go": stmtBody("F", 12, false)})
	writeFile(t, root, "pkg/b/b.go", stmtBody("G", 12, false))
	commitDupChange(t, root)
	code, stdout, stderr := runDupCheck(t, root)
	assert.Equal(t, 1, code, stdout+stderr)
	assert.Equal(t, 1, findingLines(stdout, "rule 1:"), stdout)
	assert.Equal(t, 1, findingLines(stdout, "rule 2:"), stdout)
	assert.Equal(t, 0, findingLines(stdout, "rule 3:"), stdout)
	assert.NotContains(t, stdout, "duplication gate: pass")
}

func TestDuplicationCheckGrowingExistingCloneFiresRule3(t *testing.T) {
	root := dupRepo(t, map[string]string{
		"pkg/a/a.go": stmtBody("F", 12, false),
		"pkg/b/b.go": stmtBody("G", 13, false),
	})
	writeFile(t, root, "pkg/a/a.go", stmtBody("F", 13, false))
	commitDupChange(t, root)
	code, stdout, stderr := runDupCheck(t, root)
	assert.Equal(t, 1, code, stdout+stderr)
	assert.Equal(t, 1, findingLines(stdout, "pkg/a/a.go:"), stdout)
	assert.Contains(t, stdout, "rule 3: ")
	assert.Equal(t, 0, findingLines(stdout, "rule 2:"), stdout)
}

func TestDuplicationCheckPureReflowFiresRule1Only(t *testing.T) {
	root := dupRepo(t, map[string]string{
		"pkg/a/a.go": stmtBody("F", 12, false),
		"pkg/b/b.go": stmtBody("G", 12, false),
	})
	writeFile(t, root, "pkg/a/a.go", stmtBody("F", 12, true))
	commitDupChange(t, root)
	code, stdout, stderr := runDupCheck(t, root)
	assert.Equal(t, 1, code, stdout+stderr)
	assert.Equal(t, 1, findingLines(stdout, "rule 1:"), stdout)
	assert.Equal(t, 0, findingLines(stdout, "rule 2:"), stdout)
	assert.Equal(t, 0, findingLines(stdout, "rule 3:"), stdout)
}

func TestDuplicationCheckIdenticalToMergeBasePasses(t *testing.T) {
	root := dupRepo(t, map[string]string{
		"pkg/a/a.go": stmtBody("F", 12, false),
		"pkg/b/b.go": stmtBody("G", 12, false),
	})
	code, stdout, stderr := runDupCheck(t, root)
	assert.Equal(t, 0, code, stdout+stderr)
	assert.Equal(t, "duplication gate: pass\n", stdout)
}

func TestDuplicationCheckAnnotations(t *testing.T) {
	base := map[string]string{"pkg/a/a.go": stmtBody("F", 12, false)}
	annotated := func(target string) string {
		src := stmtBody("G", 12, false)
		return strings.Replace(src, "func G", "//duplication:justified "+target+" -- deliberate build boundary\nfunc G", 1)
	}

	t.Run("valid annotation passes", func(t *testing.T) {
		root := dupRepo(t, base)
		writeFile(t, root, "pkg/b/b.go", annotated("pkg/a/a.go"))
		commitDupChange(t, root)
		code, stdout, stderr := runDupCheck(t, root)
		assert.Equal(t, 0, code, stdout+stderr)
		assert.Contains(t, stdout, "duplication gate: pass")
	})

	t.Run("invalid annotation on a new copy fails and is printed", func(t *testing.T) {
		root := dupRepo(t, base)
		writeFile(t, root, "pkg/b/b.go", annotated("pkg/missing.go"))
		commitDupChange(t, root)
		code, stdout, stderr := runDupCheck(t, root)
		assert.Equal(t, 1, code, stdout+stderr)
		assert.Equal(t, 1, findingLines(stdout, "rule 1:"), stdout)
		assert.Equal(t, 1, findingLines(stdout, "rule 2:"), stdout)
		assert.Contains(t, stdout, "invalid annotation: pkg/b/b.go:3: ")
	})

	t.Run("invalid annotation adding no duplication passes", func(t *testing.T) {
		root := dupRepo(t, base)
		writeFile(t, root, "pkg/c/c.go", "package p\n\n//duplication:justified pkg/missing.go -- nothing here\nfunc H() {}\n")
		commitDupChange(t, root)
		code, stdout, stderr := runDupCheck(t, root)
		assert.Equal(t, 0, code, stdout+stderr)
		assert.Contains(t, stdout, "duplication gate: pass")
	})
}

func TestDuplicationCheckExitsTwoOnShallowClone(t *testing.T) {
	root := dupRepo(t, map[string]string{"pkg/a/a.go": stmtBody("F", 12, false)})
	clone := filepath.Join(t.TempDir(), "clone")
	runGit(t, root, "clone", "-q", "--depth", "1", "--branch", "develop", "file://"+root, clone)
	code, _, stderr := runDupCheck(t, clone)
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "history too shallow to compute merge-base")
}

func TestDuplicationCheckBadFlag(t *testing.T) {
	var so, se bytes.Buffer
	assert.Equal(t, 2, duplicationCmd([]string{"check", "-nope"}, &so, &se))
}
