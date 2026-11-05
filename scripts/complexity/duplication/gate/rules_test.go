// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package gate

import (
	"strings"
	"testing"
)

// Cases the rules deliberately allow. Each has its own test.

func TestAllowedIdenticalPreviousAndCurrent(t *testing.T) {
	files := map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))}
	expectRules(t, Evaluate(detect(t, files), detect(t, files), both))
}

func TestAllowedDivergentEditToOneCopy(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	// Replacing the middle statement of one copy splits (shrinks) the clone.
	edited := src([]int{0, 1, 2, 11, 4, 5})
	cur := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": edited})
	expectRules(t, Evaluate(prev, cur, both))
}

func TestAllowedIdenticalEditToBothCopies(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	edited := strings.Replace(src(seq(0, 6)), "defer g(c)", "go g(c)", 1)
	cur := detect(t, map[string]string{"a.go": edited, "b.go": edited})
	if len(cur.Runs) == 0 {
		t.Fatal("fixture invalid: no clone left")
	}
	expectRules(t, Evaluate(prev, cur, both))
}

func TestAllowedCloneMovedToAnotherFile(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	cur := detect(t, map[string]string{"a.go": src(seq(0, 6)), "c.go": src(seq(0, 6))})
	expectRules(t, Evaluate(prev, cur, []string{"b.go", "c.go"}))
}

func TestAllowedRenamedFile(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	cur := detect(t, map[string]string{"a.go": src(seq(0, 6)), "renamed.go": src(seq(0, 6))})
	expectRules(t, Evaluate(prev, cur, []string{"renamed.go"}))
}

func TestAllowedCommentAddedInsideClone(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	commented := strings.Replace(src(seq(0, 6)), "\tgo f(a, b)\n", "\t// note\n\tgo f(a, b)\n", 1)
	cur := detect(t, map[string]string{"a.go": commented, "b.go": commented})
	expectRules(t, Evaluate(prev, cur, both))
}

func TestAllowedBlankLineAdded(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	spaced := strings.Replace(src(seq(0, 6)), "\tgo f(a, b)\n", "\n\tgo f(a, b)\n", 1)
	cur := detect(t, map[string]string{"a.go": spaced, "b.go": spaced})
	expectRules(t, Evaluate(prev, cur, both))
}

func TestAllowedGrowthInUntouchedFile(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	cur := detect(t, map[string]string{"a.go": src(seq(0, 7)), "b.go": src(seq(0, 7))})
	// Rule 1 still reports the aggregate; no per-run rule fires off the touched list.
	got := Evaluate(prev, cur, []string{"unrelated.go"})
	for _, f := range got.Findings {
		if f.Rule != 1 {
			t.Fatalf("unexpected finding %v", f)
		}
	}
}

func TestFindingsSortedDeterministic(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	cur := detect(t, map[string]string{"a.go": src(seq(0, 7)), "b.go": src(seq(0, 7))})
	first := strs(Evaluate(prev, cur, []string{"b.go", "a.go"}))
	second := strs(Evaluate(prev, cur, []string{"a.go", "b.go"}))
	if strings.Join(first, "\n") != strings.Join(second, "\n") {
		t.Fatalf("%v != %v", first, second)
	}
}

func TestBackslashTouchedPaths(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "pkg/b.go": src(seq(6, 12))})
	cur := detect(t, map[string]string{"a.go": src(seq(0, 6)), "pkg/b.go": src(seq(0, 6))})
	expectRules(t, Evaluate(prev, cur, []string{`pkg\b.go`}), 1, 2)
}
