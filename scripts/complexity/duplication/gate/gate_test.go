// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package gate

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/scripts/complexity/duplication/detector"
)

const k = 10

// pool holds structurally distinct statements so a block never clones itself.
var pool = []string{
	"a = b + c * 1",
	"if a < b { c++ }",
	"for i := range b { c = append(c, i) }",
	"switch a { case 1: b = 2 }",
	"go f(a, b)",
	"defer g(c)",
	"x, y := <-ch, a[1:2]",
	"return &T{A: 1, B: \"s\"}",
	"m[a] = func() int { return 3 }",
	"select { case v := <-ch: _ = v }",
	"a.b.c = d.e(f)[g]",
	"for a < 5 { a += 2 }",
}

// src builds a Go file whose function body holds the given pool statements,
// one per line, followed by the extra lines.
func src(stmts []int, extra ...string) string {
	var b strings.Builder
	b.WriteString("package p\n\nfunc F() {\n")
	for _, i := range stmts {
		b.WriteString("\t" + pool[i] + "\n")
	}
	for _, e := range extra {
		b.WriteString("\t" + e + "\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func seq(from, to int) []int {
	var s []int
	for i := from; i < to; i++ {
		s = append(s, i)
	}
	return s
}

func detect(t *testing.T, files map[string]string) detector.Result {
	t.Helper()
	var fs []detector.File
	for p, s := range files {
		fs = append(fs, detector.File{Path: p, Src: []byte(s)})
	}
	r, err := detector.Detect(fs, k)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func strs(r Result) []string {
	out := []string{}
	for _, f := range r.Findings {
		out = append(out, f.String())
	}
	return out
}

func rules(r Result) []int {
	out := []int{}
	for _, f := range r.Findings {
		out = append(out, f.Rule)
	}
	return out
}

func expectRules(t *testing.T, got Result, want ...int) {
	t.Helper()
	if want == nil {
		want = []int{}
	}
	if !reflect.DeepEqual(rules(got), want) {
		t.Fatalf("rules = %v, want %v; findings: %v", rules(got), want, strs(got))
	}
}

var both = []string{"a.go", "b.go"}

func TestRule1PureReflowFiresOnlyRule1(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	// Break lines after commas and binary operators: no semicolon is inserted,
	// so the token stream is unchanged.
	reflow := strings.ReplaceAll(src(seq(0, 6)), ", ", ",\n\t\t")
	reflow = strings.ReplaceAll(reflow, " + ", " +\n\t\t")
	cur := detect(t, map[string]string{"a.go": reflow, "b.go": reflow})
	if cur.DuplicatedLines <= prev.DuplicatedLines {
		t.Fatalf("fixture invalid: lines %d -> %d", prev.DuplicatedLines, cur.DuplicatedLines)
	}
	got := Evaluate(prev, cur, both)
	expectRules(t, got, 1)
	want := fmt.Sprintf("aggregate: rule 1: duplicated lines %d -> %d", prev.DuplicatedLines, cur.DuplicatedLines)
	if strs(got)[0] != want {
		t.Fatalf("got %q want %q", strs(got)[0], want)
	}
}

func TestRule2NewCopy(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(6, 12))})
	cur := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	got := Evaluate(prev, cur, []string{"b.go"})
	expectRules(t, got, 1, 2)
	if f := got.Findings[1]; f.File != "b.go" {
		t.Fatalf("finding %v", f)
	}
	// An untouched file is not flagged by rule 2.
	expectRules(t, Evaluate(prev, cur, nil), 1)
}

func TestRule3aThirdCopy(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6)), "c.go": src(seq(6, 12))})
	cur := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6)), "c.go": src(seq(0, 6))})
	got := Evaluate(prev, cur, []string{"c.go"})
	expectRules(t, got, 1, 3)
	if got.Findings[1].File != "c.go" {
		t.Fatalf("finding %v", got.Findings[1])
	}
	// Rule 3 also holds when only the pre-existing copies are touched.
	expectRules(t, Evaluate(prev, cur, []string{"a.go"}), 1, 3)
}

func TestRule3bBothCopiesExtended(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	cur := detect(t, map[string]string{"a.go": src(seq(0, 7)), "b.go": src(seq(0, 7))})
	got := Evaluate(prev, cur, both)
	expectRules(t, got, 1, 3, 3)
	if got.Findings[1].File != "a.go" || got.Findings[2].File != "b.go" {
		t.Fatalf("findings %v", strs(got))
	}
}

func TestRule3bFillingGapMergesRuns(t *testing.T) {
	// Two shared segments separated by a differing line become one longer run.
	mk := func(mid string) string {
		head := strings.TrimSuffix(src(seq(0, 5)), "}\n")
		tail := strings.TrimPrefix(src(seq(6, 11)), "package p\n\nfunc F() {\n")
		return head + "\t" + mid + "\n" + tail
	}
	prev := detect(t, map[string]string{"a.go": mk("p = 1"), "b.go": mk("q = 2 + 3")})
	cur := detect(t, map[string]string{"a.go": mk("p = 1"), "b.go": mk("p = 1")})
	if len(prev.Runs) != 4 || len(cur.Runs) != 2 {
		t.Fatalf("fixture invalid: runs %d -> %d", len(prev.Runs), len(cur.Runs))
	}
	got := Evaluate(prev, cur, []string{"b.go"})
	expectRules(t, got, 3)
	if got.Findings[0].File != "b.go" {
		t.Fatalf("finding %v", got.Findings[0])
	}
}

func TestInvalidAnnotationTreatedAsUnannotated(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(6, 12))})
	for name, ann := range map[string]string{
		"empty reason":       "//duplication:justified a.go --\n",
		"path not in bucket": "//duplication:justified c.go -- why\n",
	} {
		t.Run(name, func(t *testing.T) {
			cur := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": ann + src(seq(0, 6)), "c.go": src(seq(6, 12))})
			if len(cur.InvalidAnnotations) != 1 {
				t.Fatalf("fixture invalid: %v", cur.InvalidAnnotations)
			}
			got := Evaluate(prev, cur, []string{"b.go"})
			expectRules(t, got, 1, 2)
		})
	}
}

func TestInvalidAnnotationWithoutNewDuplicationIsClean(t *testing.T) {
	files := map[string]string{
		"a.go": src(seq(0, 6)),
		"b.go": "//duplication:justified c.go -- why\n" + src(seq(0, 6)),
	}
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(0, 6))})
	cur := detect(t, files)
	if len(cur.InvalidAnnotations) != 1 {
		t.Fatalf("fixture invalid: %v", cur.InvalidAnnotations)
	}
	expectRules(t, Evaluate(prev, cur, both))
}

func TestValidAnnotationOnNewCopyIsClean(t *testing.T) {
	prev := detect(t, map[string]string{"a.go": src(seq(0, 6)), "b.go": src(seq(6, 12))})
	cur := detect(t, map[string]string{
		"a.go": src(seq(0, 6)),
		"b.go": "//duplication:justified a.go -- generated mirror\n" + src(seq(0, 6)),
	})
	if len(cur.InvalidAnnotations) != 0 || len(cur.Runs) != 0 || cur.AnnotatedLines == 0 {
		t.Fatalf("fixture invalid: runs %d invalid %v", len(cur.Runs), cur.InvalidAnnotations)
	}
	expectRules(t, Evaluate(prev, cur, both))
}
