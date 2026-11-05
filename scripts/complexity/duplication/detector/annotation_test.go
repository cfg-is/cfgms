// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package detector

import "testing"

func TestParseAnnotations(t *testing.T) {
	got := parseAnnotations([]comment{
		{1, "//duplication:justified a/b.go -- twin of the generator"},
		{2, "//duplication:justified a/b.go --"},
		{3, "//duplication:justified a/b.go reason"},
		{4, "//duplication:justified"},
		{5, "//duplication:justifiedx a.go -- r"},
		{6, "// ordinary comment"},
		{7, "/* duplication:justified a.go -- r */"},
	})
	if len(got) != 4 {
		t.Fatalf("got %d annotations: %+v", len(got), got)
	}
	if got[0].err != "" || got[0].path != "a/b.go" || got[0].reason != "twin of the generator" {
		t.Errorf("valid parsed wrong: %+v", got[0])
	}
	if got[1].err != "empty reason" {
		t.Errorf("empty reason: %+v", got[1])
	}
	if got[2].err == "" || got[3].err == "" {
		t.Errorf("malformed accepted: %+v %+v", got[2], got[3])
	}
}

func TestAttachRun(t *testing.T) {
	runs := []runSpan{{startLine: 10, endLine: 20}, {startLine: 24, endLine: 30}, {startLine: 22, endLine: 23}}
	for _, c := range []struct{ line, want int }{
		{15, 0}, {10, 0}, {20, 0}, {21, 2}, {19 + 0, 0}, {9, 0}, {7, 0}, {6, -1}, {27, 1}, {35, -1},
	} {
		if got := attachRun(runs, c.line); got != c.want {
			t.Errorf("attachRun(%d) = %d, want %d", c.line, got, c.want)
		}
	}
}
