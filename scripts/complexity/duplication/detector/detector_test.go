// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package detector

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const testK = 30

func TestThresholdBelowTwoErrors(t *testing.T) {
	for _, k := range []int{-1, 0, 1} {
		if _, err := Detect(nil, k); err == nil {
			t.Errorf("threshold %d: want error", k)
		}
	}
}

// TestDefaultThresholdMatchesCalibrationDoc keeps the constant equal to the
// number the calibration record states and justifies.
func TestDefaultThresholdMatchesCalibrationDoc(t *testing.T) {
	doc, err := os.ReadFile("../../../../docs/development/duplication-gate-calibration.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("`detector.DefaultThreshold` is (\\d+)").FindSubmatch(doc)
	if m == nil {
		t.Fatal("calibration doc does not state detector.DefaultThreshold")
	}
	want, _ := strconv.Atoi(string(m[1]))
	if DefaultThreshold != want {
		t.Fatalf("DefaultThreshold = %d, calibration doc states %d", DefaultThreshold, want)
	}
}

func TestRenamedIdentifiersAndLiteralsFormOneRun(t *testing.T) {
	a := File{"a.go", src(fn("alpha", 1, 12))}
	b := File{"b.go", src(fn("beta", 900, 12))}
	r := mustDetect(t, []File{a, b}, testK)
	if len(r.Runs) != 2 {
		t.Fatalf("runs = %d, want 2: %+v", len(r.Runs), r.Runs)
	}
	for _, run := range r.Runs {
		if run.Tokens != len(tokenize("x", a.Src).kinds) {
			t.Errorf("run covers %d tokens, want whole file", run.Tokens)
		}
		if len(run.Windows) != run.Tokens-testK+1 {
			t.Errorf("windows = %d, tokens = %d", len(run.Windows), run.Tokens)
		}
	}
	if r.DuplicatedLines == 0 {
		t.Fatal("no duplicated lines")
	}
}

func TestOperatorOrKeywordDifferenceBreaksClone(t *testing.T) {
	base := fn("f", 1, 12)
	edits := map[string]func(string) string{
		"operator": func(l string) string { return strings.Replace(l, " = ", " += ", 1) },
		"keyword":  func(l string) string { return "go " + strings.TrimSpace(l) },
	}
	const diffLine = 11 // statement 6 of the body, after the 4-line header and func line
	for name, edit := range edits {
		lines := strings.Split(base, "\n")
		lines[6] = edit(lines[6])
		diff := strings.Join(lines, "\n")
		r := mustDetect(t, []File{{"a.go", src(base)}, {"b.go", src(diff)}}, testK)
		if len(r.Runs) == 0 {
			t.Fatalf("%s: expected clones on both sides of the difference", name)
		}
		for _, run := range r.Runs {
			if run.StartLine < diffLine && run.EndLine > diffLine {
				t.Fatalf("%s: clone spans the difference: lines %d-%d", name, run.StartLine, run.EndLine)
			}
		}
	}
}

func TestThresholdBoundary(t *testing.T) {
	// find n so that the function body has exactly testK tokens after the shared header.
	for n := 1; n < 20; n++ {
		a := File{"a.go", src(fn("f", 1, n))}
		total := len(tokenize("a.go", a.Src).kinds)
		if total != testK {
			continue
		}
		b := File{"b.go", src(fn("g", 2, n))}
		if r := mustDetect(t, []File{a, b}, testK); len(r.Runs) != 2 || r.Runs[0].Tokens != testK {
			t.Fatalf("exactly threshold: %+v", r.Runs)
		}
		if r := mustDetect(t, []File{a, b}, testK+1); len(r.Runs) != 0 {
			t.Fatalf("below threshold reported: %+v", r.Runs)
		}
		return
	}
	// token count per statement is not a divisor of testK: use the derived K instead.
	a := File{"a.go", src(fn("f", 1, 4))}
	b := File{"b.go", src(fn("g", 2, 4))}
	total := len(tokenize("a.go", a.Src).kinds)
	if r := mustDetect(t, []File{a, b}, total); len(r.Runs) != 2 {
		t.Fatalf("exactly threshold not reported: %+v", r.Runs)
	}
	if r := mustDetect(t, []File{a, b}, total+1); len(r.Runs) != 0 {
		t.Fatalf("below threshold reported: %+v", r.Runs)
	}
}

func TestHeadersAloneProduceNoRun(t *testing.T) {
	hdr := "package p\n\nimport (\n" + strings.Repeat("\t\"fmt\"\n", 60) + ")\n"
	r := mustDetect(t, []File{{"a.go", []byte(hdr)}, {"b.go", []byte(hdr)}}, 5)
	if len(r.Runs) != 0 || r.DuplicatedLines != 0 {
		t.Fatalf("header-only clone: %+v", r)
	}
}

func TestThreeCopiesCountedOncePerLine(t *testing.T) {
	body := fn("f", 1, 12)
	files := []File{{"a.go", src(body)}, {"b.go", src(body)}, {"c.go", src(body)}}
	r := mustDetect(t, files, testK)
	if len(r.Runs) != 3 {
		t.Fatalf("runs = %d", len(r.Runs))
	}
	if want := 14; r.DuplicatedLines != 3*want { // 12 statements + func line + closing brace, per file
		t.Fatalf("DuplicatedLines = %d, want %d", r.DuplicatedLines, 3*want)
	}
	for h, m := range r.Mult {
		if m != 3 {
			t.Fatalf("Mult[%x] = %d, want 3", h, m)
		}
	}
	if len(r.Mult) == 0 {
		t.Fatal("empty Mult")
	}
}

func TestHashCollisionIsNotAClone(t *testing.T) {
	old := windowHashMask
	windowHashMask = 0
	t.Cleanup(func() { windowHashMask = old })
	a := File{"a.go", []byte("package p\nfunc f() { a = 1 + 2 * 3 - 4 }\n")}
	b := File{"b.go", []byte("package p\ntype T struct { A int; B string; C float64 }\n")}
	r := mustDetect(t, []File{a, b}, 8)
	if len(r.Runs) != 0 || len(r.Mult) != 0 {
		t.Fatalf("collision produced clone: %+v", r)
	}
	// Equal content still clones under the weak hash.
	r = mustDetect(t, []File{a, {"c.go", a.Src}}, 8)
	if len(r.Runs) != 2 {
		t.Fatalf("true clone lost under weak hash: %+v", r.Runs)
	}
}

func TestRepetitiveSingleFileNotCloneOfItself(t *testing.T) {
	s := "package p\nfunc f() {\n" + strings.Repeat("a;", 20) + "\n}\n"
	r := mustDetect(t, []File{{"a.go", []byte(s)}}, 40)
	if len(r.Runs) != 0 || r.DuplicatedLines != 0 {
		t.Fatalf("self clone: %+v", r)
	}
}

func TestBlankAndCommentLinesDoNotChangeDuplicatedLines(t *testing.T) {
	a := File{"a.go", src(fn("f", 1, 12))}
	b := File{"b.go", src(fn("g", 2, 12))}
	base := mustDetect(t, []File{a, b}, testK)
	padded := strings.ReplaceAll(string(b.Src), "\n\t", "\n\n// note\n\t")
	r := mustDetect(t, []File{a, {"b.go", []byte(padded)}}, testK)
	if r.DuplicatedLines != base.DuplicatedLines {
		t.Fatalf("DuplicatedLines = %d, want %d", r.DuplicatedLines, base.DuplicatedLines)
	}
}

func annotated(path, reason string, body string) []byte {
	return src(fmt.Sprintf("//duplication:justified %s -- %s\n%s", path, reason, body))
}

func TestAnnotations(t *testing.T) {
	body := fn("f", 1, 12)
	plain := File{"b.go", src(fn("g", 2, 12))}
	cases := []struct {
		name        string
		src         []byte
		wantInvalid string // substring; empty means valid
	}{
		{"valid from above", annotated("b.go", "generated twin", body), ""},
		{"empty reason", src("//duplication:justified b.go --\n" + body), "empty reason"},
		{"path not in bucket", annotated("zzz.go", "why", body), "not a duplicate partner"},
		{"own path only", annotated("a.go", "why", body), "not a duplicate partner"},
		{"malformed", src("//duplication:justified b.go because\n" + body), "malformed"},
		{"unattachable", src("//duplication:justified b.go -- far\n\n\n\n\n" + body), "attaches to no clone run"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := mustDetect(t, []File{{"a.go", c.src}, plain}, testK)
			if c.wantInvalid == "" {
				if len(r.InvalidAnnotations) != 0 {
					t.Fatalf("invalid: %+v", r.InvalidAnnotations)
				}
				// a.go's run is exempt; b.go loses its only partner.
				if len(r.Runs) != 0 || len(r.Mult) != 0 || r.DuplicatedLines != 0 {
					t.Fatalf("annotated run still counted: %+v", r)
				}
				if r.AnnotatedLines == 0 {
					t.Fatal("AnnotatedLines = 0")
				}
				return
			}
			if len(r.InvalidAnnotations) != 1 || !strings.Contains(r.InvalidAnnotations[0].Reason, c.wantInvalid) {
				t.Fatalf("invalid = %+v, want %q", r.InvalidAnnotations, c.wantInvalid)
			}
			if r.AnnotatedLines != 0 {
				t.Fatalf("invalid annotation exempted lines: %d", r.AnnotatedLines)
			}
			if strings.Contains(c.name, "path") || c.name == "empty reason" || c.name == "malformed" || c.name == "unattachable" {
				if len(r.Runs) != 2 {
					t.Fatalf("invalid annotation must exempt nothing: %+v", r.Runs)
				}
			}
		})
	}
}

func TestAnnotationAttachmentByContainmentAndDistance(t *testing.T) {
	body := fn("f", 1, 12)
	lines := strings.Split(body, "\n")
	inside := strings.Join(lines[:6], "\n") + "\n//duplication:justified b.go -- inside\n" + strings.Join(lines[6:], "\n")
	b := File{"b.go", src(fn("g", 2, 12))}
	r := mustDetect(t, []File{{"a.go", src(inside)}, b}, testK)
	if len(r.InvalidAnnotations) != 0 || r.AnnotatedLines == 0 || len(r.Runs) != 0 {
		t.Fatalf("containment: %+v", r)
	}
	// 3 lines above (two blank lines between) attaches; 4 does not.
	three := src("//duplication:justified b.go -- ok\n\n\n" + body)
	r = mustDetect(t, []File{{"a.go", three}, b}, testK)
	if len(r.InvalidAnnotations) != 0 || r.AnnotatedLines == 0 {
		t.Fatalf("3 lines above: %+v", r)
	}
	four := src("//duplication:justified b.go -- ok\n\n\n\n" + body)
	r = mustDetect(t, []File{{"a.go", four}, b}, testK)
	if len(r.InvalidAnnotations) != 1 {
		t.Fatalf("4 lines above: %+v", r.InvalidAnnotations)
	}
}

func TestMutualAnnotationValidForBoth(t *testing.T) {
	body := fn("f", 1, 12)
	a := File{"a.go", annotated("b.go", "twin", body)}
	b := File{"b.go", annotated("a.go", "twin", body)}
	r := mustDetect(t, []File{a, b}, testK)
	if len(r.InvalidAnnotations) != 0 || len(r.Runs) != 0 || r.DuplicatedLines != 0 || r.AnnotatedLines == 0 {
		t.Fatalf("mutual: %+v", r)
	}
}

func TestDeterministic(t *testing.T) {
	body := fn("f", 1, 12)
	a := File{"a.go", src(body)}
	b := File{"b.go", src(fn("g", 5, 12))}
	c := File{"c.go", annotated("a.go", "twin", body)}
	d := File{"d.go", src("//duplication:justified x.go --\n" + fn("h", 1, 3))}
	first := mustDetect(t, []File{a, b, c, d}, testK)
	again := mustDetect(t, []File{a, b, c, d}, testK)
	if !reflect.DeepEqual(first.Mult, again.Mult) {
		t.Fatal("Mult differs between calls")
	}
	for _, order := range [][]File{{d, c, b, a}, {b, d, a, c}, {c, a, d, b}} {
		got := mustDetect(t, order, testK)
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("order changed output:\n%+v\n%+v", first, got)
		}
	}
}
