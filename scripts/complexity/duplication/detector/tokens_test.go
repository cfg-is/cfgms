// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package detector

import (
	"fmt"
	"go/token"
	"strings"
	"testing"
)

// fn renders a function with n statements whose operator sequences come from
// a fixed generator, so no two windows of one body are equal. ident and lit
// vary identifier names and literal values without changing the token stream.
func fn(ident string, lit, n int) string {
	ops := []string{"+", "-", "*", "/", "%", "&", "|", "^"}
	var b strings.Builder
	fmt.Fprintf(&b, "func %s() {\n", ident)
	seed := uint32(12345)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\t%s%d = %s%d", ident, i, ident, i)
		for j := 0; j < 6; j++ {
			seed = seed*1664525 + 1013904223
			fmt.Fprintf(&b, " %s %d", ops[(seed>>24)%8], lit+j)
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func src(body string) []byte { return []byte("package p\n\nimport \"fmt\"\n\n" + body) }

func mustDetect(t *testing.T, files []File, k int) Result {
	t.Helper()
	r, err := Detect(files, k)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return r
}

func TestTokenizeNormalizesAndSkipsHeader(t *testing.T) {
	a := tokenize("a.go", []byte("package a\nimport (\n\t\"x\"\n\ty \"z\"\n)\nimport \"q\"\nfunc f() { v := 1 // c\n}\n"))
	b := tokenize("b.go", []byte("package bb\nfunc g() { w := 2.5 }\n"))
	if a.kinds[0] != token.FUNC {
		t.Fatalf("header not skipped: %v", a.kinds)
	}
	if len(a.comments) != 1 || a.comments[0].line != 7 {
		t.Fatalf("comments = %+v", a.comments)
	}
	// identifiers collapse; literal kinds differ (INT vs FLOAT).
	if a.kinds[1] != token.IDENT || b.kinds[1] != token.IDENT {
		t.Fatalf("idents: %v %v", a.kinds, b.kinds)
	}
	if a.kinds[7] == b.kinds[7] {
		t.Fatalf("INT and FLOAT literals must differ")
	}
}

func TestWindowHashesDeterministicRolling(t *testing.T) {
	kinds := tokenize("a.go", src(fn("f", 1, 10))).kinds
	h1 := windowHashes(kinds, 7)
	h2 := windowHashes(kinds, 7)
	for i := range h1 {
		if h1[i] != h2[i] {
			t.Fatal("not deterministic")
		}
		var direct uint64
		for _, k := range kinds[i : i+7] {
			direct = direct*hashBase + mix(k)
		}
		if direct != h1[i] {
			t.Fatalf("rolling hash differs from direct at %d", i)
		}
	}
	if windowHashes(kinds[:3], 7) != nil {
		t.Fatal("short input must give no windows")
	}
}
