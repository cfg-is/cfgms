// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ccOf(t *testing.T, body string) int {
	t.Helper()
	fns := analyzeSrc(t, "a.go", "package a\n\nfunc F() {\n"+body+"\n}\n")
	require.Len(t, fns, 1)
	return fns[0].CC
}

func TestCyclomaticRules(t *testing.T) {
	cases := []struct {
		name, body string
		want       int
	}{
		{"empty", ``, 1},
		{"if", `if a {}`, 2},
		{"else adds nothing", `if a {} else {}`, 2},
		{"else if is another if", `if a {} else if b {}`, 3},
		{"for", `for a {}`, 2},
		{"range", `for range a {}`, 2},
		{"switch case", `switch a { case 1: case 2: }`, 3},
		{"switch default adds nothing", `switch a { case 1: default: }`, 2},
		{"switch alone", `switch a { }`, 1},
		{"type switch case", `switch a.(type) { case int: case string: default: }`, 3},
		{"select case", `select { case <-a: case b <- 1: default: }`, 3},
		{"and", `_ = a && b`, 2},
		{"or", `_ = a || b`, 2},
		{"defer and go add nothing", `defer f(); go f()`, 1},
		{"arithmetic and bitwise add nothing", `_ = a & b | c + d`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ccOf(t, tc.body))
		})
	}
}

func TestCyclomaticErrNilCountsAsDecision(t *testing.T) {
	// Deliberate, founder-approved decision: no special case for error checks.
	assert.Equal(t, 2, ccOf(t, `if err != nil { return }`))
}

func TestClosureFoldsIntoDeclaringFunction(t *testing.T) {
	fns := analyzeSrc(t, "a.go", "package a\n\nfunc F() {\n\tg := func() {\n\t\tif a {}\n\t}\n\tg()\n}\n")
	require.Len(t, fns, 1)
	assert.Equal(t, "F", fns[0].Name)
	assert.Equal(t, 2, fns[0].CC)
}
