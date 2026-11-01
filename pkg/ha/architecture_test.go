// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ha

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// rawLeaderPrimitives lists the raw Raft replication-protocol methods whose use
// outside pkg/ha requires an //architecture:allow-raw-leader annotation.
// IsLeader is the deprecated alias retained during the #3389 migration; it
// forwards to IsRaftLeader and is equally prohibited outside pkg/ha.
var rawLeaderPrimitives = map[string]bool{
	"IsRaftLeader": true,
	"IsLeader":     true,
}

// checkForRawLeaderCalls scans the parsed Go source for calls to raw leader
// primitives and returns a slice of "file:line" violation strings. A call
// annotated with //architecture:allow-raw-leader on the same line is exempt.
func checkForRawLeaderCalls(path string, src []byte) []string {
	lines := strings.Split(string(src), "\n")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil
	}

	var violations []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !rawLeaderPrimitives[sel.Sel.Name] {
			return true
		}
		pos := fset.Position(sel.Pos())
		lineIdx := pos.Line - 1
		if lineIdx >= 0 && lineIdx < len(lines) {
			if strings.Contains(lines[lineIdx], "//architecture:allow-raw-leader") {
				return true
			}
		}
		violations = append(violations, fmt.Sprintf("%s:%d", filepath.ToSlash(path), pos.Line))
		return true
	})
	return violations
}

// TestRawLeaderRuleDetectsViolation proves the detection logic fires on a raw call
// and stays silent on an annotated one. This verifies the rule is live, not silent.
func TestRawLeaderRuleDetectsViolation(t *testing.T) {
	t.Run("bare_IsRaftLeader_is_violation", func(t *testing.T) {
		src := []byte(`package foo
func f(m interface{ IsRaftLeader() bool }) {
	_ = m.IsRaftLeader()
}
`)
		violations := checkForRawLeaderCalls("testdata/fake.go", src)
		assert.NotEmpty(t, violations, "expected a violation for unannotated IsRaftLeader call")
	})

	t.Run("annotated_IsRaftLeader_is_allowed", func(t *testing.T) {
		src := []byte(`package foo
func f(m interface{ IsRaftLeader() bool }) {
	_ = m.IsRaftLeader() //architecture:allow-raw-leader -- observational only, not an admission decision
}
`)
		violations := checkForRawLeaderCalls("testdata/fake.go", src)
		assert.Empty(t, violations, "expected no violation for annotated IsRaftLeader call")
	})

	t.Run("bare_IsLeader_deprecated_alias_is_violation", func(t *testing.T) {
		src := []byte(`package foo
func f(m interface{ IsLeader() bool }) {
	_ = m.IsLeader()
}
`)
		violations := checkForRawLeaderCalls("testdata/fake.go", src)
		assert.NotEmpty(t, violations, "expected a violation for unannotated IsLeader call")
	})

	t.Run("annotated_IsLeader_is_allowed", func(t *testing.T) {
		src := []byte(`package foo
func f(m interface{ IsLeader() bool }) {
	_ = m.IsLeader() //architecture:allow-raw-leader -- deprecated path, observational only
}
`)
		violations := checkForRawLeaderCalls("testdata/fake.go", src)
		assert.Empty(t, violations, "expected no violation for annotated IsLeader call")
	})

	t.Run("struct_field_read_is_not_flagged", func(t *testing.T) {
		// Reading a bool field named IsLeader from a struct is not a method call —
		// the rule must not produce false positives for field access.
		src := []byte(`package foo
type Status struct{ IsLeader bool }
func f(s Status) bool { return s.IsLeader }
`)
		violations := checkForRawLeaderCalls("testdata/fake.go", src)
		assert.Empty(t, violations, "struct field reads must not be flagged")
	})
}
