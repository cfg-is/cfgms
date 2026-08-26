// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ha

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestNoRawLeaderPrimitiveOutsidePkgHA enforces that IsRaftLeader() and the
// deprecated IsLeader() are never called outside pkg/ha without an explicit
// //architecture:allow-raw-leader annotation that states the reason.
//
// Outside pkg/ha, use HasLeadership() for all authority (admission) decisions.
// For status and observability handlers that genuinely need raw protocol state,
// annotate the call on the same line:
//
//	raftIsLeader := haManager.IsRaftLeader() //architecture:allow-raw-leader -- <reason>
//
// Known evasion limits: the rule detects method calls by name. It does not detect
// the raw primitive accessed through an interface that re-exposes it (IsRaftLeader
// is intentionally absent from ClusterManager, so this requires holding the
// concrete *Manager or *RaftConsensus type), nor through a local wrapper function
// that re-exposes IsRaftLeader under a different name. These limits are
// intentional — the rule catches the obvious direct call. Wrappers that smuggle the
// primitive should be treated as violations of the same intent.
func TestNoRawLeaderPrimitiveOutsidePkgHA(t *testing.T) {
	repoRoot := findHARepoRoot(t)
	haPkgPath := filepath.Join(repoRoot, "pkg", "ha")

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "worktrees" || d.Name() == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// pkg/ha is the owning package; internal uses of IsRaftLeader/IsLeader are expected.
		if rel, relErr := filepath.Rel(haPkgPath, path); relErr == nil && !strings.HasPrefix(rel, "..") {
			return nil
		}

		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		fileViolations := checkForRawLeaderCalls(path, src)
		// Make paths relative to repo root for readable output.
		for _, v := range fileViolations {
			rel, relErr := filepath.Rel(repoRoot, strings.SplitN(v, ":", 2)[0])
			if relErr == nil {
				parts := strings.SplitN(v, ":", 2)
				if len(parts) == 2 {
					v = filepath.ToSlash(rel) + ":" + parts[1]
				}
			}
			violations = append(violations, v)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, violations,
		"raw leader primitive (IsRaftLeader/IsLeader) called outside pkg/ha without "+
			"//architecture:allow-raw-leader annotation; use HasLeadership() for authority "+
			"decisions, or annotate observational call sites with the reason: %v", violations)
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

// findHARepoRoot walks up from the working directory to find the repository root.
func findHARepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod not found)")
		}
		dir = parent
	}
}
