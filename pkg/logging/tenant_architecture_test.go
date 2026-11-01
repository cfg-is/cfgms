//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tenantAuthzComparisonPattern matches a tenant-equality comparison shaped like an
// authorization decision (e.g. "trigger.TenantID != tenantID"). It is intentionally
// a plain text signature, not an AST match: the comparison side is arbitrary, and
// the point is only to detect that a file extracting the tenant is also gating
// something on it.
var tenantAuthzComparisonPattern = regexp.MustCompile(`\.TenantID\s*(!=|==)`)

// checkForLoggingTenantAuthzMisuse scans parsed Go source for calls to
// logging.ExtractTenantFromContext in a file that also contains a tenant-equality
// comparison, and returns "file:line" violation strings for each unannotated call.
// A call annotated with //architecture:allow-log-tenant-authz on the same line is
// exempt — see TestNoLoggingTenantForAuthorization for the rule this backs.
func checkForLoggingTenantAuthzMisuse(path string, src []byte) []string {
	if !tenantAuthzComparisonPattern.Match(src) {
		// No tenant-equality comparison in this file at all — whatever tenant value
		// ExtractTenantFromContext returns here cannot be gating access.
		return nil
	}

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
		if sel.Sel.Name != "ExtractTenantFromContext" {
			return true
		}
		pos := fset.Position(sel.Pos())
		lineIdx := pos.Line - 1
		if lineIdx >= 0 && lineIdx < len(lines) {
			if strings.Contains(lines[lineIdx], "//architecture:allow-log-tenant-authz") {
				return true
			}
		}
		violations = append(violations, fmt.Sprintf("%s:%d", filepath.ToSlash(path), pos.Line))
		return true
	})
	return violations
}

// TestNoLoggingTenantForAuthorization enforces that logging.ExtractTenantFromContext
// — a logging convenience that reads the tenant purely to tag log lines — is never
// the source of a tenant value used in an authorization-shaped equality check
// (Issue #4326). The two confirmed bypasses this story fixes,
// features/workflow/trigger.ListTriggers and debug_engine.StartDebugSession, took
// exactly this shape: a logging accessor's return value silently doubled as an
// access-control decision, and because the accessor read a different, never-written
// context key than the authentication middleware sets, the decision always saw an
// empty tenant.
//
// The canonical, and only, source for a tenant value used in an authorization
// decision is ctxkeys.TenantID, read directly and failed closed when absent.
//
// A file that legitimately needs both — a log line tagged with the tenant, and an
// unrelated tenant-equality check reading its value from ctxkeys.TenantID directly —
// does not trip this rule: it fires only when the *same accessor call* feeds a
// tenant comparison, and an intentional exception can be annotated on the call line:
//
//	tenantID := logging.ExtractTenantFromContext(ctx) //architecture:allow-log-tenant-authz -- <reason>
//
// features/siem is excluded: it is unreachable from every binary today and its
// tenant-context call sites are a separate, tracked decision (Issue #4326 scope).
func TestNoLoggingTenantForAuthorization(t *testing.T) {
	repoRoot := findLoggingRepoRoot(t)
	loggingPkgPath := filepath.Join(repoRoot, "pkg", "logging")
	siemPkgPath := filepath.Join(repoRoot, "features", "siem")

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
		// pkg/logging is the owning package; its own internal helpers are expected.
		if rel, relErr := filepath.Rel(loggingPkgPath, path); relErr == nil && !strings.HasPrefix(rel, "..") {
			return nil
		}
		// features/siem: unreachable from every binary, disposition tracked separately.
		if rel, relErr := filepath.Rel(siemPkgPath, path); relErr == nil && !strings.HasPrefix(rel, "..") {
			return nil
		}

		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		fileViolations := checkForLoggingTenantAuthzMisuse(path, src)
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
		"logging.ExtractTenantFromContext (a logging-only accessor) feeds a tenant "+
			"equality comparison; read ctxkeys.TenantID directly for authorization "+
			"decisions and fail closed when absent, or annotate a genuinely unrelated "+
			"co-occurrence with //architecture:allow-log-tenant-authz -- <reason>: %v",
		violations)
}

// TestLoggingTenantAuthzRuleDetectsViolation proves the detection logic fires on an
// unannotated co-occurrence and stays silent on an annotated one or a file with no
// tenant-equality comparison at all.
func TestLoggingTenantAuthzRuleDetectsViolation(t *testing.T) {
	t.Run("unannotated_extract_with_tenant_check_is_violation", func(t *testing.T) {
		src := []byte(`package foo
func f(ctx context.Context, trigger *Trigger) bool {
	tenantID := logging.ExtractTenantFromContext(ctx)
	return trigger.TenantID != tenantID
}
`)
		violations := checkForLoggingTenantAuthzMisuse("testdata/fake.go", src)
		assert.NotEmpty(t, violations, "expected a violation for unannotated ExtractTenantFromContext beside a tenant check")
	})

	t.Run("annotated_extract_with_tenant_check_is_allowed", func(t *testing.T) {
		src := []byte(`package foo
func f(ctx context.Context, trigger *Trigger) bool {
	tenantID := logging.ExtractTenantFromContext(ctx) //architecture:allow-log-tenant-authz -- unrelated log tag, gate reads ctxkeys.TenantID separately
	return trigger.TenantID != otherTenantID
}
`)
		violations := checkForLoggingTenantAuthzMisuse("testdata/fake.go", src)
		assert.Empty(t, violations, "expected no violation for annotated ExtractTenantFromContext")
	})

	t.Run("extract_without_any_tenant_check_is_allowed", func(t *testing.T) {
		src := []byte(`package foo
func f(ctx context.Context) string {
	tenantID := logging.ExtractTenantFromContext(ctx)
	logger.Info("event", "tenant", tenantID)
	return tenantID
}
`)
		violations := checkForLoggingTenantAuthzMisuse("testdata/fake.go", src)
		assert.Empty(t, violations, "log-only use with no tenant-equality comparison in the file must not be flagged")
	})
}

// findLoggingRepoRoot walks up from the working directory to find the repository root.
func findLoggingRepoRoot(t *testing.T) string {
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
