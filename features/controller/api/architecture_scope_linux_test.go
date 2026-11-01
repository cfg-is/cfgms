//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandlersConsumeCallerScope enforces, for features/controller/api, that a
// handler registered through a wrapper-indirection call (see
// architecture_scope_test.go's package doc comment for the exact rule, its
// deliberate scope, and its known evasion limits) does not read a caller-supplied
// identifier (mux.Vars(r)) without consuming caller tenant scope — either directly
// or via a same-file helper — unless annotated:
//
//	//architecture:allow-unscoped-tenant-read -- <reason>
//
// following the same restricted-caller / annotate-don't-weaken pattern as
// //architecture:allow-raw-leader (pkg/ha/architecture_test.go). There is no
// exemption list: every currently-known instance of this rule's corpus
// (handlers_workflows.go's wrapper-registered routes) is either compliant or
// annotated with a real reason, not grandfathered in by name.
func TestHandlersConsumeCallerScope(t *testing.T) {
	repoRoot := findScopeRepoRoot(t)
	pkgDir := filepath.Join(repoRoot, "features", "controller", "api")

	entries, err := os.ReadDir(pkgDir)
	require.NoError(t, err)

	fset := token.NewFileSet()
	// funcsByFile scopes the one-hop helper credit to the same file, per the rule's
	// documented limits.
	funcsByFile := make(map[string]map[string]string)
	var handlerNames []string

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, e.Name())
		src, readErr := os.ReadFile(path) // #nosec G304 -- repo scan reads controlled source files
		if readErr != nil {
			continue
		}

		funcs, parseErr := extractFuncSources(fset, path, src)
		require.NoError(t, parseErr, "failed to parse %s", path)
		funcsByFile[e.Name()] = funcs

		names, wrapErr := findWrapperIndirectedHandlers(fset, path, src)
		require.NoError(t, wrapErr, "failed to scan %s for wrapper-indirected routes", path)
		handlerNames = append(handlerNames, names...)
	}

	var violations []string
	seen := make(map[string]bool)
	for _, name := range handlerNames {
		if seen[name] {
			continue
		}
		seen[name] = true

		var body string
		var declFile string
		for file, funcs := range funcsByFile {
			if b, ok := funcs[name]; ok {
				body = b
				declFile = file
				break
			}
		}
		if body == "" {
			// Declared outside this directory (a different package) or a
			// same-named-but-different symbol; nothing this test can check.
			continue
		}
		if !readsCallerSuppliedIdentifier(body) {
			continue
		}
		if isAnnotatedAllowUnscoped(body) {
			continue
		}
		if consumesScope(body, funcsByFile[declFile]) {
			continue
		}
		violations = append(violations, fmt.Sprintf("%s (%s)", name, declFile))
	}
	sort.Strings(violations)

	assert.Empty(t, violations,
		"handler(s) registered through wrapper indirection in features/controller/api "+
			"read a caller-supplied identifier (mux.Vars) without consuming caller "+
			"tenant scope (isWithinTenantScope/callerTenantID/isAuthorizedForTenant/"+
			"ctxkeys.TenantScopeKey/ctxkeys.TenantID), directly or via a same-file "+
			"helper; annotate a genuinely pre-authentication handler with "+
			"//architecture:allow-unscoped-tenant-read -- <reason>, or wire in the "+
			"scope check: %v", violations)
}

// findScopeRepoRoot walks up from the working directory to find the repository root.
func findScopeRepoRoot(t *testing.T) string {
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
