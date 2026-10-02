//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findControllerRepoRoot walks up from the working directory to find the repository
// root (presence of go.mod). Named to avoid conflicting with findRepoRoot in pkg/cert.
func findControllerRepoRoot(t *testing.T) string {
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

// ---- [REQUIRED TEST] structural: no non-certificate code path sets CertSerial --------

// TestCertSerial_OnlySetByExtractAdminPrincipal is the [REQUIRED TEST]: it walks every
// non-test .go file in features/controller/api and asserts that "CertSerial:" appears
// as a struct field only inside extractAdminPrincipal. A later change setting it on a
// session or cookie principal — e.g. for audit correlation — would otherwise silently
// widen principalHasCertifiedRootScope's gate with no failing test to catch it.
func TestCertSerial_OnlySetByExtractAdminPrincipal(t *testing.T) {
	repoRoot := findControllerRepoRoot(t)
	apiDir := filepath.Join(repoRoot, "features", "controller", "api")

	entries, err := os.ReadDir(apiDir)
	require.NoError(t, err)

	fset := token.NewFileSet()
	var violations []string

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(apiDir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err, "parse %s", path)

		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				kv, ok := inner.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				ident, ok := kv.Key.(*ast.Ident)
				if !ok || ident.Name != "CertSerial" {
					return true
				}
				if fn.Name.Name != "extractAdminPrincipal" {
					violations = append(violations, fmt.Sprintf("%s:%d sets CertSerial in func %s",
						name, fset.Position(kv.Pos()).Line, fn.Name.Name))
				}
				return true
			})
			return false // FuncDecl bodies do not nest, no need to recurse further at this level
		})
	}

	assert.Empty(t, violations,
		"CertSerial must be set only inside extractAdminPrincipal: %v", violations)
}

// TestPrincipalHasCertifiedRootScope_SingleCallSite is the structural lock for the AC
// "the gate is a single named predicate with one call site": counts occurrences of the
// predicate's name across non-test source in this package. Exactly two are expected —
// the func declaration and its one call site inside resolveGrantedMarkers.
func TestPrincipalHasCertifiedRootScope_SingleCallSite(t *testing.T) {
	repoRoot := findControllerRepoRoot(t)
	apiDir := filepath.Join(repoRoot, "features", "controller", "api")
	entries, err := os.ReadDir(apiDir)
	require.NoError(t, err)

	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(apiDir, name))
		require.NoError(t, err)
		count += strings.Count(string(data), "principalHasCertifiedRootScope(")
	}
	assert.Equal(t, 2, count,
		"principalHasCertifiedRootScope must have exactly one call site outside its own declaration")
}
