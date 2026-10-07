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

// Rule (Issue #4656): a tenant ID is a single DNS-label token and never contains
// "/" (ADR-025 Amendment 1), so a `strings.HasPrefix(x, y+"/")` descendant test
// can never match a real tenant ID. Subtree containment resolves through the
// tenant store's ParentID ancestry instead. This test keeps the prefix shape out
// of the controller API, controller service and reports API packages.
//
// A call that legitimately compares slash-separated non-tenant paths carries
// `//architecture:allow-path-prefix -- <reason>` on the same line, in the style of
// //architecture:allow-raw-leader.
//
// Known evasion limits: the rule matches the literal call shape only. A prefix
// built into a variable first (`p := y + "/"; strings.HasPrefix(x, p)`) or a
// differently-named wrapper is not detected.

const pathPrefixAnnotation = "//architecture:allow-path-prefix"

// tenantPrefixScanDirs are the packages scanned, relative to the repository root.
var tenantPrefixScanDirs = []string{
	"features/controller/api",
	"features/controller/service",
	"features/reports/api",
}

// findPathPrefixViolations parses src and returns "file:line" for every
// strings.HasPrefix(<x>, <y>+"/") call not carrying the allow annotation on its line.
func findPathPrefixViolations(filename string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(src), "\n")
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "HasPrefix" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
			return true
		}
		bin, ok := call.Args[1].(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			return true
		}
		lit, ok := bin.Y.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || lit.Value != `"/"` {
			return true
		}
		line := fset.Position(call.Pos()).Line
		if line-1 < len(lines) && strings.Contains(lines[line-1], pathPrefixAnnotation) {
			return true
		}
		out = append(out, fmt.Sprintf("%s:%d", filename, line))
		return true
	})
	return out, nil
}

func TestPathPrefixDetectionFiresOnSyntheticViolation(t *testing.T) {
	cases := map[string]struct {
		line string
		want int
	}{
		"no spaces":   {`ok := strings.HasPrefix(a, b+"/")`, 1},
		"with spaces": {`ok := strings.HasPrefix(a, b + "/")`, 1},
		"annotated":   {`ok := strings.HasPrefix(a, b+"/") //architecture:allow-path-prefix -- selector path`, 0},
		"no slash":    {`ok := strings.HasPrefix(a, b)`, 0},
		"other call":  {`ok := other.HasPrefix(a, b+"/")`, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			src := "package x\n\nimport \"strings\"\n\nfunc f(a, b string) bool {\n\t" + tc.line + "\n\treturn ok\n}\n"
			got, err := findPathPrefixViolations("synthetic.go", []byte(src))
			require.NoError(t, err)
			assert.Len(t, got, tc.want)
		})
	}
}

func TestNoPathPrefixTenantScopeCheck(t *testing.T) {
	root := findTenantPrefixRepoRoot(t)
	var violations []string
	for _, dir := range tenantPrefixScanDirs {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		require.NoError(t, err)
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			src, err := os.ReadFile(filepath.Join(root, dir, name))
			require.NoError(t, err)
			found, err := findPathPrefixViolations(filepath.Join(dir, name), src)
			require.NoError(t, err)
			violations = append(violations, found...)
		}
	}
	assert.Empty(t, violations,
		"strings.HasPrefix(x, y+\"/\") never matches a real tenant ID (ADR-025 Amendment 1); "+
			"resolve subtree containment through the tenant ParentID ancestry, or annotate a "+
			"non-tenant path comparison with //architecture:allow-path-prefix -- <reason>: %v", violations)
}

func findTenantPrefixRepoRoot(t *testing.T) string {
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
