// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service_test

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

	"github.com/stretchr/testify/require"
)

// retiredClusterSymbols names the GetAllStewardsCluster split's supporting
// machinery, retired by ADR-031 Decision 3 (Issue #3764) in favor of one
// cluster-safe-by-construction fleet source (ControllerService.ListFleetStewards).
// Issue #3741's root cause was this split existing at all: dispatch consumers
// had to individually choose the dispatch-safe-but-node-local source vs. the
// fleet-wide-but-not-dispatch-safe one, and #3741 documented a case where that
// choice was made incorrectly. The fix removes the choice rather than
// documenting it more carefully.
//
// GetAllStewards is checked separately (checkForRetiredGetAllStewardsMethod)
// rather than as a plain identifier: "GetAllStewards" is also the name of an
// unrelated, still-valid fleet.StewardProvider interface method implemented by
// several other types (controllerServiceAdapter, fleet.MemoryQuery's provider,
// the monitoring steward collector). Only a method declared on
// *ControllerService itself is the retired one.
var retiredClusterSymbols = map[string]bool{
	"GetAllStewardsCluster":   true,
	"StartClusterRefresh":     true,
	"refreshClusterInventory": true,
	"clusterFleetQuery":       true,
}

// findGoRepoRoot walks up from the working directory to the nearest go.mod.
func findGoRepoRoot(t *testing.T) string {
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

// checkForRetiredClusterIdentifiers scans parsed Go source for ast.Ident nodes
// (actual identifier references — declarations, calls, field/selector names)
// matching a retired symbol. Comment text is not visited by ast.Inspect, so a
// file explaining the retirement in prose (as controller_service.go's
// ListFleetStewards doc comment does) is not a violation — only a live
// identifier reference is.
func checkForRetiredClusterIdentifiers(path string, src []byte) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil
	}

	var violations []string
	ast.Inspect(f, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if !retiredClusterSymbols[ident.Name] {
			return true
		}
		pos := fset.Position(ident.Pos())
		violations = append(violations, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(path), pos.Line, ident.Name))
		return true
	})
	violations = append(violations, checkForRetiredGetAllStewardsMethod(fset, f, path)...)
	return violations
}

// receiverTypeName returns the bare type name of a method's receiver,
// stripping the leading "*" for a pointer receiver.
func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// checkForRetiredGetAllStewardsMethod flags a method literally named
// GetAllStewards declared on ControllerService — the retired, node-local-only
// method — without flagging the many other types that legitimately implement
// fleet.StewardProvider's unrelated GetAllStewards() method.
func checkForRetiredGetAllStewardsMethod(fset *token.FileSet, f *ast.File, path string) []string {
	var violations []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "GetAllStewards" {
			return true
		}
		if receiverTypeName(fn.Recv) != "ControllerService" {
			return true
		}
		pos := fset.Position(fn.Pos())
		violations = append(violations, fmt.Sprintf("%s:%d: ControllerService.GetAllStewards", filepath.ToSlash(path), pos.Line))
		return true
	})
	return violations
}

// TestRetiredClusterSymbolsAreGone is the [REQUIRED TEST] regression test
// naming GetAllStewardsCluster, ControllerService.GetAllStewards, StartClusterRefresh,
// refreshClusterInventory, and clusterFleetQuery as retired: none of these
// identifiers may exist anywhere in non-test, non-vendor Go source (Issue
// #3764 Migration Completeness AC). This file's own retiredClusterSymbols map
// and comment above are excluded because they live in a _test.go file (the
// rule scans production source), and because the map's keys are Go string
// literals, not identifiers — ast.Inspect never visits them as *ast.Ident.
func TestRetiredClusterSymbolsAreGone(t *testing.T) {
	repoRoot := findGoRepoRoot(t)

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "worktrees", ".cache", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path) // #nosec G304 -- repo-tree walk over a known filesystem, not user input
		if readErr != nil {
			return readErr
		}
		violations = append(violations, checkForRetiredClusterIdentifiers(path, src)...)
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, violations,
		"retired GetAllStewardsCluster/ControllerService.GetAllStewards/StartClusterRefresh/refreshClusterInventory/clusterFleetQuery symbols must not reappear:\n%s",
		strings.Join(violations, "\n"))
}
