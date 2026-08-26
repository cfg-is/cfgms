// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

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

// ratchetResetNames are the identifiers that clear the persisted Raft-term fence
// state. No file outside features/steward/registration may name any of them.
//
// ClearRatchet is the method on config.FenceRatchet. resetFenceRatchetOnEnrollment
// is the enrollment-path reset in client_http.go; it is unexported, so the compiler
// already rejects an out-of-package call, and it is listed here so that re-exporting
// it — which would restore the "any package can proxy the reset" hole — is caught by
// this test rather than by review. ResetFenceRatchetOnEnrollment is listed for the
// same reason: the exported spelling must not come back.
var ratchetResetNames = map[string]bool{
	"ClearRatchet":                   true,
	"resetFenceRatchetOnEnrollment":  true,
	"ResetFenceRatchetOnEnrollment":  true,
	"resetFenceRatchetForEnrollment": true,
}

// TestNoRatchetClearCallerOutsideRegistration enforces that ClearRatchet —
// the method on config.FenceRatchet that wipes the persisted Raft-term fence
// state — and the enrollment-path reset that calls it are never named outside
// the features/steward/registration package.
//
// This structural guarantee is the physical isolation that makes the
// enrollment-path reset safe: an attacker who controls the command channel
// cannot reach ClearRatchet because no call path from features/steward/client
// (the command-receive package) to ClearRatchet — or to any wrapper around it —
// exists in the source tree.
//
// The test is modeled on TestNoGetCertificatesByTypeOutsideCertPackage in
// pkg/cert/architecture_test.go and #3391's pattern in this epic batch.
// Test files (_test.go) are excluded — they are test infrastructure, not
// production code paths.
func TestNoRatchetClearCallerOutsideRegistration(t *testing.T) {
	repoRoot := findRegistrationRepoRoot(t)
	registrationPkgPath := filepath.Join(repoRoot, "features", "steward", "registration")

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip agent dispatch worktrees and the Go module cache.
			if d.Name() == "worktrees" || d.Name() == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}

		// Exclude test files and non-Go files.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		// The registration package is the sole allowed caller: skip it.
		if rel, relErr := filepath.Rel(registrationPkgPath, path); relErr == nil && !strings.HasPrefix(rel, "..") {
			return nil
		}

		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil
		}

		// Inspect every identifier rather than only selector expressions: a selector's
		// Sel is itself an *ast.Ident, so this covers pkg.Reset(...) and x.ClearRatchet()
		// as well as a bare call reference or a method value.
		//
		// Function/method declaration names are exempt: ClearRatchet is *declared* in
		// features/steward/config (that is where the state lives), and the rule under
		// test is about who may call it, not where it is defined. A wrapper declared
		// elsewhere is still caught, because its body has to name ClearRatchet.
		declNames := map[*ast.Ident]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if fn, isFunc := n.(*ast.FuncDecl); isFunc && fn.Name != nil {
				declNames[fn.Name] = true
				return true
			}
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if ratchetResetNames[ident.Name] && !declNames[ident] {
				pos := fset.Position(ident.Pos())
				rel, relErr := filepath.Rel(repoRoot, pos.Filename)
				if relErr != nil {
					rel = pos.Filename
				}
				violations = append(violations,
					fmt.Sprintf("%s:%d (%s)", filepath.ToSlash(rel), pos.Line, ident.Name))
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, violations,
		"fence-ratchet reset named outside features/steward/registration; "+
			"move the call to the enrollment path in client_http.go: %v", violations)
}

// findRegistrationRepoRoot walks up from the working directory to find the
// repository root (identified by the presence of go.mod).
func findRegistrationRepoRoot(t *testing.T) string {
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
