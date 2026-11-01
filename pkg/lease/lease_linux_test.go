//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package lease

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// [REQUIRED TEST] Structural guard: CurrentHolder must take the store's own
// validity verdict rather than comparing the stored expiry to this host's wall
// clock. The behavioral tests above cannot distinguish the two on a
// single-process flatfile store, where both clocks are the same clock — but
// against the database provider the difference is a fail-open split brain: a
// host whose clock trails the database server would read an unexpired lease as
// expired (and vice versa), which is precisely the cross-host offset ADR-029
// Decision 2 / Issue #2037 keeps out of authority decisions. Monotonic
// elapsed-time use elsewhere in the file (recordLocalAuthority's time.Now
// baseline, HasLocalAuthority's time.Since) is deliberately untouched by this
// guard.
func TestManager_CurrentHolder_UsesStoreValidityNotLocalWallClock(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "lease.go", nil, 0)
	require.NoError(t, err)

	var checked bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "CurrentHolder" {
			return true
		}
		checked = true
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			sel, ok := inner.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			assert.False(t, pkg.Name == "time" && sel.Sel.Name == "Now",
				"CurrentHolder must not read this host's wall clock; validity is the store's verdict (LeaseState.Valid)")
			return true
		})
		return false
	})
	require.True(t, checked, "CurrentHolder not found in lease.go")
}
