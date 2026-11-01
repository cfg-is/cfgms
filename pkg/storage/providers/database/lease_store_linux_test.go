//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// [REQUIRED TEST] Structural guard for the invariant above: no caller-side
// wall clock may reach the lease SQL. This runs even where no PostgreSQL test
// database is reachable (every behavioral test in this file skips there), so
// the regression cannot land unnoticed. Elapsed-time helpers are unaffected —
// the ban is on time.Now, the absolute wall clock.
func TestDatabaseLeaseStore_NoClientClockInLeaseAuthorityPath(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "lease_store.go", nil, 0)
	require.NoError(t, err)

	guarded := map[string]bool{"AcquireOrRenew": true, "getLease": true, "GetLease": true, "Release": true}

	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || !guarded[fn.Name.Name] {
			return true
		}
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
				"%s must not read this host's wall clock: expiry and validity are derived by the database server, "+
					"and a cross-host clock offset must never enter a lease authority decision", fn.Name.Name)
			return true
		})
		return false
	})
}
