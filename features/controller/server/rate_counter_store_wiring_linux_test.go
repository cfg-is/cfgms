//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServer_New_CallsRateCounterStoreWiring is layer 1: the composition root must
// actually invoke wireClusterRateCounterStore. Without this, every functional test
// below could pass while a clustered controller silently kept per-node abuse budgets
// — the store would be created by CreateClusterStorageManager and then never handed
// to anything.
func TestServer_New_CallsRateCounterStoreWiring(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	require.NoError(t, err, "parsing features/controller/server/server.go")

	var newFunc *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "New" && fn.Recv == nil {
			newFunc = fn
			break
		}
	}
	require.NotNil(t, newFunc, "server.go must declare func New — the controller composition root")

	called := false
	ast.Inspect(newFunc, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, isIdent := call.Fun.(*ast.Ident); isIdent && ident.Name == "wireClusterRateCounterStore" {
			called = true
			return false
		}
		return true
	})
	assert.True(t, called,
		"Server.New must call wireClusterRateCounterStore, or a clustered controller's abuse budgets stay per-node no matter what the storage tier created")
}
