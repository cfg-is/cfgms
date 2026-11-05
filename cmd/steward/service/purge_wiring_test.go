// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUninstallPurgesRegistrationToken checks, syntactically, that each
// platform manager's Uninstall calls purgeRegistrationToken(purge) exactly once
// outside any function literal. Uninstall cannot be run unelevated, and the
// _darwin/_windows files are excluded from a Linux build, so the files are
// parsed directly.
func TestUninstallPurgesRegistrationToken(t *testing.T) {
	managers := []struct{ file, recv string }{
		{"manager_linux.go", "linuxManager"},
		{"manager_darwin.go", "darwinManager"},
		{"manager_windows.go", "windowsManager"},
	}
	for _, m := range managers {
		t.Run(m.file, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), m.file, nil, 0)
			require.NoError(t, err)

			var fn *ast.FuncDecl
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv == nil || fd.Name.Name != "Uninstall" || len(fd.Recv.List) != 1 {
					continue
				}
				recv := fd.Recv.List[0].Type
				if star, ok := recv.(*ast.StarExpr); ok {
					recv = star.X
				}
				if id, ok := recv.(*ast.Ident); ok && id.Name == m.recv {
					fn = fd
				}
			}
			require.NotNil(t, fn, "Uninstall method on %s not found", m.recv)

			calls, inLiteral := 0, 0
			var walk func(n ast.Node, lit bool)
			walk = func(n ast.Node, lit bool) {
				ast.Inspect(n, func(c ast.Node) bool {
					switch x := c.(type) {
					case *ast.FuncLit:
						walk(x.Body, true)
						return false
					case *ast.CallExpr:
						id, ok := x.Fun.(*ast.Ident)
						if !ok || id.Name != "purgeRegistrationToken" {
							return true
						}
						if lit {
							inLiteral++
						}
						if len(x.Args) == 1 {
							if arg, ok := x.Args[0].(*ast.Ident); ok && arg.Name == "purge" {
								calls++
							}
						}
					}
					return true
				})
			}
			walk(fn.Body, false)

			assert.Equal(t, 1, calls, "want exactly one purgeRegistrationToken(purge) call")
			assert.Zero(t, inLiteral, "call must not be inside a function literal")
		})
	}
}
