//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/hex"
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

// funcSourceText returns the exact source text of the top-level function funcName
// declared in filename, via AST parse rather than string search — used to assert
// directly against the implementation (Issue #3694 AC) rather than only against
// observed output.
func funcSourceText(t *testing.T, filename, funcName string) string {
	t.Helper()
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	require.NoError(t, err)
	src, err := os.ReadFile(filename)
	require.NoError(t, err)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != funcName {
			continue
		}
		start := fset.Position(fd.Pos()).Offset
		end := fset.Position(fd.End()).Offset
		return string(src[start:end])
	}
	t.Fatalf("function %s not found in %s", funcName, filename)
	return ""
}

// TestGenerateOperatorNonce_UsesCryptoRandDirectly is a required test (Issue #3694
// AC): the nonce-generation call site uses crypto/rand — not math/rand, a counter,
// or a timestamp — and produces at least 16 bytes. Verified directly against the
// implementation (AST-extracted source of generateOperatorNonce, plus a
// package-wide scan for a stray math/rand import), not just observed output
// variance across calls, per the AC's own wording.
func TestGenerateOperatorNonce_UsesCryptoRandDirectly(t *testing.T) {
	fn := funcSourceText(t, "steward.go", "generateOperatorNonce")
	assert.Contains(t, fn, "rand.Read", "must generate the nonce via crypto/rand.Read")
	assert.NotContains(t, fn, "math/rand", "must not use math/rand")
	assert.NotContains(t, fn, "time.Now", "must not derive the nonce from a timestamp")
	assert.NotContains(t, fn, "uuid", "must not derive the nonce from a UUID")
	assert.NotContains(t, fn, "counter", "must not derive the nonce from a counter")

	// Confirm "rand" resolves to crypto/rand in this file, not a package-wide
	// math/rand import that could shadow it. Only non-test files are scanned: this
	// very test's source legitimately contains the literal string being searched
	// for (in this comment and assertion), which would otherwise self-match.
	pkgFiles, err := filepath.Glob("*.go")
	require.NoError(t, err)
	mathRandImport := `"math/rand"`
	for _, f := range pkgFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		content, err := os.ReadFile(f)
		require.NoError(t, err)
		assert.NotContains(t, string(content), mathRandImport,
			"non-test package file must not import math/rand (file %s)", f)
	}

	require.GreaterOrEqual(t, operatorNonceBytes, 16,
		"the nonce byte length constant must meet the AC's 16-byte floor")

	nonce, err := generateOperatorNonce()
	require.NoError(t, err)
	decoded, err := hex.DecodeString(nonce)
	require.NoError(t, err, "nonce must be valid hex")
	assert.GreaterOrEqual(t, len(decoded), 16, "generated nonce must be at least 16 bytes")
}
