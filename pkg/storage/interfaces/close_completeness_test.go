// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// closeExemptStoreFields lists StorageManager store fields that are deliberately NOT
// closed by Close(), each with a written reason. This is an exemption list, not a
// baseline to grow: a field belongs here only when closing it would be wrong, never
// because closing it was forgotten.
//
// A store that owns a connection, file handle or other OS resource must be closed.
// A store that is a thin view over a handle some other store already owns must not be
// closed twice, and belongs here.
var closeExemptStoreFields = map[string]string{}

// TestCloseCoversEveryStoreField asserts that every store field on StorageManager
// appears in the slots list inside (*StorageManager).Close(), or is exempt above.
//
// Why this exists. A store that opens its own SQLite connection and is left out of
// that list leaks the handle. On Linux nothing observable happens. On Windows the
// leaked handle holds a file lock and t.TempDir() cleanup fails with "file in use by
// another process" — and because //go:build windows tests never run PR-side, the
// first execution is the merge queue, which evicts the pull request. That is a
// several-hour feedback loop for a one-line omission.
//
// It happened twice on 2026-09-04 alone, on two different stores (routingStore in
// Issue #3764, nodeRegistryStore in Issue #3763), which is what motivated a check that
// enumerates the fields rather than naming them one at a time. A per-store assertion
// only ever catches the store it names; this one catches the next store nobody has
// written yet.
//
// This is a static check on purpose. It reads the source rather than constructing a
// manager, so it needs no database, runs in milliseconds, and — the point — fails on
// Linux, at the moment the field is added, instead of in the queue on Windows.
func TestCloseCoversEveryStoreField(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "provider.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse provider.go: %v", err)
	}

	declared := storageManagerStoreFields(t, file)
	if len(declared) == 0 {
		t.Fatal("found no store fields on StorageManager — the struct was renamed or " +
			"restructured, and this test is no longer checking anything")
	}

	closed := closeSlotFields(t, file)
	if len(closed) == 0 {
		t.Fatal("found no sm.<field> entries in the Close() slots list — Close() was " +
			"restructured, and this test is no longer checking anything")
	}

	var missing []string
	for _, field := range declared {
		if _, ok := closed[field]; ok {
			continue
		}
		if _, exempt := closeExemptStoreFields[field]; exempt {
			continue
		}
		missing = append(missing, field)
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Errorf("StorageManager store field(s) missing from (*StorageManager).Close():\n"+
			"    %s\n\n"+
			"Add each to the slots list in Close(). A store that opens its own connection "+
			"and is not closed there leaks the handle, which is invisible on Linux and "+
			"fails on Windows in the merge queue.\n"+
			"If closing one would genuinely be wrong — for example it is a view over a "+
			"handle another store owns — add it to closeExemptStoreFields with the reason "+
			"instead.",
			strings.Join(missing, "\n    "))
	}

	// The reverse direction: an entry in the slots list naming a field that no longer
	// exists cannot compile, so it needs no check. An exemption naming a field that no
	// longer exists compiles fine and silently weakens this test, so it does.
	declaredSet := make(map[string]struct{}, len(declared))
	for _, f := range declared {
		declaredSet[f] = struct{}{}
	}
	for field := range closeExemptStoreFields {
		if _, ok := declaredSet[field]; !ok {
			t.Errorf("closeExemptStoreFields names %q, which is not a field on "+
				"StorageManager — remove the stale exemption", field)
		}
	}
}

// storageManagerStoreFields returns the names of StorageManager's store fields, in
// declaration order. A field counts as a store when its name ends in "Store", which
// matches every current field and is the convention the struct is written to.
func storageManagerStoreFields(t *testing.T, file *ast.File) []string {
	t.Helper()

	var fields []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "StorageManager" {
			return true
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok || structType.Fields == nil {
			return false
		}
		for _, f := range structType.Fields.List {
			for _, name := range f.Names {
				if strings.HasSuffix(name.Name, "Store") {
					fields = append(fields, name.Name)
				}
			}
		}
		return false
	})
	return fields
}

// closeSlotFields returns the set of field names referenced as sm.<field> anywhere
// inside (*StorageManager).Close(). Reading the whole function body rather than only
// the slots composite literal keeps the check working if the list is ever refactored
// into several appends or a helper call, at the cost of also accepting a field that is
// closed by some other means in there — which is a pass either way.
func closeSlotFields(t *testing.T, file *ast.File) map[string]struct{} {
	t.Helper()

	fields := make(map[string]struct{})
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Close" || fn.Recv == nil || fn.Body == nil {
			continue
		}
		if !receiverIsStorageManager(fn.Recv) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "sm" {
				fields[sel.Sel.Name] = struct{}{}
			}
			return true
		})
	}
	return fields
}

// receiverIsStorageManager reports whether a method receiver is *StorageManager.
func receiverIsStorageManager(recv *ast.FieldList) bool {
	if recv == nil || len(recv.List) != 1 {
		return false
	}
	star, ok := recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	ident, ok := star.X.(*ast.Ident)
	return ok && ident.Name == "StorageManager"
}
