// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package main implements a lightweight log-injection linter for CFGMS.
//
// It catches the recurring CodeQL class "Log entries created from user input"
// at commit time, before code reaches CI. The linter parses each Go file with
// go/ast, identifies variables tainted by HTTP-derived sources (mux.Vars,
// r.URL.Query, r.Header, r.FormValue, decoded request bodies), then verifies
// every slog/logger call that uses them wraps them in logging.SanitizeLogValue.
//
// Scope: by default, every Go file under features/**/api/. Pass file paths as
// args to limit the check (used by the pre-commit hook for staged files only).
//
// Exit codes: 0 = clean, 1 = findings, 2 = parse/IO error.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// taintSourceCalls are call expressions whose result is user-controlled.
// The key is the full selector (pkg.Method) — values that compare against it
// are matched after we collapse the AST selector into a dotted string.
var taintSourceCalls = map[string]struct{}{
	"mux.Vars":              {},
	"r.URL.Query":           {},
	"r.Header.Get":          {},
	"r.FormValue":           {},
	"r.Form.Get":            {},
	"r.PostFormValue":       {},
	"r.PostForm.Get":        {},
	"json.NewDecoder":       {}, // tainted iff Decode target is then logged; handled separately
	"querystring.Unmarshal": {},
}

// loggerMethods are the slog/logger methods we treat as logging sinks.
var loggerMethods = map[string]struct{}{
	"Debug": {}, "Info": {}, "Warn": {}, "Error": {}, "Fatal": {}, "Panic": {},
}

// sanitizerCalls are wrappers that neutralize taint.
var sanitizerCalls = map[string]struct{}{
	"logging.SanitizeLogValue": {},
	"SanitizeLogValue":         {}, // dot-imported case
}

type finding struct {
	file string
	line int
	msg  string
}

func main() {
	flag.Parse()
	files := flag.Args()

	if len(files) == 0 {
		discovered, err := defaultScope()
		if err != nil {
			fmt.Fprintf(os.Stderr, "lint-log-injection: scope discovery: %v\n", err)
			os.Exit(2)
		}
		files = discovered
	}

	var findings []finding
	for _, f := range files {
		if !strings.HasSuffix(f, ".go") || strings.HasSuffix(f, "_test.go") {
			continue
		}
		info, err := os.Stat(f)
		if err != nil || info.IsDir() {
			continue
		}
		fs, err := analyzeFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lint-log-injection: %s: %v\n", f, err)
			os.Exit(2)
		}
		findings = append(findings, fs...)
	}

	if len(findings) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr, "❌ log-injection findings (wrap user-input with logging.SanitizeLogValue):")
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "  %s:%d: %s\n", f.file, f.line, f.msg)
	}
	os.Exit(1)
}

// defaultScope returns all .go files under features/**/api/ that aren't tests.
func defaultScope() ([]string, error) {
	var out []string
	err := filepath.WalkDir("features", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Only files under .../api/ subtrees.
		if !strings.Contains(path, "/api/") {
			return nil
		}
		out = append(out, path)
		return nil
	})
	return out, err
}

// analyzeFile parses a single file and reports log-injection findings.
// Taint is tracked per function scope so a name reassigned to a safe value in
// one function does not leak taint into another.
func analyzeFile(path string) ([]finding, error) {
	fset := token.NewFileSet()
	src, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
	if err != nil {
		return nil, err
	}

	structFields := collectStructFields(src)

	var findings []finding
	for _, decl := range src.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		findings = append(findings, analyzeFunc(fset, fn, structFields)...)
	}
	return findings, nil
}

// collectStructFields walks the file's top-level type declarations and returns
// a registry of struct name → field name → field type identifier (e.g. "bool",
// "string", "int64"). Anonymous and embedded fields are ignored. Cross-package
// types resolve to "" — the caller must treat unknown types as potentially
// string-like (current default behavior) to avoid silently dropping findings.
func collectStructFields(src *ast.File) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, decl := range src.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			fields := map[string]string{}
			for _, f := range st.Fields.List {
				typ := exprString(f.Type)
				for _, name := range f.Names {
					fields[name.Name] = typ
				}
			}
			out[ts.Name.Name] = fields
		}
	}
	return out
}

// isScalarType returns true for Go types that cannot carry log-injection
// payloads. Strings and byte slices are deliberately excluded — those are the
// types the linter exists to catch. Unknown types (cross-package, generics)
// return false so the linter stays conservative on its first encounter.
func isScalarType(typ string) bool {
	switch typ {
	case "bool",
		"int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64",
		"uintptr",
		"float32", "float64",
		"complex64", "complex128",
		"rune",
		"time.Time", "time.Duration":
		return true
	}
	return false
}

// analyzeFunc applies the two-pass taint analysis within a single function body.
func analyzeFunc(fset *token.FileSet, fn *ast.FuncDecl, structFields map[string]map[string]string) []finding {
	tainted := collectTaintedVars(fn.Body)
	varTypes := collectVarTypes(fn.Body)

	var findings []finding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if _, isLogger := loggerMethods[sel.Sel.Name]; !isLogger {
			return true
		}
		if !looksLikeLogger(sel.X) {
			return true
		}
		for i, arg := range call.Args {
			if i == 0 {
				if _, ok := arg.(*ast.BasicLit); ok {
					continue
				}
			}
			if !isTaintedExpr(arg, tainted) {
				continue
			}
			// Type-aware suppression: a tainted struct's bool/int/etc. field
			// cannot carry an injection payload. CodeQL's "Log entries from
			// user input" rule doesn't flag these either, so neither do we.
			if sel, ok := arg.(*ast.SelectorExpr); ok {
				if isProvablyScalar(sel, varTypes, structFields) {
					continue
				}
			}
			pos := fset.Position(arg.Pos())
			findings = append(findings, finding{
				file: pos.Filename,
				line: pos.Line,
				msg:  fmt.Sprintf("tainted value %q logged without logging.SanitizeLogValue", exprString(arg)),
			})
		}
		return true
	})
	return findings
}

// collectVarTypes returns a function-scoped map from variable name to its
// declared struct type name. Only patterns that pin a type unambiguously are
// recorded: `var x T` and `var x T{...}`. Composite literals (`x := T{}`),
// type-asserted assignments, and short-decls from typed function returns all
// resolve via the same `exprString` over the type expression. Cross-package
// types remain dotted (`pkg.T`) — collectStructFields keys on simple names, so
// they won't match and the linter stays conservative on imports.
func collectVarTypes(root ast.Node) map[string]string {
	out := map[string]string{}
	ast.Inspect(root, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.DeclStmt:
			gen, ok := v.Decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				return true
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || vs.Type == nil {
					continue
				}
				typ := exprString(vs.Type)
				for _, name := range vs.Names {
					out[name.Name] = typ
				}
			}
		case *ast.AssignStmt:
			if v.Tok != token.DEFINE || len(v.Lhs) != 1 || len(v.Rhs) != 1 {
				return true
			}
			id, ok := v.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			// `x := T{...}` — composite literal pins the type.
			if cl, ok := v.Rhs[0].(*ast.CompositeLit); ok && cl.Type != nil {
				out[id.Name] = exprString(cl.Type)
			}
		}
		return true
	})
	return out
}

// isProvablyScalar returns true when the SelectorExpr's field type can be
// determined from same-file declarations AND that type is a non-string scalar
// (bool, int*, float*, time.Time, etc.). Returns false on any uncertainty so
// the caller falls through to the normal flag path.
func isProvablyScalar(sel *ast.SelectorExpr, varTypes map[string]string, structFields map[string]map[string]string) bool {
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	typeName, ok := varTypes[id.Name]
	if !ok {
		return false
	}
	fields, ok := structFields[typeName]
	if !ok {
		return false
	}
	fieldType, ok := fields[sel.Sel.Name]
	if !ok {
		return false
	}
	return isScalarType(fieldType)
}

// collectTaintedVars returns a set of identifier names that are assigned from
// a taint source somewhere in the given subtree. Callers pass a function body
// so taint stays function-scoped — a name reassigned to a safe value in
// another function doesn't get tainted here.
func collectTaintedVars(root ast.Node) map[string]struct{} {
	tainted := map[string]struct{}{}

	ast.Inspect(root, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			// Only consider := and = with one Rhs.
			if len(v.Rhs) == 0 {
				return true
			}
			for idx, lhs := range v.Lhs {
				if idx >= len(v.Rhs) {
					break
				}
				rhs := v.Rhs[idx]
				if len(v.Rhs) == 1 && len(v.Lhs) > 1 {
					rhs = v.Rhs[0]
				}
				if !isTaintSourceExpr(rhs) {
					continue
				}
				if id, ok := lhs.(*ast.Ident); ok {
					tainted[id.Name] = struct{}{}
				}
			}
		case *ast.DeclStmt:
			gen, ok := v.Decl.(*ast.GenDecl)
			if !ok {
				return true
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i < len(vs.Values) && isTaintSourceExpr(vs.Values[i]) {
						tainted[name.Name] = struct{}{}
					}
				}
			}
		}
		return true
	})

	// If json.NewDecoder(r.Body).Decode(&<name>) appears, treat <name>.* as tainted via prefix.
	ast.Inspect(root, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Decode" {
			return true
		}
		// Chain pattern: json.NewDecoder(r.Body).Decode(&req)
		if inner, ok := sel.X.(*ast.CallExpr); ok {
			if isCallTo(inner, "json.NewDecoder") || isCallTo(inner, "xml.NewDecoder") {
				if len(call.Args) == 1 {
					if unary, ok := call.Args[0].(*ast.UnaryExpr); ok && unary.Op == token.AND {
						if id, ok := unary.X.(*ast.Ident); ok {
							tainted[id.Name] = struct{}{}
						}
					}
				}
			}
		}
		return true
	})

	return tainted
}

// isTaintSourceExpr returns true if the expression is a known HTTP taint source.
func isTaintSourceExpr(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.CallExpr:
		if name := selectorString(v.Fun); name != "" {
			if _, ok := taintSourceCalls[name]; ok {
				return true
			}
		}
	case *ast.IndexExpr:
		// mux.Vars(r)["key"] pattern: IndexExpr X = CallExpr mux.Vars(r)
		if call, ok := v.X.(*ast.CallExpr); ok {
			if isCallTo(call, "mux.Vars") {
				return true
			}
		}
	case *ast.SelectorExpr:
		// r.URL.Path, r.URL.RawQuery, etc.
		if s := selectorString(v); s == "r.URL.Path" || s == "r.URL.RawQuery" || s == "r.RequestURI" || s == "r.RemoteAddr" {
			return true
		}
	}
	return false
}

// isTaintedExpr returns true if the expression evaluates to user-controlled data
// AND is not wrapped in a sanitizer.
func isTaintedExpr(e ast.Expr, tainted map[string]struct{}) bool {
	if isSanitized(e) {
		return false
	}
	switch v := e.(type) {
	case *ast.Ident:
		_, ok := tainted[v.Name]
		return ok
	case *ast.SelectorExpr:
		// Tainted root identifier with a field selector (e.g. req.Foo, tainted via Decode).
		if id, ok := v.X.(*ast.Ident); ok {
			if _, t := tainted[id.Name]; t {
				return true
			}
		}
		// Direct r.URL.Path etc.
		if isTaintSourceExpr(v) {
			return true
		}
	case *ast.CallExpr:
		// Inline taint sources e.g. mux.Vars(r)["id"]
		if isTaintSourceExpr(v) {
			return true
		}
	case *ast.IndexExpr:
		if isTaintSourceExpr(v) {
			return true
		}
	}
	return false
}

// isSanitized returns true if the expression is a call to logging.SanitizeLogValue
// or a known sanitizer alias.
func isSanitized(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	name := selectorString(call.Fun)
	if name == "" {
		// Bare identifier (dot-import case)
		if id, ok := call.Fun.(*ast.Ident); ok {
			if _, s := sanitizerCalls[id.Name]; s {
				return true
			}
		}
		return false
	}
	_, ok = sanitizerCalls[name]
	return ok
}

// looksLikeLogger returns true when the receiver of a `.Debug/.Info/...` call
// matches a logger identifier. Conservative: identifier endings of "logger"
// or "Logger" or known field accessors.
func looksLikeLogger(e ast.Expr) bool {
	s := exprString(e)
	if s == "" {
		return false
	}
	tail := s
	if i := strings.LastIndex(s, "."); i >= 0 {
		tail = s[i+1:]
	}
	tail = strings.ToLower(tail)
	return strings.HasSuffix(tail, "logger") || tail == "log" || tail == "slog"
}

// isCallTo returns true if expr is a call to fn (dotted name like "json.NewDecoder").
func isCallTo(call *ast.CallExpr, fn string) bool {
	return selectorString(call.Fun) == fn
}

// selectorString collapses a selector-chain expr like `r.URL.Query` to its
// dotted form, or returns "" if the expression isn't a chain of Ident/Selector.
func selectorString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		left := selectorString(v.X)
		if left == "" {
			return ""
		}
		return left + "." + v.Sel.Name
	}
	return ""
}

// exprString is a small printer for diagnostic messages.
func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprString(v.Fun) + "(...)"
	case *ast.IndexExpr:
		return exprString(v.X) + "[...]"
	}
	return "<expr>"
}
