// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package main implements a lightweight log-injection linter for CFGMS.
//
// It catches the recurring CodeQL class "Log entries created from user input"
// at commit time, before code reaches CI. The linter parses each Go file with
// go/ast, identifies variables tainted by HTTP-derived sources (mux.Vars,
// r.URL.Query, r.Header, r.FormValue, decoded request bodies), then verifies
// every slog/logger call that uses them wraps them in logging.SanitizeLogValue.
//
// Scope: by default, every non-test Go file in the repository, skipping
// dot-prefixed directories (.cache, .git, ...) and bin/, build/, data/,
// node_modules/, vendor/ — build/runtime artifacts and vendored third-party
// source, never CFGMS code under test. Pass file paths as args to limit the
// check (used by the pre-commit hook for staged files only).
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
	"sort"
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
	// CFGMS's own context-aware logging convention (logging.Logger,
	// *logging.ModuleLogger).
	"DebugCtx": {}, "InfoCtx": {}, "WarnCtx": {}, "ErrorCtx": {}, "FatalCtx": {},
	// stdlib log/slog's context-aware convention — distinct spelling, same sink class.
	"DebugContext": {}, "InfoContext": {}, "WarnContext": {}, "ErrorContext": {},
}

// sanitizerCalls are wrappers that neutralize taint.
var sanitizerCalls = map[string]struct{}{
	"logging.SanitizeLogValue":        {},
	"SanitizeLogValue":                {}, // dot-imported case
	"logging.SanitizeFieldsRecursive": {},
	"SanitizeFieldsRecursive":         {}, // dot-imported case
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
		discovered, err := discoverScope(".")
		if err != nil {
			fmt.Fprintf(os.Stderr, "lint-log-injection: scope discovery: %v\n", err)
			os.Exit(2)
		}
		files = discovered
	}

	// Group files by directory before analysis: same-package resolution
	// (see analyzePackage's doc comment) needs every file in a package
	// visible to one call graph, not analyzed one at a time.
	groups := map[string][]string{}
	var groupOrder []string
	for _, f := range files {
		if !strings.HasSuffix(f, ".go") || strings.HasSuffix(f, "_test.go") {
			continue
		}
		info, err := os.Stat(f)
		if err != nil || info.IsDir() {
			continue
		}
		dir := filepath.Dir(f)
		if _, ok := groups[dir]; !ok {
			groupOrder = append(groupOrder, dir)
		}
		groups[dir] = append(groups[dir], f)
	}

	var findings []finding
	for _, dir := range groupOrder {
		fs, err := analyzePackage(groups[dir])
		if err != nil {
			fmt.Fprintf(os.Stderr, "lint-log-injection: %s: %v\n", dir, err)
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

// noiseDirs are directory names skipped entirely during scope discovery:
// build/runtime artifacts and vendored third-party source, never CFGMS code.
var noiseDirs = map[string]struct{}{
	"bin":          {},
	"build":        {},
	"data":         {},
	"node_modules": {},
	"vendor":       {},
}

// discoverScope returns all non-test .go files under root, skipping
// dot-prefixed directories and the noiseDirs listed above.
func discoverScope(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name != "." && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			if _, skip := noiseDirs[name]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
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
		findings = append(findings, analyzeFunc(fset, fn, structFields, nil, nil)...)
	}
	return findings, nil
}

// analyzePackage parses every file in paths as one resolution unit and
// reports log-injection findings across all of them, including taint that
// flows into a callee's parameter from a same-package caller's
// already-tainted argument.
//
// Resolution-boundary decision: same-package (files grouped by directory in
// main(), the same grouping CFGMS's own convention already uses — a
// features/* package's HTTP handlers and their helpers are routinely split
// across sibling files by concern). Same-file resolution was rejected as too
// narrow for that reason: a caller in one file and a callee in a sibling file
// of the same package is a realistic, generalizable shape, not an edge case.
// Whole-corpus (cross-package) resolution was rejected as materially out of
// proportion to this story: it requires building a single call graph over
// every file in scope, which means real import resolution and the same
// GOOS-sensitivity gopls/go/packages already has (see CLAUDE.md's own
// warning that a Linux run of gopls is blind to `//go:build windows` files) —
// a concern this AST-only, no-import-resolution linter has never had to
// carry before. Same-package resolution catches the interprocedural gap this
// story exists for (see the worked example in issue #4089) without taking on
// that cost.
func analyzePackage(paths []string) ([]finding, error) {
	fset := token.NewFileSet()
	structFields := map[string]map[string]string{}
	funcs := map[string]*ast.FuncDecl{}
	ambiguous := map[string]struct{}{}
	var order []*ast.FuncDecl

	for _, p := range paths {
		src, err := parser.ParseFile(fset, p, nil, parser.AllErrors)
		if err != nil {
			return nil, err
		}
		for name, fields := range collectStructFields(src) {
			structFields[name] = fields
		}
		for _, decl := range src.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, exists := funcs[fn.Name.Name]; exists {
				// Two functions/methods share this name in the resolution
				// unit (e.g. distinct types both implementing String() or
				// Error()). Call-site matching is by name only (no receiver
				// type info in an AST-only linter), so an ambiguous name
				// would attribute one type's tainted call argument to every
				// same-named method in the package — resolveParameterTaint
				// excludes ambiguous names rather than over-matching them.
				ambiguous[fn.Name.Name] = struct{}{}
			}
			funcs[fn.Name.Name] = fn
			order = append(order, fn)
		}
	}
	for name := range ambiguous {
		delete(funcs, name)
	}

	paramTaint := resolveParameterTaint(funcs)
	funcResults := collectFuncResultTypes(funcs)

	var findings []finding
	for _, fn := range order {
		findings = append(findings, analyzeFunc(fset, fn, structFields, paramTaint[fn.Name.Name], funcResults)...)
	}
	return findings, nil
}

// collectFuncResultTypes records, for every function in the resolution unit,
// the positional list of its result type names (`(int, error)` → ["int",
// "error"]). It is the type-resolution half of the same-package boundary
// analyzePackage establishes: knowing a same-package callee's result types
// lets collectVarTypes pin the type of `n, err := s.countThings(...)` and so
// lets the existing scalar suppression (isScalarType) drop a finding on an
// int that a tainted argument merely influenced the *value* of. An int cannot
// carry a CR/LF injection payload no matter where its value came from.
//
// funcs is analyzePackage's registry, which already excludes names declared
// more than once in the unit — an ambiguous name would otherwise let one
// type's result types be attributed to a same-named method on another type,
// and here that mistake suppresses findings rather than adding them.
func collectFuncResultTypes(funcs map[string]*ast.FuncDecl) map[string][]string {
	out := make(map[string][]string, len(funcs))
	for name, fn := range funcs {
		if fn.Type == nil || fn.Type.Results == nil {
			continue
		}
		var types []string
		for _, f := range fn.Type.Results.List {
			typ := exprString(f.Type)
			count := len(f.Names)
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i++ {
				types = append(types, typ)
			}
		}
		out[name] = types
	}
	return out
}

// receiverName returns the name a method binds its receiver to (`s` in
// `func (s *Server) handle(...)`), or "" for a plain function or a method
// with an unnamed receiver.
func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 || len(fn.Recv.List[0].Names) == 0 {
		return ""
	}
	return fn.Recv.List[0].Names[0].Name
}

// funcParamTaintRounds bounds the interprocedural fixed point in
// resolveParameterTaint: how many times it alternates recomputing each
// function's local taint (from the parameter taint discovered so far) and
// rescanning call sites (to grow that parameter taint) before stopping.
// Mirrors the 5-round bound collectTaintedVars' own intraprocedural fixed
// point already uses (main.go, the loop in collectTaintedVars) for the same
// reason: five hops through a same-package call graph is far beyond any real
// handler-to-helper call depth, and it bounds mutual or self recursion in the
// graph without needing separate cycle detection.
const funcParamTaintRounds = 5

// resolveParameterTaint builds a same-package call graph over funcs and
// returns, for each function name, the set of its own parameter names that
// are passed a tainted argument at any call site within funcs. The result is
// conservative and over-approximate to match this linter's existing bias
// (see collectStructFields' doc comment on unknown cross-package types): a
// parameter is marked tainted if *any* call site taints it, and calls are
// matched by callee name alone (method receivers are not type-checked), so a
// same-named function or method elsewhere in the package can cause a
// parameter to be treated as tainted even when that specific call site isn't
// the one responsible.
//
// That name-only matching is over-approximate, but the resolution is not
// uniformly fail-closed: analyzePackage deletes every name declared more than
// once in the unit (two types both implementing String(), Error(), Close(), …)
// from funcs before calling this, so an ambiguous name is *excluded* from
// parameter-taint resolution rather than over-matched. A real finding that is
// only reachable through a duplicated method name in the same package is
// therefore silently dropped, not merely surfaced for dismissal — a known,
// accepted precision-over-recall tradeoff. It is deliberate: matching an
// unrelated same-named method across unrelated types was measured to inflate
// the repo-wide finding count from 40 to 146, nearly all false positives.
// Findings behind an ambiguous name remain the caller's responsibility to
// catch by review. Unambiguous names keep the conservative bias described
// above: those over-approximations only add findings a human must dismiss.
func resolveParameterTaint(funcs map[string]*ast.FuncDecl) map[string]map[string]struct{} {
	paramTaint := map[string]map[string]struct{}{}
	// Iterate a sorted name list, not the map: Go randomizes map iteration
	// order per run, which would make the bounded fixed point's per-round
	// convergence path (and, for deep chains that exhaust funcParamTaintRounds,
	// potentially the final result) vary between runs of a security linter
	// whose test suite asserts a byte-exact findings snapshot.
	names := make([]string, 0, len(funcs))
	for name := range funcs {
		paramTaint[name] = map[string]struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)

	for round := 0; round < funcParamTaintRounds; round++ {
		localTainted := map[string]map[string]struct{}{}
		for _, name := range names {
			localTainted[name] = collectTaintedVars(funcs[name].Body, paramTaint[name])
		}

		changed := false
		for _, name := range names {
			fn := funcs[name]
			caller := localTainted[name]
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				calleeName := calleeFuncName(call.Fun)
				callee, ok := funcs[calleeName]
				if !ok {
					return true
				}
				params := paramNames(callee.Type.Params)
				for i, arg := range call.Args {
					if i >= len(params) {
						break // extra/variadic args beyond the declared, named parameters
					}
					pname := params[i]
					if pname == "" || pname == "_" {
						continue
					}
					if _, already := paramTaint[calleeName][pname]; already {
						continue
					}
					if exprCarriesTaint(arg, caller) {
						paramTaint[calleeName][pname] = struct{}{}
						changed = true
					}
				}
				return true
			})
		}
		if !changed {
			break
		}
	}

	return paramTaint
}

// calleeFuncName extracts the plain function/method name a call expression's
// Fun targets — the Ident name for a direct call, or the selector's Sel name
// for a method call (irrespective of receiver type; see resolveParameterTaint's
// doc comment on why that's an intentional over-approximation).
func calleeFuncName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// paramNames flattens a function's parameter field list into one name per
// positional parameter, expanding fields that declare multiple names
// (`a, b string`) into repeated entries so index i still lines up with
// argument i at a call site.
func paramNames(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var out []string
	for _, f := range fields.List {
		if len(f.Names) == 0 {
			out = append(out, "") // unnamed parameter, never taintable by name
			continue
		}
		for _, n := range f.Names {
			out = append(out, n.Name)
		}
	}
	return out
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

// analyzeFunc applies the two-pass taint analysis within a single function
// body. paramTaint is the set of fn's own parameter names known to receive a
// tainted argument from a same-package caller (nil when fn is analyzed in
// isolation, e.g. via analyzeFile) — it seeds collectTaintedVars the same way
// a taint-source assignment would. funcResults is the resolution unit's
// result-type registry (nil when fn is analyzed in isolation), used only to
// pin local variable types for scalar suppression.
func analyzeFunc(fset *token.FileSet, fn *ast.FuncDecl, structFields map[string]map[string]string, paramTaint map[string]struct{}, funcResults map[string][]string) []finding {
	tainted := collectTaintedVars(fn.Body, paramTaint)
	varTypes := collectVarTypes(fn, funcResults)

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
			// Same suppression for a bare identifier whose own type is
			// provably a non-string scalar (`tail := 100` later reassigned
			// from strconv.Atoi, `n, err := s.countThings(...)`). Taint
			// tracks where a value came from; an int, bool or time.Time
			// cannot encode a forged log record regardless.
			if id, ok := arg.(*ast.Ident); ok {
				if isScalarType(varTypes[id.Name]) {
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
// declared type name. Only patterns that pin a type unambiguously are
// recorded: `var x T`, `x := T{...}`, `x := <untyped literal>`, and a
// short-decl whose right-hand side is a call to a function in the same
// resolution unit (`n, err := s.countThings(...)` → n is that function's
// first result type). Cross-package types remain dotted (`pkg.T`) —
// collectStructFields keys on simple names, so they won't match and the
// linter stays conservative on imports.
//
// A name that resolves to two different types within the function (a
// shadowing re-declaration in a nested scope, which this flat walk cannot
// distinguish) is demoted to the unknown type "", because the only consumer
// of this map suppresses findings: guessing wrong must never silently drop
// one. funcResults may be nil, in which case no same-package call is
// resolved.
func collectVarTypes(fn *ast.FuncDecl, funcResults map[string][]string) map[string]string {
	out := map[string]string{}
	recv := receiverName(fn)

	// Every binding is recorded, including the ones whose type could not be
	// inferred (""). Recording those matters as much as the resolved ones: a
	// name bound once to an int and once to an unresolved expression must
	// come out unknown, not int, or the second binding inherits the first
	// binding's suppression.
	record := func(name, typ string) {
		if name == "" || name == "_" {
			return
		}
		if prev, seen := out[name]; seen && prev != typ {
			out[name] = "" // ambiguous within the function — treat as unknown
			return
		}
		out[name] = typ
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
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
					record(name.Name, typ)
				}
			}
		case *ast.AssignStmt:
			if v.Tok != token.DEFINE {
				return true
			}
			// `a, b := f(...)` — one call supplying every LHS positionally.
			var results []string
			if len(v.Rhs) == 1 && len(v.Lhs) > 1 {
				if call, ok := unparen(v.Rhs[0]).(*ast.CallExpr); ok {
					if r, ok := samePackageResultTypes(call, recv, funcResults); ok && len(r) == len(v.Lhs) {
						results = r
					}
				}
			}
			for i, lhs := range v.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				switch {
				case results != nil:
					record(id.Name, results[i])
				case len(v.Lhs) == len(v.Rhs):
					record(id.Name, staticTypeOf(v.Rhs[i], recv, funcResults))
				default:
					record(id.Name, "") // unresolved multi-value RHS
				}
			}
		}
		return true
	})
	return out
}

// staticTypeOf names the type an expression evaluates to, for the narrow set
// of forms that pin one without a full type checker: a composite literal, an
// untyped constant literal, the predeclared booleans, and a call to a
// single-result function in the same resolution unit. Everything else returns
// "" (unknown), which the caller treats as "not provably scalar".
func staticTypeOf(e ast.Expr, recv string, funcResults map[string][]string) string {
	switch v := unparen(e).(type) {
	case *ast.CompositeLit:
		if v.Type != nil {
			return exprString(v.Type)
		}
	case *ast.BasicLit:
		switch v.Kind {
		case token.INT:
			return "int"
		case token.FLOAT:
			return "float64"
		case token.IMAG:
			return "complex128"
		case token.CHAR:
			return "rune"
		case token.STRING:
			return "string"
		}
	case *ast.Ident:
		if v.Name == "true" || v.Name == "false" {
			return "bool"
		}
	case *ast.CallExpr:
		if results, ok := samePackageResultTypes(v, recv, funcResults); ok && len(results) == 1 {
			return results[0]
		}
	}
	return ""
}

// samePackageResultTypes resolves a call expression to a function declared in
// the same resolution unit and returns its positional result types.
//
// Only two call shapes are accepted, and deliberately so: a bare identifier
// call (`paginateStewards(...)`, which can only name a function in this
// package or a builtin, and builtins are absent from funcResults), and a
// method call on the enclosing function's own receiver (`s.revoke(...)`,
// which is a method on this package's own type). A selector call on any
// other identifier is rejected even when the name matches, because
// `client.Get(...)` on an imported type would otherwise borrow the result
// types of an unrelated same-named local function — and since this registry
// feeds finding *suppression*, that mistake would hide a real finding rather
// than add a spurious one.
func samePackageResultTypes(call *ast.CallExpr, recv string, funcResults map[string][]string) ([]string, bool) {
	if funcResults == nil {
		return nil, false
	}
	var name string
	switch fun := unparen(call.Fun).(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		id, ok := unparen(fun.X).(*ast.Ident)
		if !ok || recv == "" || id.Name != recv {
			return nil, false
		}
		name = fun.Sel.Name
	default:
		return nil, false
	}
	results, ok := funcResults[name]
	return results, ok
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
// a taint source, or derived from an already-tainted value, somewhere in the
// given subtree. Callers pass a function body so taint stays function-scoped
// — a name reassigned to a safe value in another function doesn't get
// tainted here.
//
// seed pre-populates the returned set before propagation runs — used to mark
// a function's own parameters as tainted when a same-package caller passes a
// tainted argument (see resolveParameterTaint). A nil seed analyzes the body
// in isolation, matching this function's original single-argument behavior.
func collectTaintedVars(root ast.Node, seed map[string]struct{}) map[string]struct{} {
	tainted := map[string]struct{}{}
	for name := range seed {
		tainted[name] = struct{}{}
	}

	// `var x = <source>` pins x directly. The general AssignStmt case
	// (including the direct-source assignment `x := <source>`) is handled by
	// the unified fixed-point loop below, since taintPropagatesFrom already
	// recognizes a raw taint source on its first check.
	ast.Inspect(root, func(n ast.Node) bool {
		decl, ok := n.(*ast.DeclStmt)
		if !ok {
			return true
		}
		gen, ok := decl.Decl.(*ast.GenDecl)
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

	// Unified propagation pass. A single fixed-point loop covers every shape
	// a tainted value can flow through on its way to a sink:
	//
	//   - a direct assignment from a raw taint source (x := mux.Vars(r)["id"])
	//   - a method call on an already-tainted receiver, chained or not
	//     (r.URL.Query().Get("id") / q.Get("id") where q := r.URL.Query())
	//   - a plain alias (alias := id)
	//   - fmt.Sprintf / string concatenation over a tainted operand
	//   - any call carrying a tainted argument (fmt.Errorf wraps, gRPC/store
	//     calls whose error message quotes the offending input) -- regardless
	//     of what the result is named; an error produced from tainted input
	//     carries that input back out inside its message text, so logging it
	//     bare is the same injection as logging the value, whether it's bound
	//     to `err` or reassigned to something else first
	//   - a struct-field write (s.Field = tainted) or a composite literal at
	//     declaration (s := &T{Field: tainted}) taints the whole containing
	//     variable, not just the field -- deliberately over-approximate, so a
	//     later bare-identifier use of that variable as a call argument is
	//     already caught by the existing anyArgTainted machinery
	//
	// Iterated to a fixed point so a multi-hop chain (tainted arg -> alias ->
	// Sprintf -> wrapped err) resolves in one call. Five rounds is far beyond
	// any real handler's depth and bounds a pathological input.
	for i := 0; i < 5; i++ {
		changed := false
		ast.Inspect(root, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) == 0 {
				return true
			}
			for idx, lhs := range assign.Lhs {
				var rhs ast.Expr
				switch {
				case idx < len(assign.Rhs):
					rhs = assign.Rhs[idx]
				case len(assign.Rhs) == 1:
					rhs = assign.Rhs[0]
				default:
					continue
				}
				switch l := lhs.(type) {
				case *ast.SelectorExpr:
					rootID, ok := l.X.(*ast.Ident)
					if !ok {
						continue
					}
					if _, already := tainted[rootID.Name]; already {
						continue
					}
					if taintPropagatesFrom(rhs, tainted) {
						tainted[rootID.Name] = struct{}{}
						changed = true
					}
				case *ast.Ident:
					if _, already := tainted[l.Name]; already {
						continue
					}
					if taintPropagatesFrom(rhs, tainted) {
						tainted[l.Name] = struct{}{}
						changed = true
					}
				}
			}
			return true
		})
		if !changed {
			break
		}
	}

	return tainted
}

// taintPropagatesFrom reports whether assigning rhs to a variable should
// taint that variable, given the currently-known tainted set. It is the
// single decision point collectTaintedVars' fixed-point loop calls for every
// assignment LHS, covering direct taint sources (via isTaintedExpr), method
// calls on tainted receivers, calls carrying tainted arguments (guarded by
// transmitsWithoutEchoing the same way the error-wrap rule always was),
// string concatenation, and composite literals / unary address-of.
func taintPropagatesFrom(rhs ast.Expr, tainted map[string]struct{}) bool {
	if isTaintedExpr(rhs, tainted) {
		return true
	}
	switch v := unparen(rhs).(type) {
	case *ast.CallExpr:
		if isSanitized(v) || transmitsWithoutEchoing(v) {
			return false
		}
		return anyArgTainted(v.Args, tainted)
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return false
		}
		return exprCarriesTaint(v.X, tainted) || exprCarriesTaint(v.Y, tainted)
	case *ast.CompositeLit:
		return exprCarriesTaint(v, tainted)
	case *ast.UnaryExpr:
		return exprCarriesTaint(v, tainted)
	}
	return false
}

// unparen strips any enclosing parentheses from an expression.
func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// isMethodCallOnTaintedReceiver reports whether call is a method call whose
// receiver (after unwrapping parens) is either an identifier already in the
// tainted set, or itself a recognized taint source expression. This covers
// both r.URL.Query().Get("id") (receiver is the source call itself) and
// q := r.URL.Query(); q.Get("id") (receiver is a tainted identifier).
func isMethodCallOnTaintedReceiver(call *ast.CallExpr, tainted map[string]struct{}) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	recv := unparen(sel.X)
	if id, ok := recv.(*ast.Ident); ok {
		if _, ok := tainted[id.Name]; ok {
			return true
		}
	}
	return isTaintSourceExpr(recv)
}

// transmitOnlyMethods send bytes somewhere. Their errors describe the transport
// -- a closed socket, a short write -- and never quote the payload, so a tainted
// argument does not make the returned error tainted. Distinguishing these from
// calls that parse or look up the value (a decode error quotes the offending
// input, a gRPC status quotes the rejected field) is what keeps this rule from
// flagging every `w.Write` error in the codebase.
var transmitOnlyMethods = map[string]struct{}{
	"Write": {}, "WriteString": {}, "WriteHeader": {}, "Writeln": {},
	"Flush": {}, "Close": {}, "Copy": {}, "CopyN": {},
	"Fprint": {}, "Fprintf": {}, "Fprintln": {}, "Print": {}, "Printf": {}, "Println": {},
}

// transmitsWithoutEchoing reports whether a call only ships its arguments
// onward, so its error cannot carry them back.
func transmitsWithoutEchoing(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		_, ok := transmitOnlyMethods[fn.Sel.Name]
		return ok
	case *ast.Ident:
		_, ok := transmitOnlyMethods[fn.Name]
		return ok
	}
	return false
}

// anyArgTainted reports whether any argument carries tainted data, looking
// through the wrappers a request argument is normally built with: `&pb.Req{...}`,
// a composite literal's field values, and nested calls like `proto.String(id)`.
func anyArgTainted(args []ast.Expr, tainted map[string]struct{}) bool {
	for _, a := range args {
		if exprCarriesTaint(a, tainted) {
			return true
		}
	}
	return false
}

func exprCarriesTaint(e ast.Expr, tainted map[string]struct{}) bool {
	if e == nil {
		return false
	}
	if isTaintedExpr(e, tainted) {
		return true
	}
	switch v := e.(type) {
	case *ast.UnaryExpr:
		return exprCarriesTaint(v.X, tainted)
	case *ast.ParenExpr:
		return exprCarriesTaint(v.X, tainted)
	case *ast.CompositeLit:
		for _, el := range v.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if exprCarriesTaint(kv.Value, tainted) {
					return true
				}
				continue
			}
			if exprCarriesTaint(el, tainted) {
				return true
			}
		}
	case *ast.CallExpr:
		if isSanitized(v) {
			return false
		}
		return anyArgTainted(v.Args, tainted)
	case *ast.BinaryExpr:
		return exprCarriesTaint(v.X, tainted) || exprCarriesTaint(v.Y, tainted)
	}
	return false
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
		// A method call on an already-tainted receiver, chained or not
		// (r.URL.Query().Get("id"), or q.Get("id") where q is tainted).
		if isMethodCallOnTaintedReceiver(v, tainted) {
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
	return strings.HasSuffix(tail, "logger") || tail == "log" || tail == "slog" || tail == "l"
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
