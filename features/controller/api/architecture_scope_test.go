// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file holds the detection logic for TestHandlersConsumeCallerScope
// (architecture_scope_linux_test.go, run by `make check-architecture`), plus unit
// tests proving that logic fires on a synthetic violation and stays silent on an
// annotated or already-compliant one — the same split pkg/ha uses between
// architecture_test.go (detection logic + TestRawLeaderRuleDetectsViolation) and
// architecture_linux_test.go (the real repo-scanning enforcement test).
//
// Rule (Issue #4316): a handler registered through a wrapper-indirection call —
// where the route registration's handler argument is itself the result of calling a
// local closure, such as handlers_workflows.go's `wrap("read", h.handleGetWorkflow)`
// — must consume the caller's tenant scope if it reads a caller-supplied identifier
// (mux.Vars(r)), either directly or via a helper function defined in the same file.
//
// Scope of this rule, deliberately: only wrapper-indirected registrations are
// checked, not every handler in the package directly registered via
// `s.requirePermission(resourceType, action)(http.HandlerFunc(s.handleX))`. That
// direct-registration convention already carries ~100 pre-existing call sites this
// story does not remediate (tracked as separate follow-up work); gating all of them
// here would either break the build or require an exemption list, both of which the
// story explicitly rules out. The wrapper-indirection shape is exactly the case a
// naive checker misses (the resourceType and the handler never appear next to each
// other syntactically), so this is the corpus this story can respons­ibly gate today
// — extending it to direct registrations is the next story's job once those call
// sites are fixed, not a broadened exclusion path on this one.
//
// Known evasion limits, in the same spirit as pkg/ha's raw-leader rule:
//   - "reads a caller-supplied identifier" is detected only as a literal
//     `mux.Vars(` call. A handler that instead reads an identifier from a decoded
//     JSON body, a query parameter, or a header is not detected.
//   - "consumes the scope value" is detected as a literal reference to one of a
//     fixed set of known symbol names, in the handler's own body or in a function
//     defined in the SAME FILE that the handler calls by name (one hop, not a full
//     transitive call graph). A helper under a different name in another file, or a
//     deeper call chain, is not credited.
//   - "wrapper indirection" is detected as a call whose Fun is a bare local
//     identifier (e.g. `wrap(...)`). A wrapper reached through a package-qualified
//     or method-valued reference is not detected.

// scopeConsumingSymbols are the call/reference patterns that count as "consuming"
// the caller's tenant scope. A handler (or a same-file helper it calls) referencing
// any of these has made some tenant-scoping decision about the caller-supplied
// identifier it read — the rule does not judge whether that decision is correct,
// only that one was made.
var scopeConsumingSymbols = []string{
	"isWithinTenantScope(",
	"callerTenantID(",
	"isAuthorizedForTenant(",
	"tenantAccessForScope(",
	"callerTenantFilter(",
	"callerOwnTenant(",
	"selectListTenant(",
	"ctxkeys.TenantScopeKey",
	"ctxkeys.TenantID",
}

// scopeAnnotation is the escape hatch for a handler that is legitimately
// pre-authentication (no caller identity yet to scope), in the style of
// //architecture:allow-raw-leader (pkg/ha/architecture_test.go). There is no
// exemption list — every use must carry a written reason at the call site.
const scopeAnnotation = "//architecture:allow-unscoped-tenant-read"

var identifierCallPattern = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// extractFuncSources parses src and returns the source text of every top-level func
// declaration (including methods), keyed by function name.
func extractFuncSources(fset *token.FileSet, path string, src []byte) (map[string]string, error) {
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		startPos := fn.Pos()
		if fn.Doc != nil {
			// Include the doc comment so an annotation placed above the func
			// keyword (this codebase's convention for //architecture:allow-*
			// annotations that don't fit on the call site's own line) is visible
			// to the text-based checks below.
			startPos = fn.Doc.Pos()
		}
		start := fset.Position(startPos).Offset
		end := fset.Position(fn.End()).Offset
		if start < 0 || end > len(src) || start > end {
			continue
		}
		out[fn.Name.Name] = string(src[start:end])
	}
	return out, nil
}

// containsAny reports whether text contains any of needles.
func containsAny(text string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(text, n) {
			return true
		}
	}
	return false
}

// consumesScope reports whether text itself references a scope-consuming symbol, or
// calls (by name, same-file only) a helper present in funcs that does.
func consumesScope(text string, funcs map[string]string) bool {
	if containsAny(text, scopeConsumingSymbols) {
		return true
	}
	for _, m := range identifierCallPattern.FindAllStringSubmatch(text, -1) {
		callee, ok := funcs[m[1]]
		if !ok {
			continue
		}
		if containsAny(callee, scopeConsumingSymbols) {
			return true
		}
	}
	return false
}

// readsCallerSuppliedIdentifier reports whether text reads a request-scoped
// identifier the caller controls — today, a mux.Vars(r) path variable.
func readsCallerSuppliedIdentifier(text string) bool {
	return strings.Contains(text, "mux.Vars(")
}

// isAnnotatedAllowUnscoped reports whether text carries the escape-hatch annotation.
func isAnnotatedAllowUnscoped(text string) bool {
	return strings.Contains(text, scopeAnnotation)
}

// findWrapperIndirectedHandlers scans src for routes registered through a local
// wrapper closure and returns the handler-shaped names passed through it. See the
// package-level doc comment above for the exact shape detected and its limits.
func findWrapperIndirectedHandlers(fset *token.FileSet, path string, src []byte) ([]string, error) {
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var handlers []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
			return true
		}
		if len(call.Args) < 2 {
			return true
		}
		handlers = append(handlers, findIndirectedHandlerNames(call.Args[1])...)
		return true
	})
	return handlers, nil
}

// findIndirectedHandlerNames looks for a handler reference reached through a call
// to a bare local identifier (not a package- or method-selector — e.g. not
// `s.requirePermission(...)`), and returns the handler-shaped names passed as
// arguments to that call.
func findIndirectedHandlerNames(expr ast.Expr) []string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil
	}
	if _, isLocalIdent := call.Fun.(*ast.Ident); !isLocalIdent {
		return nil
	}
	var names []string
	for _, arg := range call.Args {
		switch a := arg.(type) {
		case *ast.SelectorExpr:
			if looksLikeHandlerName(a.Sel.Name) {
				names = append(names, a.Sel.Name)
			}
		case *ast.Ident:
			if looksLikeHandlerName(a.Name) {
				names = append(names, a.Name)
			}
		}
	}
	return names
}

// looksLikeHandlerName matches this codebase's handleXxx naming convention for
// HTTP handler methods.
func looksLikeHandlerName(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "handle")
}

// TestScopeConsumptionRuleDetectsViolation proves the detection logic fires on an
// unannotated handler that reads mux.Vars without consuming scope, credits a
// same-file helper call (one-hop), and stays silent on an annotated call — the same
// shape as pkg/ha's TestRawLeaderRuleDetectsViolation. This verifies the rule is
// live, not silent.
func TestScopeConsumptionRuleDetectsViolation(t *testing.T) {
	fset := token.NewFileSet()

	t.Run("bare_mux_vars_without_scope_check_is_violation", func(t *testing.T) {
		src := []byte(`package foo
func (s *Server) handleGetThing(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_ = id
}
`)
		funcs, err := extractFuncSources(fset, "testdata/fake1.go", src)
		require.NoError(t, err)
		body := funcs["handleGetThing"]
		require.NotEmpty(t, body)
		assert.True(t, readsCallerSuppliedIdentifier(body))
		assert.False(t, isAnnotatedAllowUnscoped(body))
		assert.False(t, consumesScope(body, funcs), "expected a violation: no scope-consuming symbol anywhere")
	})

	t.Run("direct_isWithinTenantScope_call_is_allowed", func(t *testing.T) {
		src := []byte(`package foo
func (s *Server) handleGetThing(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if !isWithinTenantScope(s.callerTenantID(r), id) {
		return
	}
}
`)
		funcs, err := extractFuncSources(fset, "testdata/fake2.go", src)
		require.NoError(t, err)
		body := funcs["handleGetThing"]
		require.NotEmpty(t, body)
		assert.True(t, readsCallerSuppliedIdentifier(body))
		assert.True(t, consumesScope(body, funcs), "expected no violation: isWithinTenantScope is called directly")
	})

	t.Run("same_file_helper_one_hop_is_allowed", func(t *testing.T) {
		src := []byte(`package foo
func (h *WorkflowHandler) storeForRequest(r *http.Request) *Store {
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	return NewStore(tenantID)
}
func (h *WorkflowHandler) handleGetWorkflow(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["id"]
	store := h.storeForRequest(r)
	_, _ = store.Get(name)
}
`)
		funcs, err := extractFuncSources(fset, "testdata/fake3.go", src)
		require.NoError(t, err)
		body := funcs["handleGetWorkflow"]
		require.NotEmpty(t, body)
		assert.True(t, readsCallerSuppliedIdentifier(body))
		assert.False(t, containsAny(body, scopeConsumingSymbols), "handler's own body must not directly reference a consuming symbol in this fixture")
		assert.True(t, consumesScope(body, funcs), "expected no violation: storeForRequest (same file) reads ctxkeys.TenantID")
	})

	t.Run("helper_in_different_file_is_not_credited", func(t *testing.T) {
		src := []byte(`package foo
func (s *Server) handleGetThing(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	store := s.storeForRequest(r)
	_, _ = store.Get(id)
}
`)
		funcs, err := extractFuncSources(fset, "testdata/fake4.go", src)
		require.NoError(t, err)
		body := funcs["handleGetThing"]
		require.NotEmpty(t, body)
		// storeForRequest is not declared in this file's funcs map (it lives
		// elsewhere), so the one-hop credit must not fire.
		assert.False(t, consumesScope(body, funcs), "expected a violation: the consuming helper is not in the same file")
	})

	t.Run("annotated_call_is_allowed", func(t *testing.T) {
		src := []byte(`package foo
//architecture:allow-unscoped-tenant-read -- pre-authentication health probe, no caller identity yet
func (s *Server) handleHealthProbe(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_ = id
}
`)
		funcs, err := extractFuncSources(fset, "testdata/fake5.go", src)
		require.NoError(t, err)
		body := funcs["handleHealthProbe"]
		require.NotEmpty(t, body)
		assert.True(t, readsCallerSuppliedIdentifier(body))
		assert.True(t, isAnnotatedAllowUnscoped(body), "expected the annotation to be visible in the function's doc comment")
	})

	t.Run("no_mux_vars_is_not_applicable", func(t *testing.T) {
		src := []byte(`package foo
func (s *Server) handleListThings(w http.ResponseWriter, r *http.Request) {
	_ = "no caller-supplied identifier read here"
}
`)
		funcs, err := extractFuncSources(fset, "testdata/fake6.go", src)
		require.NoError(t, err)
		body := funcs["handleListThings"]
		require.NotEmpty(t, body)
		assert.False(t, readsCallerSuppliedIdentifier(body))
	})
}

// TestFindWrapperIndirectedHandlers_DetectsIndirectionNotDirectCalls proves the
// discovery function sees a handler registered through a local wrapper closure
// (the shape AC6 requires — handlers_workflows.go's `wrap(...)`), and does NOT
// pick up a directly-registered handler gated by the well-known requirePermission
// call — that direct-registration convention is deliberately out of this rule's
// scope (see the package doc comment above).
func TestFindWrapperIndirectedHandlers_DetectsIndirectionNotDirectCalls(t *testing.T) {
	fset := token.NewFileSet()
	src := []byte(`package foo
func (h *WorkflowHandler) RegisterWorkflowRoutes(router *mux.Router) error {
	gate := h.requirePermFn
	wrap := func(action string, fn http.HandlerFunc) http.Handler {
		return gate("workflow", action)(fn)
	}
	router.Handle("/{id}", wrap("read", h.handleGetWorkflow)).Methods("GET")
	router.Handle("/{id}", s.requirePermission("steward", "read")(http.HandlerFunc(s.handleGetSteward))).Methods("GET")
	return nil
}
`)
	handlers, err := findWrapperIndirectedHandlers(fset, "testdata/routes.go", src)
	require.NoError(t, err)
	assert.Contains(t, handlers, "handleGetWorkflow", "wrapper-indirected handler must be discovered")
	assert.NotContains(t, handlers, "handleGetSteward", "directly-registered handler must not be discovered by this rule")
}
