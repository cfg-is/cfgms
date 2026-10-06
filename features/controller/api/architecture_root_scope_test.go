// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rootScopeAnnotation is the escape hatch for a root-allow decision made outside
// tenantAccessForScope, in the style of //architecture:allow-raw-leader: it must
// sit on the same line as the call and carry a written reason.
const rootScopeAnnotation = "//architecture:allow-root-scope -- "

// rootAllowPattern matches the calls that grant a root caller access without
// consulting tenantAccessForScope: a TenantScope's IsRoot(), and
// isWithinTenantScope, which admits everything for the empty caller tenant
// callerTenantFilter returns to a root caller.
var rootAllowPattern = regexp.MustCompile(`\.IsRoot\(\)|\bisWithinTenantScope\(`)

// rootScopeExemptFuncs are the functions that ARE the tenant decision, where a
// root check is the decision itself rather than a bypass of it.
var rootScopeExemptFuncs = map[string]bool{
	"tenantAccessForScope": true,
	"isWithinTenantScope":  true,
}

var funcNamePattern = regexp.MustCompile(`^func (?:\([^)]*\) )?(\w+)`)

// callerTenantAssign matches a variable assigned the caller's tenant filter —
// "" for a root caller — from callerTenantFilter, callerTenantID or
// authRunAccess (whose second result is that filter).
var callerTenantAssign = regexp.MustCompile(
	`(?:^|[\s(])(\w+)\s*:?=\s*(?:s\.)?(?:callerTenantFilter|callerTenantID)\(` +
		`|(?:^|\s)\w+,\s*(\w+),\s*\w+\s*:?=\s*s\.authRunAccess\(`)

// inlineCallerTenantCompare matches the filter compared with "" without a
// variable in between.
var inlineCallerTenantCompare = regexp.MustCompile(`(?:callerTenantFilter|callerTenantID)\([^)]*\)\s*[!=]=\s*""`)

// comparesCallerTenant reports whether line compares the caller's tenant filter
// with "" — the hand-written form of "is this caller root" — either inline or
// through a variable the current function assigned from it.
func comparesCallerTenant(line string, callerVars map[string]bool) bool {
	if inlineCallerTenantCompare.MatchString(line) {
		return true
	}
	for name := range callerVars {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*[!=]=\s*""`).MatchString(line) {
			return true
		}
	}
	return false
}

// checkRootAllowCalls returns "path:line: text" for every root-allow call in src
// that is outside an exempt function and lacks the annotation with a reason.
func checkRootAllowCalls(path string, src []byte) []string {
	var violations []string
	currentFunc := ""
	callerVars := map[string]bool{}
	for i, line := range strings.Split(string(src), "\n") {
		if m := funcNamePattern.FindStringSubmatch(line); m != nil {
			currentFunc = m[1]
			callerVars = map[string]bool{}
		}
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "//") {
			continue
		}
		if m := callerTenantAssign.FindStringSubmatch(line); m != nil {
			for _, name := range m[1:] {
				if name != "" && name != "_" {
					callerVars[name] = true
				}
			}
		}
		if !rootAllowPattern.MatchString(line) && !comparesCallerTenant(line, callerVars) {
			continue
		}
		if strings.HasPrefix(code, "func isWithinTenantScope(") || rootScopeExemptFuncs[currentFunc] {
			continue
		}
		idx := strings.Index(line, rootScopeAnnotation)
		if idx >= 0 && strings.TrimSpace(line[idx+len(rootScopeAnnotation):]) != "" {
			continue
		}
		violations = append(violations, fmt.Sprintf("%s:%d: %s", path, i+1, code))
	}
	return violations
}

// TestRootScopeDecisionsGoThroughTenantAccess enforces Issue #4665's single
// decision point for root callers in features/controller/api: a root caller's
// access to a tenant's records is decided by tenantAccessForScope, which holds a
// principal subject to the ADR-025 crossing boundary to a crossing. Any other
// place that lets a root caller through — a TenantScope.IsRoot() branch, or an
// isWithinTenantScope call fed callerTenantFilter's root answer — must carry
//
//	//architecture:allow-root-scope -- <reason>
//
// on the same line: a fleet-wide resource owned by no tenant, a tenant the root
// caller selected and that already passed the crossing, list or by-ID read
// breadth, or a comparison that does not involve the caller at all.
//
// Annotate, don't weaken: if the rule fires on a legitimate decision, add the
// annotation with the reason rather than an exemption.
//
// It also covers the hand-written form: comparing the caller's tenant filter
// (from callerTenantFilter, callerTenantID or authRunAccess) with "".
//
// Known evasion limits: the rule matches by name, line by line, within one
// function. It does not follow the filter through a parameter, a struct field
// or a local wrapper. Those are violations of the same intent.
func TestRootScopeDecisionsGoThroughTenantAccess(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	var violations []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		violations = append(violations, checkRootAllowCalls(f, src)...)
	}
	sort.Strings(violations)
	assert.Empty(t, violations,
		"root-allow decision outside tenantAccessForScope without "+rootScopeAnnotation+
			"<reason>; route it through tenantAccessForScope, or annotate it with why root may pass: %v", violations)
}

// TestRootScopeRuleDetectsViolation proves the rule fires on an unannotated
// root-allow call and on an annotation with no reason, and stays quiet on an
// annotated call and inside tenantAccessForScope.
func TestRootScopeRuleDetectsViolation(t *testing.T) {
	src := []byte(`package api

func a(scope ctxkeys.TenantScope) bool {
	return scope.IsRoot()
}

func b(caller, tenant string) bool {
	return isWithinTenantScope(caller, tenant) //architecture:allow-root-scope --
}

func c(scope ctxkeys.TenantScope) bool {
	return scope.IsRoot() //architecture:allow-root-scope -- fleet-wide resource
}

func (s *Server) tenantAccessForScope(scope ctxkeys.TenantScope) bool {
	return scope.IsRoot()
}
`)
	violations := checkRootAllowCalls("x.go", src)
	require.Len(t, violations, 2, "%v", violations)
	assert.Contains(t, violations[0], "x.go:4:")
	assert.Contains(t, violations[1], "x.go:8:")
}
