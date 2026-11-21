// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// unresolvedPermissionSites names the requirePermission call sites whose arguments are not
// string literals or package constants because they are parameters of a local closure. The
// IDs each one receives are listed here and checked like any other route permission; the test
// fails if the site disappears (a stale entry) or if any other site cannot be resolved.
var unresolvedPermissionSites = map[string][]string{
	// guard(resource, action, h) in registerDirectoryCredentialRoutes.
	"routes_directory_credentials.go": {"directory:credential-list", "directory:credential-reveal"},
}

// routePermissionIDs returns every permission ID checked through requirePermission in the
// package's non-test sources, keyed by ID to the call sites that check it. Arguments are
// resolved from string literals and same-package string constants. A call whose arguments
// resolve to neither is reported in unresolved (as "file:line").
func routePermissionIDs(t *testing.T) (ids map[string][]string, unresolved map[string][]string) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	require.NoError(t, err)
	pkg, ok := pkgs["api"]
	require.True(t, ok, "package api must parse")

	consts := map[string]string{}
	for _, f := range pkg.Files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, err := strconv.Unquote(lit.Value); err == nil {
							consts[name.Name] = v
						}
					}
				}
			}
		}
	}
	resolve := func(e ast.Expr) (string, bool) {
		switch x := e.(type) {
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return "", false
			}
			v, err := strconv.Unquote(x.Value)
			return v, err == nil
		case *ast.Ident:
			v, ok := consts[x.Name]
			return v, ok
		}
		return "", false
	}

	ids = map[string][]string{}
	unresolved = map[string][]string{}
	for path, f := range pkg.Files {
		file := strings.TrimPrefix(path, "./")
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "requirePermission" || len(call.Args) != 2 {
				return true
			}
			site := file + ":" + strconv.Itoa(fset.Position(call.Pos()).Line)
			res, rok := resolve(call.Args[0])
			act, aok := resolve(call.Args[1])
			if !rok || !aok {
				unresolved[file] = append(unresolved[file], site)
				return true
			}
			id := res + ":" + act
			ids[id] = append(ids[id], site)
			return true
		})
	}
	return ids, unresolved
}

// TestEveryRoutePermissionIsGrantableOrExempt is a [REQUIRED TEST] for Issue #6383: every
// permission a route checks with requirePermission must be grantable through account and API
// key create (isKnownPermission), or be one of the named ungrantable IDs. Without it a route
// can require a permission no account can hold, so only an implicit-admin principal reaches it.
func TestEveryRoutePermissionIsGrantableOrExempt(t *testing.T) {
	ids, unresolved := routePermissionIDs(t)
	require.NotEmpty(t, ids, "the AST walk must find the package's requirePermission call sites")

	for file, sites := range unresolved {
		want, named := unresolvedPermissionSites[file]
		if !named {
			t.Errorf("requirePermission call with arguments that are neither string literals nor package constants, and not named in unresolvedPermissionSites: %v", sites)
			continue
		}
		for _, id := range want {
			assert.True(t, isKnownPermission(id) || ungrantablePermissions[id],
				"%s: closure-supplied permission %q is neither grantable nor exempt", file, id)
		}
	}
	for file := range unresolvedPermissionSites {
		assert.Contains(t, unresolved, file, "unresolvedPermissionSites names %s but it has no unresolved requirePermission call; remove the stale entry", file)
	}

	var bad []string
	for id, sites := range ids {
		if !isKnownPermission(id) && !ungrantablePermissions[id] {
			bad = append(bad, id+" ("+strings.Join(sites, ", ")+")")
		}
	}
	sort.Strings(bad)
	assert.Empty(t, bad, "route permissions that no account or API key can be granted; add to knownPermissions or, if deliberately ungrantable, to ungrantablePermissions")
}

// TestUngrantablePermissionsAreExactlyTheWebAuthnPair pins the exemption list: widening it
// reopens the drift this story closed, so a change here must be deliberate.
func TestUngrantablePermissionsAreExactlyTheWebAuthnPair(t *testing.T) {
	assert.Equal(t, map[string]bool{
		"webauthn:assert-presence": true,
		"webauthn:elevate":         true,
	}, ungrantablePermissions)
	for id := range ungrantablePermissions {
		assert.False(t, isKnownPermission(id), "%s is exempt because it is not grantable", id)
		_, ok := permissionAssurance[id]
		assert.True(t, ok, "%s lives in permissionAssurance", id)
	}
}

// TestRoutePermissionsAreGrantableWithSiblingAssurance covers the thirteen IDs of Issue #6383
// and the assurance chosen for the writes.
func TestRoutePermissionsAreGrantableWithSiblingAssurance(t *testing.T) {
	for _, id := range routePermissions {
		assert.True(t, isKnownPermission(id), "%s must be grantable", id)
	}
	assert.Len(t, routePermissions, 13)

	assert.Equal(t, permissionAssurance["config:push"], permissionAssurance["config:rollback"], "config:rollback mirrors config:push")
	assert.Equal(t, permissionAssurance["refresh:approve"], permissionAssurance["refresh:reject"], "refresh:reject mirrors refresh:approve")
	assert.Equal(t, permissionAssurance["rbac:update-role"].Min, permissionAssurance["role:write"].Min, "role:write mirrors the rbac:*-role writes")
	assert.Equal(t, permissionAssurance["rbac:update-role"].RequireUserPresence, permissionAssurance["role:write"].RequireUserPresence, "role:write mirrors the rbac:*-role writes")
	// Deleting a role reduces access, so it stays tap-free (Issue #6408, ADR-021 Amendment 13).
	assert.Equal(t, []string{"DELETE /api/v1/roles/{name}"}, permissionAssurance["role:write"].PresenceExemptRoutes)
	assert.Equal(t, session.AssuranceStrong, permissionAssurance["role:write"].Min)

	for _, id := range []string{
		"audit:list", "case:create", "case:list", "case:read", "case:update",
		"refresh:get-policy", "refresh:list-pending", "role:read", "steward:tag:read", "steward:tag:write",
	} {
		_, has := permissionAssurance[id]
		assert.False(t, has, "%s has no assurance entry, like its siblings", id)
	}
}

// TestAccounts_NewRoutePermissionsGrantAccessThroughRouter is a [REQUIRED TEST] for Issue
// #6383: an account created through POST /api/v1/accounts with case:list and audit:list is
// accepted, and a session for it reaches GET /api/v1/cases and GET /api/v1/audit/entries.
func TestAccounts_NewRoutePermissionsGrantAccessThroughRouter(t *testing.T) {
	server := setupCasesTestServer(t)
	seedAccountTenants(t, server)

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username:    "case-audit-reader",
		TenantID:    "client-1",
		Permissions: []string{"case:list", "audit:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	acct, err := server.getAccount(context.Background(), "case-audit-reader")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.ElementsMatch(t, []string{"case:list", "audit:list"}, acct.Permissions)

	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	server.SetSessionManager(session.NewManager(cfg, store, time.Now))
	_, token, err := server.sessionManager.Issue(context.Background(), acct.ID, "cfg-cli", acct.TenantID)
	require.NoError(t, err)

	for _, path := range []string{"/api/v1/cases", "/api/v1/audit/entries"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		out := httptest.NewRecorder()
		server.router.ServeHTTP(out, req)
		assert.Equal(t, http.StatusOK, out.Code, "%s: body: %s", path, out.Body.String())
	}

	// A permission the account was not granted stays denied.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", strings.NewReader(`{"tenant_id":"client-1"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	server.router.ServeHTTP(out, req)
	assert.Equal(t, http.StatusForbidden, out.Code, "case:create was not granted; body: %s", out.Body.String())
}

// TestAccounts_NewRoutePermissionsCannotBeEscalated is a [REQUIRED TEST] for Issue #6383:
// the PERMISSION_ESCALATION guard covers the newly grantable IDs on both create and update.
func TestAccounts_NewRoutePermissionsCannotBeEscalated(t *testing.T) {
	server := setupTestServer(t)
	seedAccountTenants(t, server)

	caller := &Principal{
		ID:          "limited-new-perm-caller",
		TenantID:    "client-1",
		Assurance:   session.AssuranceStrong,
		Permissions: []string{"account:create", "account:update"},
	}
	for _, perm := range []string{"case:list", "audit:list"} {
		rec := postAccount(t, server, caller, AccountRequest{
			Username:    "escalate-" + strings.ReplaceAll(perm, ":", "-"),
			TenantID:    "client-1",
			Permissions: []string{perm},
		})
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s: body: %s", perm, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "PERMISSION_ESCALATION", perm)
	}

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: "escalate-update-target", TenantID: "client-1"})
	require.Equal(t, http.StatusCreated, rec.Code)
	newPerms := []string{"role:write"}
	rec = putAccount(t, server, caller, "escalate-update-target", AccountUpdateRequest{Permissions: &newPerms})
	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "PERMISSION_ESCALATION")
}
