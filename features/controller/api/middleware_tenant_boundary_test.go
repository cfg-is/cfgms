// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// tenantBoundaryRoute describes one route whose path names a specific tenant, together
// with the permission requirePermission is constructed with for it and the mux path
// variable carrying the tenant.
//
// remedy marks the two ADR-025 Decision 2 endpoints the middleware boundary must NOT
// pre-empt (tenantCrossingRemedyPermissions): break-glass is how a root-scoped caller
// obtains its first crossing, and the grant endpoint refuses root-scoped callers outright
// in its own handler.
type tenantBoundaryRoute struct {
	method     string
	template   string
	pathVar    string
	permission string
	remedy     bool
}

// tenantBoundaryRouteTable enumerates every tenant-targeting route under /api/v1/tenants.
// TestTenantBoundaryRouteTable_MatchesRouter keeps it exhaustive: a new tenant-targeting
// route fails that test until it is listed here, at which point the boundary assertions
// below apply to it automatically. That coupling is the regression control — before it,
// the ADR-025 root<->MSP boundary was re-established handler-by-handler, and the routes
// whose handlers never called authorizeTenantAccess (suspend, config-source/test,
// refresh-policy, assurance-policy) silently sat outside it.
var tenantBoundaryRouteTable = []tenantBoundaryRoute{
	{http.MethodGet, "/api/v1/tenants/{id}", "id", "tenant:read", false},
	{http.MethodPut, "/api/v1/tenants/{id}", "id", "tenant:update", false},
	{http.MethodPost, "/api/v1/tenants/{id}/suspend", "id", "tenant:manage", false},
	{http.MethodPost, "/api/v1/tenants/{id}/config-source/test", "id", "tenant:manage", false},
	{http.MethodGet, "/api/v1/tenants/{id}/access-grants", "id", "tenant:crossing-list", false},
	{http.MethodGet, "/api/v1/tenants/{tenant_id}/reboot-window", "tenant_id", "reboot_window:read", false},
	{http.MethodPut, "/api/v1/tenants/{tenant_id}/reboot-window", "tenant_id", "reboot_window:override", false},
	{http.MethodPost, "/api/v1/tenants/{id}/access-grants", "id", "tenant:crossing-grant", true},
	{http.MethodPost, "/api/v1/tenants/{id}/break-glass", "id", "tenant:crossing-break-glass", true},
	{http.MethodGet, "/api/v1/tenants/{tenant_path:.+}/refresh-policy", "tenant_path", "refresh:get-policy", false},
	{http.MethodPut, "/api/v1/tenants/{tenant_path:.+}/refresh-policy", "tenant_path", "refresh:set-policy", false},
	{http.MethodGet, "/api/v1/tenants/{tenant_path:.+}/assurance-policy", "tenant_path", "assurance-policy:get", false},
	{http.MethodPut, "/api/v1/tenants/{tenant_path:.+}/assurance-policy", "tenant_path", "assurance-policy:set", false},
}

func (e tenantBoundaryRoute) String() string { return e.method + " " + e.template }

// TestTenantBoundaryRouteTable_MatchesRouter asserts tenantBoundaryRouteTable lists
// exactly the registered routes that name a tenant in their path. Adding a tenant-targeting
// route without listing it here fails this test, which is what forces the new route through
// the root-scope boundary assertions in this file.
func TestTenantBoundaryRouteTable_MatchesRouter(t *testing.T) {
	server := setupTestServer(t)

	var registered []string
	for _, entry := range walkRoutes(t, server.router) {
		// Only routes that name a specific tenant: "/api/v1/tenants/{...".
		if strings.HasPrefix(entry.path, "/api/v1/tenants/{") {
			registered = append(registered, entry.String())
		}
	}
	sort.Strings(registered)

	expected := make([]string, 0, len(tenantBoundaryRouteTable))
	for _, e := range tenantBoundaryRouteTable {
		expected = append(expected, e.String())
	}
	sort.Strings(expected)

	assert.Equal(t, expected, registered,
		"every tenant-targeting route must be listed in tenantBoundaryRouteTable so the "+
			"ADR-025 root<->MSP boundary assertions in this file cover it")
}

// boundaryTestServer builds a crossing-store-backed server with a "root" tenant and an
// "msp-a" child of it — the exact shape ADR-025 Decision 1 governs.
func boundaryTestServer(t *testing.T) *Server {
	t.Helper()
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)
	return server
}

// serveBoundaryRoute runs entry's permission middleware around a probe handler with
// principal in context and the tenant path variable set to targetTenant, returning the
// recorder and whether the probe was reached.
func serveBoundaryRoute(t *testing.T, server *Server, entry tenantBoundaryRoute, principal *Principal, targetTenant string) (*httptest.ResponseRecorder, bool) {
	t.Helper()

	reached := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	parts := strings.SplitN(entry.permission, ":", 2)
	require.Len(t, parts, 2, "permission %q must be resource:action", entry.permission)
	handler := server.requirePermission(parts[0], parts[1])(probe)

	path := strings.Replace(entry.template, "{"+entry.pathVar+"}", targetTenant, 1)
	path = strings.Replace(path, "{"+entry.pathVar+":.+}", targetTenant, 1)
	req := httptest.NewRequest(entry.method, path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{entry.pathVar: targetTenant})
	ctx := context.WithValue(req.Context(), principalContextKey, principal)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, principal.TenantID)
	req = req.WithContext(ctx)

	// Permissions carrying RequireUserPresence would 401 at the presence gate before the
	// boundary check runs, which would make these assertions pass for the wrong reason.
	if permReq, found := permissionAssurance[entry.permission]; found && permReq.RequireUserPresence {
		req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, principal.ID))
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, reached
}

// boundaryTestPrincipal returns a root-scoped principal shaped like a real mTLS
// SaaS-operator: AssuranceStrong plus a cert serial, so neither the assurance gate nor
// the former Tier-3 gate is what stops the request.
func boundaryTestPrincipal(id string) *Principal {
	p := rootScopedPrincipal(id)
	p.CertSerial = "boundary-test-serial"
	return p
}

// TestRootScopedPrincipal_BlockedOnEveryTenantRoute is the regression test for the
// ADR-025 Decision 1 gap: a root-scoped SaaS-operator with no active crossing must be
// stopped before ANY tenant-targeting handler runs — not only in the handlers that
// happen to call authorizeTenantAccess. Before the middleware boundary check, this test
// failed on tenant:manage's suspend and config-source/test and on the refresh-policy and
// assurance-policy routes: the probe was reached, meaning a root-scoped operator could
// suspend an MSP tenant or drive a config-source test against that tenant's git
// credential with no grant and no break-glass record.
func TestRootScopedPrincipal_BlockedOnEveryTenantRoute(t *testing.T) {
	server := boundaryTestServer(t)
	caller := boundaryTestPrincipal("root-operator-1")

	for _, entry := range tenantBoundaryRouteTable {
		entry := entry
		if entry.remedy {
			continue
		}
		t.Run(entry.String(), func(t *testing.T) {
			rec, reached := serveBoundaryRoute(t, server, entry, caller, "msp-a")

			require.False(t, reached,
				"root-scoped caller without a crossing must not reach the %s handler", entry.permission)
			require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)

			var body map[string]interface{}
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
			assert.Equal(t, "tenant_crossing_required", body["error"])
			assert.Equal(t, "/api/v1/tenants/msp-a/break-glass", body["break_glass_endpoint"],
				"the challenge must name the remedy so a legitimate break-glass invocation has a path forward")
		})
	}
}

// TestRootScopedPrincipal_RemedyRoutesNotPreEmpted verifies the boundary check does not
// close the door it exists to open: break-glass (and the grant endpoint, whose handler
// refuses root-scoped callers itself) must still reach their handlers, otherwise a
// root-scoped operator could never obtain a first crossing.
func TestRootScopedPrincipal_RemedyRoutesNotPreEmpted(t *testing.T) {
	server := boundaryTestServer(t)
	caller := boundaryTestPrincipal("root-operator-1")

	for _, entry := range tenantBoundaryRouteTable {
		entry := entry
		if !entry.remedy {
			continue
		}
		t.Run(entry.String(), func(t *testing.T) {
			rec, reached := serveBoundaryRoute(t, server, entry, caller, "msp-a")

			assert.True(t, reached,
				"%s must reach its handler: the middleware boundary must not pre-empt the remedy path", entry.permission)
			assert.NotContains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
		})
	}
}

// TestRootScopedPrincipal_AllowedOnEveryTenantRouteWithActiveCrossing is the positive
// half: with an active grant (ADR-025 Decision 2(a)) the same caller must reach every
// handler. Without this, a blanket deny would satisfy the test above while breaking
// legitimate, consented support access.
func TestRootScopedPrincipal_AllowedOnEveryTenantRouteWithActiveCrossing(t *testing.T) {
	server := boundaryTestServer(t)
	caller := boundaryTestPrincipal("root-operator-1")

	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(context.Background(), &business.TenantCrossing{
		ID:          "grant-boundary-1",
		TenantID:    "msp-a",
		PrincipalID: caller.ID,
		Kind:        business.TenantCrossingKindGrant,
		GrantedBy:   "msp-a-admin",
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Hour),
	}))

	for _, entry := range tenantBoundaryRouteTable {
		entry := entry
		t.Run(entry.String(), func(t *testing.T) {
			_, reached := serveBoundaryRoute(t, server, entry, caller, "msp-a")
			assert.True(t, reached,
				"an active grant must admit the root-scoped caller to %s", entry.permission)
		})
	}
}

// TestRootScopedPrincipal_RootTenantItselfAlwaysAllowed verifies the boundary confines a
// root-scoped caller to "root" rather than locking it out of its own scope (ADR-025
// Decision 1) — the operator manages the root tenant with no crossing at all.
func TestRootScopedPrincipal_RootTenantItselfAlwaysAllowed(t *testing.T) {
	server := boundaryTestServer(t)
	caller := boundaryTestPrincipal("root-operator-1")

	for _, entry := range tenantBoundaryRouteTable {
		entry := entry
		t.Run(entry.String(), func(t *testing.T) {
			_, reached := serveBoundaryRoute(t, server, entry, caller, rootTenantID)
			assert.True(t, reached,
				"a root-scoped caller must reach %s for the root tenant itself", entry.permission)
		})
	}
}

// TestUnscopedAdmin_UnaffectedOnEveryTenantRoute pins that the new boundary applies only
// to explicitly root-scoped principals: an ordinary unscoped admin (RootScoped == false,
// every admin cert and session issued before the marker existed) keeps today's access.
func TestUnscopedAdmin_UnaffectedOnEveryTenantRoute(t *testing.T) {
	server := boundaryTestServer(t)
	admin := &Principal{
		ID:          "admin-1",
		Name:        "mtls-admin:admin-1",
		Assurance:   session.AssuranceStrong,
		GlobalScope: true,
		TenantID:    "",
		CertSerial:  "boundary-test-serial",
	}

	for _, entry := range tenantBoundaryRouteTable {
		entry := entry
		t.Run(entry.String(), func(t *testing.T) {
			_, reached := serveBoundaryRoute(t, server, entry, admin, "msp-a")
			assert.True(t, reached,
				"an unscoped (non-root-scoped) admin must be unaffected by the ADR-025 boundary on %s", entry.permission)
		})
	}
}
