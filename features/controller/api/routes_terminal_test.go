// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTerminalScopeTestServer builds a minimal Server with a real ControllerService
// registry seeded with the given stewards (id → tenant). Only the fields the
// terminal tenant-scoping wrapper touches are populated.
func newTerminalScopeTestServer(t *testing.T, stewards map[string]string) *Server {
	t.Helper()
	cs := service.NewControllerService(logging.NewNoopLogger())
	for id, tenant := range stewards {
		require.NoError(t, cs.RegisterSteward(id, tenant, "addr", "active"))
	}
	return &Server{controllerService: cs}
}

// serveTerminalScope drives a request through the wrapper with a sentinel
// downstream handler and returns the recorder plus whether the downstream ran.
func serveTerminalScope(s *Server, callerTenant, stewardID string) (*httptest.ResponseRecorder, *bool) {
	reached := new(bool)
	wrapped := s.tenantScopedTerminalWrapper(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/ws/"+stewardID, nil)
	req = mux.SetURLVars(req, map[string]string{"steward_id": stewardID})
	if callerTenant != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, callerTenant))
	}
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec, reached
}

// TestTerminalScope_SameTenantAllowed verifies a caller reaches a steward owned
// by its own tenant.
func TestTerminalScope_SameTenantAllowed(t *testing.T) {
	s := newTerminalScopeTestServer(t, map[string]string{"steward-a": "root/msp-a"})
	rec, reached := serveTerminalScope(s, "root/msp-a", "steward-a")
	assert.True(t, *reached, "same-tenant steward must reach the terminal handler")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestTerminalScope_DescendantTenantAllowed verifies a caller reaches a steward
// in a descendant tenant subtree.
func TestTerminalScope_DescendantTenantAllowed(t *testing.T) {
	s := newTerminalScopeTestServer(t, map[string]string{"steward-child": "root/msp-a/client-1"})
	rec, reached := serveTerminalScope(s, "root/msp-a", "steward-child")
	assert.True(t, *reached, "descendant-tenant steward must reach the terminal handler")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestTerminalScope_CrossTenantRejected verifies the core isolation guarantee: a
// scoped caller in tenant A cannot open a terminal to a steward owned by tenant B.
// The response is 404 (not 403) so steward existence is not disclosed cross-tenant.
func TestTerminalScope_CrossTenantRejected(t *testing.T) {
	s := newTerminalScopeTestServer(t, map[string]string{"steward-b": "root/msp-b"})
	rec, reached := serveTerminalScope(s, "root/msp-a", "steward-b")
	assert.False(t, *reached, "cross-tenant steward must NOT reach the terminal handler")
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant terminal access must be rejected with 404")
}

// TestTerminalScope_UnknownStewardRejected verifies an unknown steward yields 404.
func TestTerminalScope_UnknownStewardRejected(t *testing.T) {
	s := newTerminalScopeTestServer(t, nil)
	rec, reached := serveTerminalScope(s, "root/msp-a", "ghost")
	assert.False(t, *reached)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestTerminalScope_SiblingPrefixNotAncestor verifies that a tenant string which
// merely shares a prefix (root/msp-a vs root/msp-ab) is not treated as ancestry.
func TestTerminalScope_SiblingPrefixNotAncestor(t *testing.T) {
	s := newTerminalScopeTestServer(t, map[string]string{"steward-ab": "root/msp-ab"})
	rec, reached := serveTerminalScope(s, "root/msp-a", "steward-ab")
	assert.False(t, *reached, "prefix-sharing sibling tenant must not be treated as descendant")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// serveTerminalScopeAsRootScoped drives a request through the wrapper with a root-scoped
// principal in context (ADR-025 Amendment 1 A1.3). callerTenant is intentionally not set
// in context because root-scoped principals have TenantID == "".
func serveTerminalScopeAsRootScoped(s *Server, principal *Principal, stewardID string) (*httptest.ResponseRecorder, *bool) {
	reached := new(bool)
	wrapped := s.tenantScopedTerminalWrapper(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/ws/"+stewardID, nil)
	req = mux.SetURLVars(req, map[string]string{"steward_id": stewardID})
	ctx := req.Context()
	ctx = context.WithValue(ctx, principalContextKey, principal)
	// TenantID intentionally absent: root-scoped principals have TenantID == "".
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req.WithContext(ctx))
	return rec, reached
}

// TestTerminalScope_RootScoped_NilTenantManager_Returns401Challenge verifies the
// ADR-025 Decision 1 root-scoped guard (Issue #3303): when tenantManager is nil,
// the wrapper fails closed with a tenant-crossing challenge rather than allowing
// access, matching authorizeRootScopedTenantAccess's nil-store stance.
func TestTerminalScope_RootScoped_NilTenantManager_Returns401Challenge(t *testing.T) {
	s := newTerminalScopeTestServer(t, map[string]string{"steward-msp": "root/msp-a"})
	// tenantManager is nil by default in the minimal test server.
	principal := rootScopedPrincipal("root-op")
	rec, reached := serveTerminalScopeAsRootScoped(s, principal, "steward-msp")
	assert.False(t, *reached, "root-scoped caller with nil tenantManager must not reach handler")
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"root-scoped caller with nil tenantManager must receive a crossing challenge")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`,
		"challenge must advertise the tenant-crossing remedy")
}

// TestTerminalScope_RootScoped_NoCrossing_Returns401Challenge verifies the
// REQUIRED TEST from ADR-025 Decision 1 (Issue #3303, AC "asserts the guard denies
// a foreign-tenant/foreign-subtree request"): a root-scoped principal without an
// active crossing for the steward's tenant receives a step-up-shaped challenge.
func TestTerminalScope_RootScoped_NoCrossing_Returns401Challenge(t *testing.T) {
	// Full server with a real tenantManager and crossing store — mirrors
	// setupCrossingTestServer but also seeds a steward in controllerService.
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	require.NoError(t, server.controllerService.RegisterSteward("steward-msp", "msp-a", "addr", "active"))

	principal := rootScopedPrincipal("root-op")
	rec, reached := serveTerminalScopeAsRootScoped(server, principal, "steward-msp")
	assert.False(t, *reached, "root-scoped caller without crossing must not reach handler")
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"root-scoped caller without crossing must receive a tenant-crossing challenge")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
}

// TestTerminalScope_RootScoped_WithCrossing_Allowed verifies the REQUIRED TEST
// counterpart (Issue #3303, AC "allows an in-scope one"): a root-scoped principal
// with an active crossing grant for the steward's tenant reaches the downstream handler.
func TestTerminalScope_RootScoped_WithCrossing_Allowed(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-b", ParentID: "root"})
	require.NoError(t, err)

	require.NoError(t, server.controllerService.RegisterSteward("steward-msp-b", "msp-b", "addr", "active"))

	// Grant a crossing for the root-scoped operator to msp-b.
	principal := rootScopedPrincipal("root-op-2")
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID:          "grant-terminal-1",
		TenantID:    "msp-b",
		PrincipalID: principal.ID,
		Kind:        business.TenantCrossingKindGrant,
		GrantedBy:   "msp-b-admin",
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Hour),
	}))

	rec, reached := serveTerminalScopeAsRootScoped(server, principal, "steward-msp-b")
	assert.True(t, *reached, "root-scoped caller with active crossing must reach the handler")
	assert.Equal(t, http.StatusOK, rec.Code)
}
