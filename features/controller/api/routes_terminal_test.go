// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
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
