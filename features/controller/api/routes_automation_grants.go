// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerAutomationGrantRoutes) }

// registerAutomationGrantRoutes wires the grant lifecycle (ADR-036 section 3): create,
// list and revoke. Create is gated by automation-grant:create (Strong with a presence
// tap), revoke by automation-grant:revoke (Strong, no tap: it only removes power) and
// list by automation-grant:read, which is outside the assurance surface. None allows
// machine access. These routes are deliberately not registered through
// registerAutomationRoute, so automationRouteGuard refuses a grant principal on them.
//
// Tenant-crossing classification: create and revoke authorize the grant tenant through
// authorizeTenantAccess in the handler, and list through authorizeSelectedTenant.
func registerAutomationGrantRoutes(s *Server, api *mux.Router) {
	grants := api.PathPrefix("/automation/grants").Subrouter()
	grants.Handle("", s.requirePermission("automation-grant", "create")(http.HandlerFunc(s.handleCreateAutomationGrant))).Methods("POST")
	grants.Handle("", s.requirePermission("automation-grant", "read")(http.HandlerFunc(s.handleListAutomationGrants))).Methods("GET")
	grants.Handle("/{id}", s.requirePermission("automation-grant", "revoke")(http.HandlerFunc(s.handleRevokeAutomationGrant))).Methods("DELETE")
}
