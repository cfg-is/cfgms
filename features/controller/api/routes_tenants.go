// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerTenantRoutes) }

// registerTenantRoutes registers all routes on the /tenants subrouter.
// Covers two regions of the original setupRouter: the core tenant CRUD (region 1)
// and the per-tenant refresh-policy endpoints (region 2), both on the same variable.
func registerTenantRoutes(s *Server, api *mux.Router) {
	// Tenant management endpoints (Issue #1396, Issue #1848)
	tenants := api.PathPrefix("/tenants").Subrouter()
	tenants.Handle("", s.requirePermission("tenant", "create")(http.HandlerFunc(s.handleCreateTenant))).Methods("POST")
	tenants.Handle("/{id}", s.requirePermission("tenant", "read")(http.HandlerFunc(s.handleGetTenant))).Methods("GET")
	tenants.Handle("/{id}/suspend",
		s.requirePermission("tenant", "manage")(http.HandlerFunc(s.handleSuspendTenant))).Methods("POST")
	tenants.Handle("/{id}/config-source/test",
		s.requirePermission("tenant", "manage")(http.HandlerFunc(s.handleConfigSourceTest))).Methods("POST")

	// Per-tenant refresh policy endpoints (Issue #2097).
	// {tenant_path:.+} allows '/' in the path variable for hierarchical tenant IDs.
	tenants.Handle("/{tenant_path:.+}/refresh-policy",
		s.requirePermission("refresh", "get-policy")(http.HandlerFunc(s.handleGetRefreshPolicy))).Methods("GET")
	tenants.Handle("/{tenant_path:.+}/refresh-policy",
		s.requirePermission("refresh", "set-policy")(http.HandlerFunc(s.handleSetRefreshPolicy))).Methods("PUT")

	// Per-tenant assurance-policy endpoints (Issue #2839).
	// assurance-policy:get is an ordinary RBAC gate (not in permissionAssurance), so reads
	// stay unrestricted at the assurance layer — matching refresh:get-policy's absence from
	// that map. assurance-policy:set requires AssuranceStrong (declared in assurance.go).
	tenants.Handle("/{tenant_path:.+}/assurance-policy",
		s.requirePermission("assurance-policy", "get")(http.HandlerFunc(s.handleGetAssurancePolicy))).Methods("GET")
	tenants.Handle("/{tenant_path:.+}/assurance-policy",
		s.requirePermission("assurance-policy", "set")(http.HandlerFunc(s.handleSetAssurancePolicy))).Methods("PUT")
}
