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
	// Tenant management endpoints (Issue #1396, Issue #1848, Issue #3125)
	tenants := api.PathPrefix("/tenants").Subrouter()
	tenants.Handle("", s.requirePermission("tenant", "list")(http.HandlerFunc(s.handleListTenants))).Methods("GET")
	tenants.Handle("", s.requirePermission("tenant", "create")(http.HandlerFunc(s.handleCreateTenant))).Methods("POST")
	tenants.Handle("/{id}", s.requirePermission("tenant", "read")(http.HandlerFunc(s.handleGetTenant))).Methods("GET")
	tenants.Handle("/{id}", s.requirePermission("tenant", "update")(http.HandlerFunc(s.handleUpdateTenant))).Methods("PUT")
	tenants.Handle("/{id}/suspend",
		s.requirePermission("tenant", "manage")(http.HandlerFunc(s.handleSuspendTenant))).Methods("POST")
	tenants.Handle("/{id}/restore",
		s.requirePermission("tenant", "manage")(http.HandlerFunc(s.handleRestoreTenant))).Methods("POST")
	tenants.Handle("/{id}/config-source/test",
		s.requirePermission("tenant", "manage")(http.HandlerFunc(s.handleConfigSourceTest))).Methods("POST")

	// Tenant deletion pipeline (ADR-027 Decisions 3-4, Issue #3182).
	// POST requests deletion; DELETE cancels; GET reads the pending state;
	// POST /approve is the dual-control terminal approval step.
	tenants.Handle("/{id}/delete",
		s.requirePermission("tenant", "delete")(http.HandlerFunc(s.handleRequestTenantDeletion))).Methods("POST")
	tenants.Handle("/{id}/delete",
		s.requirePermission("tenant", "delete")(http.HandlerFunc(s.handleCancelTenantDeletion))).Methods("DELETE")
	tenants.Handle("/{id}/delete",
		s.requirePermission("tenant", "read")(http.HandlerFunc(s.handleGetPendingDeletion))).Methods("GET")
	tenants.Handle("/{id}/delete/approve",
		s.requirePermission("tenant", "approve-delete")(http.HandlerFunc(s.handleApproveTenantDeletion))).Methods("POST")

	// Tenant-crossing grant and break-glass endpoints (ADR-025 Decision 2, Issue #3125).
	tenants.Handle("/{id}/access-grants",
		s.requirePermission("tenant", "crossing-grant")(http.HandlerFunc(s.handleCreateTenantCrossingGrant))).Methods("POST")
	tenants.Handle("/{id}/access-grants",
		s.requirePermission("tenant", "crossing-list")(http.HandlerFunc(s.handleListTenantCrossings))).Methods("GET")
	tenants.Handle("/{id}/break-glass",
		s.requirePermission("tenant", "crossing-break-glass")(http.HandlerFunc(s.handleTenantBreakGlass))).Methods("POST")

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

	// Tenant-default reboot_window endpoints (Issue #2979). reboot_window.override is
	// intentionally distinct from config.update (ADR-026 decision 3) — a holder of
	// config.update alone must receive 403 on the PUT.
	tenants.Handle("/{tenant_id}/reboot-window",
		s.requirePermission("reboot_window", "read")(http.HandlerFunc(s.handleGetTenantRebootWindow))).Methods("GET")
	tenants.Handle("/{tenant_id}/reboot-window",
		s.requirePermission("reboot_window", "override")(http.HandlerFunc(s.handlePutTenantRebootWindow))).Methods("PUT")
}
