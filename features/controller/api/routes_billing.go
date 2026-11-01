// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerBillingRoutes) }

// registerBillingRoutes registers the billing report endpoints (ADR-025 Amendment 6).
// The routes sit on the api router directly so routes_tenants.go is untouched; this file
// sorts before it, so its /tenants/{id}/billing-report is registered first.
func registerBillingRoutes(s *Server, api *mux.Router) {
	api.Handle("/billing/report",
		s.requirePermission("tenant", "billing-read")(http.HandlerFunc(s.handleRootBillingReport))).Methods("GET")
	api.Handle("/tenants/{id}/billing-report",
		s.requirePermission("tenant", "billing-read")(http.HandlerFunc(s.handleTenantBillingReport))).Methods("GET")
}
