// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerRebootWindowRoutes) }

// registerRebootWindowRoutes wires reboot_window endpoints under
// /api/v1/tenants/{id}/reboot-window and /api/v1/stewards/{id}/reboot-window.
//
// Permission gate (ADR-026 decision 3): reboot_window.override is intentionally
// distinct from config.update — a holder of config.update alone must receive 403.
func registerRebootWindowRoutes(s *Server, api *mux.Router) {
	// Register under the same /tenants prefix-subrouter the tenant registrar uses so no
	// new * /api/v1/tenants/{id} wildcard subrouter entry is added to the route table.
	tenants := api.PathPrefix("/tenants").Subrouter()
	tenants.Handle("/{tenant_id}/reboot-window",
		s.requirePermission("reboot_window", "read")(http.HandlerFunc(s.handleGetTenantRebootWindow)),
	).Methods("GET")
	tenants.Handle("/{tenant_id}/reboot-window",
		s.requirePermission("reboot_window", "override")(http.HandlerFunc(s.handlePutTenantRebootWindow)),
	).Methods("PUT")

	// Same approach for stewards.
	stewards := api.PathPrefix("/stewards").Subrouter()
	stewards.Handle("/{id}/reboot-window",
		s.requirePermission("reboot_window", "read")(http.HandlerFunc(s.handleGetStewardRebootWindow)),
	).Methods("GET")
	stewards.Handle("/{id}/reboot-window",
		s.requirePermission("reboot_window", "override")(http.HandlerFunc(s.handlePutStewardRebootWindow)),
	).Methods("PUT")
}
