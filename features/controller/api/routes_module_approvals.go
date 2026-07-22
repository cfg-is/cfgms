// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerModuleApprovalRoutes) }

func registerModuleApprovalRoutes(s *Server, api *mux.Router) {
	// Module bundle approval endpoints (Issue #2728).
	// GET /modules/approvals — permission-gated only (reads are outside the AssuranceStrong
	// surface; module:list-approvals is absent from permissionAssurance by design).
	// POST .../approve and POST .../reject — AssuranceStrong via permissionAssurance.
	moduleApprovals := api.PathPrefix("/modules/approvals").Subrouter()
	moduleApprovals.Handle("",
		s.requirePermission("module", "list-approvals")(http.HandlerFunc(s.handleListModuleApprovals))).Methods("GET")
	moduleApprovals.Handle("/{address}/approve",
		s.requirePermission("module", "approve")(http.HandlerFunc(s.handleApproveModuleBundle))).Methods("POST")
	moduleApprovals.Handle("/{address}/reject",
		s.requirePermission("module", "reject")(http.HandlerFunc(s.handleRejectModuleBundle))).Methods("POST")
}
