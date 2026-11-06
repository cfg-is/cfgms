// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerContentApprovalRoutes) }

// registerContentApprovalRoutes registers the script approval routes (Issue #5839,
// Epic #5421). Approve is gated by content-approval:approve (Strong, presence tap)
// and withdrawal by content-approval:revoke (Strong, no tap); neither allows an
// API-key or grant principal.
// The permission resource shares its name with the protected storage namespace, so the
// route names it through the store's constant rather than repeating the literal.
func registerContentApprovalRoutes(s *Server, api *mux.Router) {
	approvals := api.PathPrefix("/automation/approvals/scripts").Subrouter()
	approvals.Handle("", s.requirePermission("automation-approval", "read")(http.HandlerFunc(s.handleListScriptApprovals))).Methods("GET")
	approvals.Handle("", s.requirePermission(contentApprovalNamespace, "approve")(http.HandlerFunc(s.handleApproveScript))).Methods("POST")
	approvals.Handle("/{id}/{version}/{approval_hash}", s.requirePermission(contentApprovalNamespace, "revoke")(http.HandlerFunc(s.handleRevokeScriptApproval))).Methods("DELETE")
}
