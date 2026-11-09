// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerContentApprovalWorkflowRoutes) }

// registerContentApprovalWorkflowRoutes registers the workflow approval routes
// (Issue #5858, Epic #5421), the workflow counterpart of the script routes. Approve is
// gated by content-approval:approve (Strong, presence tap) and withdrawal by
// content-approval:revoke (Strong, no tap); neither allows an API-key or grant principal.
func registerContentApprovalWorkflowRoutes(s *Server, api *mux.Router) {
	approvals := api.PathPrefix("/automation/approvals/workflows").Subrouter()
	approvals.Handle("", s.requirePermission("automation-approval", "read")(http.HandlerFunc(s.handleListWorkflowApprovals))).Methods("GET")
	approvals.Handle("", s.requirePermission(contentApprovalNamespace, "approve")(http.HandlerFunc(s.handleApproveWorkflow))).Methods("POST")
	approvals.Handle("/{id}/{version}/{approval_hash}", s.requirePermission(contentApprovalNamespace, "revoke")(http.HandlerFunc(s.handleRevokeWorkflowApproval))).Methods("DELETE")
}
