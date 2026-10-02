// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCredentialApproveRoutes) }

// registerCredentialApproveRoutes wires POST /api/v1/credential-requests/{id}/approve
// (Issue #3718) through the self-registration seam, mirroring
// registerCredentialRequestRoutes (Issue #3717) and registerSigningCredentialRoutes
// (Issue #3693). Kept in its own file per the story's file boundaries — the approve
// handler, its marker-authority rule, and its tests are new surface distinct from the
// #3717 queue.
func registerCredentialApproveRoutes(s *Server, api *mux.Router) {
	api.Handle("/credential-requests/{id}/approve",
		s.requirePermission("credential-request", "approve")(http.HandlerFunc(s.handleApproveCredentialRequest)),
	).Methods("POST")
}
