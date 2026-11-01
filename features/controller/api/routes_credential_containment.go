// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCredentialContainmentRoutes) }

// registerCredentialContainmentRoutes wires the revocation and containment endpoints
// for enrolment-issued credentials (Issue #3725). Every route here is an ordinary
// admin-authenticated route on the api subrouter, gated at AssuranceStrong via
// permissionAssurance (list-orphaned excepted — a read surface, mirroring
// credential-request:list / cert-binding:list).
func registerCredentialContainmentRoutes(s *Server, api *mux.Router) {
	api.Handle("/enrolment-tokens/{id}/revoke-issued-credentials",
		s.requirePermission("enrolment-token", "revoke-issued")(http.HandlerFunc(s.handleRevokeCredentialsByEnrolmentToken)),
	).Methods("POST")

	requests := api.PathPrefix("/credential-requests").Subrouter()
	requests.Handle("/{id}/cancel",
		s.requirePermission("credential-request", "cancel")(http.HandlerFunc(s.handleCancelCredentialRequest)),
	).Methods("POST")
	requests.Handle("/orphaned",
		s.requirePermission("credential-request", "list-orphaned")(http.HandlerFunc(s.handleListOrphanedCredentials)),
	).Methods("GET")
	requests.Handle("/orphaned/{serial}/revoke",
		s.requirePermission("credential-request", "revoke-orphaned")(http.HandlerFunc(s.handleRevokeOrphanedCredential)),
	).Methods("POST")
}
