// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerRegistrationTokenRoutes) }

func registerRegistrationTokenRoutes(s *Server, api *mux.Router) {
	// Registration token management endpoints (Story #264)
	regTokens := api.PathPrefix("/registration/tokens").Subrouter()
	regTokens.Handle("", s.requirePermission("registration", "list-tokens")(http.HandlerFunc(s.handleListRegistrationTokens))).Methods("GET")
	regTokens.Handle("", s.requirePermission("registration", "create-token")(http.HandlerFunc(s.handleCreateRegistrationToken))).Methods("POST")
	regTokens.Handle("/{token}", s.requirePermission("registration", "read-token")(http.HandlerFunc(s.handleGetRegistrationToken))).Methods("GET")
	regTokens.Handle("/{token}", s.requirePermission("registration", "delete-token")(http.HandlerFunc(s.handleDeleteRegistrationToken))).Methods("DELETE")
	regTokens.Handle("/{token}/revoke", s.requirePermission("registration", "revoke-token")(http.HandlerFunc(s.handleRevokeRegistrationToken))).Methods("POST")
	regTokens.Handle("/{tenant_id}/rotate", s.requirePermission("registration", "rotate-token")(http.HandlerFunc(s.handleRotateRegistrationToken))).Methods("POST")
}
