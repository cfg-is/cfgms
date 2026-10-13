// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerIdentityCloneRoutes) }

// registerIdentityCloneRoutes registers the operator actions for a detected
// identity clone (ADR-034 §5). The list route is a literal segment under
// /stewards, so it must be matched before the /stewards/{id} wildcard; route
// registrars run in source-file order and this file sorts ahead of
// routes_stewards.go. TestIdentityCloneRoutes_ListNotShadowedByStewardID pins it.
func registerIdentityCloneRoutes(s *Server, api *mux.Router) {
	api.Handle("/stewards/identity-clones", s.requirePermission("steward", "read")(http.HandlerFunc(s.handleListIdentityClones))).Methods("GET")
	api.Handle("/stewards/{id}/credentials/rotate", s.requirePermission("steward", "rotate-credentials")(http.HandlerFunc(s.handleRotateCredentials))).Methods("POST") // AssuranceStrong via permissionAssurance
	api.Handle("/stewards/{id}/identity/move", s.requirePermission("steward", "move-identity")(http.HandlerFunc(s.handleMoveIdentity))).Methods("POST")                // AssuranceStrong via permissionAssurance
}
