// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerSigningCredentialRoutes) }

func registerSigningCredentialRoutes(s *Server, api *mux.Router) {
	sc := api.PathPrefix("/signing-credential").Subrouter()
	sc.Handle("/request", s.requirePermission("signing-credential", "request")(http.HandlerFunc(s.handleRequestSigningCredential))).Methods("POST")
}
