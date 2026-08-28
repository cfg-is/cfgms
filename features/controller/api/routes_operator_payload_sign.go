// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerOperatorPayloadSignRoutes) }

func registerOperatorPayloadSignRoutes(s *Server, api *mux.Router) {
	ops := api.PathPrefix("/operator-payload/sign").Subrouter()
	ops.Handle("/begin", s.requirePermission("operator-payload", "sign")(http.HandlerFunc(s.handleOperatorPayloadSignBegin))).Methods("POST")
	ops.Handle("/finish", s.requirePermission("operator-payload", "sign")(http.HandlerFunc(s.handleOperatorPayloadSignFinish))).Methods("POST")
}
