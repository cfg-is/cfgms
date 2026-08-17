// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerAlertRoutes) }

func registerAlertRoutes(s *Server, api *mux.Router) {
	alerts := api.PathPrefix("/alerts").Subrouter()
	alerts.Handle("/{id}/acknowledge",
		s.requirePermission("alert", "acknowledge")(http.HandlerFunc(s.handleAcknowledgeAlert)),
	).Methods("POST")
	alerts.Handle("/{id}/silence",
		s.requirePermission("alert", "silence")(http.HandlerFunc(s.handleSilenceAlert)),
	).Methods("POST")
}
