// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerTerminalRoutes) }

// registerTerminalRoutes registers GET /terminal/ws/{steward_id} behind the
// "terminal:create" permission gate (AssuranceStrong per permissionAssurance).
// The handler is resolved lazily from s.terminalHandler so it can be wired via
// SetTerminalHandler after the server is constructed.
func registerTerminalRoutes(s *Server, api *mux.Router) {
	api.Handle(
		"/terminal/ws/{steward_id}",
		s.requirePermission("terminal", "create")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.mu.RLock()
			h := s.terminalHandler
			s.mu.RUnlock()
			if h == nil {
				http.Error(w, "terminal service not available", http.StatusServiceUnavailable)
				return
			}
			h.ServeHTTP(w, r)
		})),
	).Methods("GET")
}
