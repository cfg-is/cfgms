// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerContentLibraryModeRoutes) }

// registerContentLibraryModeRoutes wires the approval mode of the caller tenant's
// script or workflow library (Issue #5840, ADR-036 section 2). PUT is gated by
// content-library:set-mode (Strong with a presence tap, no machine access, in
// permissionAssurance); GET by content-library:read, which is outside the assurance
// surface. There is deliberately no other route that writes the mode.
func registerContentLibraryModeRoutes(s *Server, api *mux.Router) {
	api.Handle("/automation/libraries/{kind}/mode",
		s.requirePermission("content-library", "read")(http.HandlerFunc(s.handleGetLibraryMode))).Methods("GET")
	api.Handle("/automation/libraries/{kind}/mode",
		s.requirePermission("content-library", "set-mode")(http.HandlerFunc(s.handlePutLibraryMode))).Methods("PUT")
}
