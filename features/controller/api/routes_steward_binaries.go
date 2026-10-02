// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerStewardBinaryRoutes) }

func registerStewardBinaryRoutes(s *Server, api *mux.Router) {
	// Steward binary publish/get endpoints (Issue #1944).
	// Distinct from the installer artifact namespace; blobs live under "steward-binaries".
	stewardBinaries := api.PathPrefix("/installer/steward-binaries").Subrouter()
	stewardBinaries.Handle("/{version}/{platform}/{arch}",
		s.requirePermission("installer", "publish:steward")(http.HandlerFunc(s.handlePublishStewardBinary))).Methods("POST")
	stewardBinaries.Handle("/{version}/{platform}/{arch}",
		s.requirePermission("installer", "read")(http.HandlerFunc(s.handleGetStewardBinary))).Methods("GET")
}
