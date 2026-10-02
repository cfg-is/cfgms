// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerModuleListRoutes) }

func registerModuleListRoutes(s *Server, api *mux.Router) {
	// GET /modules — full module catalog, every approval status (Issue #4270).
	// Reuses module:list-approvals: same actor and read-only surface as
	// GET /modules/approvals (routes_module_approvals.go), which stays
	// pending-only for the web UI's review queue (useModuleQueue.ts) and must
	// not be repurposed to also serve this catalog view.
	api.Handle("/modules",
		s.requirePermission("module", "list-approvals")(http.HandlerFunc(s.handleListModules))).Methods("GET")
}
