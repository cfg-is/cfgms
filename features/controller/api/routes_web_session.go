// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerWebSessionRoutes) }

// registerWebSessionRoutes wires GET /api/v1/web/session through the self-registration
// seam. Unlike the base-router /web/csrf, /web/logout and /web/passkey/login/* routes,
// it needs a resolved principal, so it is mounted on the authenticated api subrouter
// (cookie authentication; a GET needs no CSRF header). Gating is inline in the handler
// (a cookie web session reading its own identity), so there is no requirePermission
// guard and no permissionAssurance entry.
func registerWebSessionRoutes(s *Server, api *mux.Router) {
	api.Handle("/web/session", http.HandlerFunc(s.handleGetWebSession)).Methods("GET")
}
