// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerNotificationRoutes) }

// registerNotificationRoutes registers the controller-wide email delivery
// endpoints (Issue #4710). All three share the notification:configure
// permission, which is root-scoped and requires AssuranceStrong.
func registerNotificationRoutes(s *Server, api *mux.Router) {
	n := api.PathPrefix("/notifications/email").Subrouter()
	n.Handle("", s.requirePermission("notification", "configure")(http.HandlerFunc(s.handleGetEmailSettings))).Methods("GET")
	n.Handle("/credential", s.requirePermission("notification", "configure")(http.HandlerFunc(s.handlePutEmailCredential))).Methods("PUT")
	n.Handle("/test", s.requirePermission("notification", "configure")(http.HandlerFunc(s.handleTestEmail))).Methods("POST")
}
