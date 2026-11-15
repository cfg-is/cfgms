// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerMSPEmailSenderRoutes) }

// registerMSPEmailSenderRoutes registers the per-MSP email sender endpoints
// (Issue #6243). They sit on the api router directly so routes_tenants.go is
// untouched. All three share the notification:configure-msp permission
// (AssuranceStrong), so viewing the sender asks for the same proof as changing it.
func registerMSPEmailSenderRoutes(s *Server, api *mux.Router) {
	api.Handle("/tenants/{id}/email-sender",
		s.requirePermission("notification", "configure-msp")(http.HandlerFunc(s.handleGetMSPEmailSender))).Methods("GET")
	api.Handle("/tenants/{id}/email-sender",
		s.requirePermission("notification", "configure-msp")(http.HandlerFunc(s.handlePutMSPEmailSender))).Methods("PUT")
	api.Handle("/tenants/{id}/email-sender",
		s.requirePermission("notification", "configure-msp")(http.HandlerFunc(s.handleDeleteMSPEmailSender))).Methods("DELETE")
}
