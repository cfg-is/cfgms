// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerWebAuthnRoutes) }

func registerWebAuthnRoutes(s *Server, api *mux.Router) {
	// WebAuthn presence-assertion endpoints (Issue #2784: step-up challenge + presence enforcement).
	// These endpoints implement the fresh user-presence gesture (ADR-021 Decision 4) required by
	// permissions with RequireUserPresence=true (module:approve, module:reject, publisher-trust:add).
	// The principal must already hold AssuranceStrong (webauthn:assert-presence is in permissionAssurance).
	// On success, finish mints a short-lived (presenceTokenTTL), single-use token returned to the client;
	// the client attaches it via X-Presence-Token header on the guarded request.
	// Cross-reference: #2728/#2732 implementers consume permissionAssurance entries for module:approve/reject.
	webAuthnRouter := api.PathPrefix("/webauthn").Subrouter()
	webAuthnRouter.Handle("/presence/begin",
		s.requirePermission("webauthn", "assert-presence")(http.HandlerFunc(s.handlePresenceBegin))).Methods("POST")
	webAuthnRouter.Handle("/presence/finish",
		s.requirePermission("webauthn", "assert-presence")(http.HandlerFunc(s.handlePresenceFinish))).Methods("POST")
}
