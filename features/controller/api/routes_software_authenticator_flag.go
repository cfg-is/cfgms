// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerSoftwareAuthenticatorFlagRoutes) }

// registerSoftwareAuthenticatorFlagRoutes wires the route that sets the account's
// software-authenticator flag (Issue #6141). It is gated by
// account:set-software-authenticator (Strong with a presence tap, no machine access,
// in permissionAssurance). Enabling additionally needs a root-scope caller; clearing
// needs the same tenant scope as account:update. There is deliberately no other route
// that can set the flag: the account create/update bodies do not carry it.
func registerSoftwareAuthenticatorFlagRoutes(s *Server, api *mux.Router) {
	api.Handle("/accounts/{username}/software-authenticator",
		s.requirePermission("account", "set-software-authenticator")(http.HandlerFunc(s.handlePutSoftwareAuthenticatorFlag))).Methods("PUT")
}
