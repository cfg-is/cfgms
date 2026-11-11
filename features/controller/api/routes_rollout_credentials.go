// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerRolloutCredentialRoutes) }

// registerRolloutCredentialRoutes wires the one route that mints the scoped rollout
// credential (Issue #6066). It is gated by rollout-credential:create (Strong with a
// presence tap, no machine access, in permissionAssurance), so no API key can mint
// one. There is deliberately no other route that writes the credential kind.
func registerRolloutCredentialRoutes(s *Server, api *mux.Router) {
	api.Handle("/rollout-credentials",
		s.requirePermission("rollout-credential", "create")(http.HandlerFunc(s.handleCreateRolloutCredential))).Methods("POST")
}
