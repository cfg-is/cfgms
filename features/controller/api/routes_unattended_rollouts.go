// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerUnattendedRolloutRoutes) }

// registerUnattendedRolloutRoutes wires the cell's unattended rollout setting
// (Issue #6065). The path sits outside /rollout because GET /rollout/{rollout_id}
// would match "unattended". PUT is gated by rollout-automation:set (Strong with a
// presence tap, no machine access, in permissionAssurance); GET by
// rollout-automation:read, which is outside the assurance surface. There is
// deliberately no other route that writes the setting.
func registerUnattendedRolloutRoutes(s *Server, api *mux.Router) {
	api.Handle("/rollout-settings/unattended",
		s.requirePermission("rollout-automation", "read")(http.HandlerFunc(s.handleGetUnattendedRollout))).Methods("GET")
	api.Handle("/rollout-settings/unattended",
		s.requirePermission("rollout-automation", "set")(http.HandlerFunc(s.handlePutUnattendedRollout))).Methods("PUT")
}
