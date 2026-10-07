// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCliPresenceRoutes) }

// registerCliPresenceRoutes wires the CLI presence-relay endpoints (Issue #4287)
// through the self-registration seam, mirroring registerCliLoginRoutes.
//
// Unlike cli-login's lodge/collect, every route here is mounted on the authenticated
// api subrouter: a presence request can only be lodged, read, or collected by a
// principal that already holds a real credential (mTLS, session, or cookie) — there is
// no anonymous bootstrap step in this flow, since the CLI already passed the
// assurance-level gate before ever seeing a presence challenge. Gating is inline
// (handleLodgeCliPresenceRequest / handleCollectCliPresenceRequest check the principal
// and its assurance/account directly) rather than via requirePermission, so this story
// adds no new permissionAssurance entry.
func registerCliPresenceRoutes(s *Server, api *mux.Router) {
	lodgeHandler := s.cliPresenceLodgeLimiter.middleware(s.trustedProxies,
		http.HandlerFunc(s.handleLodgeCliPresenceRequest),
	)
	api.Handle("/cli-presence/lodge", lodgeHandler).Methods("POST")

	api.Handle("/cli-presence/{id}", http.HandlerFunc(s.handleGetCliPresenceRequest)).Methods("GET")

	collectHandler := s.cliPresenceCollectLimiter.middleware(s.trustedProxies,
		http.HandlerFunc(s.handleCollectCliPresenceRequest),
	)
	api.Handle("/cli-presence/{id}/collect", collectHandler).Methods("POST")
}
