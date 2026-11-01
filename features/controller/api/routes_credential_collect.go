// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCredentialCollectRoutes) }

// registerCredentialCollectRoutes wires POST /api/v1/credential-requests/{id}/collect
// (Issue #3719) through the self-registration seam, mirroring
// registerCredentialRequestRoutes (Issue #3717) and registerCredentialApproveRoutes
// (Issue #3718).
//
// Collect is unauthenticated by API key or mTLS — gated entirely on the collect secret
// presented as a bearer credential — so it is mounted on s.router (the base/public
// router), not the authenticated api subrouter passed in, exactly like lodge. It is
// rate limited per source address (Issue #3719 implementation note; limiter shape from
// Issue #3714).
func registerCredentialCollectRoutes(s *Server, _ *mux.Router) {
	collectHandler := s.credentialRequestCollectLimiter.middleware(s.trustedProxies,
		http.HandlerFunc(s.handleCollectCredentialRequest),
	)
	s.router.Handle("/api/v1/credential-requests/{id}/collect", collectHandler).Methods("POST")
}
