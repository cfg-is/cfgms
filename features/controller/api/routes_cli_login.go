// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCliLoginRoutes) }

// registerCliLoginRoutes wires the browser-authenticated CLI login endpoints (Issue
// #3721) through the self-registration seam, mirroring registerCredentialRequestRoutes
// and registerCredentialCollectRoutes.
//
// Lodge and collect are unauthenticated by API key or mTLS — lodge is the bootstrap
// path (no prior credential), and collect is gated entirely on the CLI-generated
// verifier presented as a bearer credential. Both are mounted on s.router (the
// base/public router), not the authenticated api subrouter passed in, exactly like
// credential-request lodge/collect. Both are rate limited per source address (Issue
// #3721 implementation note; limiter shape from Issue #3714).
//
// Approve requires an authenticated, AssuranceStrong browser session
// (requirePermission("cli-login", "approve"), permissionAssurance) and is mounted on
// the authenticated api subrouter. The GET read (Issue #3722) shares the same gate —
// the confirmation screen's only way to learn the true user code — and is exempt from
// the leadership check that guards approve/collect's mutating branches, mirroring how
// collect's own polling stays available on a non-leader (see handlers_cli_login.go).
//
// The lodge and collect handlers are built into named variables before being handed to
// Handle(), rather than inline, mirroring registerCredentialRequestRoutes: architecture_
// test.go's mutating-handler scanner (TestNoUngatedMutatingHandler) walks a route's
// handler expression and returns the first <ident>.<field> selector it finds as the
// "handler name" — an inline sourceRateLimiter.middleware(trustedProxies, next) call
// would make it misidentify the trustedProxies argument as the handler. Both handlers
// still call HasLeadership() directly in their own bodies (see handlers_cli_login.go).
func registerCliLoginRoutes(s *Server, api *mux.Router) {
	api.Handle("/cli-login/{id}",
		s.requirePermission("cli-login", "approve")(http.HandlerFunc(s.handleGetCliLoginRequest)),
	).Methods("GET")

	api.Handle("/cli-login/{id}/approve",
		s.requirePermission("cli-login", "approve")(http.HandlerFunc(s.handleApproveCliLoginRequest)),
	).Methods("POST")

	lodgeHandler := s.cliLoginLodgeLimiter.middleware(s.trustedProxies,
		http.HandlerFunc(s.handleLodgeCliLoginRequest),
	)
	s.router.Handle("/api/v1/cli-login/lodge", lodgeHandler).Methods("POST")

	collectHandler := s.cliLoginCollectLimiter.middleware(s.trustedProxies,
		http.HandlerFunc(s.handleCollectCliLoginRequest),
	)
	s.router.Handle("/api/v1/cli-login/{id}/collect", collectHandler).Methods("POST")
}
