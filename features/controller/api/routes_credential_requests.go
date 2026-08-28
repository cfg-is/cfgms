// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCredentialRequestRoutes) }

// registerCredentialRequestRoutes wires the enrolment-token and credential-request
// endpoints (Issue #3717). Every route here — including lodge — is registered
// through this self-registration seam rather than the shared setupRouter body.
//
// Lodge is deliberately mounted on s.router (the base/public router), not on the
// authenticated api subrouter passed in: it carries no API key or mTLS credential,
// only the pre-shared enrolment token as a bearer value, exactly mirroring how
// POST /api/v1/register bypasses authenticationMiddleware in setupRouter. Mint,
// revoke, list and deny are ordinary admin-authenticated routes on api.
func registerCredentialRequestRoutes(s *Server, api *mux.Router) {
	// Enrolment token lifecycle — AssuranceStrong (permissionAssurance), rate limited
	// per source address on mint (Issue #3717 implementation note).
	//
	// The mint and lodge handlers are built into named variables before being handed
	// to Handle(), rather than inline, because architecture_test.go's mutating-handler
	// scanner (TestNoUngatedMutatingHandler) walks a route's handler expression and
	// returns the first <ident>.<field> selector it finds as the "handler name" — for
	// a two-argument wrapper like sourceRateLimiter.middleware(trustedProxies, next),
	// an inline call would make it misidentify the trustedProxies argument itself as
	// the handler. Both handlers still call HasLeadership() directly in their own
	// bodies (see handlers_credential_requests.go).
	mintHandler := s.enrolmentTokenMintLimiter.middleware(s.trustedProxies,
		s.requirePermission("enrolment-token", "mint")(http.HandlerFunc(s.handleMintEnrolmentToken)),
	)
	tokens := api.PathPrefix("/enrolment-tokens").Subrouter()
	tokens.Handle("", mintHandler).Methods("POST")
	tokens.Handle("/{id}/revoke",
		s.requirePermission("enrolment-token", "revoke")(http.HandlerFunc(s.handleRevokeEnrolmentToken)),
	).Methods("POST")

	// Pending credential-request queue.
	requests := api.PathPrefix("/credential-requests").Subrouter()
	requests.Handle("",
		s.requirePermission("credential-request", "list")(http.HandlerFunc(s.handleListCredentialRequests)),
	).Methods("GET")
	requests.Handle("/{id}/deny",
		s.requirePermission("credential-request", "deny")(http.HandlerFunc(s.handleDenyCredentialRequest)),
	).Methods("POST")

	// Lodge — unauthenticated by API key/mTLS; gated by the enrolment token itself.
	// Rate limited per source address (Issue #3717 implementation note).
	lodgeHandler := s.credentialRequestLodgeLimiter.middleware(s.trustedProxies,
		http.HandlerFunc(s.handleLodgeCredentialRequest),
	)
	s.router.Handle("/api/v1/credential-requests/lodge", lodgeHandler).Methods("POST")
}
