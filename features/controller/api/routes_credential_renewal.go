// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCredentialRenewalRoutes) }

// registerCredentialRenewalRoutes wires POST /api/v1/credential-renewal (Issue #3724)
// through the self-registration seam, mirroring registerCredentialApproveRoutes
// (Issue #3718) and registerCredentialCollectRoutes (Issue #3719).
//
// Unlike collect, this is mounted on the authenticated api subrouter, not the base
// router: renewal's authentication IS mTLS admin-cert authentication
// (authenticationMiddleware -> extractAdminPrincipal), not a bearer secret. It is
// deliberately NOT wrapped in requirePermission — the presented certificate itself is
// the authorization (handlers_credential_renewal.go's doc comment), and a headless
// enrolment-issued host account typically holds no RBAC permissions at all.
func registerCredentialRenewalRoutes(s *Server, api *mux.Router) {
	api.Handle("/credential-renewal", http.HandlerFunc(s.handleRenewCredential)).Methods("POST")
}
