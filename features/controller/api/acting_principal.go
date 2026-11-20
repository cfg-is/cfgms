// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import "net/http"

// requireActingPrincipal returns the authenticated principal that a handler records as
// the actor of a change, or writes 401 AUTHENTICATION_REQUIRED and returns false when
// the request context holds no principal or one with an empty ID. A record that says
// who acted names this principal's ID; no handler substitutes a placeholder name.
func (s *Server) requireActingPrincipal(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil || principal.ID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return nil, false
	}
	return principal, true
}
