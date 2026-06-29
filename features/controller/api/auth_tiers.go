// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"time"
)

// authTier defines the authentication strength an endpoint requires.
type authTier int

const (
	TierPublic   authTier = 0 // No authentication (registered on the base router, not the api subrouter)
	TierAny      authTier = 1 // Any valid credential: API key OR mTLS admin cert
	TierElevated authTier = 2 // Reserved for future use
	TierMTLSOnly authTier = 3 // mTLS admin cert required; API-key callers rejected even with matching permissions
)

// tier3Permissions is the authoritative set of permission IDs whose REST endpoints
// require mTLS (Issue #1419). It is the one place that declares the Tier-3 surface;
// S3 wraps exactly these routes and S4's startup scan reports keys holding any of them.
var tier3Permissions = map[string]struct{}{
	"certificate:provision":        {}, // POST /certificates/provision
	"certificate:rotate":           {}, // POST /certificates/signing/rotate
	"rbac:create-role":             {}, // POST /rbac/roles
	"rbac:update-role":             {}, // PUT /rbac/roles/{id}
	"rbac:delete-role":             {}, // DELETE /rbac/roles/{id}
	"api-key:create":               {}, // POST /api-keys
	"api-key:delete":               {}, // DELETE /api-keys/{id}
	"registration:create-token":    {}, // POST /registration/tokens
	"registration:delete-token":    {}, // DELETE /registration/tokens/{token}
	"registration:revoke-token":    {}, // POST /registration/tokens/{token}/revoke
	"registration:rotate-token":    {}, // POST /registration/tokens/{tenant_id}/rotate
	"registration:approve":         {}, // POST /registration/{id}/approve, /approve-all, /approve-by-cidr
	"registration:manage-ip-trust": {}, // POST + DELETE /registration/ip-trust
	"tenant:create":                {}, // POST /tenants
}

// requireTier returns middleware that enforces the given authentication tier.
// Tiers below TierMTLSOnly are a no-op passthrough — zero enforcement overhead.
// TierMTLSOnly rejects any caller that is not an mTLS admin principal (principal.IsAdmin
// is the sole discriminator; the permission set is never consulted). On rejection an
// audit event is emitted via auditAuthorizationDecision before writing the 403 response.
func (s *Server) requireTier(tier authTier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if tier < TierMTLSOnly {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, _ := r.Context().Value(principalContextKey).(*Principal)
			if principal == nil || !principal.IsAdmin {
				subjectID := ""
				tenantID := ""
				if principal != nil {
					subjectID = principal.ID
					tenantID = principal.TenantID
				}
				decision := &AuthorizationDecision{
					Granted:   false,
					Action:    r.Method,
					Decision:  "DENY",
					Reason:    "mTLS required (Tier-3 endpoint)",
					CheckedAt: time.Now(),
					SubjectID: subjectID,
					TenantID:  tenantID,
				}
				s.auditAuthorizationDecision(r, decision)
				s.writeErrorResponse(w, http.StatusForbidden, "mTLS admin certificate required for this endpoint", "MTLS_REQUIRED")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
