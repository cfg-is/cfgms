// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
)

// automationGrantAuthThrottleKeyPrefix namespaces the failed-grant-credential
// throttle inside the counter table shared with the operator-payload sign throttle.
const automationGrantAuthThrottleKeyPrefix = "automation-grant-auth:ip:"

// automationGrantPrincipal builds the principal for a verified grant (ADR-036
// section 3). It is a machine principal with no permissions, never root scoped and
// never implicit admin, confined to the grant's tenant subtree.
func automationGrantPrincipal(g *AutomationGrant) *Principal {
	return &Principal{
		Channel:       AuthChannelAutomationGrant,
		ID:            g.ID,
		Name:          g.Name,
		Assurance:     session.AssuranceMachine,
		GlobalScope:   false,
		RootScoped:    false,
		ImplicitAdmin: false,
		AccountBound:  false,
		Permissions:   nil,
		TenantID:      g.TenantID,
	}
}

// bearerGrantCredential returns the Authorization Bearer token when it carries the
// grant prefix. The Authorization Bearer header is the only carrier of a grant
// credential.
func bearerGrantCredential(r *http.Request) (string, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(tok, automationGrantCredentialPrefix) {
		return "", false
	}
	return tok, true
}

// authenticateAutomationGrant handles a request that carries a grant credential. It
// always terminates the request: it either calls next with a grant principal or writes
// a refusal, and a refused grant credential never falls through to the API-key path.
// The grant is re-read from the store on every request, so a revocation is seen on
// the very next one.
//
// Failed attempts share the per-IP throttle and backoff schedule of the
// operator-payload sign ceremony (checkSignThrottle/recordSignFailure over the shared
// rate counter store). The API-key path has no per-credential failure throttle, only
// the router-wide authDefense per-source budget, which also applies here; this
// throttle is in addition to it.
func (s *Server) authenticateAutomationGrant(w http.ResponseWriter, r *http.Request, credential string, next http.Handler) {
	if r.Header.Get("X-API-Key") != "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Conflicting credentials: an automation grant and an API key cannot both be present",
			"CONFLICTING_CREDENTIALS")
		return
	}

	throttleKey := ""
	if ipKey := s.clientIPKey(r); ipKey != "" {
		throttleKey = automationGrantAuthThrottleKeyPrefix + ipKey
		if blocked, wait := s.checkSignThrottle(throttleKey); blocked {
			s.logger.Warn("Automation grant authentication: per-IP throttle active",
				"retry_after_seconds", int(wait.Seconds()))
			s.writeErrorResponse(w, http.StatusTooManyRequests,
				"Too many failed attempts — try again later", "THROTTLED")
			return
		}
	}

	s.mu.RLock()
	store := s.automationGrantStore
	s.mu.RUnlock()
	if store == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Invalid automation grant credential", "INVALID_AUTOMATION_GRANT")
		return
	}

	grant, reason, err := store.GetByCredential(r.Context(), credential)
	if err != nil {
		if !errors.Is(err, ErrInvalidGrantCredential) {
			s.logger.Error("Automation grant lookup failed",
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusServiceUnavailable,
				"Authorization data is temporarily unavailable", "SERVICE_UNAVAILABLE")
			return
		}
		if throttleKey != "" {
			s.recordSignFailure(throttleKey)
		}
		s.logger.Warn("Automation grant credential refused",
			"reason", logging.SanitizeLogValue(string(reason)))
		s.writeErrorResponse(w, http.StatusUnauthorized, "Invalid automation grant credential", "INVALID_AUTOMATION_GRANT")
		return
	}

	principal := automationGrantPrincipal(grant)
	ctx := context.WithValue(r.Context(), principalContextKey, principal)
	ctx = context.WithValue(ctx, ctxkeys.UserIDKey, logging.SanitizeLogValue(grant.ID))
	ctx = context.WithValue(ctx, ctxkeys.TenantID, grant.TenantID)
	// Never the root scope: NewRootScope is reserved for a verified admin certificate.
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(grant.TenantID))
	next.ServeHTTP(w, r.WithContext(ctx))
}
