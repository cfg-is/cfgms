// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2493: web logout endpoint with pre-session CSRF and audit (ADR-018 §3, §4).
// Issue #2993: password login removed — login is now passkey-only (see handlers_passkey_login.go).
//
// Endpoints registered on the base router (TierPublic) with explicit
// authDefense.Middleware wrapping (security A5.4):
//
//	GET  /api/v1/web/csrf   — issues the ADR-018 §3 pre-session CSRF cookie
//	POST /api/v1/web/logout — session-CSRF-checked; server-side revocation + cookie clearing
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Cookie and header names for the web-session CSRF mechanism (ADR-018 §3).
const (
	cookieWebSession  = "cfgms_session"  // HttpOnly; set on login, cleared on logout
	cookieCSRFSession = "cfgms_csrf"     // session-bound; non-HttpOnly so JS can read it
	cookieCSRFPre     = "cfgms_csrf_pre" // pre-session; single-use, gates the login POST
	headerCSRFToken   = "X-CSRF-Token"
	preCSRFMaxAge     = 10 * 60 // 10 minutes TTL for the pre-session CSRF cookie
)

// generateCSRFToken returns 32 crypto/rand bytes encoded as base64url without padding.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// handleGetWebCSRF handles GET /api/v1/web/csrf (ADR-018 §3).
// Issues a short-lived pre-session CSRF token in a Secure;SameSite=Strict cookie.
// The browser echoes this value as X-CSRF-Token on the login POST (double-submit pattern).
// Safe method; no authentication required.
func (s *Server) handleGetWebCSRF(w http.ResponseWriter, r *http.Request) {
	tok, err := generateCSRFToken()
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate CSRF token", "CSRF_GEN_ERROR")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRFPre,
		Value:    tok,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   preCSRFMaxAge,
	})
	s.writeSuccessResponse(w, map[string]interface{}{"ok": true})
}

// handleWebLogout handles POST /api/v1/web/logout (ADR-018 §4).
// CSRF-checked (session-bound X-CSRF-Token required). Revokes the server-side
// session so subsequent cookie use returns 401. Always clears both cookies.
func (s *Server) handleWebLogout(w http.ResponseWriter, r *http.Request) {
	if s.webSessionManager == nil {
		clearWebSessionCookies(w)
		s.writeSuccessResponse(w, map[string]interface{}{"ok": true})
		return
	}

	// Read session cookie — no cookie means nothing to revoke.
	sessionCookie, cookieErr := r.Cookie(cookieWebSession)
	if cookieErr != nil {
		clearWebSessionCookies(w)
		s.writeSuccessResponse(w, map[string]interface{}{"ok": true})
		return
	}

	// Validate the session.
	sess, valErr := s.webSessionManager.Validate(r.Context(), sessionCookie.Value)
	if valErr != nil {
		clearWebSessionCookies(w)
		errCode := "SESSION_INVALID"
		switch {
		case errors.Is(valErr, session.ErrSessionRevoked):
			errCode = "SESSION_REVOKED"
		case errors.Is(valErr, session.ErrSessionExpired):
			errCode = "SESSION_EXPIRED"
		}
		s.writeErrorResponse(w, http.StatusUnauthorized, "Session expired or invalid", errCode)
		return
	}

	// CSRF check: X-CSRF-Token header must match the session-bound server-side token.
	csrfHeader := r.Header.Get(headerCSRFToken)
	stored, _ := s.csrfTokens.Load(sess.ID)
	storedStr, _ := stored.(string)
	if csrfHeader == "" || storedStr == "" || subtle.ConstantTimeCompare([]byte(csrfHeader), []byte(storedStr)) != 1 {
		s.writeErrorResponse(w, http.StatusForbidden, "CSRF token mismatch", "CSRF_MISMATCH")
		return
	}

	// Revoke session and remove CSRF token entry.
	if revErr := s.webSessionManager.Revoke(r.Context(), sess.ID); revErr != nil {
		// Revocation failed: the server-side session persists and remains replayable
		// by anyone who captured the token, even though we clear the client cookies.
		// Must be observable so the security property violation is not silent.
		s.logger.Warn("Web logout: failed to revoke session (session remains replayable)",
			"session_id", logging.SanitizeLogValue(sess.ID),
			"error", logging.SanitizeLogValue(revErr.Error()))
	}
	s.csrfTokens.Delete(sess.ID)

	clearWebSessionCookies(w)

	s.emitWebLoginAudit(r.Context(), sess.PrincipalID, sess.TenantID, "web.logout", business.AuditResultSuccess)
	s.logger.Info("Web logout",
		"principal_id", logging.SanitizeLogValue(sess.PrincipalID),
		"session_id", logging.SanitizeLogValue(sess.ID),
		"remote_addr", logging.SanitizeLogValue(r.RemoteAddr))

	s.writeSuccessResponse(w, map[string]interface{}{"ok": true})
}

// clearWebSessionCookies expires both the session and CSRF cookies (Max-Age=0).
// cfgms_session is HttpOnly (mirrors login-time design); cfgms_csrf is not (JS reads it).
func clearWebSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{cookieWebSession, cookieCSRFSession} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			MaxAge:   -1, // serialised as Max-Age=0 → delete
			Path:     "/",
			Secure:   true,
			HttpOnly: name == cookieWebSession,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

// emitWebLoginAudit records a web-login lifecycle audit event.
// Fields: sanitized username, tenant, outcome. Credential material is never included.
// No-op when auditManager is nil.
func (s *Server) emitWebLoginAudit(ctx context.Context, username, tenantID, action string, result business.AuditResult) {
	if s.auditManager == nil {
		return
	}
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	// Severity is outcome-aware: success (including logout) is Low; failure/denial is High.
	severity := business.AuditSeverityHigh
	if result == business.AuditResultSuccess {
		severity = business.AuditSeverityLow
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventAuthentication).
		Action(action).
		User(logging.SanitizeLogValue(username), business.AuditUserTypeHuman).
		Resource("web-session", logging.SanitizeLogValue(username), "").
		Result(result).
		Severity(severity)
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit web login audit event",
			"action", action,
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
