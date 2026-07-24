// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2493: web login/logout endpoints with pre-session CSRF, lockout, and audit
// (ADR-018 §3, §4).
//
// Three endpoints registered on the base router (TierPublic) with explicit
// authDefense.Middleware wrapping (security A5.4):
//
//	GET  /api/v1/web/csrf   — issues the ADR-018 §3 pre-session CSRF cookie
//	POST /api/v1/web/login  — CSRF-checked, lockout-gated, credential-verified; mints session
//	POST /api/v1/web/logout — session-CSRF-checked; server-side revocation + cookie clearing
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
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

// webLoginRequest is the POST /api/v1/web/login body.
type webLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

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

// handleWebLogin handles POST /api/v1/web/login (ADR-018 §3, §4).
//
// Sequence enforced in order:
//  1. webSessionManager availability check → 503
//  2. Pre-session CSRF double-submit: cfgms_csrf_pre cookie == X-CSRF-Token header → 403 on mismatch
//  3. Parse credentials from request body
//  4. Revoke any valid existing cfgms_session (session-fixation defence)
//  5. Lockout gate: account locked → uniform 401 (timing-equalized via dummy argon2id)
//  6. VerifyWebCredential → uniform 401 on any failure (bad user, bad password)
//  7. Issue FRESH session via webSessionManager.Issue
//  8. Generate per-session CSRF token (crypto/rand), store server-side in csrfTokens
//  9. Set cfgms_session (HttpOnly) and cfgms_csrf (non-HttpOnly) cookies; clear cfgms_csrf_pre
//  10. Emit sanitized audit event; response body never contains any token (security A5.5)
func (s *Server) handleWebLogin(w http.ResponseWriter, r *http.Request) {
	if s.webSessionManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Web session management not available", "SESSION_UNAVAILABLE")
		return
	}

	// Step 2: pre-session CSRF double-submit check.
	// Absent or mismatched → 403 (before any credential work).
	preCSRFCookie, err := r.Cookie(cookieCSRFPre)
	if err != nil {
		s.writeErrorResponse(w, http.StatusForbidden, "CSRF token required", "CSRF_REQUIRED")
		return
	}
	csrfHeader := r.Header.Get(headerCSRFToken)
	if csrfHeader == "" || subtle.ConstantTimeCompare([]byte(preCSRFCookie.Value), []byte(csrfHeader)) != 1 {
		s.writeErrorResponse(w, http.StatusForbidden, "CSRF token mismatch", "CSRF_MISMATCH")
		return
	}

	// Step 3: parse credentials.
	var req webLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	// Step 4: revoke any existing session (session-fixation defence).
	// A pre-login cfgms_session value must never be valid post-login.
	if existing, cookieErr := r.Cookie(cookieWebSession); cookieErr == nil {
		if existSess, valErr := s.webSessionManager.Validate(r.Context(), existing.Value); valErr == nil {
			if revErr := s.webSessionManager.Revoke(r.Context(), existSess.ID); revErr != nil {
				// Session-fixation defence failure: the pre-login session may remain
				// valid alongside the session we are about to issue. Must be observable.
				s.logger.Warn("Web login: failed to revoke pre-login session (fixation defence)",
					"session_id", logging.SanitizeLogValue(existSess.ID),
					"error", logging.SanitizeLogValue(revErr.Error()))
			}
			s.csrfTokens.Delete(existSess.ID)
		}
	}

	// Step 5: lockout gate (enforcement owner: #2493; state owner: #2490).
	// A locked account returns the identical 401 as wrong-password (no disclosure).
	// Timing equalisation: burn a dummy argon2id derivation so the locked path
	// has the same latency as the wrong-password path.
	if locked, _ := s.webAccountLocked(req.Username); locked {
		_, _ = verifyWebPassword(req.Password, dummyWebAccountHash())
		s.emitWebLoginAudit(r.Context(), req.Username, "", "web.login.lockout", business.AuditResultDenied)
		s.logger.Warn("Web login blocked: account locked",
			"username", logging.SanitizeLogValue(req.Username),
			"remote_addr", logging.SanitizeLogValue(r.RemoteAddr))
		s.writeErrorResponse(w, http.StatusUnauthorized, "Invalid credentials", "INVALID_CREDENTIALS")
		return
	}

	// Step 6: verify credentials.
	// ErrInvalidWebCredential is the uniform error for bad-user, bad-password, and
	// malformed-input (ADR-018 §3 / #2490 uniformity contract).
	principalID, tenantID, _, verErr := s.VerifyWebCredential(r.Context(), req.Username, req.Password)
	if verErr != nil {
		if errors.Is(verErr, ErrInvalidWebCredential) {
			s.emitWebLoginAudit(r.Context(), req.Username, "", "web.login.failure", business.AuditResultFailure)
			s.logger.Warn("Web login failed",
				"username", logging.SanitizeLogValue(req.Username),
				"remote_addr", logging.SanitizeLogValue(r.RemoteAddr))
		} else {
			s.logger.Error("Web login: credential verification error",
				"username", logging.SanitizeLogValue(req.Username),
				"error", logging.SanitizeLogValue(verErr.Error()))
		}
		s.writeErrorResponse(w, http.StatusUnauthorized, "Invalid credentials", "INVALID_CREDENTIALS")
		return
	}

	// Step 7: issue FRESH session.
	sess, token, issueErr := s.webSessionManager.Issue(r.Context(), principalID, "web-login", tenantID)
	if issueErr != nil {
		s.logger.Error("Web login: failed to issue session",
			"principal_id", logging.SanitizeLogValue(principalID),
			"error", issueErr)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create session", "SESSION_ERROR")
		return
	}

	// Step 8: generate per-session CSRF token and store server-side (security A5.3).
	csrfToken, genErr := generateCSRFToken()
	if genErr != nil {
		// Roll back the freshly issued session. If revocation also fails the session
		// is orphaned in the store (client gets 500 but the token persists), so the
		// rollback failure must be logged to make the orphan detectable.
		if revErr := s.webSessionManager.Revoke(r.Context(), sess.ID); revErr != nil {
			s.logger.Error("Web login: failed to roll back session after CSRF generation failure (orphaned session)",
				"session_id", logging.SanitizeLogValue(sess.ID),
				"error", logging.SanitizeLogValue(revErr.Error()))
		}
		s.logger.Error("Web login: failed to generate CSRF token", "error", genErr)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate CSRF token", "CSRF_GEN_ERROR")
		return
	}
	s.csrfTokens.Store(sess.ID, csrfToken)

	// Step 9: set cookies (security A5.1).
	http.SetCookie(w, &http.Cookie{
		Name:     cookieWebSession,
		Value:    token,
		HttpOnly: true, // token unreadable by JS
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRFSession,
		Value:    csrfToken,
		HttpOnly: false, // non-HttpOnly by design: JS reads this to set X-CSRF-Token header
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
	// Clear the pre-session CSRF cookie — single-use.
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRFPre,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// Step 10: audit and respond. Token is never written to the body (security A5.5).
	// Issue #2919: include tenant_id and root_scope so the frontend can initialise
	// TenantScopeProvider with the correct rootPath on the session just established.
	// root_scope is derived from tenantID == "" — after Issue #2919's defense-in-depth
	// fix, an empty TenantID in session can only originate from an explicit RootScope grant.
	s.emitWebLoginAudit(r.Context(), req.Username, tenantID, "web.login.success", business.AuditResultSuccess)
	s.logger.Info("Web login success",
		"username", logging.SanitizeLogValue(req.Username),
		"principal_id", logging.SanitizeLogValue(principalID),
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"root_scope", tenantID == "",
		"session_id", logging.SanitizeLogValue(sess.ID),
		"remote_addr", logging.SanitizeLogValue(r.RemoteAddr))

	s.writeSuccessResponse(w, map[string]interface{}{
		"ok":         true,
		"tenant_id":  tenantID,
		"root_scope": tenantID == "",
	})
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
