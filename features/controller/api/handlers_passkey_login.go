// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2993: passkey-only web login (ADR-021 Amendment 1, ADR-018 §3, §4).
//
// Routes (registered on the base router with authDefense.Middleware):
//
//	POST /api/v1/web/passkey/login/begin
//	     Pre-session CSRF checked (double-submit). Optional body: PasskeyLoginBeginRequest.
//	     Returns a WebAuthn discoverable-login assertion challenge; sets cfgms_passkey_ceremony
//	     (HttpOnly) cookie. The username field (if provided) is stored as a session hint only —
//	     the response is always a discoverable challenge (no allowCredentials) regardless of
//	     whether the username exists or has enrolled credentials. This prevents account and
//	     credential enumeration: all three cases (unknown, unenrolled, enrolled) return the
//	     same response shape (Issue #2993 AC).
//
//	POST /api/v1/web/passkey/login/finish
//	     Verifies the authenticator assertion (always via FinishDiscoverableLogin). On success:
//	       - Issues a session immediately at AssuranceStrong (ADR-021 Decision 3).
//	       - Sets cfgms_session (HttpOnly) and cfgms_csrf (non-HttpOnly) cookies.
//	       - Revokes any prior session cookie (session-fixation defence).
//	       - Emits web.passkey.login.success audit event.
//	     On failure: emits web.passkey.login.failure audit event.
//
// Security properties:
//   - No username/credential enumeration: begin always returns a discoverable challenge.
//   - Per-account and per-IP throttle on failures (no hard lockout).
//   - SameSite=Strict on the ceremony cookie provides CSRF protection for the finish endpoint.
//   - Session-fixation defence: an existing cfgms_session is revoked before a new one is issued.
//   - Issued session revoked on Elevate or CSRF-generation failure (no orphaned Basic sessions).
package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// generateCeremonyID returns a 32-byte cryptographically random identifier, base64url-encoded.
// Used to key pending passkey login sessions in passkeyLoginSessions.
func generateCeremonyID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// handlePasskeyLoginBegin handles POST /api/v1/web/passkey/login/begin.
//
// Always issues a discoverable (usernameless) WebAuthn assertion challenge regardless of
// whether a username is provided in the request body. An optional username is stored as a
// session hint for per-account throttle accounting and audit — it is never used to populate
// allowCredentials, so the response is indistinguishable for enrolled, unenrolled, and
// non-existent accounts (Issue #2993 AC: no account-enumeration oracle).
func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	s.mu.RLock()
	mgr := s.webSessionManager
	s.mu.RUnlock()
	if mgr == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Session manager not configured", "SESSION_UNAVAILABLE")
		return
	}

	// Pre-session CSRF double-submit check (ADR-018 §3): the browser must echo the
	// cfgms_csrf_pre cookie value as the X-CSRF-Token header. Both must be present and
	// equal (constant-time). This guards against CSRF on the login form POST itself.
	csrfCookie, cookieErr := r.Cookie(cookieCSRFPre)
	csrfHeader := r.Header.Get(headerCSRFToken)
	if cookieErr != nil || csrfCookie.Value == "" || csrfHeader == "" ||
		subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(csrfHeader)) != 1 {
		s.writeErrorResponse(w, http.StatusForbidden,
			"CSRF token missing or mismatched", "CSRF_MISMATCH")
		return
	}

	// Decode the optional request body. Cap at 4 KB to prevent unbounded reads.
	var req PasskeyLoginBeginRequest
	if r.Body != nil {
		limited := io.LimitReader(r.Body, 4096)
		_ = json.NewDecoder(limited).Decode(&req)
	}

	// Validate username format if provided; this does not disclose account existence.
	if req.Username != "" {
		if validateErr := validateWebUsername(req.Username); validateErr != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, validateErr.Error(), "INVALID_USERNAME")
			return
		}
	}

	// Always use discoverable (resident-key) flow. This produces a uniform response for
	// all callers — the shape does not change based on account existence or credential
	// enrollment, closing the account-enumeration oracle (Issue #2993 AC).
	assertion, sessionData, err := wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.logger.Error("Passkey login begin: BeginDiscoverableLogin failed",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to begin passkey login", "WEBAUTHN_BEGIN_ERROR")
		return
	}

	ceremonyID, genErr := generateCeremonyID()
	if genErr != nil {
		s.logger.Error("Passkey login begin: failed to generate ceremony ID",
			"error", logging.SanitizeLogValue(genErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to generate ceremony ID", "CEREMONY_GEN_ERROR")
		return
	}

	s.passkeyLoginSessions.Store(ceremonyID, &passkeyLoginSession{
		data:         *sessionData,
		expires:      time.Now().Add(passkeyLoginCeremonyMaxAge * time.Second),
		accountID:    req.Username,
		discoverable: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     cookiePasskeyCeremony,
		Value:    ceremonyID,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   passkeyLoginCeremonyMaxAge,
	})

	s.writeResponse(w, http.StatusOK, assertion)
}

// handlePasskeyLoginFinish handles POST /api/v1/web/passkey/login/finish.
//
// Verifies the authenticator assertion via FinishDiscoverableLogin (always, matching the
// discoverable begin). Resolves the account from the userHandle provided by the authenticator
// (stored as account UUID at registration time). On success issues a session at
// AssuranceStrong (ADR-021 Decision 3) and revokes any pre-existing session cookie to
// defend against session fixation.
func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	s.mu.RLock()
	mgr := s.webSessionManager
	s.mu.RUnlock()
	if mgr == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Session manager not configured", "SESSION_UNAVAILABLE")
		return
	}

	// Bind this finish call to the begin call via the ceremony cookie.
	ceremonyCookie, cookieErr := r.Cookie(cookiePasskeyCeremony)
	if cookieErr != nil || ceremonyCookie.Value == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"No active login session — call begin first", "NO_ACTIVE_LOGIN_SESSION")
		return
	}
	ceremonyID := ceremonyCookie.Value

	// Load and unconditionally delete the pending session (single-use enforcement).
	rawSession, ok := s.passkeyLoginSessions.LoadAndDelete(ceremonyID)
	if !ok {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"No active login session — call begin first", "NO_ACTIVE_LOGIN_SESSION")
		return
	}
	pending, ok := rawSession.(*passkeyLoginSession)
	if !ok {
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Invalid session state", "SESSION_STATE_ERROR")
		return
	}

	if time.Now().After(pending.expires) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Login session expired — restart with begin", "SESSION_EXPIRED")
		return
	}

	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Per-IP throttle check (fast rejection without account resolution).
	if sourceIP != "" {
		if blocked, _ := s.checkPasskeyLoginThrottle("ip:" + sourceIP); blocked {
			s.emitWebLoginAudit(r.Context(), "", "", "web.passkey.login.failure", business.AuditResultFailure)
			s.writeErrorResponse(w, http.StatusTooManyRequests,
				"Too many failed attempts — try again later", "THROTTLED")
			return
		}
	}

	// Per-account throttle check using the username hint from begin (if provided).
	if pending.accountID != "" {
		if blocked, _ := s.checkPasskeyLoginThrottle("account:" + pending.accountID); blocked {
			s.emitWebLoginAudit(r.Context(), pending.accountID, "", "web.passkey.login.failure", business.AuditResultFailure)
			s.writeErrorResponse(w, http.StatusTooManyRequests,
				"Too many failed attempts — try again later", "THROTTLED")
			return
		}
	}

	// Always use FinishDiscoverableLogin (matches the always-discoverable begin).
	// The handler resolves the account from the authenticator-provided userHandle,
	// which the authenticator stores as the account UUID at registration time.
	var acct *webAccount
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) == 0 {
			return nil, fmt.Errorf("blank user handle")
		}
		found, err := s.getWebAccountByID(r.Context(), string(userHandle))
		if err != nil || found == nil {
			return nil, err
		}
		acct = found
		return buildWebauthnUser(found), nil
	}

	credential, finishErr := wa.FinishDiscoverableLogin(handler, pending.data, r)
	if finishErr != nil {
		s.logger.Warn("Passkey login finish: FinishDiscoverableLogin failed",
			"source_ip", logging.SanitizeLogValue(sourceIP),
			"error", logging.SanitizeLogValue(finishErr.Error()))
		if sourceIP != "" {
			s.recordPasskeyLoginFailure("ip:" + sourceIP)
		}
		if pending.accountID != "" {
			s.recordPasskeyLoginFailure("account:" + pending.accountID)
		}
		// Emit failure audit. Account identity may be unknown if the assertion failed
		// before the user-handler callback was reached.
		auditUsername := pending.accountID
		if acct != nil {
			auditUsername = acct.Username
		}
		s.emitWebLoginAudit(r.Context(), auditUsername, "", "web.passkey.login.failure", business.AuditResultFailure)
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	// Sign-count advancement check (W3C WebAuthn §7.2 step 21).
	// A non-advancing count suggests an authenticator clone; reject and record failure.
	newSignCount := credential.Authenticator.SignCount
	var storedSignCount uint32
	for _, c := range acct.Credentials {
		if string(c.ID) == string(credential.ID) {
			storedSignCount = c.SignCount
			break
		}
	}
	if (storedSignCount > 0 || newSignCount > 0) && newSignCount <= storedSignCount {
		s.logger.Warn("Passkey login finish: sign count not advancing — potential authenticator clone",
			"source_ip", logging.SanitizeLogValue(sourceIP),
			"stored_count", storedSignCount,
			"response_count", newSignCount)
		if sourceIP != "" {
			s.recordPasskeyLoginFailure("ip:" + sourceIP)
		}
		s.recordPasskeyLoginFailure("account:" + acct.Username)
		s.emitWebLoginAudit(r.Context(), acct.Username, acct.TenantID, "web.passkey.login.failure", business.AuditResultFailure)
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	// Issue #3126: check whether the account is disabled before issuing a session.
	// VerifyWebCredential returns ErrInvalidWebCredential for disabled accounts.
	// The error message is deliberately identical to the WebAuthn verification error
	// so the response does not disclose the reason for rejection.
	if credErr := s.VerifyWebCredential(acct); credErr != nil {
		s.recordPasskeyLoginFailure("account:" + acct.Username)
		s.emitWebLoginAudit(r.Context(), acct.Username, acct.TenantID, "web.passkey.login.failure", business.AuditResultFailure)
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	// Persist the advanced sign count.
	updatedAcct := *acct
	updatedAcct.Credentials = make([]WebAuthnCredential, len(acct.Credentials))
	copy(updatedAcct.Credentials, acct.Credentials)
	for i, c := range updatedAcct.Credentials {
		if string(c.ID) == string(credential.ID) {
			updatedAcct.Credentials[i].SignCount = newSignCount
			break
		}
	}
	if persistErr := s.persistWebAccount(r.Context(), &updatedAcct, acct.Username); persistErr != nil {
		s.logger.Error("Passkey login finish: failed to persist sign count",
			"username", logging.SanitizeLogValue(acct.Username),
			"error", logging.SanitizeLogValue(persistErr.Error()))
		// Non-fatal: cryptographic verification succeeded; proceed with login.
	} else {
		s.cacheWebAccount(&updatedAcct)
	}

	// Session-fixation defence: revoke any pre-existing session cookie before
	// issuing a new one. Best-effort — a revocation failure does not abort the login.
	if sessionCookie, cErr := r.Cookie(cookieWebSession); cErr == nil && sessionCookie.Value != "" {
		if sess, valErr := mgr.Validate(r.Context(), sessionCookie.Value); valErr == nil {
			_ = mgr.Revoke(r.Context(), sess.ID)
		}
	}

	// Issue a Basic session, then immediately elevate to Strong (ADR-021 Decision 3).
	// A login-time passkey assertion is phishing-resistant and earns Strong directly.
	issuedSess, _, issueErr := mgr.Issue(r.Context(), acct.ID, "web", acct.TenantID)
	if issueErr != nil {
		s.logger.Error("Passkey login finish: failed to issue session",
			"username", logging.SanitizeLogValue(acct.Username),
			"error", logging.SanitizeLogValue(issueErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to issue session", "SESSION_ERROR")
		return
	}

	_, newToken, elevateErr := mgr.Elevate(r.Context(), issuedSess.ID, credential.ID, sourceIP)
	if elevateErr != nil {
		s.logger.Error("Passkey login finish: failed to elevate session",
			"username", logging.SanitizeLogValue(acct.Username),
			"error", logging.SanitizeLogValue(elevateErr.Error()))
		_ = mgr.Revoke(r.Context(), issuedSess.ID)
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to elevate session", "SESSION_ELEVATION_ERROR")
		return
	}

	// Mint and store a session-bound CSRF token for subsequent state-mutating requests.
	csrfToken, csrfErr := generateCSRFToken()
	if csrfErr != nil {
		s.logger.Error("Passkey login finish: failed to generate CSRF token",
			"username", logging.SanitizeLogValue(acct.Username),
			"error", logging.SanitizeLogValue(csrfErr.Error()))
		_ = mgr.Revoke(r.Context(), issuedSess.ID)
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to generate CSRF token", "CSRF_GEN_ERROR")
		return
	}
	s.csrfTokens.Store(issuedSess.ID, csrfToken)

	// Set the session cookie (HttpOnly — JS must not read the session token).
	http.SetCookie(w, &http.Cookie{
		Name:     cookieWebSession,
		Value:    newToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	// Set the CSRF cookie (NOT HttpOnly — JS reads it to set X-CSRF-Token on mutations).
	// #nosec G124 -- this double-submit CSRF cookie must be readable by browser
	// code; Secure and SameSite=Strict prevent transport and cross-site exposure.
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRFSession,
		Value:    csrfToken,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	// Clear the ceremony and pre-CSRF cookies (single-use; no longer needed).
	http.SetCookie(w, &http.Cookie{
		Name:     cookiePasskeyCeremony,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	// #nosec G124 -- the pre-session CSRF deletion cookie intentionally mirrors
	// the readable cookie's attributes so the browser removes the correct cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRFPre,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	s.emitWebLoginAudit(r.Context(), acct.Username, acct.TenantID, "web.passkey.login.success", business.AuditResultSuccess)
	s.logger.Info("Passkey login successful",
		"username", logging.SanitizeLogValue(acct.Username),
		"source_ip", logging.SanitizeLogValue(sourceIP))

	s.writeResponse(w, http.StatusOK, PasskeyLoginFinishResponse{
		OK:        true,
		Username:  acct.Username,
		TenantID:  acct.TenantID,
		RootScope: acct.RootScope,
	})
}

// checkPasskeyLoginThrottle returns (true, retryAfter) when the key is currently throttled,
// or (false, 0) when the call may proceed.
func (s *Server) checkPasskeyLoginThrottle(key string) (blocked bool, retryAfter time.Duration) {
	raw, ok := s.passkeyLoginThrottle.Load(key)
	if !ok {
		return false, 0
	}
	rec, ok := raw.(*elevateThrottleRecord)
	if !ok {
		return false, 0
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !rec.nextAllowed.IsZero() && time.Now().Before(rec.nextAllowed) {
		return true, time.Until(rec.nextAllowed)
	}
	return false, 0
}

// recordPasskeyLoginFailure increments the failure counter for key and sets the
// next-allowed timestamp. Reuses the elevateBackoff schedule and elevateThrottleRecord
// type — the throttle policy is identical.
func (s *Server) recordPasskeyLoginFailure(key string) {
	raw, _ := s.passkeyLoginThrottle.LoadOrStore(key, &elevateThrottleRecord{})
	rec := raw.(*elevateThrottleRecord)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.fails++
	delay := elevateBackoff(rec.fails)
	if delay > 0 {
		rec.nextAllowed = time.Now().Add(delay)
	}
}
