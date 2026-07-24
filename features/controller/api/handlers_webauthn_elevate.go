// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2965: WebAuthn step-up elevation — Basic → Strong (ADR-021 Amendment 2).
//
// Routes (webauthn:elevate permission, AssuranceBasic minimum):
//
//	POST /api/v1/webauthn/elevate/begin
//	     Generates a WebAuthn assertion challenge scoped to the caller's account
//	     credentials. The challenge is stored server-side keyed by session ID —
//	     never trusted from the client.
//
//	POST /api/v1/webauthn/elevate/finish
//	     Verifies the authenticator assertion, rotates the session token, and
//	     upgrades the session to AssuranceStrong. Returns the new assurance level
//	     and sets the rotated session cookie.
//
// Security properties enforced here:
//   - Session bound: the pending session is keyed by session ID (not by account or username)
//     so a second concurrent browser tab cannot consume another tab's elevation ceremony.
//   - Server-side credential resolution: the account is loaded from context principal ID —
//     never from a client-supplied username or credential hint.
//   - Single-use challenge: the elevation session is deleted (LoadAndDelete) at the start
//     of every finish call, preventing replay.
//   - Sign-count advancement: if either the stored or response sign count is nonzero, the
//     response count must strictly exceed the stored count (per W3C WebAuthn §7.2 step 21).
//   - Per-session and per-IP throttle with backoff (no hard lockout).
//   - Successful elevation audited: account, credential ID, source IP.
//   - Session-revoke path is never gated on the throttle (ADR-021 Amendment 2).
package api

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/cfgis/cfgms/pkg/logging"
)

// webAuthnElevateSession holds state for an in-progress step-up elevation ceremony.
// Stored in s.webAuthnElevateSessions keyed by session ID. Single-use: deleted via
// LoadAndDelete at the start of handleStepUpFinish regardless of outcome.
type webAuthnElevateSession struct {
	data      webauthn.SessionData
	expires   time.Time
	accountID string // principal.ID at begin time; finish re-derives this from context
}

// elevateThrottleRecord tracks per-key failed elevation attempts with exponential backoff.
// Keys in s.webAuthnElevateThrottle are "session:<sessionID>" or "ip:<sourceIP>".
// No hard lockout: callers may always retry after nextAllowed. The session-revoke path
// is not gated on this throttle (ADR-021 Amendment 2).
type elevateThrottleRecord struct {
	mu          sync.Mutex
	fails       int
	nextAllowed time.Time
}

// handleStepUpBegin handles POST /api/v1/webauthn/elevate/begin.
//
// Issues a WebAuthn assertion challenge scoped to the calling principal's registered
// credentials. The pending session is stored server-side keyed by the web session ID
// (from context) — never by a client-supplied identifier.
//
// The endpoint requires a cookie-authenticated web session (webSessionIDContextKey
// present in context). API-key and mTLS-cert callers have no web session to elevate
// and receive 400/SESSION_REQUIRED.
func (s *Server) handleStepUpBegin(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized,
			"Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	sessID, _ := r.Context().Value(webSessionIDContextKey).(string)
	if sessID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Step-up elevation requires a cookie-authenticated web session", "SESSION_REQUIRED")
		return
	}

	acct, err := s.getWebAccount(r.Context(), principal.ID)
	if err != nil {
		s.logger.Error("Step-up begin: failed to load web account",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to load web account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound,
			"Web account not found", "WEB_ACCOUNT_NOT_FOUND")
		return
	}
	if len(acct.Credentials) == 0 {
		s.writeErrorResponse(w, http.StatusConflict,
			"No WebAuthn credentials registered — enroll a passkey first", "NO_CREDENTIALS")
		return
	}

	user := buildWebauthnUser(acct)

	assertion, sessionData, err := wa.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.logger.Error("Step-up begin: BeginLogin failed",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to begin step-up ceremony", "WEBAUTHN_BEGIN_ERROR")
		return
	}

	s.webAuthnElevateSessions.Store(sessID, &webAuthnElevateSession{
		data:      *sessionData,
		expires:   time.Now().Add(webAuthnSessionTTL),
		accountID: principal.ID,
	})

	s.logger.Info("WebAuthn step-up elevation ceremony started",
		"principal_id", logging.SanitizeLogValue(principal.ID),
		"session_id", logging.SanitizeLogValue(sessID))

	s.writeResponse(w, http.StatusOK, assertion)
}

// handleStepUpFinish handles POST /api/v1/webauthn/elevate/finish.
//
// Verifies the authenticator assertion response against the server-stored challenge,
// checks sign-count advancement, calls webSessionManager.Elevate to rotate the session
// token and set AssuranceStrong, then sets the rotated cookie.
//
// A per-session and per-IP throttle with exponential backoff guards against brute-force
// attempts. No hard lockout is applied; the session-revoke path is not gated (ADR-021
// Amendment 2). Successful elevations are audited.
func (s *Server) handleStepUpFinish(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized,
			"Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	sessID, _ := r.Context().Value(webSessionIDContextKey).(string)
	if sessID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Step-up elevation requires a cookie-authenticated web session", "SESSION_REQUIRED")
		return
	}

	acct, err := s.getWebAccount(r.Context(), principal.ID)
	if err != nil {
		s.logger.Error("Step-up finish: failed to load web account",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to load web account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound,
			"Web account not found", "WEB_ACCOUNT_NOT_FOUND")
		return
	}

	// Load and unconditionally delete the pending session (single-use enforcement).
	rawSession, ok := s.webAuthnElevateSessions.LoadAndDelete(sessID)
	if !ok {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"No active elevation session — call begin first", "NO_ACTIVE_ELEVATION_SESSION")
		return
	}
	pending, ok := rawSession.(*webAuthnElevateSession)
	if !ok {
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Invalid session state", "SESSION_STATE_ERROR")
		return
	}
	if time.Now().After(pending.expires) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Elevation session expired — restart with begin", "SESSION_EXPIRED")
		return
	}

	// Extract source IP for throttle key and session binding.
	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Check per-session and per-IP throttle before the expensive FinishLogin call.
	if blocked, wait := s.checkElevateThrottle("session:" + sessID); blocked {
		s.logger.Warn("Step-up finish: per-session throttle active",
			"session_id", logging.SanitizeLogValue(sessID),
			"retry_after_seconds", int(wait.Seconds()))
		s.writeErrorResponse(w, http.StatusTooManyRequests,
			"Too many failed attempts — try again later", "THROTTLED")
		return
	}
	if sourceIP != "" {
		if blocked, wait := s.checkElevateThrottle("ip:" + sourceIP); blocked {
			s.logger.Warn("Step-up finish: per-IP throttle active",
				"source_ip", logging.SanitizeLogValue(sourceIP),
				"retry_after_seconds", int(wait.Seconds()))
			s.writeErrorResponse(w, http.StatusTooManyRequests,
				"Too many failed attempts — try again later", "THROTTLED")
			return
		}
	}

	user := buildWebauthnUser(acct)

	// Full server-side assertion verification: challenge (against the server-stored session
	// value, never the client-echoed field), origin, RP-ID, and ECDSA/RS256 signature.
	credential, err := wa.FinishLogin(user, pending.data, r)
	if err != nil {
		s.logger.Warn("Step-up finish: FinishLogin failed",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"session_id", logging.SanitizeLogValue(sessID),
			"source_ip", logging.SanitizeLogValue(sourceIP),
			"error", logging.SanitizeLogValue(err.Error()))
		s.recordElevateFailure("session:" + sessID)
		if sourceIP != "" {
			s.recordElevateFailure("ip:" + sourceIP)
		}
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	// Sign-count advancement check (W3C WebAuthn §7.2 step 21).
	// If either the stored or response count is nonzero, the response must strictly exceed
	// the stored count. Authenticators that do not implement sign counters return 0 for both;
	// the spec permits this (0→0 is allowed, not a suspected clone signal).
	newSignCount := credential.Authenticator.SignCount
	var storedSignCount uint32
	for _, c := range acct.Credentials {
		if string(c.ID) == string(credential.ID) {
			storedSignCount = c.SignCount
			break
		}
	}
	if (storedSignCount > 0 || newSignCount > 0) && newSignCount <= storedSignCount {
		s.logger.Warn("Step-up finish: sign count not advancing — potential authenticator clone",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"session_id", logging.SanitizeLogValue(sessID),
			"stored_count", storedSignCount,
			"response_count", newSignCount)
		s.recordElevateFailure("session:" + sessID)
		if sourceIP != "" {
			s.recordElevateFailure("ip:" + sourceIP)
		}
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	// Persist the advanced sign count. The credential is matched by ID.
	updatedAcct := *acct
	updatedAcct.Credentials = make([]WebAuthnCredential, len(acct.Credentials))
	copy(updatedAcct.Credentials, acct.Credentials)
	for i, c := range updatedAcct.Credentials {
		if string(c.ID) == string(credential.ID) {
			updatedAcct.Credentials[i].SignCount = newSignCount
			break
		}
	}
	if persistErr := s.persistWebAccount(r.Context(), &updatedAcct, principal.ID); persistErr != nil {
		s.logger.Error("Step-up finish: failed to persist updated sign count",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(persistErr.Error()))
		// Non-fatal for session elevation: sign-count persistence failing does not
		// compromise the cryptographic verification already performed. Log the error and proceed.
	} else {
		s.cacheWebAccount(&updatedAcct)
	}

	// Elevate the session: rotate the token and set AssuranceStrong.
	_, newToken, elevateErr := s.webSessionManager.Elevate(r.Context(), sessID, credential.ID, sourceIP)
	if elevateErr != nil {
		s.logger.Error("Step-up finish: session elevation failed",
			"session_id", logging.SanitizeLogValue(sessID),
			"error", logging.SanitizeLogValue(elevateErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to elevate session", "SESSION_ELEVATION_ERROR")
		return
	}

	// Set the rotated session cookie. The CSRF token binding survives because it is
	// keyed by session ID, which does not change during elevation (Issue #2965).
	http.SetCookie(w, &http.Cookie{
		Name:     cookieWebSession,
		Value:    newToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	now := time.Now().UTC()
	s.logger.Info("WebAuthn step-up elevation successful",
		"principal_id", logging.SanitizeLogValue(principal.ID),
		"session_id", logging.SanitizeLogValue(sessID),
		"credential_id", logging.SanitizeLogValue(string(credential.ID)),
		"source_ip", logging.SanitizeLogValue(sourceIP),
		"elevated_at", now.Format(time.RFC3339))

	s.writeResponse(w, http.StatusOK, StepUpElevateFinishResponse{
		Assurance:  "strong",
		ElevatedAt: now,
	})
}

// checkElevateThrottle returns (true, retryAfter) when the key is currently throttled,
// or (false, 0) when the call may proceed. Thread-safe.
func (s *Server) checkElevateThrottle(key string) (blocked bool, retryAfter time.Duration) {
	raw, ok := s.webAuthnElevateThrottle.Load(key)
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

// recordElevateFailure increments the failure counter for key and sets the next-allowed
// timestamp based on the backoff schedule. No hard lockout is ever applied.
func (s *Server) recordElevateFailure(key string) {
	raw, _ := s.webAuthnElevateThrottle.LoadOrStore(key, &elevateThrottleRecord{})
	rec := raw.(*elevateThrottleRecord)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.fails++
	delay := elevateBackoff(rec.fails)
	if delay > 0 {
		rec.nextAllowed = time.Now().Add(delay)
	}
}

// elevateBackoff returns the cooldown duration after a given number of consecutive failures.
// No value in this schedule should be so large as to effectively lock out the account —
// the maximum is 10 minutes, which an attacker can wait out but which impedes brute-force
// at typical PIN lengths. The caller may always revoke the session regardless of throttle state.
func elevateBackoff(fails int) time.Duration {
	switch {
	case fails <= 2:
		return 0
	case fails <= 4:
		return 10 * time.Second
	case fails <= 7:
		return 30 * time.Second
	case fails <= 11:
		return 2 * time.Minute
	default:
		return 10 * time.Minute
	}
}
