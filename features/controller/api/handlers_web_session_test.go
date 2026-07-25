// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2993: tests for passkey-only web login/logout, pre-session CSRF on begin,
// session-bound CSRF middleware, and sanitized audit events (ADR-018 §3, ADR-021 §3).
//
// All success-path tests drive the handlers directly using W3C NoneES256 spec vectors
// (see handlers_webauthn_elevate_test.go) injected into s.passkeyLoginSessions so we
// can deterministically control the challenge without calling handlePasskeyLoginBegin.
// No mocks; all WebAuthn verification runs through the real go-webauthn library.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// --- helpers ---

// setupPasskeySessionServer creates a server with WebAuthn configured for the
// NoneES256 spec-vector RP, a web session manager, and the spec-vector credential
// injected into the test account. Use this for tests that need a successful login.
func setupPasskeySessionServer(t *testing.T) (*Server, string) {
	t.Helper()
	server, username := setupWebAuthnServer(t, svAuthRPID, []string{svAuthOrigin})

	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	store := session.NewMemStore(webCfg, time.Now)
	t.Cleanup(store.Close)
	server.SetWebSessionManager(session.NewManager(webCfg, store, time.Now))

	credIDBytes, err := hex.DecodeString(svAuthCredentialIDHex)
	require.NoError(t, err)
	pubKeyBytes, err := hex.DecodeString(svAuthPublicKeyHex)
	require.NoError(t, err)
	injectCredentialWithPublicKey(t, server, username, credIDBytes, pubKeyBytes, 0)

	return server, username
}

// doPasskeyLogin drives a complete passkey-login finish using the NoneES256 spec vectors.
// It injects a passkeyLoginSession directly (bypassing begin), then calls
// handlePasskeyLoginFinish. Callers can pass an existingSession token to verify
// session-fixation revocation.
func doPasskeyLogin(t *testing.T, srv *Server, username, existingSession string) *httptest.ResponseRecorder {
	t.Helper()

	credIDBytes, err := hex.DecodeString(svAuthCredentialIDHex)
	require.NoError(t, err)
	challengeBytes, err := hex.DecodeString(svAuthChallengeHex)
	require.NoError(t, err)
	authDataBytes, err := hex.DecodeString(svAuthAuthDataHex)
	require.NoError(t, err)
	clientDataJSONBytes, err := hex.DecodeString(svAuthClientDataJSONHex)
	require.NoError(t, err)
	sigBytes, err := hex.DecodeString(svAuthSignatureHex)
	require.NoError(t, err)

	acct, lookupErr := srv.getWebAccount(context.Background(), username)
	require.NoError(t, lookupErr)
	require.NotNil(t, acct, "account %q must exist before passkey login", username)

	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)
	sd := webauthn.SessionData{
		Challenge:            challenge,
		RelyingPartyID:       svAuthRPID,
		UserID:               []byte(acct.ID),
		UserVerification:     protocol.VerificationPreferred,
		AllowedCredentialIDs: [][]byte{credIDBytes},
		Expires:              time.Now().Add(10 * time.Minute),
	}

	ceremonyID, genErr := generateCeremonyID()
	require.NoError(t, genErr)
	srv.passkeyLoginSessions.Store(ceremonyID, &passkeyLoginSession{
		data:         sd,
		expires:      time.Now().Add(passkeyLoginCeremonyMaxAge * time.Second),
		accountID:    username,
		discoverable: false,
	})

	body := buildAssertionBody(t, credIDBytes, authDataBytes, clientDataJSONBytes, sigBytes)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", body)
	req.AddCookie(&http.Cookie{Name: cookiePasskeyCeremony, Value: ceremonyID})
	if existingSession != "" {
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: existingSession})
	}
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)
	return rec
}

// doPasskeyLoginBegin calls handlePasskeyLoginBegin directly with the given pre-session
// CSRF token (both cookie and header). If csrfToken is empty, neither is sent.
func doPasskeyLoginBegin(t *testing.T, srv *Server, csrfToken, username string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyBytes []byte
	if username != "" {
		var err error
		bodyBytes, err = json.Marshal(PasskeyLoginBeginRequest{Username: username})
		require.NoError(t, err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/begin", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	if csrfToken != "" {
		req.Header.Set(headerCSRFToken, csrfToken)
		req.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrfToken})
	}
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginBegin(rec, req)
	return rec
}

// doCSRF calls GET /api/v1/web/csrf and returns the pre-session CSRF cookie value.
func doCSRF(t *testing.T, srv *Server) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/csrf", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "GET /csrf body: %s", rec.Body.String())

	var tok string
	for _, c := range readSetCookies(t, rec) {
		if c.Name == cookieCSRFPre {
			tok = c.Value
			break
		}
	}
	require.NotEmpty(t, tok, "GET /csrf must set %s cookie", cookieCSRFPre)
	return tok
}

// extractCookie returns the named cookie value from the Set-Cookie response headers.
func extractCookie(rec *httptest.ResponseRecorder, name string) string {
	for _, c := range readSetCookies(nil, rec) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// readSetCookies parses Set-Cookie headers from the recorder response.
func readSetCookies(_ *testing.T, rec *httptest.ResponseRecorder) []*http.Cookie {
	resp := &http.Response{Header: rec.Result().Header}
	return resp.Cookies()
}

// doLogout sends POST /api/v1/web/logout with the session + CSRF cookies and header.
func doLogout(t *testing.T, srv *Server, sessionTok, csrfTok string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/logout", nil)
	req.Header.Set(headerCSRFToken, csrfTok)
	req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionTok})
	req.AddCookie(&http.Cookie{Name: cookieCSRFSession, Value: csrfTok})
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	return rec
}

// --- tests ---

// TestPasskeyLogin_SuccessSetsBothCookies verifies that a valid passkey assertion sets
// cfgms_session (HttpOnly) and cfgms_csrf (non-HttpOnly), the body contains no token
// (security A5.5), the ceremony and pre-CSRF cookies are cleared, and the session
// is immediately AssuranceStrong (ADR-021 Decision 3).
func TestPasskeyLogin_SuccessSetsBothCookies(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	rec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, rec.Code, "login body: %s", rec.Body.String())

	cookieMap := make(map[string]*http.Cookie)
	for _, c := range readSetCookies(nil, rec) {
		cookieMap[c.Name] = c
	}

	// cfgms_session: HttpOnly, Secure, SameSite=Strict.
	sess, ok := cookieMap[cookieWebSession]
	require.True(t, ok, "cfgms_session must be set")
	assert.True(t, sess.HttpOnly, "cfgms_session must be HttpOnly")
	assert.True(t, sess.Secure, "cfgms_session must be Secure")
	assert.Equal(t, http.SameSiteStrictMode, sess.SameSite)
	assert.NotEmpty(t, sess.Value)

	// cfgms_csrf: NOT HttpOnly (JS must read it to set X-CSRF-Token), Secure, Strict.
	csrf, ok := cookieMap[cookieCSRFSession]
	require.True(t, ok, "cfgms_csrf must be set")
	assert.False(t, csrf.HttpOnly, "cfgms_csrf must NOT be HttpOnly (JS reads it)")
	assert.True(t, csrf.Secure)
	assert.Equal(t, http.SameSiteStrictMode, csrf.SameSite)
	assert.NotEmpty(t, csrf.Value)

	// Ceremony and pre-CSRF cookies must be cleared.
	if ceremony, ok := cookieMap[cookiePasskeyCeremony]; ok {
		assert.LessOrEqual(t, ceremony.MaxAge, 0, "ceremony cookie must be cleared on success")
	}
	if pre, ok := cookieMap[cookieCSRFPre]; ok {
		assert.LessOrEqual(t, pre.MaxAge, 0, "pre-CSRF cookie must be cleared on success")
	}

	// Response body must not contain session or CSRF tokens (security A5.5).
	body := rec.Body.String()
	assert.NotContains(t, body, sess.Value, "response body must not contain the session token")
	assert.NotContains(t, body, csrf.Value, "response body must not contain the CSRF token")

	// The issued session must validate as AssuranceStrong (ADR-021 Decision 3).
	srv.mu.RLock()
	mgr := srv.webSessionManager
	srv.mu.RUnlock()
	webSess, err := mgr.Validate(context.Background(), sess.Value)
	require.NoError(t, err)
	assert.Equal(t, session.AssuranceStrong, webSess.Assurance,
		"session must be AssuranceStrong immediately after passkey login")
}

// TestPasskeyLogin_ResponseCarriesTenantScope verifies that the finish response
// body exposes tenant_id and root_scope. Both the tenant-scoped and root-scoped
// shapes are asserted (Issue #2919).
func TestPasskeyLogin_ResponseCarriesTenantScope(t *testing.T) {
	decodeScope := func(t *testing.T, rec *httptest.ResponseRecorder) (string, bool) {
		t.Helper()
		var env struct {
			Data PasskeyLoginFinishResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), "body: %s", rec.Body.String())
		require.True(t, env.Data.OK, "response must report ok=true")
		return env.Data.TenantID, env.Data.RootScope
	}

	t.Run("tenant-scoped account returns tenant_id and root_scope=false", func(t *testing.T) {
		srv, username := setupPasskeySessionServer(t)
		rec := doPasskeyLogin(t, srv, username, "")
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		// setupWebAuthnServer creates accounts without a tenant; check from the account.
		acct, err := srv.getWebAccount(context.Background(), username)
		require.NoError(t, err)
		tenantID, rootScope := decodeScope(t, rec)
		assert.Equal(t, acct.TenantID, tenantID)
		assert.False(t, rootScope, "tenant-scoped login must report root_scope=false")
	})

	t.Run("root-scoped account returns empty tenant_id and root_scope=true", func(t *testing.T) {
		srv, _ := setupPasskeySessionServer(t)
		const rootUser = "root-passkey-user"
		rec := postWebAccount(t, srv, testAdminPrincipal(), WebAccountRequest{
			Username:  rootUser,
			RootScope: true,
		})
		require.Equal(t, http.StatusCreated, rec.Code, "root account setup: %s", rec.Body.String())

		credIDBytes, err := hex.DecodeString(svAuthCredentialIDHex)
		require.NoError(t, err)
		pubKeyBytes, err := hex.DecodeString(svAuthPublicKeyHex)
		require.NoError(t, err)
		injectCredentialWithPublicKey(t, srv, rootUser, credIDBytes, pubKeyBytes, 0)

		loginRec := doPasskeyLogin(t, srv, rootUser, "")
		require.Equal(t, http.StatusOK, loginRec.Code, "body: %s", loginRec.Body.String())
		tenantID, rootScope := decodeScope(t, loginRec)
		assert.Empty(t, tenantID, "root-scoped login must return empty tenant_id")
		assert.True(t, rootScope, "root-scoped login must report root_scope=true")
	})
}

// TestPasskeyLogin_PreSessionCSRFRequired verifies that begin returns 403 when
// the pre-session CSRF double-submit check fails (cookie absent, header absent,
// or header value mismatched). SameSite=Strict on the ceremony cookie handles
// the finish endpoint; no CSRF check is performed there.
func TestPasskeyLogin_PreSessionCSRFRequired(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)

	t.Run("no CSRF cookie or header", func(t *testing.T) {
		rec := doPasskeyLoginBegin(t, srv, "" /* no token */, "")
		assert.Equal(t, http.StatusForbidden, rec.Code, "absent CSRF must yield 403")
		assert.Contains(t, rec.Body.String(), "CSRF")
	})

	t.Run("CSRF cookie present but no header", func(t *testing.T) {
		csrfToken := doCSRF(t, srv)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/begin", nil)
		req.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrfToken})
		// no X-CSRF-Token header
		rec := httptest.NewRecorder()
		srv.handlePasskeyLoginBegin(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "missing header must yield 403")
	})

	t.Run("CSRF cookie with mismatched header", func(t *testing.T) {
		csrfToken := doCSRF(t, srv)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/begin", nil)
		req.Header.Set(headerCSRFToken, "tampered-csrf-value")
		req.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrfToken})
		rec := httptest.NewRecorder()
		srv.handlePasskeyLoginBegin(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "mismatched CSRF must yield 403")
	})

	t.Run("valid CSRF passes the gate", func(t *testing.T) {
		csrfToken := doCSRF(t, srv)
		rec := doPasskeyLoginBegin(t, srv, csrfToken, "")
		// Without a username, begins a discoverable ceremony → 200 with challenge JSON.
		assert.Equal(t, http.StatusOK, rec.Code, "valid CSRF must pass the gate; body: %s", rec.Body.String())
		// A ceremony cookie must be set.
		var found bool
		for _, c := range readSetCookies(nil, rec) {
			if c.Name == cookiePasskeyCeremony {
				found = true
				assert.True(t, c.HttpOnly, "ceremony cookie must be HttpOnly")
				assert.True(t, c.Secure, "ceremony cookie must be Secure")
				assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
				assert.Equal(t, passkeyLoginCeremonyMaxAge, c.MaxAge)
			}
		}
		assert.True(t, found, "begin must set cfgms_passkey_ceremony cookie on success")
	})
}

// TestPasskeyLogin_SessionFixation verifies that:
// (a) Two successful logins produce distinct session tokens.
// (b) A cfgms_session cookie from before a new login is revoked (session-fixation defence).
func TestPasskeyLogin_SessionFixation(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	rec1 := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, rec1.Code, "first login body: %s", rec1.Body.String())
	tok1 := extractCookie(rec1, cookieWebSession)
	require.NotEmpty(t, tok1, "first login must set cfgms_session")

	// Second login carries tok1 in the session cookie → handler must revoke it.
	rec2 := doPasskeyLogin(t, srv, username, tok1)
	require.Equal(t, http.StatusOK, rec2.Code, "second login body: %s", rec2.Body.String())
	tok2 := extractCookie(rec2, cookieWebSession)
	require.NotEmpty(t, tok2, "second login must set cfgms_session")

	assert.NotEqual(t, tok1, tok2, "two logins must produce distinct session tokens")

	// tok1 must have been revoked by the second login.
	srv.mu.RLock()
	mgr := srv.webSessionManager
	srv.mu.RUnlock()
	_, err := mgr.Validate(context.Background(), tok1)
	assert.Error(t, err, "pre-login token must be invalidated by a subsequent login (session-fixation defence)")
}

// TestPasskeyLogin_NoWebAuthn_503 verifies that both begin and finish return 503 when
// WebAuthn is not configured on the server.
func TestPasskeyLogin_NoWebAuthn_503(t *testing.T) {
	srv := setupTestServer(t)
	// No WebAuthn configured.

	t.Run("begin", func(t *testing.T) {
		rec := httptest.NewRecorder()
		srv.handlePasskeyLoginBegin(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("finish", func(t *testing.T) {
		rec := httptest.NewRecorder()
		srv.handlePasskeyLoginFinish(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
	})
}

// TestPasskeyLogin_NoSessionManager_503 verifies that both begin and finish return 503
// when the session manager has not been configured on the server.
func TestPasskeyLogin_NoSessionManager_503(t *testing.T) {
	srv := setupTestServer(t)
	wa, err := NewWebAuthnFromConfig(svAuthRPID, svAuthRPID, []string{svAuthOrigin})
	require.NoError(t, err)
	srv.SetWebAuthn(wa)
	// No webSessionManager set.

	csrfToken := "any-csrf-token"

	t.Run("begin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(headerCSRFToken, csrfToken)
		req.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrfToken})
		rec := httptest.NewRecorder()
		srv.handlePasskeyLoginBegin(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "SESSION_UNAVAILABLE", errCode(t, rec.Body.Bytes()))
	})

	t.Run("finish", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: cookiePasskeyCeremony, Value: "any-id"})
		rec := httptest.NewRecorder()
		srv.handlePasskeyLoginFinish(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "SESSION_UNAVAILABLE", errCode(t, rec.Body.Bytes()))
	})
}

// TestPasskeyLogin_NoCeremonyCookie_400 verifies that finish returns 400 when the
// cfgms_passkey_ceremony cookie is absent.
func TestPasskeyLogin_NoCeremonyCookie_400(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", nil)
	// no ceremony cookie
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))
}

// TestPasskeyLogin_UnknownCeremonyID_400 verifies that finish returns 400 when the
// ceremony cookie value is not in the pending-sessions map.
func TestPasskeyLogin_UnknownCeremonyID_400(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", nil)
	req.AddCookie(&http.Cookie{Name: cookiePasskeyCeremony, Value: "not-a-real-ceremony-id"})
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))
}

// TestPasskeyLogin_ExpiredCeremony_400 verifies that finish returns 400 when the
// ceremony session exists but has already expired.
func TestPasskeyLogin_ExpiredCeremony_400(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)

	const ceremonyID = "expired-ceremony-id"
	srv.passkeyLoginSessions.Store(ceremonyID, &passkeyLoginSession{
		data:         webauthn.SessionData{},
		expires:      time.Now().Add(-1 * time.Second), // already expired
		accountID:    "any-user",
		discoverable: false,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", nil)
	req.AddCookie(&http.Cookie{Name: cookiePasskeyCeremony, Value: ceremonyID})
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "SESSION_EXPIRED", errCode(t, rec.Body.Bytes()))
}

// TestPasskeyLogin_Throttled_429 verifies that finish returns 429 when the
// per-ceremony throttle has accumulated enough failures.
func TestPasskeyLogin_Throttled_429(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	const ceremonyID = "throttle-ceremony-id"
	// Accumulate enough failures to trigger the backoff.
	for i := 0; i < 4; i++ {
		srv.recordPasskeyLoginFailure("ceremony:" + ceremonyID)
	}

	// Inject a fresh, non-expired session.
	srv.passkeyLoginSessions.Store(ceremonyID, &passkeyLoginSession{
		data:         webauthn.SessionData{},
		expires:      time.Now().Add(5 * time.Minute),
		accountID:    username,
		discoverable: false,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", nil)
	req.AddCookie(&http.Cookie{Name: cookiePasskeyCeremony, Value: ceremonyID})
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "THROTTLED", errCode(t, rec.Body.Bytes()))
}

// TestPasskeyLogin_AssuranceStrongAfterLogin is the [REQUIRED TEST] for ADR-021
// Decision 3: the session issued at passkey login carries AssuranceStrong immediately
// (Issue + Elevate in the same handler).
func TestPasskeyLogin_AssuranceStrongAfterLogin(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	rec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	sessionTok := extractCookie(rec, cookieWebSession)
	require.NotEmpty(t, sessionTok)

	srv.mu.RLock()
	mgr := srv.webSessionManager
	srv.mu.RUnlock()

	webSess, err := mgr.Validate(context.Background(), sessionTok)
	require.NoError(t, err)
	assert.Equal(t, session.AssuranceStrong, webSess.Assurance,
		"session must carry AssuranceStrong immediately after passkey login (ADR-021 §3)")
}

// TestWebLogout_RevokesSessionAndClearsCookies verifies that logout revokes the
// server-side session (subsequent use returns an error), and both session and CSRF
// cookies are cleared in the response.
func TestWebLogout_RevokesSessionAndClearsCookies(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	loginRec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, loginRec.Code)

	sessionTok := extractCookie(loginRec, cookieWebSession)
	csrfTok := extractCookie(loginRec, cookieCSRFSession)
	require.NotEmpty(t, sessionTok)
	require.NotEmpty(t, csrfTok)

	logoutRec := doLogout(t, srv, sessionTok, csrfTok)
	assert.Equal(t, http.StatusOK, logoutRec.Code, "logout body: %s", logoutRec.Body.String())

	// Both session and CSRF cookies must be cleared (MaxAge ≤ 0).
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range readSetCookies(nil, logoutRec) {
		cookieMap[c.Name] = c
	}
	for _, name := range []string{cookieWebSession, cookieCSRFSession} {
		c, ok := cookieMap[name]
		if assert.True(t, ok, "Set-Cookie must include %s on logout", name) {
			assert.LessOrEqual(t, c.MaxAge, 0, "%s must be cleared (Max-Age ≤ 0)", name)
		}
	}

	// cfgms_session deletion cookie must carry HttpOnly.
	if sess, ok := cookieMap[cookieWebSession]; ok {
		assert.True(t, sess.HttpOnly, "cfgms_session deletion cookie must be HttpOnly")
	}
	// cfgms_csrf deletion cookie must NOT be HttpOnly (matches its login-time design).
	if csrfCk, ok := cookieMap[cookieCSRFSession]; ok {
		assert.False(t, csrfCk.HttpOnly, "cfgms_csrf deletion cookie must NOT be HttpOnly")
	}

	// Server-side session must be revoked.
	srv.mu.RLock()
	mgr := srv.webSessionManager
	srv.mu.RUnlock()
	_, err := mgr.Validate(context.Background(), sessionTok)
	assert.Error(t, err, "revoked session must not validate after logout")
}

// TestWebLogout_CSRFRequired verifies that logout returns 403 when X-CSRF-Token is
// missing or mismatched.
func TestWebLogout_CSRFRequired(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	loginRec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, loginRec.Code)

	sessionTok := extractCookie(loginRec, cookieWebSession)
	csrfTok := extractCookie(loginRec, cookieCSRFSession)
	require.NotEmpty(t, sessionTok)
	require.NotEmpty(t, csrfTok)

	t.Run("missing X-CSRF-Token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/logout", nil)
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionTok})
		// no X-CSRF-Token header
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("wrong X-CSRF-Token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/logout", nil)
		req.Header.Set(headerCSRFToken, "tampered")
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionTok})
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	// Clean up.
	doLogout(t, srv, sessionTok, csrfTok)
}

// TestCSRFMiddleware_SessionBound verifies the session-bound CSRF middleware on the
// api subrouter: GET is exempt; cookie-auth POST without CSRF header → 403;
// cookie-auth POST with correct CSRF header → passes; API-key POST is never checked.
func TestCSRFMiddleware_SessionBound(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)

	// Issue a session directly and inject a CSRF token (no need for passkey ceremony here).
	_, token, err := srv.webSessionManager.Issue(context.Background(),
		"webauthn-test-user", "test", "")
	require.NoError(t, err)
	webSess, err := srv.webSessionManager.Validate(context.Background(), token)
	require.NoError(t, err)

	csrfTok, err := generateCSRFToken()
	require.NoError(t, err)
	srv.csrfTokens.Store(webSess.ID, csrfTok)

	// Build the handler stack: auth → CSRF → synthetic handler.
	var reached bool
	syntheticHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	stack := srv.authenticationMiddleware(srv.csrfMiddleware(syntheticHandler))

	t.Run("GET is exempt", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: token})
		rec := httptest.NewRecorder()
		stack.ServeHTTP(rec, req)
		assert.True(t, reached, "GET must pass through CSRF middleware")
	})

	t.Run("cookie-auth POST without CSRF header → 403", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: token})
		rec := httptest.NewRecorder()
		stack.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, reached, "handler must not be reached when CSRF fails")
	})

	t.Run("cookie-auth POST with correct CSRF header → passes", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: token})
		req.Header.Set(headerCSRFToken, csrfTok)
		rec := httptest.NewRecorder()
		stack.ServeHTTP(rec, req)
		assert.True(t, reached, "handler must be reached when CSRF is correct")
		assert.NotEqual(t, http.StatusForbidden, rec.Code)
	})

	t.Run("API-key authenticated POST is never CSRF-checked", func(t *testing.T) {
		reached = false
		apiKey := NewTestKey(t, srv, []string{"steward:list"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
		req.Header.Set("X-API-Key", apiKey)
		// no X-CSRF-Token header
		rec := httptest.NewRecorder()
		stack.ServeHTTP(rec, req)
		assert.NotEqual(t, http.StatusForbidden, rec.Code,
			"API-key requests must not be blocked by CSRF middleware")
	})
}

// TestWebEndpoints_PublicBaseRouterRegistrations asserts that the passkey login
// endpoints and the legacy non-passkey endpoints are registered as expected.
func TestWebEndpoints_PublicBaseRouterRegistrations(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)

	t.Run("GET /api/v1/web/csrf is accessible", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/web/csrf", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.NotEqual(t, http.StatusNotFound, rec.Code, "GET /api/v1/web/csrf must be registered")
	})

	t.Run("POST /api/v1/web/passkey/login/begin is CSRF-gated (not 404)", func(t *testing.T) {
		// No CSRF → 403; confirms endpoint is registered and publicly reachable.
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/begin", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code,
			"POST /api/v1/web/passkey/login/begin must be CSRF-gated (not 404)")
	})

	t.Run("POST /api/v1/web/passkey/login/finish is ceremony-cookie-gated (not 404)", func(t *testing.T) {
		// No ceremony cookie → 400; confirms endpoint is registered.
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code,
			"POST /api/v1/web/passkey/login/finish must be ceremony-gated (not 404)")
	})

	t.Run("POST /api/v1/web/logout is accessible", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/logout", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.NotEqual(t, http.StatusNotFound, rec.Code, "POST /api/v1/web/logout must be registered")
	})

	t.Run("POST /api/v1/web/login is 404 (password login removed, Issue #2993)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/login", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code,
			"POST /api/v1/web/login must be 404 — password login retired (Issue #2993)")
	})
}

// TestPasskeyLogin_RateLimited verifies that repeated unauthenticated requests to
// the passkey login begin endpoint are eventually rate-limited (429) by
// authDefense.Middleware.
func TestPasskeyLogin_RateLimited(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)

	var got429 bool
	for i := 0; i < 200; i++ {
		// Hammer POST /passkey/login/begin without CSRF → 403 each time until rate-limiter fires.
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/begin", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
		// Rate limiter may also fire on /csrf.
		csrfReq := httptest.NewRequest(http.MethodGet, "/api/v1/web/csrf", nil)
		csrfRec := httptest.NewRecorder()
		srv.router.ServeHTTP(csrfRec, csrfReq)
		if csrfRec.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	assert.True(t, got429, "repeated requests must be rate-limited (429) by authDefense.Middleware")
}

// TestPasskeyLogin_AuditEvents verifies that a successful passkey login and a
// subsequent logout each emit the expected authentication audit entry.
func TestPasskeyLogin_AuditEvents(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	loginRec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, loginRec.Code, "login body: %s", loginRec.Body.String())
	sessionTok := extractCookie(loginRec, cookieWebSession)
	csrfTok := extractCookie(loginRec, cookieCSRFSession)
	require.NotEmpty(t, sessionTok)
	require.NotEmpty(t, csrfTok)

	logoutRec := doLogout(t, srv, sessionTok, csrfTok)
	require.Equal(t, http.StatusOK, logoutRec.Code, "logout body: %s", logoutRec.Body.String())

	require.NoError(t, srv.auditManager.Flush(context.Background()))

	t.Run("login success emits authentication audit event", func(t *testing.T) {
		entries, err := srv.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
			Actions: []string{"web.passkey.login.success"},
		})
		require.NoError(t, err)
		require.NotEmpty(t, entries, "passkey login must emit an audit entry")
		e := entries[0]
		assert.Equal(t, business.AuditEventAuthentication, e.EventType,
			"audit entry must be of type authentication")
		assert.Equal(t, business.AuditResultSuccess, e.Result)
	})

	t.Run("logout emits authentication audit event", func(t *testing.T) {
		entries, err := srv.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
			Actions: []string{"web.logout"},
		})
		require.NoError(t, err)
		require.NotEmpty(t, entries, "logout must emit an audit entry")
		e := entries[0]
		assert.Equal(t, business.AuditEventAuthentication, e.EventType)
		assert.Equal(t, business.AuditResultSuccess, e.Result)
	})
}
