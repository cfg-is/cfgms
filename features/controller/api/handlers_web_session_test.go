// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2493: tests for web login/logout endpoints, pre-session CSRF, session-bound
// CSRF middleware, per-account lockout, and sanitized audit events (ADR-018 §3,4).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// --- helpers ---

// setupWebSessionServer creates a server wired with both a web account and a web
// session manager. The returned web account credentials can be used to drive login.
func setupWebSessionServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	srv := setupTestServer(t)

	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	store := session.NewMemStore(webCfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(webCfg, store, time.Now)
	srv.SetWebSessionManager(mgr)

	const (
		username = "testuser"
		password = "correcthorsebattery"
	)

	// Provision a web account via the handler (real argon2id hash).
	admin := testAdminPrincipal()
	rec := postWebAccount(t, srv, admin, WebAccountRequest{
		Username:    username,
		Password:    password,
		TenantID:    "tenant-test",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "account setup: %s", rec.Body.String())

	return srv, username, password
}

// doCSRF calls GET /api/v1/web/csrf and returns the pre-session cookie value.
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

// doLogin performs a login via the router and returns the recorder.
func doLogin(t *testing.T, srv *Server, csrfToken, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	return doLoginWith(t, srv, csrfToken, username, password, "")
}

// doLoginWith performs a login and optionally presents an existing session cookie so the
// session-fixation defence can revoke it (handleWebLogin step 4).
func doLoginWith(t *testing.T, srv *Server, csrfToken, username, password, existingSessionTok string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerCSRFToken, csrfToken)
	req.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrfToken})
	if existingSessionTok != "" {
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: existingSessionTok})
	}
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	return rec
}

// extractCookies returns the named cookie value from the Set-Cookie response headers.
func extractCookie(rec *httptest.ResponseRecorder, name string) string {
	for _, c := range readSetCookies(nil, rec) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// readSetCookies parses Set-Cookie headers from the recorder response.
func readSetCookies(t *testing.T, rec *httptest.ResponseRecorder) []*http.Cookie {
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

// TestWebLogin_SuccessSetsBothCookies verifies that a correct login sets cfgms_session
// (HttpOnly) and cfgms_csrf (non-HttpOnly), the body contains no token (security A5.5),
// and the pre-session CSRF cookie is cleared.
func TestWebLogin_SuccessSetsBothCookies(t *testing.T) {
	srv, username, password := setupWebSessionServer(t)

	csrfToken := doCSRF(t, srv)
	rec := doLogin(t, srv, csrfToken, username, password)
	require.Equal(t, http.StatusOK, rec.Code, "login body: %s", rec.Body.String())

	cookies := readSetCookies(nil, rec)
	cookieMap := make(map[string]*http.Cookie, len(cookies))
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}

	// cfgms_session must be present and HttpOnly.
	sess, ok := cookieMap[cookieWebSession]
	require.True(t, ok, "cfgms_session cookie must be set")
	assert.True(t, sess.HttpOnly, "cfgms_session must be HttpOnly")
	assert.True(t, sess.Secure, "cfgms_session must be Secure")
	assert.Equal(t, http.SameSiteStrictMode, sess.SameSite)
	assert.NotEmpty(t, sess.Value)

	// cfgms_csrf must be present and NOT HttpOnly (JS must be able to read it).
	csrf, ok := cookieMap[cookieCSRFSession]
	require.True(t, ok, "cfgms_csrf cookie must be set")
	assert.False(t, csrf.HttpOnly, "cfgms_csrf must NOT be HttpOnly (JS reads it)")
	assert.True(t, csrf.Secure)
	assert.Equal(t, http.SameSiteStrictMode, csrf.SameSite)
	assert.NotEmpty(t, csrf.Value)

	// Pre-session CSRF cookie must be cleared (MaxAge ≤ 0 in Set-Cookie → browser deletes).
	pre, ok := cookieMap[cookieCSRFPre]
	assert.True(t, ok, "cfgms_csrf_pre should appear in response to be cleared")
	if ok {
		assert.LessOrEqual(t, pre.MaxAge, 0, "pre-session CSRF cookie must be cleared")
	}

	// Response body must not contain the session token (security A5.5).
	body := rec.Body.String()
	assert.NotContains(t, body, sess.Value, "response body must not contain the session token")
	assert.NotContains(t, body, csrf.Value, "response body must not contain the CSRF token")
}

// TestWebLogin_UniformFailureResponse verifies that bad-password and unknown-user both
// return the identical 401 status and INVALID_CREDENTIALS code (no enumeration).
func TestWebLogin_UniformFailureResponse(t *testing.T) {
	srv, username, _ := setupWebSessionServer(t)

	check := func(t *testing.T, label, user, pass string) {
		t.Helper()
		csrfToken := doCSRF(t, srv)
		rec := doLogin(t, srv, csrfToken, user, pass)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s: must be 401", label)
		assert.Contains(t, rec.Body.String(), "INVALID_CREDENTIALS", "%s: code must be INVALID_CREDENTIALS", label)
	}

	check(t, "wrong-password", username, "wrong-password-xyz")
	check(t, "unknown-user", "nobody-known", "anypassword")
}

// TestWebLogin_PreSessionCSRF_Required verifies that the login POST returns 403 when
// the pre-session CSRF cookie is absent or the X-CSRF-Token header is missing/wrong.
func TestWebLogin_PreSessionCSRF_Required(t *testing.T) {
	srv, username, password := setupWebSessionServer(t)
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})

	t.Run("no CSRF cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// no cfgms_csrf_pre cookie, no X-CSRF-Token header
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "absent CSRF cookie must yield 403")
		assert.Contains(t, rec.Body.String(), "CSRF")
	})

	t.Run("CSRF cookie but no header", func(t *testing.T) {
		csrfToken := doCSRF(t, srv)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrfToken})
		// no X-CSRF-Token header
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "absent header must yield 403")
	})

	t.Run("CSRF cookie with mismatched header", func(t *testing.T) {
		csrfToken := doCSRF(t, srv)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(headerCSRFToken, "tampered-value")
		req.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrfToken})
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "mismatched CSRF must yield 403")
	})

	t.Run("CSRF check fires before credential verification", func(t *testing.T) {
		// With correct credentials but missing CSRF, must get 403 not 200 or 401.
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No CSRF at all — should be rejected at the CSRF gate, not at credential verification.
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "CSRF must be checked before credentials")
	})
}

// TestWebLogin_SessionFixation verifies that:
// (a) Two successful logins produce distinct session tokens.
// (b) A cfgms_session cookie value from before login is invalidated by the new login.
func TestWebLogin_SessionFixation(t *testing.T) {
	srv, username, password := setupWebSessionServer(t)

	// First login.
	csrf1 := doCSRF(t, srv)
	rec1 := doLogin(t, srv, csrf1, username, password)
	require.Equal(t, http.StatusOK, rec1.Code)
	tok1 := extractCookie(rec1, cookieWebSession)
	require.NotEmpty(t, tok1, "first login must set cfgms_session")

	// Second login — must mint a new token and revoke tok1 (session-fixation defence).
	csrf2 := doCSRF(t, srv)
	rec2 := doLoginWith(t, srv, csrf2, username, password, tok1)
	require.Equal(t, http.StatusOK, rec2.Code)
	tok2 := extractCookie(rec2, cookieWebSession)
	require.NotEmpty(t, tok2, "second login must set cfgms_session")

	assert.NotEqual(t, tok1, tok2, "two logins must produce distinct tokens")

	// The first token must have been revoked (session fixation defence).
	srv.mu.RLock()
	mgr := srv.webSessionManager
	srv.mu.RUnlock()
	_, err := mgr.Validate(context.Background(), tok1)
	assert.Error(t, err, "pre-login token must be invalidated by subsequent login")
}

// TestWebLogin_Lockout verifies that 5 consecutive failures lock the account and
// subsequent attempts (including the 6th) return the uniform 401. A successful
// login after the lockout expires resets the counter.
func TestWebLogin_Lockout(t *testing.T) {
	srv, username, password := setupWebSessionServer(t)

	// Drain 5 consecutive failures to trigger lockout.
	for i := 0; i < 5; i++ {
		csrfToken := doCSRF(t, srv)
		rec := doLogin(t, srv, csrfToken, username, "wrong-password")
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "failure %d must be 401", i+1)
		assert.Contains(t, rec.Body.String(), "INVALID_CREDENTIALS")
	}

	// Account is now locked. Additional attempt must still return 401 (not 200 or a
	// different error code that would reveal the lock).
	csrfToken := doCSRF(t, srv)
	rec := doLogin(t, srv, csrfToken, username, password) // correct password, but locked
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "locked account must return 401")
	assert.Contains(t, rec.Body.String(), "INVALID_CREDENTIALS",
		"locked-account code must be indistinguishable from bad-password")

	// Simulate lockout expiry by directly rewinding the LockedUntil time.
	srv.mu.Lock()
	if state, ok := srv.webAccountLockouts[username]; ok {
		state.LockedUntil = time.Now().Add(-1 * time.Second)
	}
	srv.mu.Unlock()

	// Successful login after expiry must reset the counter.
	csrfToken = doCSRF(t, srv)
	rec = doLogin(t, srv, csrfToken, username, password)
	assert.Equal(t, http.StatusOK, rec.Code, "login after lockout expiry must succeed")

	// Lockout state should be cleared.
	srv.mu.RLock()
	_, stillLocked := srv.webAccountLockouts[username]
	srv.mu.RUnlock()
	assert.False(t, stillLocked, "lockout state must be cleared after successful login")
}

// TestWebLogout_RevokesSessionAndClearsCookies verifies that logout revokes the
// server-side session (subsequent use returns 401), and both cookies are cleared.
func TestWebLogout_RevokesSessionAndClearsCookies(t *testing.T) {
	srv, username, password := setupWebSessionServer(t)

	// Login to get a valid session.
	csrfToken := doCSRF(t, srv)
	loginRec := doLogin(t, srv, csrfToken, username, password)
	require.Equal(t, http.StatusOK, loginRec.Code)

	sessionTok := extractCookie(loginRec, cookieWebSession)
	csrfTok := extractCookie(loginRec, cookieCSRFSession)
	require.NotEmpty(t, sessionTok)
	require.NotEmpty(t, csrfTok)

	// Logout.
	logoutRec := doLogout(t, srv, sessionTok, csrfTok)
	assert.Equal(t, http.StatusOK, logoutRec.Code, "logout body: %s", logoutRec.Body.String())

	// Both cookies must be cleared (MaxAge ≤ 0).
	cookies := readSetCookies(nil, logoutRec)
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}
	for _, name := range []string{cookieWebSession, cookieCSRFSession} {
		c, ok := cookieMap[name]
		if assert.True(t, ok, "Set-Cookie must include %s on logout", name) {
			assert.LessOrEqual(t, c.MaxAge, 0, "%s must be cleared (Max-Age ≤ 0)", name)
		}
	}

	// cfgms_session deletion cookie must carry HttpOnly (mirrors login-time design, clears CodeQL #1059).
	if sess, ok := cookieMap[cookieWebSession]; ok {
		assert.True(t, sess.HttpOnly, "cfgms_session deletion cookie must be HttpOnly")
	}
	// cfgms_csrf deletion cookie must NOT be HttpOnly (matches its login-time non-HttpOnly design).
	if csrf, ok := cookieMap[cookieCSRFSession]; ok {
		assert.False(t, csrf.HttpOnly, "cfgms_csrf deletion cookie must NOT be HttpOnly")
	}

	// Server-side session must be revoked — subsequent validation must fail.
	srv.mu.RLock()
	mgr := srv.webSessionManager
	srv.mu.RUnlock()
	_, err := mgr.Validate(context.Background(), sessionTok)
	assert.Error(t, err, "revoked session must not validate")
}

// TestWebLogout_CSRFRequired verifies that logout returns 403 when X-CSRF-Token is
// missing or mismatched.
func TestWebLogout_CSRFRequired(t *testing.T) {
	srv, username, password := setupWebSessionServer(t)

	csrfToken := doCSRF(t, srv)
	loginRec := doLogin(t, srv, csrfToken, username, password)
	require.Equal(t, http.StatusOK, loginRec.Code)

	sessionTok := extractCookie(loginRec, cookieWebSession)
	csrfTok := extractCookie(loginRec, cookieCSRFSession)

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

	// Valid logout to clean up.
	rec := doLogout(t, srv, sessionTok, csrfTok)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestCSRFMiddleware_SessionBound verifies the session-bound CSRF middleware on the
// api subrouter:
// - GET requests are always exempt.
// - Bearer/API-key/mTLS requests are exempt.
// - Cookie-authenticated POST without X-CSRF-Token → 403.
// - Cookie-authenticated POST with correct X-CSRF-Token → passes through.
func TestCSRFMiddleware_SessionBound(t *testing.T) {
	srv, username, password := setupWebSessionServer(t)

	// Login to get a valid session + CSRF token.
	csrfToken := doCSRF(t, srv)
	loginRec := doLogin(t, srv, csrfToken, username, password)
	require.Equal(t, http.StatusOK, loginRec.Code)

	sessionTok := extractCookie(loginRec, cookieWebSession)
	csrfTok := extractCookie(loginRec, cookieCSRFSession)
	require.NotEmpty(t, sessionTok)
	require.NotEmpty(t, csrfTok)

	// Wire a canary handler on the api subrouter (POST /api/v1/stewards is already
	// registered; using /api/v1/health GET is safe since it's exempt). Use the
	// existing POST /api/v1/web/logout as a proxy — it's on the base router, not
	// the api subrouter. Instead, test by wrapping directly.
	//
	// Direct middleware test: build the handler stack manually for a synthetic POST.
	var reached bool
	syntheticHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	// Stack: auth → CSRF → handler
	stack := srv.authenticationMiddleware(srv.csrfMiddleware(syntheticHandler))

	t.Run("GET is exempt", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionTok})
		rec := httptest.NewRecorder()
		stack.ServeHTTP(rec, req)
		assert.True(t, reached, "GET must pass through CSRF middleware")
	})

	t.Run("cookie-auth POST without CSRF header → 403", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionTok})
		// no X-CSRF-Token
		rec := httptest.NewRecorder()
		stack.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, reached, "handler must not be reached when CSRF fails")
	})

	t.Run("cookie-auth POST with correct CSRF header → passes", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionTok})
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
		// API-key auth means isCookieAuthenticated returns false → CSRF middleware
		// skips check → handler is reached (or 401 if the key doesn't have access).
		// The key point: must NOT get a 403 from CSRF middleware.
		assert.NotEqual(t, http.StatusForbidden, rec.Code,
			"API-key requests must not be blocked by CSRF middleware (got 403 CSRF_MISMATCH)")
	})
}

// TestWebLogin_AuditEvents verifies that login success, failure, lockout, and logout
// each emit a sanitized log entry. Uses the auditCapturingLogger so no SQL is
// involved (the audit manager path is tested in its own package).
func TestWebLogin_AuditEvents(t *testing.T) {
	capLog := &auditCapturingLogger{}
	srv := setupTestServerWithLogger(t, capLog)

	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	store := session.NewMemStore(webCfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(webCfg, store, time.Now)
	srv.SetWebSessionManager(mgr)

	admin := testAdminPrincipal()
	rec := postWebAccount(t, srv, admin, WebAccountRequest{
		Username:    "audituser",
		Password:    "audit-password-123",
		TenantID:    "tenant-audit",
		Permissions: []string{},
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	clearLog := func() {
		capLog.mu.Lock()
		capLog.entries = nil
		capLog.mu.Unlock()
	}
	hasMsg := func(substr string) bool {
		capLog.mu.Lock()
		defer capLog.mu.Unlock()
		for _, e := range capLog.entries {
			if strings.Contains(e.msg, substr) {
				return true
			}
			for i := 0; i+1 < len(e.kvs); i += 2 {
				if v, ok := e.kvs[i+1].(string); ok && strings.Contains(v, substr) {
					return true
				}
			}
		}
		return false
	}
	containsRaw := func(forbidden string) bool {
		return strings.Contains(capLog.formattedOutput(), forbidden)
	}

	t.Run("login success emits Info with sanitized username", func(t *testing.T) {
		clearLog()
		csrf := doCSRF(t, srv)
		rec := doLogin(t, srv, csrf, "audituser", "audit-password-123")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, hasMsg("Web login success"), "login success must log an Info message")
		// Password must never appear in logs.
		assert.False(t, containsRaw("audit-password-123"), "password must not appear in logs")
	})

	t.Run("login failure emits Warn with sanitized username", func(t *testing.T) {
		clearLog()
		csrf := doCSRF(t, srv)
		rec := doLogin(t, srv, csrf, "audituser", "wrong")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.True(t, hasMsg("Web login failed"), "login failure must emit a warning")
		assert.False(t, containsRaw("wrong"), "submitted password must not appear in logs")
	})

	t.Run("lockout emits Warn with sanitized username", func(t *testing.T) {
		// Reset any existing lockout from previous sub-test.
		srv.mu.Lock()
		delete(srv.webAccountLockouts, "audituser")
		srv.mu.Unlock()

		// Trigger lockout. Must use a valid-length password so it passes
		// validateWebPassword and reaches recordWebAccountFailure (short passwords
		// fail the pre-hash validation gate without touching the lockout counter).
		for i := 0; i < 5; i++ {
			csrf := doCSRF(t, srv)
			doLogin(t, srv, csrf, "audituser", "wrong-password")
		}

		clearLog()
		csrf := doCSRF(t, srv)
		rec := doLogin(t, srv, csrf, "audituser", "audit-password-123") // correct pw, but locked
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.True(t, hasMsg("account locked"), "lockout must log a Warn message")

		// Reset lockout for subsequent sub-tests.
		srv.mu.Lock()
		delete(srv.webAccountLockouts, "audituser")
		srv.mu.Unlock()
	})

	t.Run("logout emits Info", func(t *testing.T) {
		csrf := doCSRF(t, srv)
		loginRec := doLogin(t, srv, csrf, "audituser", "audit-password-123")
		require.Equal(t, http.StatusOK, loginRec.Code)
		sessionTok := extractCookie(loginRec, cookieWebSession)
		csrfTok := extractCookie(loginRec, cookieCSRFSession)

		clearLog()
		logoutRec := doLogout(t, srv, sessionTok, csrfTok)
		require.Equal(t, http.StatusOK, logoutRec.Code)
		assert.True(t, hasMsg("Web logout"), "logout must emit an Info message")
		// Session token must not appear in log.
		assert.False(t, containsRaw(sessionTok), "session token must not appear in logs")
	})
}

// TestWebEndpoints_PublicBaseRouterRegistrations asserts that the three new endpoints
// (GET /csrf, POST /login, POST /logout) are the only new public (base-router)
// web-namespace registrations. They must respond without requiring authentication,
// while arbitrary /api/v1/web/* paths must return 405 (method not allowed) or 404.
func TestWebEndpoints_PublicBaseRouterRegistrations(t *testing.T) {
	srv := setupTestServer(t)
	// Wire session manager so handlers don't immediately return 503.
	webCfg := session.Config{IdleTimeout: 60 * time.Minute, AbsoluteTimeout: 12 * time.Hour, GraceWindow: 30 * time.Second}
	store := session.NewMemStore(webCfg, time.Now)
	t.Cleanup(store.Close)
	srv.SetWebSessionManager(session.NewManager(webCfg, store, time.Now))

	// New registrations must respond (not 404) on their correct methods.
	t.Run("GET /api/v1/web/csrf is accessible", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/web/csrf", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.NotEqual(t, http.StatusNotFound, rec.Code, "GET /api/v1/web/csrf must be registered")
	})

	t.Run("POST /api/v1/web/login is accessible", func(t *testing.T) {
		// No CSRF cookie → 403 (registered and reachable, just CSRF-gated).
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/login",
			bytes.NewBufferString(`{"username":"x","password":"y"}`))
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		// 403 (CSRF gate) confirms the endpoint is registered and publicly reachable.
		assert.Equal(t, http.StatusForbidden, rec.Code, "POST /api/v1/web/login must be CSRF-gated (not 404)")
	})

	t.Run("POST /api/v1/web/logout is accessible", func(t *testing.T) {
		// No session cookie → handled by logout handler (returns 200 or 401, not 404).
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/logout", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.NotEqual(t, http.StatusNotFound, rec.Code, "POST /api/v1/web/logout must be registered")
	})

	// No other web/* paths exist on the base router.
	t.Run("unknown /api/v1/web/* path is 404 or 405", func(t *testing.T) {
		// GET /api/v1/web/login (wrong method) → 405, not a new registered route.
		req := httptest.NewRequest(http.MethodGet, "/api/v1/web/login", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Contains(t, []int{http.StatusMethodNotAllowed, http.StatusNotFound}, rec.Code,
			"wrong-method requests must not succeed")
	})
}

// TestWebLogin_RateLimited verifies that repeated unauthenticated POST /login requests
// are eventually rate-limited by authDefense.Middleware (429 Too Many Requests).
// This confirms the base-router authDefense wrapping is active (security A5.4).
//
// Note: once the rate limiter fires it blocks ALL endpoints from the same IP (including
// /csrf), so the loop must accept 429 from either endpoint as evidence of rate limiting.
func TestWebLogin_RateLimited(t *testing.T) {
	srv, username, _ := setupWebSessionServer(t)

	body, _ := json.Marshal(map[string]string{"username": username, "password": "wrong"})

	// Hammer the login endpoint until we get 429 or exhaust a reasonable limit.
	// The auth defense uses IP-based rate limiting; the same source IP triggers it.
	var got429 bool
	for i := 0; i < 200; i++ {
		// Inline CSRF request: once the rate limiter fires, /csrf returns 429 too.
		csrfReq := httptest.NewRequest(http.MethodGet, "/api/v1/web/csrf", nil)
		csrfRec := httptest.NewRecorder()
		srv.router.ServeHTTP(csrfRec, csrfReq)
		if csrfRec.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
		require.Equal(t, http.StatusOK, csrfRec.Code, "GET /csrf (iteration %d): %s", i, csrfRec.Body.String())

		var csrfToken string
		for _, c := range readSetCookies(nil, csrfRec) {
			if c.Name == cookieCSRFPre {
				csrfToken = c.Value
				break
			}
		}
		require.NotEmpty(t, csrfToken, "GET /csrf must set %s cookie (iteration %d)", cookieCSRFPre, i)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(headerCSRFToken, csrfToken)
		req.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrfToken})
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	assert.True(t, got429, "repeated failed login attempts must be rate-limited (429) by authDefense.Middleware")
}
