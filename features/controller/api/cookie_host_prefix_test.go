// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHostPrefixCookies_LoginFlow (Issue #5023) proves, with a real Server, that
// every cookie in the login flow carries the __Host- prefix with Secure; Path=/
// and no Domain (the attributes the prefix requires).
func TestHostPrefixCookies_LoginFlow(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	// Pre-session CSRF cookie (GET /csrf).
	csrfReq := httptest.NewRequest(http.MethodGet, "/api/v1/web/csrf", nil)
	csrfRec := httptest.NewRecorder()
	srv.router.ServeHTTP(csrfRec, csrfReq)
	require.Equal(t, http.StatusOK, csrfRec.Code)
	preToken := ""

	var all []*http.Cookie
	for _, c := range readSetCookies(t, csrfRec) {
		all = append(all, c)
		if c.Name == "__Host-cfgms_csrf_pre" {
			preToken = c.Value
		}
	}
	require.NotEmpty(t, preToken)

	// Ceremony cookie (login begin) and session/CSRF cookies (login finish).
	all = append(all, readSetCookies(t, doPasskeyLoginBegin(t, srv, preToken, ""))...)
	loginRec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, loginRec.Code, "body: %s", loginRec.Body.String())
	all = append(all, readSetCookies(t, loginRec)...)

	seen := map[string]bool{}
	for _, c := range all {
		assert.Contains(t, c.Name, "__Host-", "cookie %q must use the __Host- prefix", c.Name)
		assert.True(t, c.Secure, "cookie %q must be Secure", c.Name)
		assert.Equal(t, "/", c.Path, "cookie %q must have Path=/", c.Name)
		assert.Empty(t, c.Domain, "cookie %q must not set Domain", c.Name)
		seen[c.Name] = true
	}
	for _, name := range []string{
		"__Host-cfgms_session", "__Host-cfgms_csrf", "__Host-cfgms_csrf_pre", "__Host-cfgms_passkey_ceremony",
	} {
		assert.True(t, seen[name], "expected Set-Cookie for %s", name)
	}
}

// TestHostPrefixCookies_OldSessionNameNotAuthenticated proves no fallback reads
// the pre-rename cookie name.
func TestHostPrefixCookies_OldSessionNameNotAuthenticated(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
	good := issueWebSession(t, srv, mgr, "user-1", "test-tenant")
	require.Equal(t, "__Host-cfgms_session", good.Name)

	call := func(c *http.Cookie) int {
		h := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	assert.Equal(t, http.StatusOK, call(good))
	assert.Equal(t, http.StatusUnauthorized, call(&http.Cookie{Name: "cfgms_session", Value: good.Value}))
}
