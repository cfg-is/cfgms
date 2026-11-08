// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
)

// Characterization tests for Server.authenticationMiddleware (Issue #5867). They pin
// the observable behavior of every credential source — relay principal, mTLS admin
// certificate, Bearer session token, web session cookie and API key — and the order
// in which they are tried, so the function can be restructured without changing what
// a client sees. Fixtures come from the existing tests in this package.

// middlewareauthenticationCharResult is what one request through the middleware
// produced: the recorder, and the request the wrapped handler saw (nil when the
// middleware rejected the request before reaching it).
type middlewareauthenticationCharResult struct {
	rec  *httptest.ResponseRecorder
	seen *http.Request
}

func (r middlewareauthenticationCharResult) principal() *Principal {
	if r.seen == nil {
		return nil
	}
	p, _ := r.seen.Context().Value(principalContextKey).(*Principal)
	return p
}

func middlewareauthenticationCharServe(srv *Server, req *http.Request) middlewareauthenticationCharResult {
	var res middlewareauthenticationCharResult
	res.rec = httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res.seen = r
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(res.rec, req)
	return res
}

func middlewareauthenticationCharRequireReject(t *testing.T, res middlewareauthenticationCharResult, status int, code string) {
	t.Helper()
	require.Equal(t, status, res.rec.Code, res.rec.Body.String())
	assert.Equal(t, code, errCode(t, res.rec.Body.Bytes()))
	assert.Nil(t, res.seen, "a rejected request must not reach the handler")
}

// middlewareauthenticationCharRevokeAfterValidate is the real session manager except
// that every successful Validate is immediately followed by a revocation of that
// session — a revocation landing on another node between Validate and Renew.
type middlewareauthenticationCharRevokeAfterValidate struct {
	session.Manager
}

func (m middlewareauthenticationCharRevokeAfterValidate) Validate(ctx context.Context, token string) (*session.Session, error) {
	sess, err := m.Manager.Validate(ctx, token)
	if err == nil {
		if revokeErr := m.Revoke(ctx, sess.ID); revokeErr != nil {
			return nil, revokeErr
		}
	}
	return sess, err
}

// middlewareauthenticationCharFailingRevoke is the real session manager with a
// Revoke that always fails, so the best-effort revocation branches are reached.
type middlewareauthenticationCharFailingRevoke struct {
	session.Manager
}

func (middlewareauthenticationCharFailingRevoke) Revoke(context.Context, string) error {
	return errors.New("revoke unavailable")
}

// middlewareauthenticationCharWebSessionServerWithLogger is
// setupTestServerWithWebSession with a caller-supplied logger. The logger must be
// handed to the constructor: the server's background sweeps read srv.logger, so
// assigning it afterwards is a data race.
func middlewareauthenticationCharWebSessionServerWithLogger(t *testing.T, logger logging.Logger) (*Server, session.Manager) {
	t.Helper()
	srv := setupTestServerWithLogger(t, logger)
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	store := session.NewMemStore(webCfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(webCfg, store, time.Now)
	srv.SetWebSessionManager(mgr)
	return srv, mgr
}

func middlewareauthenticationCharAPIKeyRequest(key string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", key)
	return req
}

// --- relay principal ---

func TestMiddlewareAuthenticationChar_RelayPrincipal(t *testing.T) {
	srv := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t)

	t.Run("scoped relay principal proceeds without any other credential", func(t *testing.T) {
		relay := &Principal{ID: "relay-1", TenantID: "tenant-a"}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req = req.WithContext(context.WithValue(req.Context(), relayPrincipalKey, relay))

		res := middlewareauthenticationCharServe(srv, req)

		require.Equal(t, http.StatusOK, res.rec.Code)
		require.NotNil(t, res.seen)
		assert.Same(t, req, res.seen, "the relay path hands the original request on unchanged")
	})

	t.Run("relay principal wins over a conflicting admin cert and API key header", func(t *testing.T) {
		relay := &Principal{ID: "relay-1", TenantID: "tenant-a"}
		req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards", adminCert)
		req.Header.Set("X-API-Key", "ignored")
		req = req.WithContext(context.WithValue(req.Context(), relayPrincipalKey, relay))

		res := middlewareauthenticationCharServe(srv, req)

		assert.Equal(t, http.StatusOK, res.rec.Code, "no CONFLICTING_CREDENTIALS for a relay principal")
	})

	t.Run("unscoped relay principal is refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req = req.WithContext(context.WithValue(req.Context(), relayPrincipalKey, &Principal{ID: "relay-2"}))

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusForbidden, "NO_TENANT_SCOPE")
	})

	t.Run("nil relay principal is not a relay credential", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req = req.WithContext(context.WithValue(req.Context(), relayPrincipalKey, (*Principal)(nil)))

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "MISSING_API_KEY")
	})
}

// --- mTLS admin certificate ---

func TestMiddlewareAuthenticationChar_AdminCert(t *testing.T) {
	srv := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t)

	t.Run("certificate plus API key header is rejected", func(t *testing.T) {
		req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards", adminCert)
		req.Header.Set("X-API-Key", NewTestKey(t, srv, []string{"steward:read"}))

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusBadRequest, "CONFLICTING_CREDENTIALS")
		assert.Contains(t, res.rec.Body.String(),
			"Conflicting credentials: mTLS admin cert and API key header cannot both be present")
	})

	t.Run("certificate plus Bearer header is rejected", func(t *testing.T) {
		req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards", adminCert)
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 43))

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusBadRequest, "CONFLICTING_CREDENTIALS")
	})

	t.Run("certificate alone authenticates and sets the full context", func(t *testing.T) {
		res := middlewareauthenticationCharServe(srv, requestWithTLSCert(http.MethodGet, "/api/v1/stewards", adminCert))

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		p := res.principal()
		require.NotNil(t, p)
		assert.True(t, p.RootScoped || p.GlobalScope || p.TenantID != "", "a cert principal always carries a scope")
		ctx := res.seen.Context()
		assert.Equal(t, p.TenantID, ctx.Value(ctxkeys.TenantID))
		assert.NotNil(t, ctx.Value(ctxkeys.UserIDKey))
		assert.NotNil(t, ctx.Value(ctxkeys.TenantScopeKey))
		assert.NotNil(t, ctx.Value(authRecheckContextKey), "cert path installs the liveness recheck")
		assert.NotNil(t, ctx.Value(principalRefreshContextKey), "cert path installs the principal refresh")
		assert.Nil(t, ctx.Value(authSessionContextKey), "cert path has no session reference")
		assert.Empty(t, res.rec.Header().Get("X-Session-Token"))
	})

	t.Run("certificate wins over a web session cookie", func(t *testing.T) {
		webSrv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
		cookie := issueWebSession(t, webSrv, mgr, "cert-vs-cookie", "tenant-a")
		req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards", adminCert)
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(webSrv, req)

		require.Equal(t, http.StatusOK, res.rec.Code)
		require.NotNil(t, res.principal())
		assert.Empty(t, res.rec.Header().Get("Set-Cookie"), "the cookie must not be validated or renewed")
		assert.Nil(t, res.seen.Context().Value(cookieAuthContextKey))
	})

	t.Run("certificate without the admin marker falls through to the API key", func(t *testing.T) {
		req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards", makeAdminTestCert(t, false))
		req.Header.Set("X-API-Key", NewTestKey(t, srv, []string{"steward:read"}))

		res := middlewareauthenticationCharServe(srv, req)

		require.Equal(t, http.StatusOK, res.rec.Code)
		assert.Equal(t, AuthChannelAPIKey, res.principal().Channel)
	})
}

// --- Bearer session token ---

func TestMiddlewareAuthenticationChar_BearerSession(t *testing.T) {
	t.Run("valid 43-character token authenticates and publishes the renewed token", func(t *testing.T) {
		srv := setupTestServer(t)
		token, acct := newBearerSessionForAccount(t, srv, "bearer-ok", []string{"steward:read"})
		require.Len(t, token, 43)

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		renewed := res.rec.Header().Get("X-Session-Token")
		assert.Len(t, renewed, 43, "Renew issues a new token that is published in X-Session-Token")
		assert.NotEqual(t, token, renewed)
		p := res.principal()
		require.NotNil(t, p)
		assert.Equal(t, AuthChannelCfgBearer, p.Channel)
		assert.Equal(t, acct.ID, p.ID)
		assert.Equal(t, "session:"+acct.ID, p.Name)
		assert.True(t, p.AccountBound)
		assert.False(t, p.ImplicitAdmin, "a tenant-scoped account is not an implicit admin")
		assert.False(t, p.GlobalScope)
		assert.Equal(t, []string{"steward:read"}, p.Permissions)
		assert.Equal(t, acct.TenantID, p.TenantID)
		ctx := res.seen.Context()
		assert.Equal(t, acct.TenantID, ctx.Value(ctxkeys.TenantID))
		assert.Equal(t, acct.ID, ctx.Value(ctxkeys.UserIDKey))
		ref, ok := ctx.Value(authSessionContextKey).(authSessionRef)
		require.True(t, ok)
		assert.Same(t, srv.sessionManager, ref.manager)
		assert.NotNil(t, ctx.Value(principalRefreshContextKey))
		assert.Nil(t, ctx.Value(authRecheckContextKey))
	})

	t.Run("root-scope account is an implicit admin with no enumerated permissions", func(t *testing.T) {
		srv := setupTestServer(t)
		token, _ := newBearerSessionForAccount(t, srv, "bearer-root", []string{"steward:read"})
		updateTestAccount(t, srv, "bearer-root", func(a *account) { a.RootScope = true })

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		p := res.principal()
		require.NotNil(t, p)
		assert.True(t, p.GlobalScope)
		assert.True(t, p.ImplicitAdmin)
		assert.Empty(t, p.Permissions)
		assert.NotNil(t, p.Permissions, "permissions is never nil")
	})

	t.Run("invalid 43-character token is a 401 and never falls through to the API key", func(t *testing.T) {
		srv := setupTestServer(t)
		newBearerSessionForAccount(t, srv, "bearer-invalid", nil)
		validKey := NewTestKey(t, srv, []string{"steward:read"})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 43))
		req.Header.Set("X-API-Key", validKey)

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "INVALID_SESSION_TOKEN")
		assert.Contains(t, res.rec.Body.String(), "Invalid session token")
	})

	t.Run("43-character API key is never rescued by the API-key path once a manager is wired", func(t *testing.T) {
		srv := setupTestServer(t)
		newBearerSessionForAccount(t, srv, "bearer-43key", nil)
		key := strings.Repeat("k", 43)
		srv.mu.Lock()
		srv.apiKeys[key] = &APIKey{ID: "k43", Key: key, TenantID: "tenant-a", Permissions: []string{"steward:read"}}
		srv.mu.Unlock()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+key)

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "INVALID_SESSION_TOKEN")
	})

	t.Run("43-character Bearer API key authenticates when no session manager is wired", func(t *testing.T) {
		srv := setupTestServer(t)
		srv.SetSessionManager(nil)
		key := strings.Repeat("k", 43)
		srv.mu.Lock()
		srv.apiKeys[key] = &APIKey{ID: "k43", Key: key, TenantID: "tenant-a", Permissions: []string{"steward:read"}}
		srv.mu.Unlock()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+key)

		res := middlewareauthenticationCharServe(srv, req)

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		assert.Equal(t, AuthChannelAPIKey, res.principal().Channel)
	})

	t.Run("non-43-character token falls through to the API key", func(t *testing.T) {
		srv := setupTestServer(t)
		newBearerSessionForAccount(t, srv, "bearer-fallthrough", nil)
		key := NewTestKey(t, srv, []string{"steward:read"})
		require.NotEqual(t, 43, len(key))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+key)

		res := middlewareauthenticationCharServe(srv, req)

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		assert.Equal(t, AuthChannelAPIKey, res.principal().Channel)
		assert.Empty(t, res.rec.Header().Get("X-Session-Token"))
	})

	t.Run("revoked token is SESSION_REVOKED", func(t *testing.T) {
		srv := setupTestServer(t)
		token, _ := newBearerSessionForAccount(t, srv, "bearer-revoked", nil)
		sess, err := srv.sessionManager.Validate(context.Background(), token)
		require.NoError(t, err)
		require.NoError(t, srv.sessionManager.Revoke(context.Background(), sess.ID))

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_REVOKED")
		assert.Contains(t, res.rec.Body.String(), "Session has been revoked")
	})

	t.Run("expired token is SESSION_EXPIRED", func(t *testing.T) {
		srv := setupTestServer(t)
		clock := newWebSessionTestClock()
		cfg := session.DefaultConfig()
		store := session.NewMemStore(cfg, clock.Now)
		t.Cleanup(store.Close)
		srv.SetSessionManager(session.NewManager(cfg, store, clock.Now))
		_, token, err := srv.sessionManager.Issue(context.Background(), "expiring", "cfg-cli", "tenant-a")
		require.NoError(t, err)
		clock.Advance(cfg.AbsoluteTimeout + cfg.IdleTimeout + time.Hour)

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_EXPIRED")
		assert.Contains(t, res.rec.Body.String(), "Session has expired")
	})

	t.Run("token revoked between Validate and Renew is rejected", func(t *testing.T) {
		srv := setupTestServer(t)
		token, _ := newBearerSessionForAccount(t, srv, "bearer-race", nil)
		srv.SetSessionManager(middlewareauthenticationCharRevokeAfterValidate{Manager: srv.sessionManager})

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "INVALID_SESSION_TOKEN")
		assert.Empty(t, res.rec.Header().Get("X-Session-Token"))
	})

	t.Run("disabled account is SESSION_REVOKED and its session is revoked", func(t *testing.T) {
		srv := setupTestServer(t)
		token, _ := newBearerSessionForAccount(t, srv, "bearer-disabled", nil)
		updateTestAccount(t, srv, "bearer-disabled", func(a *account) { a.Disabled = true })

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_REVOKED")
		_, err := srv.sessionManager.Validate(context.Background(), token)
		assert.Error(t, err, "the session of a disabled account must be revoked")
	})

	t.Run("a failed revocation does not change the disabled-account answer and is logged", func(t *testing.T) {
		logger := &auditCapturingLogger{}
		srv := setupTestServerWithLogger(t, logger)
		token, _ := newBearerSessionForAccount(t, srv, "bearer-disabled-norevoke", nil)
		updateTestAccount(t, srv, "bearer-disabled-norevoke", func(a *account) { a.Disabled = true })
		srv.SetSessionManager(middlewareauthenticationCharFailingRevoke{Manager: srv.sessionManager})

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_REVOKED")
		assert.Contains(t, logger.formattedOutput(), "Failed to revoke session of disabled account")
	})

	t.Run("cli-login session whose approving passkey is gone is refused", func(t *testing.T) {
		srv := setupTestServer(t)
		_, acct := newBearerSessionForAccount(t, srv, "bearer-cli", nil)
		_, token, err := srv.sessionManager.Issue(context.Background(), acct.ID, cliLoginConnectionName, acct.TenantID)
		require.NoError(t, err)

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_REVOKED")
		_, err = srv.sessionManager.Validate(context.Background(), token)
		assert.Error(t, err, "the refused cli-login session must be revoked")
	})

	t.Run("a failed revocation of a refused cli-login session is logged, the answer is unchanged", func(t *testing.T) {
		logger := &auditCapturingLogger{}
		srv := setupTestServerWithLogger(t, logger)
		_, acct := newBearerSessionForAccount(t, srv, "bearer-cli-norevoke", nil)
		_, token, err := srv.sessionManager.Issue(context.Background(), acct.ID, cliLoginConnectionName, acct.TenantID)
		require.NoError(t, err)
		srv.SetSessionManager(middlewareauthenticationCharFailingRevoke{Manager: srv.sessionManager})

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_REVOKED")
		assert.Contains(t, logger.formattedOutput(), "Failed to revoke cli-login session with a revoked credential")
	})

	t.Run("unbound session with no tenant scope is SESSION_SCOPE_INVALID", func(t *testing.T) {
		srv := setupTestServer(t)
		newBearerSessionForAccount(t, srv, "bearer-unbound", nil)
		_, token, err := srv.sessionManager.Issue(context.Background(), "no-such-account", "cfg-cli", "")
		require.NoError(t, err)

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_SCOPE_INVALID")
		assert.Contains(t, res.rec.Body.String(), "Session has no tenant scope; reconnect to obtain a new session")
	})

	t.Run("unbound session scoped to the root tenant is global-scope implicit admin", func(t *testing.T) {
		srv := setupTestServer(t)
		newBearerSessionForAccount(t, srv, "bearer-rooted", nil)
		root := srv.rootTenantID(context.Background())
		require.NotEmpty(t, root, "the fixture seeds a root tenant")
		_, token, err := srv.sessionManager.IssueRootScoped(context.Background(), "cert-principal", "cfg-cli", root)
		require.NoError(t, err)

		res := middlewareauthenticationCharServe(srv, bearerRequest(token))

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		p := res.principal()
		require.NotNil(t, p)
		assert.True(t, p.GlobalScope)
		assert.True(t, p.ImplicitAdmin)
		assert.True(t, p.RootScoped)
		assert.False(t, p.AccountBound)
		assert.Equal(t, root, p.TenantID)
	})
}

// --- web session cookie ---

func TestMiddlewareAuthenticationChar_WebCookie(t *testing.T) {
	t.Run("valid cookie authenticates and is renewed with Set-Cookie", func(t *testing.T) {
		srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
		cookie := issueWebSession(t, srv, mgr, "cookie-ok", "tenant-a")
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(srv, req)

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		setCookie := res.rec.Header().Get("Set-Cookie")
		require.NotEmpty(t, setCookie)
		assert.Contains(t, setCookie, cookieWebSession+"=")
		assert.Contains(t, setCookie, "HttpOnly")
		assert.Contains(t, setCookie, "Secure")
		assert.Contains(t, setCookie, "SameSite=Strict")
		assert.NotContains(t, setCookie, cookie.Value, "the renewed cookie carries a rotated token")
		p := res.principal()
		require.NotNil(t, p)
		assert.Equal(t, AuthChannelWebCookie, p.Channel)
		assert.Equal(t, "cookie-ok", p.ID)
		assert.Equal(t, "web-session:cookie-ok", p.Name)
		assert.True(t, p.AccountBound)
		assert.Equal(t, 1, p.AuthenticatorCount)
		assert.False(t, p.ImplicitAdmin)
		ctx := res.seen.Context()
		assert.Equal(t, true, ctx.Value(cookieAuthContextKey))
		assert.NotNil(t, ctx.Value(webSessionIDContextKey))
		ref, ok := ctx.Value(authSessionContextKey).(authSessionRef)
		require.True(t, ok)
		assert.Same(t, srv.webSessionManager, ref.manager)
		assert.NotNil(t, ctx.Value(principalRefreshContextKey))
	})

	t.Run("cookie is ignored when an API key header is present", func(t *testing.T) {
		srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
		cookie := issueWebSession(t, srv, mgr, "cookie-ignored", "tenant-a")
		req := middlewareauthenticationCharAPIKeyRequest(NewTestKey(t, srv, []string{"steward:read"}))
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(srv, req)

		require.Equal(t, http.StatusOK, res.rec.Code)
		assert.Equal(t, AuthChannelAPIKey, res.principal().Channel)
		assert.Empty(t, res.rec.Header().Get("Set-Cookie"), "an ignored cookie is not renewed")
		assert.Nil(t, res.seen.Context().Value(cookieAuthContextKey))
	})

	t.Run("an invalid cookie is not validated when a Bearer header is present", func(t *testing.T) {
		srv, _, _ := setupTestServerWithWebSession(t, time.Now)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+NewTestKey(t, srv, []string{"steward:read"}))
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: "garbage"})

		res := middlewareauthenticationCharServe(srv, req)

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		assert.Equal(t, AuthChannelAPIKey, res.principal().Channel)
	})

	t.Run("cookie without a wired web session manager falls to the API-key path", func(t *testing.T) {
		srv := setupTestServer(t)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: "anything"})

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "MISSING_API_KEY")
	})

	t.Run("no cookie falls to the API-key path", func(t *testing.T) {
		srv, _, _ := setupTestServerWithWebSession(t, time.Now)

		res := middlewareauthenticationCharServe(srv, httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "MISSING_API_KEY")
	})

	t.Run("invalid cookie is a 401 with no fall-through", func(t *testing.T) {
		srv, _, _ := setupTestServerWithWebSession(t, time.Now)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: "garbage"})

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "INVALID_SESSION_TOKEN")
		assert.Empty(t, res.rec.Header().Get("Set-Cookie"))
	})

	t.Run("revoked cookie session is SESSION_REVOKED", func(t *testing.T) {
		srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
		cookie := issueWebSession(t, srv, mgr, "cookie-revoked", "tenant-a")
		sess, err := mgr.Validate(context.Background(), cookie.Value)
		require.NoError(t, err)
		require.NoError(t, mgr.Revoke(context.Background(), sess.ID))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_REVOKED")
	})

	t.Run("expired cookie session is SESSION_EXPIRED", func(t *testing.T) {
		clock := newWebSessionTestClock()
		srv, mgr, _ := setupTestServerWithWebSession(t, clock.Now)
		cookie := issueWebSession(t, srv, mgr, "cookie-expired", "tenant-a")
		clock.Advance(13 * time.Hour)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_EXPIRED")
	})

	t.Run("cookie revoked between Validate and Renew is rejected without a Set-Cookie", func(t *testing.T) {
		srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
		cookie := issueWebSession(t, srv, mgr, "cookie-race", "tenant-a")
		srv.SetWebSessionManager(middlewareauthenticationCharRevokeAfterValidate{Manager: mgr})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "INVALID_SESSION_TOKEN")
		assert.Empty(t, res.rec.Header().Get("Set-Cookie"))
	})

	t.Run("session with no account ends as SESSION_REVOKED", func(t *testing.T) {
		srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
		cookie := issueWebSession(t, srv, mgr, "cookie-unbound", "tenant-a")
		srv.mu.Lock()
		srv.accounts = map[string]*account{}
		srv.mu.Unlock()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_REVOKED")
		_, err := mgr.Validate(context.Background(), cookie.Value)
		assert.Error(t, err, "the unbound session must be revoked server-side")
	})

	t.Run("disabled account ends the session, and a failed revocation is logged", func(t *testing.T) {
		logger := &auditCapturingLogger{}
		srv, mgr := middlewareauthenticationCharWebSessionServerWithLogger(t, logger)
		cookie := issueWebSession(t, srv, mgr, "cookie-disabled", "tenant-a")
		srv.mu.Lock()
		for _, a := range srv.accounts {
			if a.ID == "cookie-disabled" {
				a.Disabled = true
			}
		}
		srv.mu.Unlock()
		srv.SetWebSessionManager(middlewareauthenticationCharFailingRevoke{Manager: mgr})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_REVOKED")
		assert.Contains(t, logger.formattedOutput(), "Failed to revoke disabled-account web session")
	})

	t.Run("a revoked passkey ends the session with the same answer", func(t *testing.T) {
		srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
		cookie := issueWebSession(t, srv, mgr, "cookie-passkey", "tenant-a")
		srv.mu.Lock()
		for _, a := range srv.accounts {
			if a.ID == "cookie-passkey" {
				a.Credentials = nil
			}
		}
		srv.mu.Unlock()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(srv, req)

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "SESSION_REVOKED")
		assert.Contains(t, res.rec.Body.String(), "Session has been revoked")
	})

	t.Run("root-scope account is an implicit admin with global scope", func(t *testing.T) {
		srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
		cookie := issueWebSession(t, srv, mgr, "cookie-root", "tenant-a")
		srv.mu.Lock()
		for _, a := range srv.accounts {
			if a.ID == "cookie-root" {
				a.RootScope = true
			}
		}
		srv.mu.Unlock()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(srv, req)

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		p := res.principal()
		require.NotNil(t, p)
		assert.True(t, p.GlobalScope)
		assert.True(t, p.ImplicitAdmin)
		assert.Empty(t, p.Permissions)
		assert.NotNil(t, p.Permissions)
	})

	t.Run("tenant-scoped account carries its permissions verbatim", func(t *testing.T) {
		srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
		cookie := issueWebSession(t, srv, mgr, "cookie-scoped", "tenant-a")
		srv.mu.Lock()
		for _, a := range srv.accounts {
			if a.ID == "cookie-scoped" {
				a.Permissions = []string{"steward:read", "config:read"}
			}
		}
		srv.mu.Unlock()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(cookie)

		res := middlewareauthenticationCharServe(srv, req)

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		p := res.principal()
		require.NotNil(t, p)
		assert.False(t, p.GlobalScope)
		assert.False(t, p.ImplicitAdmin)
		assert.Equal(t, []string{"steward:read", "config:read"}, p.Permissions)
	})
}

// --- API key ---

func TestMiddlewareAuthenticationChar_APIKey(t *testing.T) {
	srv := setupTestServer(t)

	t.Run("no credential is MISSING_API_KEY", func(t *testing.T) {
		res := middlewareauthenticationCharServe(srv, httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "MISSING_API_KEY")
		assert.Contains(t, res.rec.Body.String(), "API key required")
	})

	t.Run("unknown key is INVALID_API_KEY", func(t *testing.T) {
		res := middlewareauthenticationCharServe(srv, middlewareauthenticationCharAPIKeyRequest("not-a-known-key"))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "INVALID_API_KEY")
		assert.Contains(t, res.rec.Body.String(), "Invalid API key")
	})

	t.Run("grant-prefixed X-API-Key is never an API key", func(t *testing.T) {
		key := automationGrantCredentialPrefix + "not-a-grant"
		srv.mu.Lock()
		srv.apiKeys[key] = &APIKey{ID: "grant-shaped", Key: key, TenantID: "tenant-a"}
		srv.mu.Unlock()
		t.Cleanup(func() {
			srv.mu.Lock()
			delete(srv.apiKeys, key)
			srv.mu.Unlock()
		})

		res := middlewareauthenticationCharServe(srv, middlewareauthenticationCharAPIKeyRequest(key))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "INVALID_API_KEY")
	})

	t.Run("expired key is EXPIRED_API_KEY", func(t *testing.T) {
		key := "expired-characterization-key"
		past := time.Now().Add(-time.Hour)
		srv.mu.Lock()
		srv.apiKeys[key] = &APIKey{ID: "expired", Key: key, TenantID: "tenant-a", ExpiresAt: &past}
		srv.mu.Unlock()
		t.Cleanup(func() {
			srv.mu.Lock()
			delete(srv.apiKeys, key)
			srv.mu.Unlock()
		})

		res := middlewareauthenticationCharServe(srv, middlewareauthenticationCharAPIKeyRequest(key))

		middlewareauthenticationCharRequireReject(t, res, http.StatusUnauthorized, "EXPIRED_API_KEY")
		assert.Contains(t, res.rec.Body.String(), "API key expired")
	})

	t.Run("key with no tenant is refused as unscoped", func(t *testing.T) {
		key := "unscoped-characterization-key"
		srv.mu.Lock()
		srv.apiKeys[key] = &APIKey{ID: "unscoped", Key: key}
		srv.mu.Unlock()
		t.Cleanup(func() {
			srv.mu.Lock()
			delete(srv.apiKeys, key)
			srv.mu.Unlock()
		})

		res := middlewareauthenticationCharServe(srv, middlewareauthenticationCharAPIKeyRequest(key))

		middlewareauthenticationCharRequireReject(t, res, http.StatusForbidden, "NO_TENANT_SCOPE")
	})

	t.Run("valid key authenticates through X-API-Key and sets the full context", func(t *testing.T) {
		key := NewTestKey(t, srv, []string{"steward:read"})

		res := middlewareauthenticationCharServe(srv, middlewareauthenticationCharAPIKeyRequest(key))

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
		p := res.principal()
		require.NotNil(t, p)
		assert.Equal(t, AuthChannelAPIKey, p.Channel)
		assert.Equal(t, session.AssuranceMachine, p.Assurance)
		assert.False(t, p.ImplicitAdmin)
		ctx := res.seen.Context()
		keyInfo, ok := ctx.Value(apiKeyContextKey).(*APIKey)
		require.True(t, ok)
		assert.Equal(t, keyInfo.ID, ctx.Value(ctxkeys.UserIDKey))
		assert.Equal(t, "test-tenant", ctx.Value(ctxkeys.TenantID))
		assert.NotNil(t, ctx.Value(ctxkeys.TenantScopeKey))
		assert.NotNil(t, ctx.Value(authRecheckContextKey))
		assert.NotNil(t, ctx.Value(principalRefreshContextKey))
	})

	t.Run("X-API-Key wins over the Authorization header", func(t *testing.T) {
		key := NewTestKey(t, srv, []string{"steward:read"})
		req := middlewareauthenticationCharAPIKeyRequest(key)
		req.Header.Set("Authorization", "Bearer some-other-token")

		res := middlewareauthenticationCharServe(srv, req)

		require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
	})
}
