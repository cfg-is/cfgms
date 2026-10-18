// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// Issue #5166: a web session lives only while the passkeys behind it exist. These
// tests drive the real authenticationMiddleware and the real revoke handler.

var (
	sessEndCredX = []byte("session-end-credential-x")
	sessEndCredY = []byte("session-end-credential-y")
)

const sessEndLoginIP = "198.51.100.77"

// sessEndServer returns a passkey-session server whose account holds passkeys X and Y,
// plus the account.
func sessEndServer(t *testing.T) (*Server, string, *account) {
	t.Helper()
	srv, username := setupPasskeySessionServer(t)
	injectCredentialWith(t, srv, username, WebAuthnCredential{ID: sessEndCredX})
	injectCredentialWith(t, srv, username, WebAuthnCredential{ID: sessEndCredY})
	acct, err := srv.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	return srv, username, acct
}

// sessEndLogin mints a web session as passkey login does (Issue, then Elevate with the
// login credential), optionally followed by step-ups. It returns the current cookie.
func sessEndLogin(t *testing.T, mgr session.Manager, acct *account, login []byte, stepUps ...[]byte) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	sess, _, err := mgr.Issue(ctx, acct.ID, "web-login", acct.TenantID)
	require.NoError(t, err)
	_, tok, err := mgr.Elevate(ctx, sess.ID, login, sessEndLoginIP)
	require.NoError(t, err)
	for _, c := range stepUps {
		_, tok, err = mgr.Elevate(ctx, sess.ID, c, sessEndLoginIP)
		require.NoError(t, err)
	}
	return &http.Cookie{Name: cookieWebSession, Value: tok}
}

func sessEndRequest(t *testing.T, srv *Server, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	return rec
}

func requireSessionRevoked(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Equal(t, "SESSION_REVOKED", errCode(t, rec.Body.Bytes()))
}

func sessEndRevoke(t *testing.T, srv *Server, username string, cred []byte) {
	t.Helper()
	rec := doRevokeCredential(t, srv, username, base64.RawURLEncoding.EncodeToString(cred))
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
}

func TestSessionEnd_RevokingLoginPasskeyEndsSession(t *testing.T) {
	srv, username, acct := sessEndServer(t)
	cookie := sessEndLogin(t, srv.webSessionManager, acct, sessEndCredX)

	require.Equal(t, http.StatusOK, sessEndRequest(t, srv, cookie).Code, "precondition: session works")

	sessEndRevoke(t, srv, username, sessEndCredX)

	requireSessionRevoked(t, sessEndRequest(t, srv, cookie))
	// The session is revoked server-side, not just refused once.
	_, err := srv.webSessionManager.Validate(context.Background(), cookie.Value)
	assert.Error(t, err, "the refused session must be revoked")
}

func TestSessionEnd_SteppedUpSession(t *testing.T) {
	t.Run("revoking the login passkey X ends a session stepped up with Y", func(t *testing.T) {
		srv, username, acct := sessEndServer(t)
		cookie := sessEndLogin(t, srv.webSessionManager, acct, sessEndCredX, sessEndCredY)
		require.Equal(t, http.StatusOK, sessEndRequest(t, srv, cookie).Code)

		sessEndRevoke(t, srv, username, sessEndCredX)

		requireSessionRevoked(t, sessEndRequest(t, srv, cookie))
	})

	t.Run("a session logged in with Y keeps working after X is revoked", func(t *testing.T) {
		srv, username, acct := sessEndServer(t)
		cookie := sessEndLogin(t, srv.webSessionManager, acct, sessEndCredY)

		sessEndRevoke(t, srv, username, sessEndCredX)

		assert.Equal(t, http.StatusOK, sessEndRequest(t, srv, cookie).Code)
	})

	t.Run("revoking the step-up passkey Y ends a session logged in with X", func(t *testing.T) {
		srv, username, acct := sessEndServer(t)
		cookie := sessEndLogin(t, srv.webSessionManager, acct, sessEndCredX, sessEndCredY)
		require.Equal(t, http.StatusOK, sessEndRequest(t, srv, cookie).Code)

		sessEndRevoke(t, srv, username, sessEndCredY)

		requireSessionRevoked(t, sessEndRequest(t, srv, cookie))
	})
}

func TestSessionEnd_UnprovenSessionsAreRefused(t *testing.T) {
	t.Run("a session with an empty LoginCredentialID is refused", func(t *testing.T) {
		srv, _, acct := sessEndServer(t)
		sess, tok, err := srv.webSessionManager.Issue(context.Background(), acct.ID, "web-login", acct.TenantID)
		require.NoError(t, err)
		require.Empty(t, sess.LoginCredentialID)

		requireSessionRevoked(t, sessEndRequest(t, srv, &http.Cookie{Name: cookieWebSession, Value: tok}))
	})

	t.Run("a session whose account is missing is refused and revoked", func(t *testing.T) {
		srv, _, _ := sessEndServer(t)
		ghost := &account{ID: "no-such-account", Username: "no-such-account"}
		cookie := sessEndLogin(t, srv.webSessionManager, ghost, sessEndCredX)

		requireSessionRevoked(t, sessEndRequest(t, srv, cookie))
		_, err := srv.webSessionManager.Validate(context.Background(), cookie.Value)
		assert.Error(t, err, "a session with no account must be revoked")
	})

	t.Run("an account lookup error gives 503 and leaves the session alive", func(t *testing.T) {
		srv, _, acct := sessEndServer(t)
		cookie := sessEndLogin(t, srv.webSessionManager, acct, sessEndCredX)
		require.Equal(t, http.StatusOK, sessEndRequest(t, srv, cookie).Code)

		healthy := srv.secretStore
		srv.secretStore = &errListSecretStore{SecretStore: healthy, listErr: errors.New("injected ListSecrets failure")}
		rec := sessEndRequest(t, srv, cookie)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		assert.Equal(t, "SERVICE_UNAVAILABLE", errCode(t, rec.Body.Bytes()))

		srv.secretStore = healthy
		assert.Equal(t, http.StatusOK, sessEndRequest(t, srv, cookie).Code,
			"a transient lookup error must not revoke the session")
	})
}

// TestSessionEnd_CrossNode mints the session on node B, revokes the passkey through
// node A, and expects node B to refuse the next request: web session managers are per
// node, so the check must read the account, not a per-node session list.
func TestSessionEnd_CrossNode(t *testing.T) {
	nodeA, nodeB := setupTwoNodeSharedStoreServers(t)
	const username = "session-end-cross-node"

	rec := postAccount(t, nodeA, testAdminPrincipal(), AccountRequest{
		Username: username, TenantID: "tenant-a", Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	injectCredentialWith(t, nodeA, username, WebAuthnCredential{ID: sessEndCredX})
	injectCredentialWith(t, nodeA, username, WebAuthnCredential{ID: sessEndCredY})

	acctFromA, err := nodeA.loadAccountFromStore(context.Background(), username, "")
	require.NoError(t, err)
	require.NotNil(t, acctFromA)
	nodeB.cacheAccount(acctFromA) // node B's in-memory copy still lists X

	cookie := sessEndLogin(t, nodeB.webSessionManager, acctFromA, sessEndCredX)
	require.Equal(t, http.StatusOK, sessEndRequest(t, nodeB, cookie).Code, "precondition: node B accepts the session")

	sessEndRevoke(t, nodeA, username, sessEndCredX)

	requireSessionRevoked(t, sessEndRequest(t, nodeB, cookie))
}

// TestSessionEnd_BearerSessionsAreNotRefused guards the CLI channel: Bearer sessions
// carry no passkey, so the credential check must not apply to them.
func TestSessionEnd_BearerSessionsAreNotRefused(t *testing.T) {
	srv := setupTestServer(t)
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)
	srv.SetSessionManager(mgr)

	_, tok, err := mgr.Issue(context.Background(), "admin", "cfg-cli", testRootTenantID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}
