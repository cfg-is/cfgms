// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #5066: passkey login finish and step-up finish must reload the account after the
// assertion verifies, refuse when the account was disabled or the signing credential was
// revoked in the meantime, and record the sign count with compare-and-swap so a refused
// write never resurrects a removed credential or clears the disabled flag.
//
// The concurrent admin write is a real write to the real secret store, performed from
// inside the store's own ListSecrets call so it lands after the handler's first read of
// the account and before its sign-count write. No component is mocked.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/session"
)

// racingSecretStore wraps the server's real secret store. After the fireOnList-th
// ListSecrets call returns, it runs hook once (simulating an administrator write racing
// the handler). With casAlwaysLoses it reports every CompareAndSwapSecret as a lost swap.
type racingSecretStore struct {
	secretsif.SecretStore

	mu            sync.Mutex
	fireOnList    int
	hook          func()
	casAlwaysLoss bool
	casCalls      int
}

func (r *racingSecretStore) ListSecrets(ctx context.Context, f *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	metas, err := r.SecretStore.ListSecrets(ctx, f)
	r.mu.Lock()
	var fire func()
	if r.hook != nil {
		r.fireOnList--
		if r.fireOnList == 0 {
			fire, r.hook = r.hook, nil
		}
	}
	r.mu.Unlock()
	if fire != nil {
		fire()
	}
	return metas, err
}

func (r *racingSecretStore) CompareAndSwapSecret(ctx context.Context, key string, expected int, req *secretsif.SecretRequest) (int, bool, error) {
	r.mu.Lock()
	r.casCalls++
	lose := r.casAlwaysLoss
	r.mu.Unlock()
	if lose {
		return 0, false, nil
	}
	return r.SecretStore.CompareAndSwapSecret(ctx, key, expected, req)
}

// installRacingStore swaps the server's secret store for a racing wrapper.
func installRacingStore(t *testing.T, srv *Server) *racingSecretStore {
	t.Helper()
	rs := &racingSecretStore{SecretStore: srv.secretStore}
	srv.secretStore = rs
	return rs
}

// mutateStoredAccount applies mutate to the account as stored and persists it, as an
// administrator's write would.
func mutateStoredAccount(t *testing.T, srv *Server, username string, mutate func(a *account)) {
	t.Helper()
	a, err := srv.loadAccountFromStore(context.Background(), username, "")
	require.NoError(t, err)
	require.NotNil(t, a)
	mutate(a)
	require.NoError(t, srv.persistAccount(context.Background(), a, "test-admin"))
}

func storedAccount(t *testing.T, srv *Server, username string) *account {
	t.Helper()
	a, err := srv.loadAccountFromStore(context.Background(), username, "")
	require.NoError(t, err)
	require.NotNil(t, a)
	return a
}

func TestPasskeyLoginFinish_CredentialRemovedDuringAssertion_Refused(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	rs := installRacingStore(t, srv)
	// 1st ListSecrets is doPasskeyLogin's own lookup, 2nd is the handler's read.
	rs.fireOnList = 2
	rs.hook = func() {
		mutateStoredAccount(t, srv, username, func(a *account) { a.Credentials = nil })
	}

	rec := doPasskeyLogin(t, srv, username, "")

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, rec.Result().Cookies(), "no session may be issued")
	assert.Empty(t, storedAccount(t, srv, username).Credentials, "revoked credential must stay removed")
}

func TestPasskeyLoginFinish_AccountDisabledDuringAssertion_Refused(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	rs := installRacingStore(t, srv)
	rs.fireOnList = 2
	rs.hook = func() {
		mutateStoredAccount(t, srv, username, func(a *account) { a.Disabled = true })
	}

	rec := doPasskeyLogin(t, srv, username, "")

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, rec.Result().Cookies(), "no session may be issued")
	assert.True(t, storedAccount(t, srv, username).Disabled, "account must stay disabled")
}

func TestPasskeyLoginFinish_SwapKeepsLosing_RefusedAfterOneRetry(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	rs := installRacingStore(t, srv)
	rs.casAlwaysLoss = true

	rec := doPasskeyLogin(t, srv, username, "")

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "body: %s", rec.Body.String())
	rs.mu.Lock()
	calls := rs.casCalls
	rs.mu.Unlock()
	assert.Equal(t, 2, calls, "one attempt plus exactly one retry")
	creds := storedAccount(t, srv, username).Credentials
	require.Len(t, creds, 1)
	assert.Zero(t, creds[0].SignCount, "nothing may be written")
}

func TestPasskeyLoginFinish_Success_UpdatesCacheVersion(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	rec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	srv.mu.RLock()
	cached := srv.accounts[username]
	srv.mu.RUnlock()
	require.NotNil(t, cached)
	assert.Equal(t, storedAccount(t, srv, username).Version, cached.Version)
}

// ---- Issue #6321: durable web-session CSRF token ----
//
// The session-bound CSRF token of a web session is stored as a SHA-256 hash on the durable
// session record, so any controller node accepts it for the session's whole lifetime.
// These tests issue a session through passkey login on one Server and then drive a second
// Server with fresh in-memory state over the same durable stores, standing in for another
// node or a restart. No component is mocked.

// csrfDurableNodes is two controller nodes over one durable session store and one
// durable account store. Each node has its own in-memory session manager caches.
type csrfDurableNodes struct {
	nodeA, nodeB *Server
	username     string
	store        session.Store
}

func setupCSRFDurableNodes(t *testing.T) *csrfDurableNodes {
	t.Helper()
	nodeA, nodeB := setupTwoNodeSharedStoreServers(t)

	wa, err := NewWebAuthnFromConfig(svAuthRPID, svAuthRPID, []string{svAuthOrigin})
	require.NoError(t, err)
	nodeA.SetWebAuthn(wa)

	const username = "csrf-durable-user"
	rec := postAccount(t, nodeA, testAdminPrincipal(), AccountRequest{Username: username})
	require.Equal(t, http.StatusCreated, rec.Code, "create account: %s", rec.Body.String())

	credID, err := hex.DecodeString(svAuthCredentialIDHex)
	require.NoError(t, err)
	pubKey, err := hex.DecodeString(svAuthPublicKeyHex)
	require.NoError(t, err)
	injectCredentialWithPublicKey(t, nodeA, username, credID, pubKey, 0)

	// One shared store behind two nodes, each with its own session.Manager (and so its own
	// in-memory cache). Direct storage-provider imports are not allowed in this package,
	// so the shared store is the contract's own session.MemStore; the provider-backed
	// stores are covered by the per-provider store tests.
	store := session.NewMemStore(session.DefaultConfig(), time.Now)
	t.Cleanup(store.Close)
	nodeA.SetDurableSessionStore(store)
	nodeB.SetDurableSessionStore(store)

	return &csrfDurableNodes{nodeA: nodeA, nodeB: nodeB, username: username, store: store}
}

// login performs a passkey login on node A and returns the session and CSRF cookie values.
func (n *csrfDurableNodes) login(t *testing.T) (sessionTok, csrfTok string) {
	t.Helper()
	rec := doPasskeyLogin(t, n.nodeA, n.username, "")
	require.Equal(t, http.StatusOK, rec.Code, "login failed: %s", rec.Body.String())
	sessionTok = extractCookie(rec, cookieWebSession)
	csrfTok = extractCookie(rec, cookieCSRFSession)
	require.NotEmpty(t, sessionTok)
	require.NotEmpty(t, csrfTok)
	return sessionTok, csrfTok
}

// postThroughCSRFStack sends a cookie-authenticated POST through authentication and
// CSRF middleware on srv and reports the recorder and whether the handler was reached.
func postThroughCSRFStack(srv *Server, sessionTok string, csrfHeader *string) (*httptest.ResponseRecorder, bool) {
	reached := false
	stack := srv.authenticationMiddleware(srv.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
	req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionTok})
	if csrfHeader != nil {
		req.Header.Set(headerCSRFToken, *csrfHeader)
	}
	rec := httptest.NewRecorder()
	stack.ServeHTTP(rec, req)
	return rec, reached
}

func TestCSRFDurable_SecondNodeAcceptsOriginalToken(t *testing.T) {
	n := setupCSRFDurableNodes(t)
	sessionTok, csrfTok := n.login(t)

	// The issuing node accepts it, and so does a node that never saw the session.
	for name, srv := range map[string]*Server{"issuing node": n.nodeA, "second node": n.nodeB} {
		rec, reached := postThroughCSRFStack(srv, sessionTok, &csrfTok)
		assert.True(t, reached, "%s must accept the original CSRF token: %d %s", name, rec.Code, rec.Body.String())
	}
}

func TestCSRFDurable_StoreHoldsOnlyTheHash(t *testing.T) {
	n := setupCSRFDurableNodes(t)
	sessionTok, csrfTok := n.login(t)

	sess, err := n.nodeB.webSessionManager.Validate(context.Background(), sessionTok)
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(csrfTok))
	assert.Equal(t, hex.EncodeToString(sum[:]), sess.CSRFTokenHash)
	assert.NotEqual(t, csrfTok, sess.CSRFTokenHash, "the raw token must never be stored")
}

func TestCSRFDurable_SecondNodeRefusesWrongOrMissingToken(t *testing.T) {
	n := setupCSRFDurableNodes(t)
	sessionTok, csrfTok := n.login(t)

	wrong := csrfTok + "x"
	empty := ""
	for name, header := range map[string]*string{"wrong": &wrong, "empty": &empty, "missing": nil} {
		t.Run(name, func(t *testing.T) {
			rec, reached := postThroughCSRFStack(n.nodeB, sessionTok, header)
			assert.False(t, reached)
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, "CSRF_MISMATCH", errCode(t, rec.Body.Bytes()))
		})
	}
}

func TestCSRFDurable_SessionWithoutBoundHashIsRefused(t *testing.T) {
	n := setupCSRFDurableNodes(t)
	acct, err := n.nodeA.getAccount(context.Background(), n.username)
	require.NoError(t, err)
	credID, err := hex.DecodeString(svAuthCredentialIDHex)
	require.NoError(t, err)

	// A session issued by a controller that predates the durable hash carries none.
	sess, _, err := n.nodeA.webSessionManager.Issue(context.Background(), acct.ID, "web", acct.TenantID)
	require.NoError(t, err)
	_, tok, err := n.nodeA.webSessionManager.Elevate(context.Background(), sess.ID, credID, "198.51.100.77")
	require.NoError(t, err)

	anyToken := "some-token"
	rec, reached := postThroughCSRFStack(n.nodeB, tok, &anyToken)
	assert.False(t, reached)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "CSRF_MISMATCH", errCode(t, rec.Body.Bytes()))
}

func TestCSRFDurable_LogoutOnSecondNodeRevokesSession(t *testing.T) {
	n := setupCSRFDurableNodes(t)
	sessionTok, csrfTok := n.login(t)

	// A wrong token cannot log out.
	rec := doLogout(t, n.nodeB, sessionTok, csrfTok+"x")
	require.Equal(t, http.StatusForbidden, rec.Code)

	rec = doLogout(t, n.nodeB, sessionTok, csrfTok)
	require.Equal(t, http.StatusOK, rec.Code, "logout body: %s", rec.Body.String())

	// The session is gone on both nodes and the same CSRF token no longer passes.
	for name, srv := range map[string]*Server{"node A": n.nodeA, "node B": n.nodeB} {
		_, err := srv.webSessionManager.Validate(context.Background(), sessionTok)
		assert.Error(t, err, "%s must reject the revoked session", name)
		rec, reached := postThroughCSRFStack(srv, sessionTok, &csrfTok)
		assert.False(t, reached, "%s must not reach the handler after logout", name)
		assert.NotEqual(t, http.StatusOK, rec.Code)
	}
}

// TestCSRFDurable_RevocationInvalidatesTokenOnEveryNode covers each revocation path other than logout (see LogoutOnSecondNode):
// the durable CSRF token hash goes with the row and validates on no node afterwards.
func TestCSRFDurable_RevocationInvalidatesTokenOnEveryNode(t *testing.T) {
	revokers := map[string]func(t *testing.T, n *csrfDurableNodes, sessionID string){
		"revoke by id": func(t *testing.T, n *csrfDurableNodes, id string) {
			require.NoError(t, n.nodeB.webSessionManager.Revoke(context.Background(), id))
		},
		"revoke all for principal": func(t *testing.T, n *csrfDurableNodes, id string) {
			sess, err := n.nodeB.webSessionManager.GetByID(context.Background(), id)
			require.NoError(t, err)
			count, err := n.nodeB.webSessionManager.RevokeAllForPrincipal(context.Background(), sess.PrincipalID)
			require.NoError(t, err)
			require.Equal(t, 1, count)
		},
		"revoke sessions for principal": func(t *testing.T, n *csrfDurableNodes, id string) {
			sess, err := n.nodeB.webSessionManager.GetByID(context.Background(), id)
			require.NoError(t, err)
			count, err := n.nodeB.revokeSessionsForPrincipal(context.Background(), sess.PrincipalID)
			require.NoError(t, err)
			require.Equal(t, 1, count)
		},
	}
	for name, revoke := range revokers {
		t.Run(name, func(t *testing.T) {
			n := setupCSRFDurableNodes(t)
			sessionTok, csrfTok := n.login(t)
			sess, err := n.nodeA.webSessionManager.Validate(context.Background(), sessionTok)
			require.NoError(t, err)
			require.True(t, n.nodeA.webCSRFTokenValid(context.Background(), sess.ID, csrfTok))
			require.True(t, n.nodeB.webCSRFTokenValid(context.Background(), sess.ID, csrfTok))

			revoke(t, n, sess.ID)

			assert.False(t, n.nodeA.webCSRFTokenValid(context.Background(), sess.ID, csrfTok))
			assert.False(t, n.nodeB.webCSRFTokenValid(context.Background(), sess.ID, csrfTok))
			// The shared store finds no record, hash included.
			_, err = n.store.GetByID(context.Background(), sess.ID)
			assert.ErrorIs(t, err, session.ErrSessionNotFound)
		})
	}
}
