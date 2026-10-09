// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #4527 (ADR-031): WebAuthn ceremony state and throttles are cluster-shared in
// ClusterMode. Every test drives two (or more) real *Server instances that share one
// real NonceStore and one real RateCounterStore — the only things production cluster
// nodes share — so begin on one node and finish on another is exercised for real.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ha"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testing/storage"
)

// clusterFixture is the shared state every node of one test cluster uses.
type clusterFixture struct {
	manager  *ha.Manager
	nonces   business.NonceStore
	counters business.RateCounterStore
}

func newClusterFixture(t *testing.T) *clusterFixture {
	t.Helper()
	sm, err := storage.CreateTestStorageManager()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	nonces := sm.GetNonceStore()
	require.NotNil(t, nonces, "test storage must provide a real NonceStore")
	return &clusterFixture{
		manager:  newNonAuthoritativeHAManager(t),
		nonces:   nonces,
		counters: pkgtesting.SetupTestRateCounterStore(),
	}
}

// join makes s a ClusterMode node on the fixture's shared stores.
func (f *clusterFixture) join(s *Server) *Server {
	s.haManager = f.manager
	s.SetNonceStore(f.nonces)
	s.SetRateCounterStore(f.counters)
	return s
}

func syncMapLen(m *sync.Map) int {
	n := 0
	m.Range(func(_, _ any) bool { n++; return true })
	return n
}

// requireNoLocalCeremonyState asserts the node-local maps were never used.
func requireNoLocalCeremonyState(t *testing.T, s *Server) {
	t.Helper()
	for name, m := range map[string]*sync.Map{
		"register": &s.webAuthnSessions, "presence": &s.webAuthnPresenceSessions,
		"presence-token": &s.presenceTokens, "elevate": &s.webAuthnElevateSessions,
		"payload-sign": &s.operatorPayloadSignSessions, "login": &s.passkeyLoginSessions,
		"enroll": &s.passkeyEnrollSessions,
	} {
		assert.Zero(t, syncMapLen(m), "ClusterMode must not use the node-local %s map", name)
	}
}

// failingNonceStore wraps a real NonceStore and fails the selected operation, the way
// failingReadSecretStore wraps a real SecretStore: real behaviour except where the test
// needs the storage layer to be down.
type failingNonceStore struct {
	business.NonceStore
	failPut, failGet bool
}

var errNonceStoreDown = errors.New("nonce store down")

func (f *failingNonceStore) PutNonce(ctx context.Context, key string, entry []byte, ttl time.Duration) error {
	if f.failPut {
		return errNonceStoreDown
	}
	return f.NonceStore.PutNonce(ctx, key, entry, ttl)
}

func (f *failingNonceStore) GetAndConsumeNonce(ctx context.Context, key string) ([]byte, bool, error) {
	if f.failGet {
		return nil, false, errNonceStoreDown
	}
	return f.NonceStore.GetAndConsumeNonce(ctx, key)
}

// passkeyFinish posts body to handlePasskeyLoginFinish carrying the ceremony cookie.
func passkeyFinish(srv *Server, ceremonyID string, body *bytes.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", body)
	req.AddCookie(&http.Cookie{Name: cookiePasskeyCeremony, Value: ceremonyID})
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)
	return rec
}

func passkeyBegin(srv *Server) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/begin", nil)
	req.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: "csrf-pre"})
	req.Header.Set(headerCSRFToken, "csrf-pre")
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginBegin(rec, req)
	return rec
}

func ceremonyCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookiePasskeyCeremony {
			return c.Value
		}
	}
	require.FailNow(t, "begin must set the ceremony cookie")
	return ""
}

func junkBody() *bytes.Reader { return bytes.NewReader([]byte(`{}`)) }

// specLoginSession is a discoverable login SessionData matching the NoneES256 vector.
func specLoginSession(t *testing.T) webauthn.SessionData {
	t.Helper()
	challengeBytes, err := hex.DecodeString(svAuthChallengeHex)
	require.NoError(t, err)
	return webauthn.SessionData{
		Challenge:        base64.RawURLEncoding.EncodeToString(challengeBytes),
		RelyingPartyID:   svAuthRPID,
		UserVerification: protocol.VerificationPreferred,
		Expires:          time.Now().Add(10 * time.Minute),
	}
}

func specLoginBody(t *testing.T, srv *Server, username string) *bytes.Reader {
	t.Helper()
	credID, err := hex.DecodeString(svAuthCredentialIDHex)
	require.NoError(t, err)
	authData, err := hex.DecodeString(svAuthAuthDataHex)
	require.NoError(t, err)
	cdj, err := hex.DecodeString(svAuthClientDataJSONHex)
	require.NoError(t, err)
	sig, err := hex.DecodeString(svAuthSignatureHex)
	require.NoError(t, err)
	acct, err := srv.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	return buildAssertionBodyWithUserHandle(t, credID, authData, cdj, sig, []byte(acct.ID))
}

// --- replay across nodes ---

func TestWebAuthnCluster_LoginBeginOnAFinishOnB(t *testing.T) {
	f := newClusterFixture(t)
	a, userA := setupPasskeySessionServer(t)
	b, userB := setupPasskeySessionServer(t)
	f.join(a)
	f.join(b)

	// Real begin on A; the finish on B must find the ceremony (it then fails
	// verification on the junk body, which is not NO_ACTIVE_LOGIN_SESSION).
	cookie := ceremonyCookieFrom(t, passkeyBegin(a))
	rec := passkeyFinish(b, cookie, junkBody())
	assert.NotEqual(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()),
		"finish on node B must see the ceremony begun on node A")

	// Single use cluster-wide: the second finish, on A, is not-found.
	rec = passkeyFinish(a, cookie, junkBody())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))
	requireNoLocalCeremonyState(t, a)
	requireNoLocalCeremonyState(t, b)

	// Full success across nodes with the spec vector.
	const ceremonyID = "spec-vector-ceremony"
	require.Equal(t, passkeyLoginStored, a.storePasskeyLoginSession(context.Background(), ceremonyID, &passkeyLoginSession{
		data: specLoginSession(t), expires: time.Now().Add(time.Minute), accountID: userA,
		discoverable: true, clientKey: a.clientIPKey(httptest.NewRequest(http.MethodPost, "/", nil)),
	}))
	rec = passkeyFinish(b, ceremonyID, specLoginBody(t, b, userB))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	rec = passkeyFinish(a, ceremonyID, specLoginBody(t, a, userA))
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))
}

func TestWebAuthnCluster_EnrollBeginOnAFinishOnB(t *testing.T) {
	f := newClusterFixture(t)
	const username = "enroll-cluster-user"
	a, _, token := setupEnrollServer(t, tvRPID, []string{tvOrigin}, username)
	b, _, _ := setupEnrollServer(t, tvRPID, []string{tvOrigin}, username)
	f.join(a)
	f.join(b)
	// Node B serves the same account record as A (the shared database in production).
	acct, err := a.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NoError(t, b.persistAccount(context.Background(), acct, "test"))
	b.cacheAccount(acct)

	require.Equal(t, http.StatusOK, doEnrollBegin(t, a, token).Code)
	rec := doEnrollFinish(t, b, token, junkBody())
	assert.NotEqual(t, "NO_ACTIVE_ENROLLMENT", errCode(t, rec.Body.Bytes()),
		"finish on node B must see the ceremony begun on node A")

	rec = doEnrollFinish(t, a, token, junkBody())
	assert.Equal(t, "NO_ACTIVE_ENROLLMENT", errCode(t, rec.Body.Bytes()))
	requireNoLocalCeremonyState(t, a)
	requireNoLocalCeremonyState(t, b)

	// The raw enrolment token is never stored: only its hash is in the key.
	require.Equal(t, http.StatusOK, doEnrollBegin(t, a, token).Code)
	_, found, err := f.nonces.GetAndConsumeNonce(context.Background(), ceremonyPrefixEnroll+token)
	require.NoError(t, err)
	assert.False(t, found, "the raw token must not be a store key")
	_, found, err = f.nonces.GetAndConsumeNonce(context.Background(), ceremonyPrefixEnroll+hashEnrollmentToken(token))
	require.NoError(t, err)
	assert.True(t, found, "the token hash is the store key")
}

func TestWebAuthnCluster_StepUpBeginOnAFinishOnB(t *testing.T) {
	f := newClusterFixture(t)
	a, username := setupPasskeySessionServer(t)
	b, _ := setupPasskeySessionServer(t)
	f.join(a)
	f.join(b)
	principal := &Principal{ID: username}
	const sessID = "elevate-cluster-session"

	require.Equal(t, http.StatusOK, doStepUpBegin(t, a, principal, sessID).Code)
	rec := doStepUpFinish(t, b, principal, sessID, junkBody())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()),
		"node B must find the ceremony and reach verification")

	rec = doStepUpFinish(t, a, principal, sessID, junkBody())
	assert.Equal(t, "NO_ACTIVE_ELEVATION_SESSION", errCode(t, rec.Body.Bytes()))
	requireNoLocalCeremonyState(t, a)
	requireNoLocalCeremonyState(t, b)
}

func TestWebAuthnCluster_RegisterPresenceAndSignAcrossNodes(t *testing.T) {
	f := newClusterFixture(t)
	a, username := setupOperatorPayloadSignServer(t)
	b, _ := setupOperatorPayloadSignServer(t)
	f.join(a)
	f.join(b)
	for _, n := range []*Server{a, b} {
		injectCredentialWithPublicKey(t, n, username, []byte("cred-cluster"), []byte("pk"), 0)
	}

	// register
	require.Equal(t, http.StatusOK, doBegin(t, a, username).Code)
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, doFinish(t, b, username, junkBody()).Body.Bytes()))
	assert.Equal(t, "NO_ACTIVE_REGISTRATION", errCode(t, doFinish(t, a, username, junkBody()).Body.Bytes()))

	// presence (key = principal ID, which is each node's own account ID for username)
	pa, pb := principalForAccount(t, a, username), principalForAccount(t, b, username)
	pb.ID = pa.ID
	acct, err := a.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NoError(t, b.persistAccount(context.Background(), acct, "test"))
	b.cacheAccount(acct)
	require.Equal(t, http.StatusOK, doPresenceBegin(t, a, pa).Code)
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, doPresenceFinish(t, b, pb).Body.Bytes()))
	assert.Equal(t, "NO_ACTIVE_PRESENCE_SESSION", errCode(t, doPresenceFinish(t, a, pa).Body.Bytes()))

	// payload sign
	sp := &Principal{ID: username}
	require.Equal(t, http.StatusOK, doSignBegin(t, a, sp, "sign-cluster-sess", validBeginBody()).Code)
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, doSignFinish(t, b, sp, "sign-cluster-sess", junkBody()).Body.Bytes()))
	assert.Equal(t, "NO_ACTIVE_SIGN_SESSION", errCode(t, doSignFinish(t, a, sp, "sign-cluster-sess", junkBody()).Body.Bytes()))

	requireNoLocalCeremonyState(t, a)
	requireNoLocalCeremonyState(t, b)
}

// --- cross-ceremony confusion ---

func TestWebAuthnCluster_CeremoniesAreNamespaced(t *testing.T) {
	f := newClusterFixture(t)
	a, username := setupOperatorPayloadSignServer(t)
	b, _ := setupOperatorPayloadSignServer(t)
	f.join(a)
	f.join(b)
	injectCredentialWithPublicKey(t, b, username, []byte("cred-ns"), []byte("pk"), 0)
	principal := &Principal{ID: username}

	// A login challenge stored under ceremony ID X cannot finish an elevation whose
	// web session ID is also X.
	const shared = "same-identifier"
	require.Equal(t, passkeyLoginStored, a.storePasskeyLoginSession(context.Background(), shared, &passkeyLoginSession{
		data: specLoginSession(t), expires: time.Now().Add(time.Minute), discoverable: true,
	}))
	rec := doStepUpFinish(t, b, principal, shared, junkBody())
	assert.Equal(t, "NO_ACTIVE_ELEVATION_SESSION", errCode(t, rec.Body.Bytes()),
		"a login entry must not satisfy an elevate finish")
	got, out := b.takePasskeyLoginSession(context.Background(), shared)
	assert.Equal(t, ceremonyOK, out, "the login entry is untouched by the elevate attempt")
	assert.NotNil(t, got)

	// A presence entry cannot finish a payload-sign ceremony.
	require.Equal(t, ceremonyOK, a.putClusterCeremony(context.Background(), ceremonyPrefixPresence, shared,
		(&webAuthnPendingSession{data: specLoginSession(t), expires: time.Now().Add(time.Minute), binding: shared}).toWire(),
		time.Minute))
	rec = doSignFinish(t, b, principal, shared, junkBody())
	assert.Equal(t, "NO_ACTIVE_SIGN_SESSION", errCode(t, rec.Body.Bytes()))
	pending, out := b.takePendingSession(context.Background(), &b.webAuthnPresenceSessions, ceremonyPrefixPresence, shared)
	assert.Equal(t, ceremonyOK, out)
	assert.NotNil(t, pending)
}

// --- binding mismatch ---

func TestWebAuthnCluster_FinishRefusesMismatchedBinding(t *testing.T) {
	f := newClusterFixture(t)
	n, username := setupOperatorPayloadSignServer(t)
	f.join(n)
	injectCredentialWithPublicKey(t, n, username, []byte("cred-bind"), []byte("pk"), 0)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)

	t.Run("elevate", func(t *testing.T) {
		require.Equal(t, ceremonyOK, n.putElevateSession(ctx, "bind-sess", &webAuthnElevateSession{
			data: specLoginSession(t), expires: exp, accountID: "someone-else"}))
		rec := doStepUpFinish(t, n, &Principal{ID: username}, "bind-sess", junkBody())
		assert.Equal(t, "NO_ACTIVE_ELEVATION_SESSION", errCode(t, rec.Body.Bytes()))
	})
	t.Run("payload-sign", func(t *testing.T) {
		require.Equal(t, ceremonyOK, n.putPayloadSignSession(ctx, "bind-sess", &operatorPayloadSignSession{
			data: specLoginSession(t), expires: exp, accountID: "someone-else"}))
		rec := doSignFinish(t, n, &Principal{ID: username}, "bind-sess", junkBody())
		assert.Equal(t, "NO_ACTIVE_SIGN_SESSION", errCode(t, rec.Body.Bytes()))
	})
	t.Run("register", func(t *testing.T) {
		require.Equal(t, ceremonyOK, n.putPendingSession(ctx, &n.webAuthnSessions, ceremonyPrefixRegister, username,
			&webAuthnPendingSession{data: specLoginSession(t), expires: exp, binding: "another-principal"}, time.Minute))
		rec := doFinish(t, n, username, junkBody())
		assert.Equal(t, "NO_ACTIVE_REGISTRATION", errCode(t, rec.Body.Bytes()))
	})
	t.Run("presence", func(t *testing.T) {
		p := principalForAccount(t, n, username)
		require.Equal(t, ceremonyOK, n.putPendingSession(ctx, &n.webAuthnPresenceSessions, ceremonyPrefixPresence, p.ID,
			&webAuthnPendingSession{data: specLoginSession(t), expires: exp, binding: "another-principal"}, time.Minute))
		rec := doPresenceFinish(t, n, p)
		assert.Equal(t, "NO_ACTIVE_PRESENCE_SESSION", errCode(t, rec.Body.Bytes()))
	})
	t.Run("login-client", func(t *testing.T) {
		l, _ := setupPasskeySessionServer(t)
		f.join(l)
		require.Equal(t, passkeyLoginStored, l.storePasskeyLoginSession(ctx, "bind-login", &passkeyLoginSession{
			data: specLoginSession(t), expires: exp, discoverable: true, clientKey: "203.0.113.9"}))
		rec := passkeyFinish(l, "bind-login", junkBody())
		assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))
	})
	t.Run("enroll", func(t *testing.T) {
		e, _, token := setupEnrollServer(t, tvRPID, []string{tvOrigin}, "enroll-bind-user")
		f.join(e)
		require.Equal(t, ceremonyOK, e.putPendingSession(ctx, &e.passkeyEnrollSessions, ceremonyPrefixEnroll,
			hashEnrollmentToken(token), &webAuthnPendingSession{data: specLoginSession(t), expires: exp, binding: "other-account"}, time.Minute))
		rec := doEnrollFinish(t, e, token, junkBody())
		assert.Equal(t, "NO_ACTIVE_ENROLLMENT", errCode(t, rec.Body.Bytes()))
	})
}

// --- expiry ---

func TestWebAuthnCluster_ExpiredEntryRefusedWithoutSweep(t *testing.T) {
	f := newClusterFixture(t)
	n, username := setupOperatorPayloadSignServer(t)
	f.join(n)
	injectCredentialWithPublicKey(t, n, username, []byte("cred-exp"), []byte("pk"), 0)

	// A long store TTL but an entry whose own expiry has passed: the finish-side check
	// refuses it even though no sweep ever ran.
	require.Equal(t, ceremonyOK, n.putElevateSession(context.Background(), "exp-sess", &webAuthnElevateSession{
		data: specLoginSession(t), expires: time.Now().Add(-time.Second), accountID: username}))
	rec := doStepUpFinish(t, n, &Principal{ID: username}, "exp-sess", junkBody())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "SESSION_EXPIRED", errCode(t, rec.Body.Bytes()))

	// And the store itself enforces the TTL: an entry put with a lapsed TTL is gone.
	require.NoError(t, f.nonces.PutNonce(context.Background(), ceremonyPrefixElevate+"ttl-sess", []byte("{}"), time.Millisecond))
	time.Sleep(20 * time.Millisecond)
	_, out := takeClusterCeremony[webAuthnElevateWire](n, context.Background(), ceremonyPrefixElevate, "ttl-sess")
	assert.Equal(t, ceremonyNotFound, out)
}

// --- presence token across nodes ---

func TestWebAuthnCluster_PresenceTokenMintedOnAConsumedOnceOnB(t *testing.T) {
	withPresencePermission(t)
	f := newClusterFixture(t)
	a := f.join(setupTestServer(t))
	b := f.join(setupTestServer(t))
	adminCert := makeSelfSignedAdminCert(t)

	token := "cluster-presence-token"
	require.Equal(t, ceremonyOK, a.putPresenceToken(context.Background(), hashPresenceToken(token), &presenceTokenRecord{
		principalID: "test-admin", expires: time.Now().Add(presenceTokenTTL),
	}))

	handler := wrapWithAuth(b, "test", "presence-required",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	call := func() *httptest.ResponseRecorder {
		req := requestWithTLSCert(http.MethodPost, "/api/v1/test/presence-action", adminCert)
		req.Header.Set(presenceTokenHeader, token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	assert.Equal(t, http.StatusOK, call().Code, "token minted on A must be accepted on B")
	rec := call()
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "second use must be refused")
	assert.Contains(t, rec.Body.String(), "presence_token_invalid")

	// The same token on node A is gone too (single use cluster-wide).
	_, out := a.takePresenceToken(context.Background(), hashPresenceToken(token))
	assert.Equal(t, ceremonyNotFound, out)
	requireNoLocalCeremonyState(t, a)
	requireNoLocalCeremonyState(t, b)
}

func TestWebAuthnCluster_PresenceTokenKeepsActionBinding(t *testing.T) {
	f := newClusterFixture(t)
	a := f.join(setupTestServer(t))
	b := f.join(setupTestServer(t))
	require.Equal(t, ceremonyOK, a.putPresenceToken(context.Background(), "h", &presenceTokenRecord{
		principalID: "p", expires: time.Now().Add(time.Minute),
		boundMethod: "POST", boundPath: "/x", boundBodyHash: "bh", boundPermissionID: "perm:1",
	}))
	rec, out := b.takePresenceToken(context.Background(), "h")
	require.Equal(t, ceremonyOK, out)
	assert.Equal(t, "POST", rec.boundMethod)
	assert.Equal(t, "/x", rec.boundPath)
	assert.Equal(t, "bh", rec.boundBodyHash)
	assert.Equal(t, "perm:1", rec.boundPermissionID)
}

// --- throttles ---

func TestWebAuthnCluster_ThrottleAccumulatesAcrossNodes(t *testing.T) {
	f := newClusterFixture(t)
	a := f.join(setupTestServer(t))
	b := f.join(setupTestServer(t))

	for name, ops := range map[string]struct {
		record func(*Server, string)
		check  func(*Server, string) (bool, time.Duration)
	}{
		"elevate": {(*Server).recordElevateFailure, (*Server).checkElevateThrottle},
		"login":   {(*Server).recordPasskeyLoginFailure, (*Server).checkPasskeyLoginThrottle},
	} {
		t.Run(name, func(t *testing.T) {
			key := "session:" + name + "-throttle"
			// elevateBackoff: 0 delay through 2 failures, the first cooldown at the 3rd.
			ops.record(a, key)
			ops.record(b, key)
			for _, n := range []*Server{a, b} {
				blocked, _ := ops.check(n, key)
				assert.False(t, blocked, "two failures must not block, as on a single node")
			}
			ops.record(b, key)
			for _, n := range []*Server{a, b} {
				blocked, wait := ops.check(n, key)
				assert.True(t, blocked, "the third failure, split across nodes, must block every node")
				assert.Positive(t, wait)
			}
		})
	}
}

func TestWebAuthnCluster_ThrottleDeniesAtStoreCapacity(t *testing.T) {
	f := newClusterFixture(t)
	f.counters = pkgtesting.SetupTestRateCounterStoreWithMaxKeys(1)
	a := f.join(setupTestServer(t))

	a.recordElevateFailure("session:fills-the-store")
	a.recordElevateFailure("session:denied") // declined at the capacity backstop
	blocked, _ := a.checkElevateThrottle("session:denied")
	assert.True(t, blocked, "a key the store declines must be denied, not left unthrottled")
}

func TestWebAuthnCluster_PerClientBeginCapAcrossNodes(t *testing.T) {
	f := newClusterFixture(t)
	a := f.join(setupTestServer(t))
	b := f.join(setupTestServer(t))
	a.passkeyLoginSessionClientCap = 4
	b.passkeyLoginSessionClientCap = 4
	ctx := context.Background()
	store := func(s *Server, id, client string) passkeyLoginStoreResult {
		return s.storePasskeyLoginSession(ctx, id, &passkeyLoginSession{
			data: specLoginSession(t), expires: time.Now().Add(time.Minute), clientKey: client})
	}

	assert.Equal(t, passkeyLoginStored, store(a, "c1", "client-1"))
	assert.Equal(t, passkeyLoginStored, store(b, "c2", "client-1"))
	assert.Equal(t, passkeyLoginStored, store(a, "c3", "client-1"))
	assert.Equal(t, passkeyLoginStored, store(b, "c4", "client-1"))
	assert.Equal(t, passkeyLoginStoreClientCapped, store(a, "c5", "client-1"), "cap is shared across nodes")
	assert.Equal(t, passkeyLoginStoreClientCapped, store(b, "c6", "client-1"), "cap is shared across nodes")
	assert.Equal(t, passkeyLoginStored, store(b, "d1", "client-2"), "another client is unaffected")

	// A finish does not give a slot back: the cap counts begins in the window.
	_, out := a.takePasskeyLoginSession(ctx, "c1")
	require.Equal(t, ceremonyOK, out)
	assert.Equal(t, passkeyLoginStoreClientCapped, store(a, "c7", "client-1"))
}

// --- fail closed ---

func TestWebAuthnCluster_UnwiredNonceStoreReturns503ForEveryCeremony(t *testing.T) {
	f := newClusterFixture(t)
	n, username := setupOperatorPayloadSignServer(t)
	injectCredentialWithPublicKey(t, n, username, []byte("cred-503"), []byte("pk"), 0)
	n.haManager = f.manager
	n.SetRateCounterStore(f.counters) // counters wired, NonceStore deliberately not
	e, _, token := setupEnrollServer(t, tvRPID, []string{tvOrigin}, "enroll-503-user")
	e.haManager = f.manager

	p := principalForAccount(t, n, username)
	sp := &Principal{ID: username}
	unavailable := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "body: %s", rec.Body.String())
		assert.Equal(t, "WEBAUTHN_CEREMONY_STORE_UNAVAILABLE", errCode(t, rec.Body.Bytes()))
	}

	t.Run("register", func(t *testing.T) {
		unavailable(t, doBegin(t, n, username))
		unavailable(t, doFinish(t, n, username, junkBody()))
	})
	t.Run("presence", func(t *testing.T) {
		unavailable(t, doPresenceBegin(t, n, p))
		unavailable(t, doPresenceFinish(t, n, p))
	})
	t.Run("presence-token", func(t *testing.T) {
		assert.Equal(t, ceremonyUnavailable, n.putPresenceToken(context.Background(), "h",
			&presenceTokenRecord{principalID: "p", expires: time.Now().Add(time.Minute)}))
		_, out := n.takePresenceToken(context.Background(), "h")
		assert.Equal(t, ceremonyUnavailable, out)

		withPresencePermission(t)
		handler := wrapWithAuth(n, "test", "presence-required",
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		req := requestWithTLSCert(http.MethodPost, "/api/v1/test/presence-action", makeSelfSignedAdminCert(t))
		req.Header.Set(presenceTokenHeader, "any-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		unavailable(t, rec)
	})
	t.Run("elevate", func(t *testing.T) {
		unavailable(t, doStepUpBegin(t, n, sp, "s503"))
		unavailable(t, doStepUpFinish(t, n, sp, "s503", junkBody()))
	})
	t.Run("payload-sign", func(t *testing.T) {
		unavailable(t, doSignBegin(t, n, sp, "s503", validBeginBody()))
		unavailable(t, doSignFinish(t, n, sp, "s503", junkBody()))
	})
	t.Run("login", func(t *testing.T) {
		l, _ := setupPasskeySessionServer(t)
		l.haManager = f.manager
		l.SetRateCounterStore(f.counters)
		unavailable(t, passkeyBegin(l))
		unavailable(t, passkeyFinish(l, "any-ceremony", junkBody()))
		requireNoLocalCeremonyState(t, l)
	})
	t.Run("enroll", func(t *testing.T) {
		unavailable(t, doEnrollBegin(t, e, token))
		unavailable(t, doEnrollFinish(t, e, token, junkBody()))
	})

	requireNoLocalCeremonyState(t, n)
	requireNoLocalCeremonyState(t, e)
}

func TestWebAuthnCluster_NonceStoreErrorRefusesRequest(t *testing.T) {
	f := newClusterFixture(t)
	n, username := setupOperatorPayloadSignServer(t)
	injectCredentialWithPublicKey(t, n, username, []byte("cred-err"), []byte("pk"), 0)
	f.join(n)
	fs := &failingNonceStore{NonceStore: f.nonces}
	n.SetNonceStore(fs)
	sp := &Principal{ID: username}

	fs.failPut = true
	assert.Equal(t, http.StatusServiceUnavailable, doBegin(t, n, username).Code, "PutNonce error refuses begin")
	assert.Equal(t, http.StatusServiceUnavailable, doStepUpBegin(t, n, sp, "e1").Code)
	assert.Equal(t, http.StatusServiceUnavailable, doSignBegin(t, n, sp, "e1", validBeginBody()).Code)
	l, _ := setupPasskeySessionServer(t)
	f.join(l)
	ls := &failingNonceStore{NonceStore: f.nonces, failPut: true}
	l.SetNonceStore(ls)
	rec := passkeyBegin(l)
	assert.Equal(t, "WEBAUTHN_CEREMONY_STORE_UNAVAILABLE", errCode(t, rec.Body.Bytes()))

	fs.failPut = false
	require.Equal(t, http.StatusOK, doStepUpBegin(t, n, sp, "e2").Code)
	fs.failGet = true
	rec = doStepUpFinish(t, n, sp, "e2", junkBody())
	assert.Equal(t, "WEBAUTHN_CEREMONY_STORE_UNAVAILABLE", errCode(t, rec.Body.Bytes()), "GetAndConsumeNonce error refuses finish")
	ls.failPut, ls.failGet = false, true
	rec = passkeyFinish(l, "x", junkBody())
	assert.Equal(t, "WEBAUTHN_CEREMONY_STORE_UNAVAILABLE", errCode(t, rec.Body.Bytes()))

	// A corrupt stored entry is consumed and refused, never half-used.
	fs.failGet = false
	require.NoError(t, f.nonces.PutNonce(context.Background(), ceremonyPrefixElevate+"corrupt", []byte("not json"), time.Minute))
	rec = doStepUpFinish(t, n, sp, "corrupt", junkBody())
	assert.Equal(t, "NO_ACTIVE_ELEVATION_SESSION", errCode(t, rec.Body.Bytes()))
}

// --- outside ClusterMode nothing changes ---

func TestWebAuthnCluster_NonClusterKeepsNodeLocalState(t *testing.T) {
	server, username := setupPasskeySessionServer(t)
	assert.False(t, server.webAuthnClusterMode())
	principal := &Principal{ID: username}
	require.Equal(t, http.StatusOK, doStepUpBegin(t, server, principal, "local-sess").Code)
	assert.Equal(t, 1, syncMapLen(&server.webAuthnElevateSessions), "non-cluster path stays in memory")

	raw, ok := server.webAuthnElevateSessions.Load("local-sess")
	require.True(t, ok)
	wire := webAuthnElevateWire{Data: raw.(*webAuthnElevateSession).data, AccountID: username}
	b, err := json.Marshal(wire)
	require.NoError(t, err)
	var back webAuthnElevateWire
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, wire.Data.Challenge, back.Data.Challenge, "SessionData survives the JSON wire round trip")
}
