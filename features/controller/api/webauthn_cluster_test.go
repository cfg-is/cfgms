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
	"strconv"
	"strings"
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
	"github.com/cfgis/cfgms/pkg/testutil/webauthntest"
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
	return bytes.NewReader(webauthntest.RawAssertionBody(credID, authData, cdj, sig, []byte(acct.ID)))
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
	shareAccount(t, a, b, username)
	principal := &Principal{ID: testAccountID(t, a, username)}
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
	sp := &Principal{ID: testAccountID(t, a, username)}
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
	shareAccount(t, a, b, username)
	principal := &Principal{ID: testAccountID(t, a, username)}

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
		rec := doStepUpFinish(t, n, &Principal{ID: testAccountID(t, n, username)}, "bind-sess", junkBody())
		assert.Equal(t, "NO_ACTIVE_ELEVATION_SESSION", errCode(t, rec.Body.Bytes()))
	})
	t.Run("payload-sign", func(t *testing.T) {
		require.Equal(t, ceremonyOK, n.putPayloadSignSession(ctx, "bind-sess", &operatorPayloadSignSession{
			data: specLoginSession(t), expires: exp, accountID: "someone-else"}))
		rec := doSignFinish(t, n, &Principal{ID: testAccountID(t, n, username)}, "bind-sess", junkBody())
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
		data: specLoginSession(t), expires: time.Now().Add(-time.Second), accountID: testAccountID(t, n, username)}))
	rec := doStepUpFinish(t, n, &Principal{ID: testAccountID(t, n, username)}, "exp-sess", junkBody())
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
	bindTestAdminCertOn(t, b, adminCert)

	token := "cluster-presence-token"
	require.Equal(t, ceremonyOK, a.putPresenceToken(context.Background(), hashPresenceToken(token), &presenceTokenRecord{
		principalID: "test-admin", expires: time.Now().Add(presenceTokenTTL),
		boundMethod: http.MethodPost, boundPath: "/api/v1/test/presence-action",
		boundBodyHash: emptyBodyHashHex, boundPermissionID: "test:presence-required",
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

// Issue #5142: the action named at presence/begin on node A survives the shared
// pending-session store and reaches finish on node B.
func TestWebAuthnCluster_PresenceSessionKeepsActionBinding(t *testing.T) {
	f := newClusterFixture(t)
	a := f.join(setupTestServer(t))
	b := f.join(setupTestServer(t))
	action := &presenceActionBinding{Method: "POST", Path: "/x", BodyHash: "bh", PermissionID: "perm:1"}
	require.Equal(t, ceremonyOK, a.putPendingSession(context.Background(), &a.webAuthnPresenceSessions,
		ceremonyPrefixPresence, "p", &webAuthnPendingSession{expires: time.Now().Add(time.Minute), binding: "p", action: action},
		time.Minute))
	got, out := b.takePendingSession(context.Background(), &b.webAuthnPresenceSessions, ceremonyPrefixPresence, "p")
	require.Equal(t, ceremonyOK, out)
	assert.Equal(t, action, got.action)
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
	a, userA := setupPasskeySessionServer(t)
	b, userB := setupPasskeySessionServer(t)
	f.join(a)
	f.join(b)
	a.passkeyLoginSessionClientCap = 4
	b.passkeyLoginSessionClientCap = 4
	ctx := context.Background()
	client := loginTestClientKey(a)
	store := func(s *Server, id, client string) passkeyLoginStoreResult {
		return s.storePasskeyLoginSession(ctx, id, &passkeyLoginSession{
			data: specLoginSession(t), expires: time.Now().Add(time.Minute), clientKey: client,
			discoverable: true})
	}

	assert.Equal(t, passkeyLoginStored, store(a, "c1", client))
	assert.Equal(t, passkeyLoginStored, store(b, "c2", client))
	assert.Equal(t, passkeyLoginStored, store(a, "c3", client))
	assert.Equal(t, passkeyLoginStored, store(b, "c4", client))
	assert.Equal(t, passkeyLoginStoreClientCapped, store(a, "c5", client), "cap is shared across nodes")
	assert.Equal(t, passkeyLoginStoreClientCapped, store(b, "c6", client), "cap is shared across nodes")
	assert.Equal(t, passkeyLoginStored, store(b, "d1", "client-2"), "another client is unaffected")

	// A finish that fails does not give a slot back: the cap counts begins in the window
	// that did not end in a successful login.
	rec := passkeyFinish(a, "c1", junkBody())
	require.NotEqual(t, http.StatusOK, rec.Code)
	assert.Equal(t, passkeyLoginStoreClientCapped, store(a, "c7", client), "a failed finish refunds nothing")

	// A successful finish, on the other node from the begin, does.
	rec = passkeyFinish(b, "c3", specLoginBody(t, b, userB))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, passkeyLoginStored, store(a, "c8", client), "a successful login gives its slot back")
	assert.Equal(t, passkeyLoginStoreClientCapped, store(b, "c9", client), "only one slot was given back")

	// Replaying the finished ceremony refunds nothing more.
	rec = passkeyFinish(a, "c3", specLoginBody(t, a, userA))
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))
	assert.Equal(t, passkeyLoginStoreClientCapped, store(a, "c10", client), "a replayed finish refunds nothing")
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
	sp := &Principal{ID: testAccountID(t, n, username)}
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
		adminCert := makeSelfSignedAdminCert(t)
		bindTestAdminCertOn(t, n, adminCert)
		req := requestWithTLSCert(http.MethodPost, "/api/v1/test/presence-action", adminCert)
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
	sp := &Principal{ID: testAccountID(t, n, username)}

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
	principal := &Principal{ID: testAccountID(t, server, username)}
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

// shareAccount makes node b hold the same account record (and so the same account
// ID) as node a, as nodes of one cluster do via the shared store.
func shareAccount(t *testing.T, a, b *Server, username string) {
	t.Helper()
	acct, err := a.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NoError(t, b.persistAccount(context.Background(), acct, "test"))
	b.cacheAccount(acct)
}

// [REQUIRED TEST] Issue #5272: the relay request ID survives the
// cluster wire round trip, so a different node enforces the same rule.
func TestWebAuthnCluster_RelayFieldsRoundTrip(t *testing.T) {
	sess := &webAuthnPendingSession{expires: time.Now().Add(time.Minute), binding: "p", relayRequestID: "cli-presence-123"}
	assert.Equal(t, "cli-presence-123", sess.toWire().toSession().relayRequestID)
	assert.Empty(t, (&webAuthnPendingSession{}).toWire().toSession().relayRequestID)
}

// --- Issue #6519: a login that succeeds does not count against the per-client begin cap ---

// loginTestClientKey is the client key the begin recorded for requests that httptest
// builds with its default remote address, which is also the key the finish computes.
func loginTestClientKey(s *Server) string {
	return s.clientIPKey(httptest.NewRequest(http.MethodPost, "/", nil))
}

// beginLoginCeremony stores a discoverable spec-vector ceremony for client on s and
// returns the store result and the stored session.
func beginLoginCeremony(t *testing.T, s *Server, id, client string) (passkeyLoginStoreResult, *passkeyLoginSession) {
	t.Helper()
	sess := &passkeyLoginSession{data: specLoginSession(t), expires: time.Now().Add(time.Minute),
		discoverable: true, clientKey: client}
	return s.storePasskeyLoginSession(context.Background(), id, sess), sess
}

// loginCreditCount reads the success count recorded for the ceremony's begin window.
func loginCreditCount(t *testing.T, f *clusterFixture, s *Server, sess *passkeyLoginSession) int {
	t.Helper()
	n, _, _, err := f.counters.Peek(context.Background(),
		passkeyLoginCreditKey(sess.clientKey, sess.beginWindowID), s.passkeyLoginBeginWindowDuration())
	require.NoError(t, err)
	return n
}

func TestWebAuthnCluster_SuccessfulLoginsDoNotCountAgainstClientCap(t *testing.T) {
	f := newClusterFixture(t)
	a, userA := setupPasskeySessionServer(t)
	b, userB := setupPasskeySessionServer(t)
	f.join(a)
	f.join(b)
	client := loginTestClientKey(a)
	nodes := []struct {
		srv  *Server
		user string
	}{{a, userA}, {b, userB}}

	for i := 0; i < 100; i++ {
		begin, finish := nodes[i%2], nodes[(i+1)%2]
		id := "ok-" + strconv.Itoa(i)
		res, _ := beginLoginCeremony(t, begin.srv, id, client)
		require.Equal(t, passkeyLoginStored, res, "begin %d", i)
		rec := passkeyFinish(finish.srv, id, specLoginBody(t, finish.srv, finish.user))
		require.Equal(t, http.StatusOK, rec.Code, "finish %d body: %s", i, rec.Body.String())
	}
}

func TestWebAuthnCluster_AbandonedBeginsReachTheClientCap(t *testing.T) {
	f := newClusterFixture(t)
	a := f.join(setupTestServer(t))
	b := f.join(setupTestServer(t))
	const limit = 3
	a.passkeyLoginSessionClientCap = limit
	b.passkeyLoginSessionClientCap = limit

	for i := 0; i < limit; i++ {
		res, _ := beginLoginCeremony(t, []*Server{a, b}[i%2], "ab-"+strconv.Itoa(i), "client-1")
		require.Equal(t, passkeyLoginStored, res, "abandoned begin %d", i)
	}
	res, _ := beginLoginCeremony(t, a, "ab-over", "client-1")
	assert.Equal(t, passkeyLoginStoreClientCapped, res, "the cap+1th abandoned begin is refused")
	res, _ = beginLoginCeremony(t, b, "other", "client-2")
	assert.Equal(t, passkeyLoginStored, res, "a second client key is unaffected")
}

func TestWebAuthnCluster_OnlyAbandonedBeginsCountWhenInterleavedWithSuccesses(t *testing.T) {
	f := newClusterFixture(t)
	a, _ := setupPasskeySessionServer(t)
	b, userB := setupPasskeySessionServer(t)
	f.join(a)
	f.join(b)
	const limit = 3
	a.passkeyLoginSessionClientCap = limit
	b.passkeyLoginSessionClientCap = limit
	client := loginTestClientKey(a)

	// Three successes interleaved with three abandoned begins: the abandoned ones alone
	// fill the cap, so nothing is refused up to here although there are 6 begins.
	for i, op := range "SASASA" {
		id := "mix-" + strconv.Itoa(i)
		res, _ := beginLoginCeremony(t, a, id, client)
		require.Equal(t, passkeyLoginStored, res, "begin %d (%c)", i, op)
		if op == 'S' {
			rec := passkeyFinish(b, id, specLoginBody(t, b, userB))
			require.Equal(t, http.StatusOK, rec.Code, "finish %d body: %s", i, rec.Body.String())
		}
	}
	res, _ := beginLoginCeremony(t, b, "mix-over", client)
	assert.Equal(t, passkeyLoginStoreClientCapped, res, "three abandoned begins are at the cap")
}

func TestWebAuthnCluster_FailedAndReplayedFinishRefundNothing(t *testing.T) {
	f := newClusterFixture(t)
	a, userA := setupPasskeySessionServer(t)
	b, userB := setupPasskeySessionServer(t)
	f.join(a)
	f.join(b)
	const limit = 3
	a.passkeyLoginSessionClientCap = limit
	b.passkeyLoginSessionClientCap = limit
	client := loginTestClientKey(a)

	// begin 1: failed finish. begin 2: success, then a replay of it. begins 3 and 4:
	// abandoned. One failed plus two abandoned fill the cap of 3; the 5th begin is refused.
	res, failed := beginLoginCeremony(t, a, "f-1", client)
	require.Equal(t, passkeyLoginStored, res)
	require.NotEqual(t, http.StatusOK, passkeyFinish(b, "f-1", junkBody()).Code)
	assert.Zero(t, loginCreditCount(t, f, a, failed), "a failed finish credits nothing")

	res, ok := beginLoginCeremony(t, a, "f-2", client)
	require.Equal(t, passkeyLoginStored, res)
	rec := passkeyFinish(b, "f-2", specLoginBody(t, b, userB))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, 1, loginCreditCount(t, f, a, ok))
	rec = passkeyFinish(a, "f-2", specLoginBody(t, a, userA))
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))
	assert.Equal(t, 1, loginCreditCount(t, f, a, ok), "a replayed finish credits nothing more")

	for _, id := range []string{"f-3", "f-4"} {
		res, _ = beginLoginCeremony(t, b, id, client)
		require.Equal(t, passkeyLoginStored, res, id)
	}
	res, _ = beginLoginCeremony(t, a, "f-5", client)
	assert.Equal(t, passkeyLoginStoreClientCapped, res, "failed + abandoned begins reach the cap")
}

func TestWebAuthnCluster_MismatchedClientFinishRefundsNothing(t *testing.T) {
	f := newClusterFixture(t)
	a, _ := setupPasskeySessionServer(t)
	b, userB := setupPasskeySessionServer(t)
	f.join(a)
	f.join(b)
	a.passkeyLoginSessionClientCap = 1
	b.passkeyLoginSessionClientCap = 1

	// A ceremony begun for another client cannot be finished (and so credited) from here.
	res, sess := beginLoginCeremony(t, a, "mm-1", "client-elsewhere")
	require.Equal(t, passkeyLoginStored, res)
	rec := passkeyFinish(b, "mm-1", specLoginBody(t, b, userB))
	require.NotEqual(t, http.StatusOK, rec.Code)
	assert.Zero(t, loginCreditCount(t, f, a, sess))
	res, _ = beginLoginCeremony(t, a, "mm-2", "client-elsewhere")
	assert.Equal(t, passkeyLoginStoreClientCapped, res)
}

func TestWebAuthnCluster_SuccessInEarlierWindowDoesNotOffsetLaterWindow(t *testing.T) {
	f := newClusterFixture(t)
	a, _ := setupPasskeySessionServer(t)
	b, userB := setupPasskeySessionServer(t)
	f.join(a)
	f.join(b)
	const limit = 3
	for _, s := range []*Server{a, b} {
		s.passkeyLoginSessionClientCap = limit
		s.passkeyLoginBeginWindowOverride = time.Second
	}
	client := loginTestClientKey(a)

	// Window 1: begin a ceremony that will only finish after the window has elapsed.
	res, late := beginLoginCeremony(t, a, "w-late", client)
	require.Equal(t, passkeyLoginStored, res)
	require.NotZero(t, late.beginWindowID)
	// Two begins in the same window share its identity.
	res, same := beginLoginCeremony(t, b, "w-same", client)
	require.Equal(t, passkeyLoginStored, res)
	require.Equal(t, late.beginWindowID, same.beginWindowID, "one window, one identity")

	time.Sleep(a.passkeyLoginBeginWindowDuration() + 200*time.Millisecond)

	// Window 2: three abandoned begins fill the cap.
	var windowTwo *passkeyLoginSession
	for i := 0; i < limit; i++ {
		res, windowTwo = beginLoginCeremony(t, a, "w2-"+strconv.Itoa(i), client)
		require.Equal(t, passkeyLoginStored, res, "window 2 begin %d", i)
	}
	require.NotEqual(t, late.beginWindowID, windowTwo.beginWindowID, "a new window has a new identity")

	// The window-1 ceremony now finishes successfully. Its credit must not offset window 2.
	rec := passkeyFinish(b, "w-late", specLoginBody(t, b, userB))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, 1, loginCreditCount(t, f, a, late), "the credit lands on the window the ceremony began in")
	assert.Zero(t, loginCreditCount(t, f, a, windowTwo), "and not on the current window")

	res, _ = beginLoginCeremony(t, b, "w2-over", client)
	assert.Equal(t, passkeyLoginStoreClientCapped, res, "a late success must not offset the current window")
}

// failingCreditCounters fails every write to a success-credit key, like a shared store
// that errors only for that key.
type failingCreditCounters struct{ business.RateCounterStore }

func (f failingCreditCounters) Increment(ctx context.Context, key string, window time.Duration) (int, time.Duration, error) {
	if strings.Contains(key, "client-ok:") {
		return 0, 0, errors.New("credit write failed")
	}
	return f.RateCounterStore.Increment(ctx, key, window)
}

func TestWebAuthnCluster_CreditWriteFailureDoesNotFailLogin(t *testing.T) {
	f := newClusterFixture(t)
	a, userA := setupPasskeySessionServer(t)
	f.join(a)
	a.SetRateCounterStore(failingCreditCounters{f.counters})
	a.passkeyLoginSessionClientCap = 1
	client := loginTestClientKey(a)

	res, _ := beginLoginCeremony(t, a, "cf-1", client)
	require.Equal(t, passkeyLoginStored, res)
	rec := passkeyFinish(a, "cf-1", specLoginBody(t, a, userA))
	assert.Equal(t, http.StatusOK, rec.Code, "the user is signed in even though the credit was not recorded")
	res, _ = beginLoginCeremony(t, a, "cf-2", client)
	assert.Equal(t, passkeyLoginStoreClientCapped, res, "the unrecorded credit leaves the begin counting")
}

func TestWebAuthnCluster_SingleNodeAndClusterAgreeOnBeginsAndSuccesses(t *testing.T) {
	const sequence = "SSAASASAAASSAAS"
	const limit = 3

	single, singleUser := setupPasskeySessionServer(t)
	single.passkeyLoginSessionClientCap = limit
	want := runLoginSequence(t, single, singleUser, sequence)

	f := newClusterFixture(t)
	node, nodeUser := setupPasskeySessionServer(t)
	f.join(node)
	node.passkeyLoginSessionClientCap = limit
	got := runLoginSequence(t, node, nodeUser, sequence)

	assert.Equal(t, want, got)
	assert.Contains(t, got, passkeyLoginStoreClientCapped, "the sequence must reach the cap")
	assert.Contains(t, got, passkeyLoginStored)
}
