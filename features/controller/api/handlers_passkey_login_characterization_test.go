// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #5822: characterization tests for Server.handlePasskeyLoginFinish. They pin the
// observable behavior (status, error code and body, cookies, audit events, throttle
// state) of every gate and outcome so the handler can be decomposed without a
// behavior change. All components are real; the assertion is the W3C NoneES256 vector.
package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
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

// handlerspasskeyloginCharStoreCeremony stores a discoverable pending login session under
// a fresh ceremony ID and returns the ID.
func handlerspasskeyloginCharStoreCeremony(t *testing.T, srv *Server, accountHint, clientKey string, expires time.Time) string {
	t.Helper()
	challengeBytes, err := hex.DecodeString(svAuthChallengeHex)
	require.NoError(t, err)
	id, err := generateCeremonyID()
	require.NoError(t, err)
	require.Equal(t, passkeyLoginStored, srv.storePasskeyLoginSession(context.Background(), id, &passkeyLoginSession{
		data: webauthn.SessionData{
			Challenge:        base64.RawURLEncoding.EncodeToString(challengeBytes),
			RelyingPartyID:   svAuthRPID,
			UserVerification: protocol.VerificationPreferred,
			Expires:          time.Now().Add(10 * time.Minute),
		},
		expires:      expires,
		accountID:    accountHint,
		discoverable: true,
		clientKey:    clientKey,
	}))
	return id
}

// handlerspasskeyloginCharFinish posts the spec-vector assertion for username to the finish
// handler with the given cookies.
func handlerspasskeyloginCharFinish(t *testing.T, srv *Server, username string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", specLoginBody(t, srv, username))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)
	return rec
}

func handlerspasskeyloginCharCeremonyCookie(id string) *http.Cookie {
	return &http.Cookie{Name: cookiePasskeyCeremony, Value: id}
}

func handlerspasskeyloginCharAuditCount(t *testing.T, srv *Server, action string) int {
	t.Helper()
	require.NoError(t, srv.auditManager.Flush(context.Background()))
	entries, err := srv.auditManager.QueryEntries(context.Background(), &business.AuditFilter{Actions: []string{action}})
	require.NoError(t, err)
	return len(entries)
}

func handlerspasskeyloginCharThrottle(srv *Server, key string) {
	for i := 0; i < 10; i++ {
		srv.recordPasskeyLoginFailure(key)
	}
}

func TestHandlerspasskeyloginChar_NoCeremonyCookie(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	rec := handlerspasskeyloginCharFinish(t, srv, username)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))

	rec = handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(""))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, rec.Result().Cookies())
}

func TestHandlerspasskeyloginChar_UnknownAndReusedCeremony(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie("never-issued"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))

	id := handlerspasskeyloginCharStoreCeremony(t, srv, username, "", time.Now().Add(time.Minute))
	first := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
	require.Equal(t, http.StatusOK, first.Code, "body: %s", first.Body.String())

	reuse := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
	assert.Equal(t, http.StatusBadRequest, reuse.Code)
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, reuse.Body.Bytes()))
	assert.Empty(t, reuse.Result().Cookies())
}

func TestHandlerspasskeyloginChar_ExpiredCeremony(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	id := handlerspasskeyloginCharStoreCeremony(t, srv, username, "", time.Now().Add(-time.Second))

	rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "SESSION_EXPIRED", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, rec.Result().Cookies())
}

func TestHandlerspasskeyloginChar_ClusterClientMismatch(t *testing.T) {
	f := newClusterFixture(t)
	srv, username := setupPasskeySessionServer(t)
	f.join(srv)
	// A ceremony begun by a different client.
	other := handlerspasskeyloginCharStoreCeremony(t, srv, username, "203.0.113.9", time.Now().Add(time.Minute))

	rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(other))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, rec.Result().Cookies())

	// The entry was consumed even though the bind failed.
	again := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(other))
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, again.Body.Bytes()))
}

func TestHandlerspasskeyloginChar_NonClusterIgnoresClientKey(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	id := handlerspasskeyloginCharStoreCeremony(t, srv, username, "203.0.113.9", time.Now().Add(time.Minute))

	rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
	assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
}

func TestHandlerspasskeyloginChar_ThrottleRejections(t *testing.T) {
	t.Run("per-ip", func(t *testing.T) {
		srv, username := setupPasskeySessionServer(t)
		ipKey := srv.clientIPKey(httptest.NewRequest(http.MethodPost, "/", nil))
		require.NotEmpty(t, ipKey)
		handlerspasskeyloginCharThrottle(srv, "ip:"+ipKey)
		id := handlerspasskeyloginCharStoreCeremony(t, srv, "", "", time.Now().Add(time.Minute))

		rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Equal(t, "THROTTLED", errCode(t, rec.Body.Bytes()))
		assert.Empty(t, rec.Result().Cookies())
		assert.Zero(t, handlerspasskeyloginCharAuditCount(t, srv, "web.passkey.login.success"))
	})
	t.Run("per-account", func(t *testing.T) {
		srv, username := setupPasskeySessionServer(t)
		handlerspasskeyloginCharThrottle(srv, "account:"+username)
		id := handlerspasskeyloginCharStoreCeremony(t, srv, username, "", time.Now().Add(time.Minute))

		rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Equal(t, "THROTTLED", errCode(t, rec.Body.Bytes()))
		assert.Empty(t, rec.Result().Cookies())
		assert.Equal(t, 1, handlerspasskeyloginCharAuditCount(t, srv, "web.passkey.login.failure"))
	})
	t.Run("account hint absent is not throttled by account key", func(t *testing.T) {
		srv, username := setupPasskeySessionServer(t)
		handlerspasskeyloginCharThrottle(srv, "account:"+username)
		id := handlerspasskeyloginCharStoreCeremony(t, srv, "", "", time.Now().Add(time.Minute))

		rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
		assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	})
}

func TestHandlerspasskeyloginChar_VerificationFailureRecordsThrottleAndAudit(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	id := handlerspasskeyloginCharStoreCeremony(t, srv, username, "", time.Now().Add(time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", junkBody())
	req.AddCookie(handlerspasskeyloginCharCeremonyCookie(id))
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, rec.Result().Cookies())
	_, present := srv.passkeyLoginThrottle.Load("account:" + username)
	assert.True(t, present, "account throttle must record the failure")
	ipKey := srv.clientIPKey(req)
	_, present = srv.passkeyLoginThrottle.Load("ip:" + ipKey)
	assert.True(t, present, "ip throttle must record the failure")
	assert.Equal(t, 1, handlerspasskeyloginCharAuditCount(t, srv, "web.passkey.login.failure"))
}

func TestHandlerspasskeyloginChar_NonAdvancingSignCountRejected(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	// The vector's signature counter is 0; a stored count of 5 means it does not advance.
	mutateStoredAccount(t, srv, username, func(a *account) {
		require.NotEmpty(t, a.Credentials)
		a.Credentials[0].SignCount = 5
	})
	srv.mu.Lock()
	delete(srv.accounts, username)
	srv.mu.Unlock()
	id := handlerspasskeyloginCharStoreCeremony(t, srv, "", "", time.Now().Add(time.Minute))

	rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
	assert.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, rec.Result().Cookies())
	_, present := srv.passkeyLoginThrottle.Load("account:" + username)
	assert.True(t, present, "failure must be recorded against the account")
	assert.Equal(t, 1, handlerspasskeyloginCharAuditCount(t, srv, "web.passkey.login.failure"))
	assert.Equal(t, uint32(5), storedAccount(t, srv, username).Credentials[0].SignCount, "stored count must not change")
}

func TestHandlerspasskeyloginChar_DisabledAccountIndistinguishableFromBadAssertion(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	// Reference response: a failed verification.
	badID := handlerspasskeyloginCharStoreCeremony(t, srv, "", "", time.Now().Add(time.Minute))
	badReq := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", junkBody())
	badReq.AddCookie(handlerspasskeyloginCharCeremonyCookie(badID))
	badRec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(badRec, badReq)
	require.Equal(t, http.StatusBadRequest, badRec.Code)

	acct, err := srv.getAccount(context.Background(), username)
	require.NoError(t, err)
	acct.Disabled = true
	require.NoError(t, srv.persistAccount(context.Background(), acct, "test-admin"))

	id := handlerspasskeyloginCharStoreCeremony(t, srv, username, "", time.Now().Add(time.Minute))
	rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))

	assert.Equal(t, badRec.Code, rec.Code)
	assert.Equal(t, errCode(t, badRec.Body.Bytes()), errCode(t, rec.Body.Bytes()))
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
	assert.Equal(t, errMessage(t, badRec.Body.Bytes()), errMessage(t, rec.Body.Bytes()))
	assert.Empty(t, rec.Result().Cookies())
	// The reference failure has no resolved identity, so only the disabled attempt is
	// attributed to the account.
	assert.Equal(t, 1, handlerspasskeyloginCharAuditCount(t, srv, "web.passkey.login.failure"))
	assert.Zero(t, handlerspasskeyloginCharAuditCount(t, srv, "web.passkey.login.success"))
}

func TestHandlerspasskeyloginChar_SuccessRevokesPriorSessionAndSetsCookies(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	first := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, first.Code, "body: %s", first.Body.String())
	oldTok := extractCookie(first, cookieWebSession)
	require.NotEmpty(t, oldTok)

	id := handlerspasskeyloginCharStoreCeremony(t, srv, username, "", time.Now().Add(time.Minute))
	rec := handlerspasskeyloginCharFinish(t, srv, username,
		handlerspasskeyloginCharCeremonyCookie(id),
		&http.Cookie{Name: cookieWebSession, Value: oldTok})
	// The vector's counter is 0 and the stored counter is still 0, so it passes again.
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	srv.mu.RLock()
	mgr := srv.webSessionManager
	srv.mu.RUnlock()
	_, err := mgr.Validate(context.Background(), oldTok)
	assert.Error(t, err, "pre-existing session must be revoked")

	cookies := map[string]*http.Cookie{}
	for _, c := range rec.Result().Cookies() {
		cookies[c.Name] = c
	}
	sess := cookies[cookieWebSession]
	require.NotNil(t, sess)
	assert.NotEmpty(t, sess.Value)
	assert.NotEqual(t, oldTok, sess.Value)
	assert.True(t, sess.HttpOnly)
	assert.True(t, sess.Secure)
	assert.Equal(t, http.SameSiteStrictMode, sess.SameSite)
	assert.Equal(t, "/", sess.Path)

	csrf := cookies[cookieCSRFSession]
	require.NotNil(t, csrf)
	assert.NotEmpty(t, csrf.Value)
	assert.False(t, csrf.HttpOnly)
	assert.True(t, csrf.Secure)
	assert.Equal(t, http.SameSiteStrictMode, csrf.SameSite)
	assert.Equal(t, "/", csrf.Path)

	cer := cookies[cookiePasskeyCeremony]
	require.NotNil(t, cer)
	assert.Empty(t, cer.Value)
	assert.Equal(t, -1, cer.MaxAge)
	assert.True(t, cer.HttpOnly)
	assert.True(t, cer.Secure)

	pre := cookies[cookieCSRFPre]
	require.NotNil(t, pre)
	assert.Empty(t, pre.Value)
	assert.Equal(t, -1, pre.MaxAge)
	assert.True(t, pre.Secure)
	assert.Equal(t, http.SameSiteStrictMode, pre.SameSite)

	// Session is Strong and bound to the CSRF token.
	valid, err := mgr.Validate(context.Background(), sess.Value)
	require.NoError(t, err)
	assert.Equal(t, "web", valid.ConnectionName)
	assert.Equal(t, session.AssuranceStrong, valid.Assurance)
	stored, ok := srv.csrfTokens.Load(valid.ID)
	require.True(t, ok)
	assert.Equal(t, csrf.Value, stored)
	assert.Equal(t, 2, handlerspasskeyloginCharAuditCount(t, srv, "web.passkey.login.success"))
}

func TestHandlerspasskeyloginChar_WebAuthnAndSessionManagerUnavailable(t *testing.T) {
	srv := setupTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", nil)
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
}

func TestHandlerspasskeyloginChar_UnresolvableUserHandleFailsVerification(t *testing.T) {
	for name, handle := range map[string][]byte{"blank": nil, "unknown": []byte("no-such-account-id")} {
		t.Run(name, func(t *testing.T) {
			srv, username := setupPasskeySessionServer(t)
			credID, err := hex.DecodeString(svAuthCredentialIDHex)
			require.NoError(t, err)
			authData, err := hex.DecodeString(svAuthAuthDataHex)
			require.NoError(t, err)
			cdj, err := hex.DecodeString(svAuthClientDataJSONHex)
			require.NoError(t, err)
			sig, err := hex.DecodeString(svAuthSignatureHex)
			require.NoError(t, err)
			id := handlerspasskeyloginCharStoreCeremony(t, srv, username, "", time.Now().Add(time.Minute))

			req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish",
				buildAssertionBodyWithUserHandle(t, credID, authData, cdj, sig, handle))
			req.AddCookie(handlerspasskeyloginCharCeremonyCookie(id))
			rec := httptest.NewRecorder()
			srv.handlePasskeyLoginFinish(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
			assert.Empty(t, rec.Result().Cookies())
			_, present := srv.passkeyLoginThrottle.Load("account:" + username)
			assert.True(t, present)
			assert.Equal(t, 1, handlerspasskeyloginCharAuditCount(t, srv, "web.passkey.login.failure"))
		})
	}
}
