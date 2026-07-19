// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2782: tests for WebAuthn passkey / FIDO2 registration.
//
// Coverage:
//   - begin: account-not-found, happy-path (session stored server-side)
//   - finish: stale challenge (SESSION_EXPIRED), reused challenge (single-use via
//     LoadAndDelete), origin mismatch, RP-ID mismatch, client-supplied assurance
//     field ignored
//   - TOTP / AssuranceStrong separation (source-level grep — ADR-021 Decision 2)
//
// All tests use real CFGMS components; no mocks.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test vectors from github.com/go-webauthn/webauthn@v0.17.0/protocol/credential_test.go.
// Real device attestations for the webauthn.io Relying Party (none-format, ES256).
const (
	tvChallenge         = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE"
	tvCredentialID      = "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g"
	tvClientDataJSON    = "eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
	tvAttestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw"
	tvRPID              = "webauthn.io"
	tvOrigin            = "https://webauthn.io"
)

// setupWebAuthnServer returns a test Server with the WebAuthn RP configured using the
// supplied rpID/rpOrigins, and a pre-created web account for webauthnTestUsername.
func setupWebAuthnServer(t *testing.T, rpID string, rpOrigins []string) (*Server, string) {
	t.Helper()
	const username = "webauthn-test-user"

	server := setupTestServer(t)

	wa, err := NewWebAuthnFromConfig(rpID, rpID, rpOrigins)
	require.NoError(t, err)
	server.SetWebAuthn(wa)

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username: username,
		Password: "not-used-in-webauthn-registration",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "create account: %s", rec.Body.String())

	return server, username
}

// tvSession builds a minimal webauthn.SessionData keyed to the test-vector challenge.
func tvSession(userID []byte, rpID string) webauthn.SessionData {
	return webauthn.SessionData{
		Challenge:        tvChallenge,
		RelyingPartyID:   rpID,
		UserID:           userID,
		UserVerification: protocol.VerificationRequired,
		Expires:          time.Now().Add(10 * time.Minute),
	}
}

// injectSession stores a webAuthnPendingSession directly, bypassing the begin step.
func injectSession(s *Server, username string, session webauthn.SessionData, ttl time.Duration) {
	s.webAuthnSessions.Store(username, &webAuthnPendingSession{
		data:    session,
		expires: time.Now().Add(ttl),
	})
}

// finishBody builds a JSON PublicKeyCredential registration response body.
// clientDataJSON and attestationObject are base64url-encoded strings.
func finishBody(t *testing.T, credID, clientDataJSON, attObj string) *bytes.Reader {
	t.Helper()
	type inner struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	}
	type outer struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response inner  `json:"response"`
	}
	b, err := json.Marshal(outer{
		ID: credID, RawID: credID, Type: "public-key",
		Response: inner{ClientDataJSON: clientDataJSON, AttestationObject: attObj},
	})
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// doBegin calls handleWebAuthnRegisterBegin directly.
func doBegin(t *testing.T, server *Server, username string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/web/accounts/%s/webauthn/register/begin", username), nil)
	req = withVars(req, map[string]string{"username": username})
	req = withPrincipal(req, testAdminPrincipal())
	rec := httptest.NewRecorder()
	server.handleWebAuthnRegisterBegin(rec, req)
	return rec
}

// doFinish calls handleWebAuthnRegisterFinish directly.
func doFinish(t *testing.T, server *Server, username string, body *bytes.Reader) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/web/accounts/%s/webauthn/register/finish", username), body)
	req = withVars(req, map[string]string{"username": username})
	req = withPrincipal(req, testAdminPrincipal())
	rec := httptest.NewRecorder()
	server.handleWebAuthnRegisterFinish(rec, req)
	return rec
}

// errCode unmarshals the error code from a JSON error-response body.
func errCode(t *testing.T, body []byte) string {
	t.Helper()
	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(body, &resp), "parse error response: %s", string(body))
	require.NotNil(t, resp.Error)
	return resp.Error.Code
}

// --- Begin ---

// TestWebAuthnRegisterBegin_NotConfigured verifies that both begin and finish return
// 503/WEBAUTHN_NOT_CONFIGURED when no WebAuthn instance has been set on the server.
func TestWebAuthnRegisterBegin_NotConfigured(t *testing.T) {
	server := setupTestServer(t) // deliberately no SetWebAuthn call

	rec := doBegin(t, server, "any-user")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))

	rec2 := doFinish(t, server, "any-user", nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec2.Code)
	assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec2.Body.Bytes()))
}

// TestWebAuthnRegisterBegin_AccountNotFound verifies that begin returns 404 when no
// account exists for the requested username.
func TestWebAuthnRegisterBegin_AccountNotFound(t *testing.T) {
	server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	rec := doBegin(t, server, "no-such-user")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "WEB_ACCOUNT_NOT_FOUND", errCode(t, rec.Body.Bytes()))
}

// TestWebAuthnRegisterBegin_Success verifies that begin returns 200 with
// PublicKeyCredentialCreationOptions and stores the pending session server-side.
func TestWebAuthnRegisterBegin_Success(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	rec := doBegin(t, server, username)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	opts, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "response.data must be an object")
	pk, ok := opts["publicKey"].(map[string]interface{})
	require.True(t, ok, "response.data.publicKey must be present")
	assert.NotEmpty(t, pk["challenge"], "server must include a challenge in the creation options")

	// The pending session must be stored server-side (not trusted from the client).
	rawSession, loaded := server.webAuthnSessions.Load(username)
	require.True(t, loaded, "session must be stored after begin")
	pending, ok := rawSession.(*webAuthnPendingSession)
	require.True(t, ok)
	assert.False(t, time.Now().After(pending.expires), "freshly created session must not be expired")
	assert.NotEmpty(t, pending.data.Challenge, "server-side session must carry the challenge")
}

// --- Finish negative tests (three distinct, per issue acceptance criteria) ---

// TestWebAuthnFinish_StaleChallenge verifies that a registration session past its
// server-side TTL is rejected with SESSION_EXPIRED before FinishRegistration runs.
func TestWebAuthnFinish_StaleChallenge(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)

	// Session whose TTL has already elapsed (negative duration → past).
	injectSession(server, username, tvSession([]byte(acct.ID), tvRPID), -1*time.Second)

	rec := doFinish(t, server, username, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "SESSION_EXPIRED", errCode(t, rec.Body.Bytes()))
}

// TestWebAuthnFinish_ReusedChallenge verifies single-use enforcement: the pending
// session is deleted on every finish attempt (LoadAndDelete), so a second call
// returns NO_ACTIVE_REGISTRATION regardless of the first call's outcome.
func TestWebAuthnFinish_ReusedChallenge(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)

	injectSession(server, username, tvSession([]byte(acct.ID), tvRPID), 10*time.Minute)

	// First call: session exists → LoadAndDelete consumes it → FinishRegistration fails
	// on the empty body (WEBAUTHN_VERIFY_ERROR), but the session is gone either way.
	firstRec := doFinish(t, server, username, nil)
	assert.Equal(t, http.StatusBadRequest, firstRec.Code)
	assert.NotEqual(t, "NO_ACTIVE_REGISTRATION", errCode(t, firstRec.Body.Bytes()),
		"first call must find the session (not return NO_ACTIVE_REGISTRATION)")

	// Second call: session was already consumed — must return NO_ACTIVE_REGISTRATION.
	secondRec := doFinish(t, server, username, nil)
	assert.Equal(t, http.StatusBadRequest, secondRec.Code)
	assert.Equal(t, "NO_ACTIVE_REGISTRATION", errCode(t, secondRec.Body.Bytes()),
		"session consumed on first call; second call must fail immediately")
}

// TestWebAuthnFinish_OriginMismatch verifies that a clientDataJSON whose origin field
// does not appear in the server's RPOrigins list is rejected by FinishRegistration.
// Distinct from TestWebAuthnFinish_RPIDMismatch: only origin is wrong here.
func TestWebAuthnFinish_OriginMismatch(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)

	injectSession(server, username, tvSession([]byte(acct.ID), tvRPID), 10*time.Minute)

	// clientDataJSON with correct challenge but wrong origin. The attestationObject
	// carries the webauthn.io RPID hash (correct for this test — only origin is wrong).
	wrongOriginCDJ := base64.RawURLEncoding.EncodeToString([]byte(
		`{"challenge":"` + tvChallenge + `","origin":"https://evil.example.com","type":"webauthn.create"}`,
	))
	rec := doFinish(t, server, username, finishBody(t, tvCredentialID, wrongOriginCDJ, tvAttestationObject))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()),
		"origin mismatch must produce WEBAUTHN_VERIFY_ERROR")
}

// TestWebAuthnFinish_RPIDMismatch verifies that a response whose authData carries an
// RP-ID hash for a different domain is rejected even when the origin is allowed.
// Distinct from TestWebAuthnFinish_OriginMismatch: the server's RPID is wrong here.
func TestWebAuthnFinish_RPIDMismatch(t *testing.T) {
	// Configure the server with a different RPID but add the test-vector origin to
	// RPOrigins so the origin check passes and only the RPID hash check fails.
	const wrongRPID = "wrong.example.com"
	server, username := setupWebAuthnServer(t, wrongRPID, []string{tvOrigin})

	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)

	injectSession(server, username, tvSession([]byte(acct.ID), wrongRPID), 10*time.Minute)

	// tvClientDataJSON has origin=https://webauthn.io (allowed) and challenge=tvChallenge (matching).
	// tvAttestationObject's authData carries sha256("webauthn.io") as rpIdHash.
	// The server expects sha256("wrong.example.com") — mismatch → WEBAUTHN_VERIFY_ERROR.
	rec := doFinish(t, server, username, finishBody(t, tvCredentialID, tvClientDataJSON, tvAttestationObject))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()),
		"RP-ID mismatch must produce WEBAUTHN_VERIFY_ERROR")
}

// TestWebAuthnFinish_ClientAssuranceIgnored verifies that an extra "assurance":"strong"
// field in the request body does not cause a panic, 500, or special assurance-level
// processing. The server must fail for a legitimate WebAuthn reason (origin mismatch
// here), not because it tried to act on the client's assurance claim.
// ADR-021 Decision 1: AssuranceStrong is derived from cryptographic verification only.
func TestWebAuthnFinish_ClientAssuranceIgnored(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)

	injectSession(server, username, tvSession([]byte(acct.ID), tvRPID), 10*time.Minute)

	// Include an extra top-level "assurance":"strong" field that the handler must ignore.
	// Wrong origin ensures FinishRegistration fails for a known WebAuthn reason.
	wrongOriginCDJ := base64.RawURLEncoding.EncodeToString([]byte(
		`{"challenge":"` + tvChallenge + `","origin":"https://evil.example.com","type":"webauthn.create"}`,
	))
	type bodyWithAssurance struct {
		ID        string `json:"id"`
		RawID     string `json:"rawId"`
		Type      string `json:"type"`
		Assurance string `json:"assurance"` // client-supplied; must be silently discarded
		Response  struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		} `json:"response"`
	}
	payload, err := json.Marshal(bodyWithAssurance{
		ID: tvCredentialID, RawID: tvCredentialID, Type: "public-key",
		Assurance: "strong",
		Response: struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		}{ClientDataJSON: wrongOriginCDJ, AttestationObject: tvAttestationObject},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/web/accounts/"+username+"/webauthn/register/finish",
		bytes.NewReader(payload))
	req = withVars(req, map[string]string{"username": username})
	req = withPrincipal(req, testAdminPrincipal())
	rec := httptest.NewRecorder()
	server.handleWebAuthnRegisterFinish(rec, req)

	// Must fail for WebAuthn verification (origin mismatch), NOT for "invalid assurance"
	// or any error stemming from the server trying to interpret the assurance claim.
	assert.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()),
		"only the WebAuthn verification result may drive the error code; assurance field is ignored")
}

// TestWebAuthnTOTPSeparation confirms that the WebAuthn registration code and the
// permission-assurance registry contain no reference to TOTP. ADR-021 Decision 2:
// TOTP must never satisfy AssuranceStrong; these subsystems must remain unconnected.
func TestWebAuthnTOTPSeparation(t *testing.T) {
	files := []struct {
		path string
		desc string
	}{
		{"handlers_webauthn.go", "WebAuthn handlers"},
		{"assurance.go", "permission-assurance registry"},
	}
	for _, f := range files {
		data, err := os.ReadFile(f.path)
		require.NoError(t, err, "read %s", f.path)
		content := string(data)
		assert.NotContains(t, content, "AuthFactorTOTP",
			"%s (%s) must not reference AuthFactorTOTP", f.path, f.desc)
		assert.NotContains(t, content, "TOTP",
			"%s (%s) must not reference TOTP", f.path, f.desc)
		assert.NotContains(t, content, "totp",
			"%s (%s) must not reference totp", f.path, f.desc)
	}
}
