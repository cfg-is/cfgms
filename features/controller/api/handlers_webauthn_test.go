// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2782: tests for WebAuthn passkey / FIDO2 registration.
//
// Coverage:
//   - begin: account-not-found, invalid username (INVALID_USERNAME), happy-path (session stored server-side)
//   - finish: invalid username, stale challenge (SESSION_EXPIRED), reused challenge (single-use via
//     LoadAndDelete), origin mismatch, RP-ID mismatch, client-supplied assurance field ignored,
//     happy-path (HTTP 201, credential persisted) using W3C spec vectors
//   - TOTP / AssuranceStrong separation (source-level grep — ADR-021 Decision 2)
//
// Server setups are shared across related subtests to bound total test runtime on
// 2-vCPU CI runners with race instrumentation: 4 setups instead of 9.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
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

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: username,
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
		fmt.Sprintf("/api/v1/accounts/%s/webauthn/register/begin", username), nil)
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
		fmt.Sprintf("/api/v1/accounts/%s/webauthn/register/finish", username), body)
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

// TestWebAuthnNotConfigured verifies that both begin and finish return
// 503/WEBAUTHN_NOT_CONFIGURED when no WebAuthn instance has been set on the server.
// Uses a single plain server (no SetWebAuthn) shared for both assertions.
func TestWebAuthnNotConfigured(t *testing.T) {
	server := setupTestServer(t)

	rec := doBegin(t, server, "any-user")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))

	rec2 := doFinish(t, server, "any-user", nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec2.Code)
	assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec2.Body.Bytes()))
}

// TestWebAuthnRegistration groups begin and finish tests under a single shared server
// (tvRPID + tvOrigin). Subtests run sequentially; each injectSession call overwrites
// any leftover session from a prior subtest, so there is no cross-subtest interference.
// A separate server is created only for the RPID-mismatch case which needs a different
// RPID configuration.
func TestWebAuthnRegistration(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	// Fetch account ID once; all subtests that need it reference this variable.
	// None of the negative finish tests register a credential, so the account is stable.
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	userID := []byte(acct.ID)

	// --- Begin subtests ---

	t.Run("Begin_AccountNotFound", func(t *testing.T) {
		rec := doBegin(t, server, "no-such-user")
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, "WEB_ACCOUNT_NOT_FOUND", errCode(t, rec.Body.Bytes()))
	})

	t.Run("Begin_InvalidUsername", func(t *testing.T) {
		// "xy" is two chars — fails ^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$ (min 3 chars total).
		rec := doBegin(t, server, "xy")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "INVALID_USERNAME", errCode(t, rec.Body.Bytes()))
	})

	t.Run("Finish_InvalidUsername", func(t *testing.T) {
		rec := doFinish(t, server, "xy", nil)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "INVALID_USERNAME", errCode(t, rec.Body.Bytes()))
	})

	t.Run("Begin_Success", func(t *testing.T) {
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
	})

	// --- Finish negative subtests (three distinct per issue AC) ---

	// TestWebAuthnFinish_StaleChallenge: session past its TTL is rejected with SESSION_EXPIRED
	// before FinishRegistration runs.
	t.Run("Finish_StaleChallenge", func(t *testing.T) {
		// Session whose TTL has already elapsed (negative duration → past).
		injectSession(server, username, tvSession(userID, tvRPID), -1*time.Second)

		rec := doFinish(t, server, username, nil)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "SESSION_EXPIRED", errCode(t, rec.Body.Bytes()))
	})

	// TestWebAuthnFinish_ReusedChallenge: single-use enforcement — the pending session is
	// deleted on every finish attempt (LoadAndDelete), so a second call returns
	// NO_ACTIVE_REGISTRATION regardless of the first call's outcome.
	t.Run("Finish_ReusedChallenge", func(t *testing.T) {
		injectSession(server, username, tvSession(userID, tvRPID), 10*time.Minute)

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
	})

	// TestWebAuthnFinish_OriginMismatch: a clientDataJSON whose origin field does not appear
	// in RPOrigins is rejected. Distinct from RPIDMismatch: only origin is wrong here.
	t.Run("Finish_OriginMismatch", func(t *testing.T) {
		injectSession(server, username, tvSession(userID, tvRPID), 10*time.Minute)

		// clientDataJSON with correct challenge but wrong origin. The attestationObject
		// carries the webauthn.io RPID hash (correct for this test — only origin is wrong).
		wrongOriginCDJ := base64.RawURLEncoding.EncodeToString([]byte(
			`{"challenge":"` + tvChallenge + `","origin":"https://evil.example.com","type":"webauthn.create"}`,
		))
		rec := doFinish(t, server, username, finishBody(t, tvCredentialID, wrongOriginCDJ, tvAttestationObject))

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()),
			"origin mismatch must produce WEBAUTHN_VERIFY_ERROR")
	})

	// TestWebAuthnFinish_RPIDMismatch: a response whose authData carries an RP-ID hash for
	// a different domain is rejected even when the origin is allowed. Needs its own server
	// because the RPID is different from the shared server's RPID.
	t.Run("Finish_RPIDMismatch", func(t *testing.T) {
		// Configure the server with a different RPID but add the test-vector origin to
		// RPOrigins so the origin check passes and only the RPID hash check fails.
		const wrongRPID = "wrong.example.com"
		mismatchServer, mismatchUsername := setupWebAuthnServer(t, wrongRPID, []string{tvOrigin})

		mismatchAcct, err := mismatchServer.getAccount(context.Background(), mismatchUsername)
		require.NoError(t, err)
		require.NotNil(t, mismatchAcct)

		injectSession(mismatchServer, mismatchUsername, tvSession([]byte(mismatchAcct.ID), wrongRPID), 10*time.Minute)

		// tvClientDataJSON has origin=https://webauthn.io (allowed) and challenge=tvChallenge (matching).
		// tvAttestationObject's authData carries sha256("webauthn.io") as rpIdHash.
		// The server expects sha256("wrong.example.com") — mismatch → WEBAUTHN_VERIFY_ERROR.
		rec := doFinish(t, mismatchServer, mismatchUsername, finishBody(t, tvCredentialID, tvClientDataJSON, tvAttestationObject))

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()),
			"RP-ID mismatch must produce WEBAUTHN_VERIFY_ERROR")
	})

	// TestWebAuthnFinish_ClientAssuranceIgnored: an extra "assurance":"strong" field in the
	// request body is silently ignored — the server fails for a legitimate WebAuthn reason
	// (origin mismatch here), not because it tried to act on the assurance claim.
	// ADR-021 Decision 1: AssuranceStrong is derived from cryptographic verification only.
	t.Run("Finish_ClientAssuranceIgnored", func(t *testing.T) {
		injectSession(server, username, tvSession(userID, tvRPID), 10*time.Minute)

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
			"/api/v1/accounts/"+username+"/webauthn/register/finish",
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
	})

	// Finish_Success: happy path — valid credential is accepted, persisted, and the handler
	// returns HTTP 201 Created. Uses the W3C Level 3 §16.2 NoneES256 spec test vector
	// (https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256). A fresh server
	// is required because the spec vector's RPID and origin differ from the shared server.
	//
	// The session uses VerificationPreferred (not Required) so that the spec vector
	// credential (UV flag not set by the spec's test authenticator) passes FinishRegistration.
	// UV enforcement in the production flow is ensured by BeginRegistration using
	// UserVerification: VerificationRequired — this test is exercising the credential
	// serialization and persistence path (persistAccount / loadAccountFromStore).
	t.Run("Finish_Success", func(t *testing.T) {
		const (
			svRPID   = "example.org"
			svOrigin = "https://example.org"
			// W3C Level 3 §16.2 NoneES256 spec test vector (hex-encoded).
			svAttObjectHex  = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220" //nolint:gosec // W3C Level 3 §16.2 spec test vector, not a real credential secret
			svClientDataHex = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
			svCredIDHex     = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec // W3C Level 3 §16.2 spec test vector credential ID, not a real credential secret
			svChallengeHex  = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
		)

		svServer, svUsername := setupWebAuthnServer(t, svRPID, []string{svOrigin})
		svAcct, err := svServer.getAccount(context.Background(), svUsername)
		require.NoError(t, err)

		svAttObj, err := hex.DecodeString(svAttObjectHex)
		require.NoError(t, err)
		svCDJ, err := hex.DecodeString(svClientDataHex)
		require.NoError(t, err)
		svCredIDBytes, err := hex.DecodeString(svCredIDHex)
		require.NoError(t, err)
		svChallengeBytes, err := hex.DecodeString(svChallengeHex)
		require.NoError(t, err)

		svCredIDStr := base64.RawURLEncoding.EncodeToString(svCredIDBytes)
		svChallenge := base64.RawURLEncoding.EncodeToString(svChallengeBytes)

		session := webauthn.SessionData{
			Challenge:        svChallenge,
			UserID:           []byte(svAcct.ID),
			UserVerification: protocol.VerificationPreferred,
			RelyingPartyID:   svRPID,
			// CredParams is populated by BeginRegistration in the real flow;
			// injected sessions must include it so FinishRegistration can verify
			// the credential's public key algorithm. ES256 matches the spec vector.
			CredParams: []protocol.CredentialParameter{
				{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			},
		}
		injectSession(svServer, svUsername, session, 10*time.Minute)

		body := finishBody(t, svCredIDStr,
			base64.RawURLEncoding.EncodeToString(svCDJ),
			base64.RawURLEncoding.EncodeToString(svAttObj))
		rec := doFinish(t, svServer, svUsername, body)
		require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

		updated, err := svServer.getAccount(context.Background(), svUsername)
		require.NoError(t, err)
		require.Len(t, updated.Credentials, 1, "credential must be persisted after successful registration")
		assert.Equal(t, svCredIDBytes, updated.Credentials[0].ID,
			"persisted credential ID must match the spec test vector")
	})
}

// --- Issue #2783: list and revoke endpoint tests ---

// doListCredentials calls handleWebAuthnListCredentials directly.
func doListCredentials(t *testing.T, server *Server, username string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/accounts/%s/webauthn/credentials", username), nil)
	req = withVars(req, map[string]string{"username": username})
	req = withPrincipal(req, testAdminPrincipal())
	rec := httptest.NewRecorder()
	server.handleWebAuthnListCredentials(rec, req)
	return rec
}

// doRevokeCredential calls handleWebAuthnRevokeCredential directly.
func doRevokeCredential(t *testing.T, server *Server, username, credIDParam string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/accounts/%s/webauthn/revoke/%s", username, credIDParam), nil)
	req = withVars(req, map[string]string{"username": username, "credential_id": credIDParam})
	req = withPrincipal(req, testAdminPrincipal())
	rec := httptest.NewRecorder()
	server.handleWebAuthnRevokeCredential(rec, req)
	return rec
}

// injectCredential adds a synthetic WebAuthn credential directly to a web account,
// bypassing the full registration ceremony.
func injectCredential(t *testing.T, server *Server, username string, credID []byte) {
	t.Helper()
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct, "account %q must exist before injecting a credential", username)
	acct.Credentials = append(acct.Credentials, WebAuthnCredential{
		ID:           credID,
		Label:        "injected-test-credential",
		RegisteredAt: time.Now(),
	})
	require.NoError(t, server.persistAccount(context.Background(), acct, "test-injector"))
}

// TestWebAuthnListCredentials verifies handleWebAuthnListCredentials (Issue #2783).
func TestWebAuthnListCredentials(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	t.Run("empty list when no credentials registered", func(t *testing.T) {
		rec := doListCredentials(t, server, username)
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		var envelope struct {
			Data WebAuthnListResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
		assert.Equal(t, username, envelope.Data.Username)
		assert.Empty(t, envelope.Data.Credentials, "newly-created account has no credentials")
	})

	credID := []byte("test-credential-id-bytes")
	injectCredential(t, server, username, credID)

	t.Run("lists injected credential with base64url ID", func(t *testing.T) {
		rec := doListCredentials(t, server, username)
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		var envelope struct {
			Data WebAuthnListResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
		require.Len(t, envelope.Data.Credentials, 1)
		assert.Equal(t, base64.RawURLEncoding.EncodeToString(credID), envelope.Data.Credentials[0].ID)
	})

	t.Run("account not found returns 404", func(t *testing.T) {
		rec := doListCredentials(t, server, "no-such-user")
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("invalid username returns 400", func(t *testing.T) {
		// Use a placeholder URL path; inject the invalid username via withVars so
		// httptest.NewRequest doesn't panic on the special characters.
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/accounts/placeholder/webauthn/credentials", nil)
		req = withVars(req, map[string]string{"username": "bad user!"})
		req = withPrincipal(req, testAdminPrincipal())
		rec := httptest.NewRecorder()
		server.handleWebAuthnListCredentials(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// TestWebAuthnRevokeCredential verifies handleWebAuthnRevokeCredential (Issue #2783).
func TestWebAuthnRevokeCredential(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	credID := []byte("revokable-credential-id")
	credIDParam := base64.RawURLEncoding.EncodeToString(credID)
	injectCredential(t, server, username, credID)

	t.Run("revokes existing credential and returns 204", func(t *testing.T) {
		rec := doRevokeCredential(t, server, username, credIDParam)
		assert.Equal(t, http.StatusNoContent, rec.Code, "body: %s", rec.Body.String())

		// Verify the credential is gone.
		acct, err := server.getAccount(context.Background(), username)
		require.NoError(t, err)
		assert.Empty(t, acct.Credentials, "credential must be removed after revocation")
	})

	t.Run("credential already revoked returns 404", func(t *testing.T) {
		rec := doRevokeCredential(t, server, username, credIDParam)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("invalid base64url credential_id returns 400", func(t *testing.T) {
		rec := doRevokeCredential(t, server, username, "not!!valid$$base64")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("account not found returns 404", func(t *testing.T) {
		rec := doRevokeCredential(t, server, "no-such-user", credIDParam)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("mTLS admin revoke last credential succeeds (no anti-lockout guard for non-cookie-auth)", func(t *testing.T) {
		// mTLS/API-key principals have no cookieAuthContextKey — the anti-lockout guard
		// (LAST_CREDENTIAL / 409) only applies to cookie-auth (human web) accounts.
		// An mTLS admin retains alternative access paths (ADR-021 §7), so the server
		// permits removal of the last credential for non-cookie-auth callers.
		_, secondUsername := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
		lastCredID := []byte("last-credential")
		lastCredIDParam := base64.RawURLEncoding.EncodeToString(lastCredID)
		injectCredential(t, server, secondUsername, lastCredID)

		rec := doRevokeCredential(t, server, secondUsername, lastCredIDParam)
		assert.Equal(t, http.StatusNoContent, rec.Code,
			"mTLS admin (cookieAuth=false) must be allowed to revoke the last credential")
	})
}

// --- Issue #2992: IDOR fix, anti-lockout guard, and CAS atomicity tests ---

// withCookieAuth returns a request with cookieAuthContextKey=true and a principal
// whose ID is the given web account's UUID — matching the session layout set by
// authenticationMiddleware for cookie-authenticated requests.
func withCookieAuth(req *http.Request, acct *account) *http.Request {
	ctx := context.WithValue(req.Context(), cookieAuthContextKey, true)
	ctx = context.WithValue(ctx, principalContextKey, &Principal{
		ID:        acct.ID,
		Name:      acct.Username,
		Assurance: session.AssuranceStrong,
	})
	return req.WithContext(ctx)
}

// doListCredentialsCookieAuth calls handleWebAuthnListCredentials as the account owner
// via a cookie-authenticated session.
func doListCredentialsCookieAuth(t *testing.T, server *Server, acct *account, pathUsername string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/accounts/%s/webauthn/credentials", pathUsername), nil)
	req = withVars(req, map[string]string{"username": pathUsername})
	req = withCookieAuth(req, acct)
	rec := httptest.NewRecorder()
	server.handleWebAuthnListCredentials(rec, req)
	return rec
}

// doRevokeCredentialCookieAuth calls handleWebAuthnRevokeCredential as the account
// owner via a cookie-authenticated session.
func doRevokeCredentialCookieAuth(t *testing.T, server *Server, acct *account, pathUsername, credIDParam string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/accounts/%s/webauthn/revoke/%s", pathUsername, credIDParam), nil)
	req = withVars(req, map[string]string{"username": pathUsername, "credential_id": credIDParam})
	req = withCookieAuth(req, acct)
	rec := httptest.NewRecorder()
	server.handleWebAuthnRevokeCredential(rec, req)
	return rec
}

// TestWebAuthnCredentialIDOR verifies that cookie-auth principals are confined to their
// own account (Issue #2992 IDOR fix).
func TestWebAuthnCredentialIDOR(t *testing.T) {
	server, usernameA := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	// Create a second account.
	recB := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: "idor-account-b"})
	require.Equal(t, http.StatusCreated, recB.Code)

	acctA, err := server.getAccount(context.Background(), usernameA)
	require.NoError(t, err)
	require.NotNil(t, acctA)

	acctB, err := server.getAccount(context.Background(), "idor-account-b")
	require.NoError(t, err)
	require.NotNil(t, acctB)

	credID := []byte("idor-target-cred")
	injectCredential(t, server, acctB.Username, credID)
	credIDParam := base64.RawURLEncoding.EncodeToString(credID)

	t.Run("cookie-auth list returns 403 when path username != session account", func(t *testing.T) {
		// acctA's session, acctB's path — must be rejected.
		rec := doListCredentialsCookieAuth(t, server, acctA, acctB.Username)
		assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
		assert.Equal(t, "FORBIDDEN", errCode(t, rec.Body.Bytes()))
	})

	t.Run("cookie-auth revoke returns 403 when path username != session account", func(t *testing.T) {
		rec := doRevokeCredentialCookieAuth(t, server, acctA, acctB.Username, credIDParam)
		assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
		assert.Equal(t, "FORBIDDEN", errCode(t, rec.Body.Bytes()))
	})

	t.Run("cookie-auth list succeeds when path username matches session account", func(t *testing.T) {
		// acctA listing their own account — path matches session.
		rec := doListCredentialsCookieAuth(t, server, acctA, acctA.Username)
		assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	})

	t.Run("credential on acctB still present after blocked revoke attempts", func(t *testing.T) {
		freshB, err := server.getAccount(context.Background(), acctB.Username)
		require.NoError(t, err)
		require.Len(t, freshB.Credentials, 1, "acctB credential must not have been touched")
	})
}

// TestWebAuthnAntiLockout verifies the server-side anti-lockout guard for cookie-auth
// principals (Issue #2992).
func TestWebAuthnAntiLockout(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)

	credID := []byte("only-passkey")
	injectCredential(t, server, username, credID)
	credIDParam := base64.RawURLEncoding.EncodeToString(credID)

	t.Run("cookie-auth last credential returns 409 LAST_CREDENTIAL", func(t *testing.T) {
		rec := doRevokeCredentialCookieAuth(t, server, acct, username, credIDParam)
		assert.Equal(t, http.StatusConflict, rec.Code, "body: %s", rec.Body.String())
		assert.Equal(t, "LAST_CREDENTIAL", errCode(t, rec.Body.Bytes()))
	})

	t.Run("credential still present after blocked revoke", func(t *testing.T) {
		fresh, err := server.getAccount(context.Background(), username)
		require.NoError(t, err)
		require.Len(t, fresh.Credentials, 1, "credential must not have been removed")
	})

	t.Run("cookie-auth revoke succeeds when two credentials exist", func(t *testing.T) {
		// Add a second credential so the first can be revoked.
		secondCredID := []byte("backup-passkey")
		injectCredential(t, server, username, secondCredID)

		// Reload the account (cache may have stale credential count).
		acct, err = server.getAccount(context.Background(), username)
		require.NoError(t, err)

		rec := doRevokeCredentialCookieAuth(t, server, acct, username, credIDParam)
		assert.Equal(t, http.StatusNoContent, rec.Code, "body: %s", rec.Body.String())

		fresh, err := server.getAccount(context.Background(), username)
		require.NoError(t, err)
		assert.Len(t, fresh.Credentials, 1, "exactly one credential must remain")
	})
}

// TestWebAuthnRevokeCAS verifies that two concurrent revokes on a two-credential
// account leave exactly one credential — the CAS mutex prevents both from
// racing past the last-credential guard and zeroing the account (Issue #2992).
func TestWebAuthnRevokeCAS(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)

	credA := []byte("cas-cred-a")
	credB := []byte("cas-cred-b")
	injectCredential(t, server, username, credA)
	injectCredential(t, server, username, credB)

	credAParam := base64.RawURLEncoding.EncodeToString(credA)
	credBParam := base64.RawURLEncoding.EncodeToString(credB)

	// Reload after injection so the in-memory cache is consistent.
	acct, err = server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.Len(t, acct.Credentials, 2)

	// Two goroutines each try to revoke one credential concurrently.
	// The account starts with 2 credentials. Each revoke brings it to 1.
	// Both should succeed — neither should see LAST_CREDENTIAL.
	// After both complete, exactly 0 credentials remain (each saw 2→1, then 1→0).
	// The CAS mutex serialises them, so the post-conditions are deterministic.
	type result struct {
		code int
		body []byte
	}
	ch := make(chan result, 2)

	go func() {
		rec := doRevokeCredentialCookieAuth(t, server, acct, username, credAParam)
		ch <- result{rec.Code, rec.Body.Bytes()}
	}()
	go func() {
		rec := doRevokeCredentialCookieAuth(t, server, acct, username, credBParam)
		ch <- result{rec.Code, rec.Body.Bytes()}
	}()

	r1 := <-ch
	r2 := <-ch

	// Both revokes target distinct credentials on a 2-credential account.
	// The serialized order is: first removes one (1 left), second removes the other (0 left).
	// With cookie-auth the last-credential guard fires if count reaches 0 during a revoke.
	// The first goroutine sees 2 credentials and removes one → 1 remains.
	// The second goroutine (now running with a fresh reload) sees 1 credential and its target
	// is the other, leaving 0 — which triggers LAST_CREDENTIAL if cookieAuth.
	//
	// Correct behaviour: exactly one of the two returns 204, the other returns 409.
	codes := []int{r1.code, r2.code}
	noContent := 0
	conflict := 0
	for _, c := range codes {
		switch c {
		case http.StatusNoContent:
			noContent++
		case http.StatusConflict:
			conflict++
		}
	}
	assert.Equal(t, 1, noContent, "exactly one revoke must succeed (204)")
	assert.Equal(t, 1, conflict, "exactly one revoke must be blocked by the anti-lockout guard (409)")

	// The account must have exactly one credential remaining.
	final, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	assert.Len(t, final.Credentials, 1, "CAS must leave exactly one credential")
}

// --- Issue #2784: presence ceremony handler error-path tests ---

// doPresenceBegin calls handlePresenceBegin directly. Pass nil principal to omit
// the principal from the request context, exercising the 401 path.
func doPresenceBegin(t *testing.T, server *Server, principal *Principal) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/presence/begin", nil)
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	rec := httptest.NewRecorder()
	server.handlePresenceBegin(rec, req)
	return rec
}

// doPresenceFinish calls handlePresenceFinish directly with an empty body.
// Pass nil principal to omit the principal from the request context.
func doPresenceFinish(t *testing.T, server *Server, principal *Principal) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/presence/finish", bytes.NewReader(nil))
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	rec := httptest.NewRecorder()
	server.handlePresenceFinish(rec, req)
	return rec
}

// injectPresenceSession stores a pending presence session directly into the server,
// bypassing handlePresenceBegin. Keyed by principalID (not a URL path variable).
func injectPresenceSession(s *Server, principalID string, sd webauthn.SessionData, ttl time.Duration) {
	s.webAuthnPresenceSessions.Store(principalID, &webAuthnPendingSession{
		data:    sd,
		expires: time.Now().Add(ttl),
	})
}

// TestWebAuthnPresenceBegin covers handlePresenceBegin, including the success path.
// BeginLogin only derives an assertion challenge from the account's registered credential
// IDs and stores server-side session data — it does not touch hardware. Hardware
// verification happens in FinishLogin (exercised in TestWebAuthnPresenceFinish). The
// happy path is therefore fully testable here with a synthetic injected credential.
func TestWebAuthnPresenceBegin(t *testing.T) {
	t.Run("Success_200_IssuesChallengeAndStoresSession", func(t *testing.T) {
		server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

		// BeginLogin needs at least one registered credential ID. Inject one
		// synthetically to reach the success branch without a real ceremony.
		credID := []byte("presence-begin-cred-id")
		injectCredential(t, server, username, credID)

		// Principal ID must match the web-account username so getAccount resolves it.
		principal := &Principal{ID: username, Name: username}
		rec := doPresenceBegin(t, server, principal)
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		// Response must carry a non-empty assertion challenge.
		var resp APIResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		opts, ok := resp.Data.(map[string]interface{})
		require.True(t, ok, "response.data must be an object")
		pk, ok := opts["publicKey"].(map[string]interface{})
		require.True(t, ok, "response.data.publicKey must be present")
		assert.NotEmpty(t, pk["challenge"], "BeginLogin must issue an assertion challenge")

		// Security-critical (ADR-021 Decision 4): the challenge must demand user
		// verification. A regression to "preferred"/"discouraged" — or dropping the
		// option — silently defeats the presence guarantee, so assert it explicitly.
		assert.Equal(t, "required", pk["userVerification"],
			"presence ceremony must require user verification (WithUserVerification(VerificationRequired))")

		// A single-use, time-bounded presence session must be stored keyed by principal ID.
		raw, ok := server.webAuthnPresenceSessions.Load(principal.ID)
		require.True(t, ok, "a presence session must be stored after begin")
		pending, ok := raw.(*webAuthnPendingSession)
		require.True(t, ok, "stored value must be a *webAuthnPendingSession")
		assert.False(t, time.Now().After(pending.expires), "freshly created session must not be expired")
		assert.NotEmpty(t, pending.data.Challenge, "server-side session must retain the challenge for FinishLogin")
	})

	t.Run("Not_Configured_503", func(t *testing.T) {
		server := setupTestServer(t)
		rec := doPresenceBegin(t, server, testAdminPrincipal())
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("No_Principal_401", func(t *testing.T) {
		server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
		rec := doPresenceBegin(t, server, nil) // no principal in context
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "AUTHENTICATION_REQUIRED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("AccountNotFound_404", func(t *testing.T) {
		server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
		// testAdminPrincipal has ID="test-mtls-admin"; no web account exists with that name.
		rec := doPresenceBegin(t, server, testAdminPrincipal())
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, "WEB_ACCOUNT_NOT_FOUND", errCode(t, rec.Body.Bytes()))
	})

	t.Run("NoCredentials_409", func(t *testing.T) {
		server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
		// A freshly-created account has zero credentials. The principal ID must equal
		// the web-account username so getAccount(ctx, principal.ID) finds it.
		principal := &Principal{ID: username, Name: username}
		rec := doPresenceBegin(t, server, principal)
		assert.Equal(t, http.StatusConflict, rec.Code)
		assert.Equal(t, "NO_CREDENTIALS", errCode(t, rec.Body.Bytes()))
	})
}

// TestWebAuthnPresenceFinish covers handlePresenceFinish error paths (Issue #2784).
// The success path (assertion verified + presence token minted) requires a real
// authenticator ceremony and is covered by the integration test suite.
func TestWebAuthnPresenceFinish(t *testing.T) {
	t.Run("Not_Configured_503", func(t *testing.T) {
		server := setupTestServer(t)
		rec := doPresenceFinish(t, server, testAdminPrincipal())
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("No_Principal_401", func(t *testing.T) {
		server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
		rec := doPresenceFinish(t, server, nil) // no principal in context
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "AUTHENTICATION_REQUIRED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("AccountNotFound_404", func(t *testing.T) {
		server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
		// testAdminPrincipal has ID="test-mtls-admin"; no web account with that name.
		rec := doPresenceFinish(t, server, testAdminPrincipal())
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, "WEB_ACCOUNT_NOT_FOUND", errCode(t, rec.Body.Bytes()))
	})

	t.Run("NoActiveSession_400", func(t *testing.T) {
		server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
		// Account exists but begin was never called — no presence session stored.
		principal := &Principal{ID: username, Name: username}
		rec := doPresenceFinish(t, server, principal)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "NO_ACTIVE_PRESENCE_SESSION", errCode(t, rec.Body.Bytes()))
	})

	t.Run("SessionExpired_400", func(t *testing.T) {
		server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
		principal := &Principal{ID: username, Name: username}

		acct, err := server.getAccount(context.Background(), username)
		require.NoError(t, err)
		require.NotNil(t, acct)

		// Inject a presence session whose TTL has already elapsed.
		injectPresenceSession(server, username, tvSession([]byte(acct.ID), tvRPID), -1*time.Second)

		rec := doPresenceFinish(t, server, principal)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "SESSION_EXPIRED", errCode(t, rec.Body.Bytes()))
	})
}

// --- Issue #2966: first-passkey enrollment via magic link ---

// setupEnrollServer creates a test server with a WebAuthn RP configured for the
// supplied rpID/origins, pre-creates a web account for the given username, and
// returns the server, username, and the raw enrollment magic-link token. The token
// is minted by handleCreateAccount (which issues it for zero-cred accounts).
func setupEnrollServer(t *testing.T, rpID string, rpOrigins []string, username string) (*Server, string, string) {
	t.Helper()
	server := setupTestServer(t)
	wa, err := NewWebAuthnFromConfig(rpID, rpID, rpOrigins)
	require.NoError(t, err)
	server.SetWebAuthn(wa)

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: username})
	require.Equal(t, http.StatusCreated, rec.Code, "create account: %s", rec.Body.String())

	var outer APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &outer))
	raw := outer.Data.(map[string]interface{})
	rawToken, _ := raw["enrollment_magic_link"].(string)
	require.NotEmpty(t, rawToken, "enrollment magic link must be minted on account creation")
	return server, username, rawToken
}

// doEnrollBegin calls handlePasskeyEnrollBegin directly with the supplied raw token.
func doEnrollBegin(t *testing.T, server *Server, rawToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/enroll/begin", nil)
	req.Header.Set(enrollmentTokenHeader, rawToken)
	rec := httptest.NewRecorder()
	server.handlePasskeyEnrollBegin(rec, req)
	return rec
}

// doEnrollFinish calls handlePasskeyEnrollFinish directly with the supplied raw token and body.
func doEnrollFinish(t *testing.T, server *Server, rawToken string, body *bytes.Reader) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/enroll/finish", body)
	req.Header.Set(enrollmentTokenHeader, rawToken)
	rec := httptest.NewRecorder()
	server.handlePasskeyEnrollFinish(rec, req)
	return rec
}

// injectEnrollSession stores a pending enrollment session keyed by the token's hash,
// bypassing the begin step — mirrors injectSession for the regular registration path.
func injectEnrollSession(s *Server, rawToken string, sess webauthn.SessionData, ttl time.Duration) {
	tokenHash := hashEnrollmentToken(rawToken)
	s.passkeyEnrollSessions.Store(tokenHash, &webAuthnPendingSession{
		data:    sess,
		expires: time.Now().Add(ttl),
	})
}

// TestPasskeyEnrollBegin tests the begin handler error paths and the happy path.
func TestPasskeyEnrollBegin(t *testing.T) {
	const username = "enroll-begin-user"
	server, _, rawToken := setupEnrollServer(t, tvRPID, []string{tvOrigin}, username)

	t.Run("NoWebAuthn", func(t *testing.T) {
		noWaServer := setupTestServer(t)
		rec := doEnrollBegin(t, noWaServer, rawToken)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("MissingToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/enroll/begin", nil)
		rec := httptest.NewRecorder()
		server.handlePasskeyEnrollBegin(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "MISSING_ENROLLMENT_TOKEN", errCode(t, rec.Body.Bytes()))
	})

	t.Run("InvalidToken", func(t *testing.T) {
		rec := doEnrollBegin(t, server, "aabbccddeeff001122334455667788990011223344") // valid length, wrong value
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "TOKEN_INVALID", errCode(t, rec.Body.Bytes()))
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		// Create a separate account and manually expire the enrollment link.
		srv2, _, tok2 := setupEnrollServer(t, tvRPID, []string{tvOrigin}, "enroll-expired-user")
		acct2, err := srv2.getAccount(context.Background(), "enroll-expired-user")
		require.NoError(t, err)
		// Backdate the expiry by an hour so the token is already expired.
		acct2.EnrollmentLinkExpiresAt = acct2.EnrollmentLinkExpiresAt.Add(-73 * time.Hour)
		require.NoError(t, srv2.persistAccount(context.Background(), acct2, "test"))
		srv2.cacheAccount(acct2)

		rec := doEnrollBegin(t, srv2, tok2)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "TOKEN_INVALID", errCode(t, rec.Body.Bytes()))
	})

	t.Run("RevokedToken", func(t *testing.T) {
		srv3, _, tok3 := setupEnrollServer(t, tvRPID, []string{tvOrigin}, "enroll-revoked-user")
		acct3, err := srv3.getAccount(context.Background(), "enroll-revoked-user")
		require.NoError(t, err)
		acct3.EnrollmentLinkRevoked = true
		require.NoError(t, srv3.persistAccount(context.Background(), acct3, "test"))
		srv3.cacheAccount(acct3)

		rec := doEnrollBegin(t, srv3, tok3)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "TOKEN_INVALID", errCode(t, rec.Body.Bytes()))
	})

	t.Run("Success", func(t *testing.T) {
		rec := doEnrollBegin(t, server, rawToken)
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		// Verify the session is keyed by tokenHash, not by username.
		tokenHash := hashEnrollmentToken(rawToken)
		raw, loaded := server.passkeyEnrollSessions.Load(tokenHash)
		require.True(t, loaded, "session must be stored under tokenHash after enroll begin")
		pending, ok := raw.(*webAuthnPendingSession)
		require.True(t, ok)
		assert.False(t, time.Now().After(pending.expires), "session must not be expired")
		assert.NotEmpty(t, pending.data.Challenge, "server-side session must carry a challenge")

		// The session must NOT be stored under the username (self-scoping invariant).
		_, usernameKeyed := server.passkeyEnrollSessions.Load(username)
		assert.False(t, usernameKeyed, "session must be keyed by tokenHash, not username")
	})
}

// TestPasskeyEnrollFinish tests the finish handler error paths and the happy path.
func TestPasskeyEnrollFinish(t *testing.T) {
	// --- W3C Level 3 §16.2 NoneES256 spec test vector (same as Finish_Success above) ---
	const (
		svRPID          = "example.org"
		svOrigin        = "https://example.org"
		svAttObjectHex  = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220" //nolint:gosec // W3C Level 3 §16.2 spec test vector, not a real credential secret
		svClientDataHex = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
		svCredIDHex     = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec // W3C Level 3 §16.2 spec test vector credential ID, not a real credential secret
		svChallengeHex  = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
		svUsername      = "enroll-finish-user"
	)

	svAttObj, err := hex.DecodeString(svAttObjectHex)
	require.NoError(t, err, "decode svAttObjectHex")
	svCDJ, err := hex.DecodeString(svClientDataHex)
	require.NoError(t, err, "decode svClientDataHex")
	svCredIDBytes, err := hex.DecodeString(svCredIDHex)
	require.NoError(t, err, "decode svCredIDHex")
	svChallengeBytes, err := hex.DecodeString(svChallengeHex)
	require.NoError(t, err, "decode svChallengeHex")
	svCredIDStr := base64.RawURLEncoding.EncodeToString(svCredIDBytes)
	svChallenge := base64.RawURLEncoding.EncodeToString(svChallengeBytes)

	t.Run("NoWebAuthn", func(t *testing.T) {
		noWaServer := setupTestServer(t)
		rec := doEnrollFinish(t, noWaServer, "aabbccddeeff001122334455667788990011223344", nil)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("MissingToken", func(t *testing.T) {
		srv, _, _ := setupEnrollServer(t, svRPID, []string{svOrigin}, "enroll-notoken-user")
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/enroll/finish", nil)
		rec := httptest.NewRecorder()
		srv.handlePasskeyEnrollFinish(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "MISSING_ENROLLMENT_TOKEN", errCode(t, rec.Body.Bytes()))
	})

	t.Run("NoActiveCeremony", func(t *testing.T) {
		srv, _, rawToken := setupEnrollServer(t, svRPID, []string{svOrigin}, "enroll-noceremony-user")
		// No begin call — no session in the map.
		rec := doEnrollFinish(t, srv, rawToken, nil)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "NO_ACTIVE_ENROLLMENT", errCode(t, rec.Body.Bytes()))
	})

	// TestPasskeyEnrollFinish_ConcurrentRedeem: LoadAndDelete is atomic, so only the
	// first finish call gets the session data. The second gets NO_ACTIVE_ENROLLMENT.
	t.Run("ConcurrentRedeem_SecondFailsWithNoActiveCeremony", func(t *testing.T) {
		srv, _, rawToken := setupEnrollServer(t, svRPID, []string{svOrigin}, "enroll-concurrent-user")
		acct, err := srv.getAccount(context.Background(), "enroll-concurrent-user")
		require.NoError(t, err)

		sess := webauthn.SessionData{
			Challenge:        svChallenge,
			UserID:           []byte(acct.ID),
			UserVerification: protocol.VerificationPreferred,
			RelyingPartyID:   svRPID,
			CredParams: []protocol.CredentialParameter{
				{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			},
		}
		injectEnrollSession(srv, rawToken, sess, 10*time.Minute)

		// First finish: session is consumed (body is wrong, so WebAuthn verify fails
		// with WEBAUTHN_VERIFY_ERROR — but the session is still deleted).
		first := doEnrollFinish(t, srv, rawToken, bytes.NewReader(nil))
		require.NotEqual(t, "NO_ACTIVE_ENROLLMENT", errCode(t, first.Body.Bytes()),
			"first call must find the session (not return NO_ACTIVE_ENROLLMENT)")

		// Second finish: session already consumed — must get NO_ACTIVE_ENROLLMENT.
		second := doEnrollFinish(t, srv, rawToken, bytes.NewReader(nil))
		assert.Equal(t, http.StatusBadRequest, second.Code)
		assert.Equal(t, "NO_ACTIVE_ENROLLMENT", errCode(t, second.Body.Bytes()),
			"second call must fail immediately because session was consumed by first")
	})

	t.Run("ExpiredSession", func(t *testing.T) {
		srv, _, rawToken := setupEnrollServer(t, svRPID, []string{svOrigin}, "enroll-expiredsession-user")
		acct, err := srv.getAccount(context.Background(), "enroll-expiredsession-user")
		require.NoError(t, err)

		sess := webauthn.SessionData{
			Challenge:      svChallenge,
			UserID:         []byte(acct.ID),
			RelyingPartyID: svRPID,
		}
		injectEnrollSession(srv, rawToken, sess, -1*time.Second) // already expired
		rec := doEnrollFinish(t, srv, rawToken, bytes.NewReader(nil))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "SESSION_EXPIRED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("TokenInvalidAtFinish", func(t *testing.T) {
		// Token is revoked between begin and finish: CAS check at finish rejects it.
		srv, _, rawToken := setupEnrollServer(t, svRPID, []string{svOrigin}, "enroll-tokeninvalid-user")
		acct, err := srv.getAccount(context.Background(), "enroll-tokeninvalid-user")
		require.NoError(t, err)

		sess := webauthn.SessionData{
			Challenge:      svChallenge,
			UserID:         []byte(acct.ID),
			RelyingPartyID: svRPID,
			CredParams: []protocol.CredentialParameter{
				{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			},
		}
		injectEnrollSession(srv, rawToken, sess, 10*time.Minute)

		// Revoke the token (simulating admin action between begin and finish).
		acct.EnrollmentLinkRevoked = true
		require.NoError(t, srv.persistAccount(context.Background(), acct, "test-admin"))
		srv.cacheAccount(acct)

		// Finish should fail with TOKEN_INVALID.
		// verifyEnrollmentToken runs before wa.FinishRegistration, so the result
		// is determinate: 401 TOKEN_INVALID, not a WebAuthn verification error.
		rec := doEnrollFinish(t, srv, rawToken,
			finishBody(t, svCredIDStr,
				base64.RawURLEncoding.EncodeToString(svCDJ),
				base64.RawURLEncoding.EncodeToString(svAttObj)))
		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"revoked token must produce 401 before WebAuthn verification is reached")
		assert.Equal(t, "TOKEN_INVALID", errCode(t, rec.Body.Bytes()),
			"revoked token must return TOKEN_INVALID error code")
	})

	t.Run("AlreadyEnrolled_CASPreconditionAtFinish", func(t *testing.T) {
		// A credential is added between begin and finish: CAS check at finish rejects it.
		srv, _, rawToken := setupEnrollServer(t, svRPID, []string{svOrigin}, "enroll-cas-user")
		acct, err := srv.getAccount(context.Background(), "enroll-cas-user")
		require.NoError(t, err)

		sess := webauthn.SessionData{
			Challenge:        svChallenge,
			UserID:           []byte(acct.ID),
			UserVerification: protocol.VerificationPreferred,
			RelyingPartyID:   svRPID,
			CredParams: []protocol.CredentialParameter{
				{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			},
		}
		injectEnrollSession(srv, rawToken, sess, 10*time.Minute)

		// Inject a credential directly (simulating another path adding a credential).
		injectCredential(t, srv, acct.Username, []byte("injected-credential"))

		// The finish should be rejected by the CAS check: account now has credentials.
		// WebAuthn verification passes first (server is configured for svRPID/svOrigin);
		// the CAS store-reload then finds the injected credential and returns 409.
		rec := doEnrollFinish(t, srv, rawToken,
			finishBody(t, svCredIDStr,
				base64.RawURLEncoding.EncodeToString(svCDJ),
				base64.RawURLEncoding.EncodeToString(svAttObj)))
		assert.Equal(t, http.StatusConflict, rec.Code,
			"CAS precondition must fire 409 when credentials exist in the store at finish time")
		assert.Equal(t, "ALREADY_ENROLLED", errCode(t, rec.Body.Bytes()),
			"CAS precondition must return ALREADY_ENROLLED error code")
	})

	// Success test: uses the W3C Level 3 §16.2 NoneES256 spec vector.
	t.Run("Success_FirstPasskeyPersisted", func(t *testing.T) {
		srv, _, rawToken := setupEnrollServer(t, svRPID, []string{svOrigin}, svUsername)
		acct, err := srv.getAccount(context.Background(), svUsername)
		require.NoError(t, err)

		sess := webauthn.SessionData{
			Challenge:        svChallenge,
			UserID:           []byte(acct.ID),
			UserVerification: protocol.VerificationPreferred,
			RelyingPartyID:   svRPID,
			CredParams: []protocol.CredentialParameter{
				{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			},
		}
		injectEnrollSession(srv, rawToken, sess, 10*time.Minute)

		body := finishBody(t, svCredIDStr,
			base64.RawURLEncoding.EncodeToString(svCDJ),
			base64.RawURLEncoding.EncodeToString(svAttObj))
		rec := doEnrollFinish(t, srv, rawToken, body)
		require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

		// Credential must be persisted.
		updated, err := srv.getAccount(context.Background(), svUsername)
		require.NoError(t, err)
		require.Len(t, updated.Credentials, 1, "exactly one credential after enrollment")
		assert.Equal(t, svCredIDBytes, updated.Credentials[0].ID,
			"persisted credential ID must match the spec vector")

		// Enrollment token must be consumed (revoked).
		assert.True(t, updated.EnrollmentLinkRevoked,
			"enrollment token must be marked as consumed after successful enrollment")

		// Token must no longer be usable for a second enrollment begin.
		rec2 := doEnrollBegin(t, srv, rawToken)
		assert.Equal(t, http.StatusUnauthorized, rec2.Code,
			"token must be unusable after enrollment (single-use)")

		// Audit event must have been written.
		require.NoError(t, srv.auditManager.Flush(context.Background()))
		entries, err := srv.auditManager.QueryEntries(context.Background(),
			&business.AuditFilter{Actions: []string{"account.passkey_enrolled"}})
		require.NoError(t, err)
		require.NotEmpty(t, entries, "account.passkey_enrolled audit entry must be written on success")
		e := entries[0]
		assert.Equal(t, "account.passkey_enrolled", e.Action)
		assert.Equal(t, svUsername, e.ResourceID)
	})
}

// TestPasskeyEnroll_SelfScopedToTokenAccount verifies that the enrollment handlers
// resolve the target account from the TOKEN, not from any caller-supplied identifier.
// This is the core fix for the cross-account credential injection vulnerability.
func TestPasskeyEnroll_SelfScopedToTokenAccount(t *testing.T) {
	// Create two separate accounts: A and B, each with their own enrollment token.
	server := setupTestServer(t)
	wa, err := NewWebAuthnFromConfig(tvRPID, tvRPID, []string{tvOrigin})
	require.NoError(t, err)
	server.SetWebAuthn(wa)

	recA := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: "enroll-account-a"})
	require.Equal(t, http.StatusCreated, recA.Code)
	var outerA APIResponse
	require.NoError(t, json.Unmarshal(recA.Body.Bytes(), &outerA))
	tokenA := outerA.Data.(map[string]interface{})["enrollment_magic_link"].(string)

	recB := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: "enroll-account-b"})
	require.Equal(t, http.StatusCreated, recB.Code)
	var outerB APIResponse
	require.NoError(t, json.Unmarshal(recB.Body.Bytes(), &outerB))
	tokenB := outerB.Data.(map[string]interface{})["enrollment_magic_link"].(string)

	// Call begin with account A's token: the ceremony is set up for account A.
	recBegin := doEnrollBegin(t, server, tokenA)
	require.Equal(t, http.StatusOK, recBegin.Code)

	// The session is keyed by tokenA's hash — not by username "enroll-account-b".
	hashA := hashEnrollmentToken(tokenA)
	_, loadedByHashA := server.passkeyEnrollSessions.Load(hashA)
	assert.True(t, loadedByHashA, "session must be stored under account-A's token hash")

	// Account B's token hash must NOT have a session (its begin was never called).
	hashB := hashEnrollmentToken(tokenB)
	_, loadedByHashB := server.passkeyEnrollSessions.Load(hashB)
	assert.False(t, loadedByHashB, "account-B's token hash must not have a session")

	// Using account B's token on finish with account A's active session must fail:
	// no session exists under tokenB's hash.
	recFinish := doEnrollFinish(t, server, tokenB, nil)
	assert.Equal(t, http.StatusBadRequest, recFinish.Code)
	assert.Equal(t, "NO_ACTIVE_ENROLLMENT", errCode(t, recFinish.Body.Bytes()),
		"presenting account-B's token when only account-A has an active session must fail")
}

// TestEnrollmentConfinement tests the enrollmentConfinementMiddleware server-side gate.
// AC: a zero-passkey cookie-auth session is refused all api routes; once enrolled (>0
// passkeys), the same request passes the confinement check.
func TestEnrollmentConfinement(t *testing.T) {
	server := setupTestServer(t)

	// A handler that always succeeds — we only test whether confinement blocks it.
	successHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	withCookieSession := func(req *http.Request, count int) *http.Request {
		ctx := context.WithValue(req.Context(), cookieAuthContextKey, true)
		ctx = context.WithValue(ctx, principalContextKey, &Principal{
			ID:                 "web-session-user",
			Assurance:          session.AssuranceBasic,
			AuthenticatorCount: count,
		})
		return req.WithContext(ctx)
	}

	t.Run("ZeroPasskeys_Blocked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
		req = withCookieSession(req, 0)
		rec := httptest.NewRecorder()
		server.enrollmentConfinementMiddleware(successHandler).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, "ENROLLMENT_REQUIRED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("NegativeAuthenticatorCount_Blocked", func(t *testing.T) {
		// -1 means account load failed; fail-closed.
		req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
		req = withCookieSession(req, -1)
		rec := httptest.NewRecorder()
		server.enrollmentConfinementMiddleware(successHandler).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, "ENROLLMENT_REQUIRED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("OnePasskey_Allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
		req = withCookieSession(req, 1)
		rec := httptest.NewRecorder()
		server.enrollmentConfinementMiddleware(successHandler).ServeHTTP(rec, req)
		// Confinement passes; the handler is reached.
		assert.Equal(t, http.StatusOK, rec.Code,
			"one passkey enrolled: confinement must allow the request")
	})

	t.Run("mTLSAdmin_NotBlockedByConfinement", func(t *testing.T) {
		// mTLS principal: cookieAuth is false → confinement does not apply.
		req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
		ctx := context.WithValue(req.Context(), cookieAuthContextKey, false)
		ctx = context.WithValue(ctx, principalContextKey, &Principal{
			ID:                 "mtls-admin",
			Assurance:          session.AssuranceStrong,
			AuthenticatorCount: 0, // default zero for non-web-session principals
		})
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		server.enrollmentConfinementMiddleware(successHandler).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code,
			"mTLS admin (cookieAuth=false) must not be blocked even with AuthenticatorCount=0")
	})

	t.Run("NoCookieAuth_NotBlocked", func(t *testing.T) {
		// Request with no cookie auth context at all.
		req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
		rec := httptest.NewRecorder()
		server.enrollmentConfinementMiddleware(successHandler).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code,
			"no cookie auth context must pass through confinement")
	})
}

// TestPasskeyEnroll_TokenHashing verifies that the enrollment token is never stored
// or compared in plaintext — the implementation must use hashEnrollmentToken (SHA-256)
// and constant-time compare (via verifyEnrollmentToken).
func TestPasskeyEnroll_TokenHashing(t *testing.T) {
	server := setupTestServer(t)
	wa, err := NewWebAuthnFromConfig(tvRPID, tvRPID, []string{tvOrigin})
	require.NoError(t, err)
	server.SetWebAuthn(wa)

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: "token-hash-user"})
	require.Equal(t, http.StatusCreated, rec.Code)

	var outer APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &outer))
	rawToken := outer.Data.(map[string]interface{})["enrollment_magic_link"].(string)

	// The stored hash must differ from the raw token.
	acct, err := server.getAccount(context.Background(), "token-hash-user")
	require.NoError(t, err)
	assert.NotEqual(t, rawToken, acct.EnrollmentLinkHash,
		"stored hash must not equal the raw token (must be hashed)")

	// The hash must equal SHA-256(rawToken).
	expectedHash := hashEnrollmentToken(rawToken)
	assert.Equal(t, expectedHash, acct.EnrollmentLinkHash,
		"stored hash must be SHA-256 of the raw token")

	// The passkeyEnrollSessions sync.Map key (after begin) must be the token hash.
	recBegin := doEnrollBegin(t, server, rawToken)
	require.Equal(t, http.StatusOK, recBegin.Code)

	_, byHash := server.passkeyEnrollSessions.Load(hashEnrollmentToken(rawToken))
	assert.True(t, byHash, "session must be stored under the token hash, not the raw token")

	_, byRaw := server.passkeyEnrollSessions.Load(rawToken)
	assert.False(t, byRaw, "session must NOT be stored under the raw token")
}

// TestWebAuthnRegisterStaysAtAssuranceStrong verifies that the existing
// webauthn:register (add-to-existing) permission is NOT lowered by Issue #2966.
// The enrollment redemption routes are separate and have no entry in permissionAssurance.
func TestWebAuthnRegisterStaysAtAssuranceStrong(t *testing.T) {
	req, ok := permissionAssurance["webauthn:register"]
	require.True(t, ok, "webauthn:register must remain in permissionAssurance")
	assert.Equal(t, session.AssuranceStrong, req.Min,
		"webauthn:register must stay at AssuranceStrong (Issue #2966 must not lower it)")
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
