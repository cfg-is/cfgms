// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2965: Tests for WebAuthn step-up elevation handlers.
//
// Coverage:
//   - handleStepUpBegin: not-configured, no-principal, no-session-id,
//     account-not-found, no-credentials, success (session stored server-side)
//   - handleStepUpFinish: not-configured, no-principal, no-session-id,
//     account-not-found, no-active-session, session-expired, throttle,
//     sign-count-clone detection, success with W3C NoneES256 assertion spec vector
//     (real WebAuthn library verification — no mocks)
//   - elevateBackoff: schedule correctness
//
// The success test uses the W3C Level 3 NoneES256 authentication spec vector from
// github.com/go-webauthn/webauthn@v0.17.0/protocol/specification_vectors_e2e_test.go.
// This matches the NoneES256 registration vector (same credential ID and public key),
// enabling end-to-end cryptographic verification without a real authenticator device.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// W3C Level 3 NoneES256 authentication spec vector.
// Source: go-webauthn@v0.17.0/protocol/specification_vectors_e2e_test.go
// TestSpecVectors_Authentication_E2E → NoneES256 vector.
//
// The same credential (identical credentialID + publicKey) appears in both the
// registration and authentication vectors, enabling a full register-then-assert
// test flow using only the spec vectors.
const (
	svAuthCredentialIDHex   = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4"
	svAuthPublicKeyHex      = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	svAuthChallengeHex      = "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
	svAuthAuthDataHex       = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
	svAuthClientDataJSONHex = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	svAuthSignatureHex      = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
	svAuthRPID              = "example.org"
	svAuthOrigin            = "https://example.org"
)

// injectElevateSession stores a pending elevation session directly into the server,
// bypassing handleStepUpBegin. Keyed by sessionID.
func injectElevateSession(s *Server, sessionID string, sd webauthn.SessionData, ttl time.Duration, accountID string) {
	s.webAuthnElevateSessions.Store(sessionID, &webAuthnElevateSession{
		data:      sd,
		expires:   time.Now().Add(ttl),
		accountID: accountID,
	})
}

// doStepUpBegin calls handleStepUpBegin directly.
func doStepUpBegin(t *testing.T, server *Server, principal *Principal, sessID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/elevate/begin", nil)
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	if sessID != "" {
		req = req.WithContext(context.WithValue(req.Context(), webSessionIDContextKey, sessID))
	}
	rec := httptest.NewRecorder()
	server.handleStepUpBegin(rec, req)
	return rec
}

// doStepUpFinish calls handleStepUpFinish directly.
func doStepUpFinish(t *testing.T, server *Server, principal *Principal, sessID string, body *bytes.Reader) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/elevate/finish", body)
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	if sessID != "" {
		req = req.WithContext(context.WithValue(req.Context(), webSessionIDContextKey, sessID))
	}
	rec := httptest.NewRecorder()
	server.handleStepUpFinish(rec, req)
	return rec
}

// injectCredentialWithPublicKey adds a WebAuthn credential with a real public key to an
// account, enabling FinishLogin to perform real cryptographic verification.
func injectCredentialWithPublicKey(t *testing.T, server *Server, username string, credID, pubKey []byte, signCount uint32) {
	t.Helper()
	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct, "account %q must exist before injecting credential", username)
	// The W3C NoneES256 spec vector authData has BE=1, BS=1 (both authData bytes 0x59 and 0x19).
	// We must store matching flags so FinishLogin's consistency check passes.
	acct.Credentials = append(acct.Credentials, WebAuthnCredential{
		ID:             credID,
		PublicKey:      pubKey,
		SignCount:      signCount,
		Label:          "spec-vector-credential",
		RegisteredAt:   time.Now(),
		BackupEligible: true,
		BackupState:    true,
	})
	require.NoError(t, server.persistWebAccount(context.Background(), acct, "test-injector"))
	server.cacheWebAccount(acct)
}

// buildAssertionBody constructs a JSON PublicKeyCredential assertion response from raw bytes.
func buildAssertionBody(t *testing.T, credID, authData, clientDataJSON, signature []byte) *bytes.Reader {
	t.Helper()
	type assertionResponse struct {
		AuthenticatorData string `json:"authenticatorData"`
		ClientDataJSON    string `json:"clientDataJSON"`
		Signature         string `json:"signature"`
	}
	type assertionCredential struct {
		ID       string            `json:"id"`
		RawID    string            `json:"rawId"`
		Type     string            `json:"type"`
		Response assertionResponse `json:"response"`
	}
	credIDBase64 := base64.RawURLEncoding.EncodeToString(credID)
	body := assertionCredential{
		ID:    credIDBase64,
		RawID: credIDBase64,
		Type:  "public-key",
		Response: assertionResponse{
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			Signature:         base64.RawURLEncoding.EncodeToString(signature),
		},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// --- TestStepUpBegin ---

func TestStepUpBegin_NotConfigured_503(t *testing.T) {
	server := setupTestServer(t)
	// No WebAuthn configured.
	rec := doStepUpBegin(t, server, testAdminPrincipal(), "some-session-id")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
}

func TestStepUpBegin_NoPrincipal_401(t *testing.T) {
	server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	rec := doStepUpBegin(t, server, nil, "some-session-id")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "AUTHENTICATION_REQUIRED", errCode(t, rec.Body.Bytes()))
}

func TestStepUpBegin_NoSessionID_400(t *testing.T) {
	server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	// No webSessionIDContextKey → should return SESSION_REQUIRED.
	rec := doStepUpBegin(t, server, testAdminPrincipal(), "" /* no session ID */)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "SESSION_REQUIRED", errCode(t, rec.Body.Bytes()))
}

func TestStepUpBegin_AccountNotFound_404(t *testing.T) {
	server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	// testAdminPrincipal has ID="test-mtls-admin"; no web account with that name.
	rec := doStepUpBegin(t, server, testAdminPrincipal(), "some-session-id")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "WEB_ACCOUNT_NOT_FOUND", errCode(t, rec.Body.Bytes()))
}

func TestStepUpBegin_NoCredentials_409(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	// A freshly-created account has zero credentials.
	principal := &Principal{ID: username, Name: username}
	rec := doStepUpBegin(t, server, principal, "some-session-id")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "NO_CREDENTIALS", errCode(t, rec.Body.Bytes()))
}

func TestStepUpBegin_Success_200(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	credID := []byte("elevate-begin-cred-id")
	injectCredential(t, server, username, credID)

	const sessID = "test-web-session-id"
	principal := &Principal{ID: username, Name: username}
	rec := doStepUpBegin(t, server, principal, sessID)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	// Session must be stored server-side keyed by session ID (not principal ID or username).
	raw, ok := server.webAuthnElevateSessions.Load(sessID)
	require.True(t, ok, "elevation session must be stored after begin")
	pending, ok := raw.(*webAuthnElevateSession)
	require.True(t, ok)
	assert.False(t, time.Now().After(pending.expires), "freshly created session must not be expired")
	assert.NotEmpty(t, pending.data.Challenge, "server-side session must hold the challenge")

	// Response must include a challenge with user-verification required.
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	opts, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "response.data must be an object")
	pk, ok := opts["publicKey"].(map[string]interface{})
	require.True(t, ok, "response.data.publicKey must be present")
	assert.NotEmpty(t, pk["challenge"])
	assert.Equal(t, "required", pk["userVerification"],
		"step-up ceremony must require user verification")
}

// --- TestStepUpFinish ---

func TestStepUpFinish_NotConfigured_503(t *testing.T) {
	server := setupTestServer(t)
	rec := doStepUpFinish(t, server, testAdminPrincipal(), "sess", nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
}

func TestStepUpFinish_NoPrincipal_401(t *testing.T) {
	server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	rec := doStepUpFinish(t, server, nil, "sess", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "AUTHENTICATION_REQUIRED", errCode(t, rec.Body.Bytes()))
}

func TestStepUpFinish_NoSessionID_400(t *testing.T) {
	server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	rec := doStepUpFinish(t, server, testAdminPrincipal(), "" /* no session */, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "SESSION_REQUIRED", errCode(t, rec.Body.Bytes()))
}

func TestStepUpFinish_AccountNotFound_404(t *testing.T) {
	server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	injectElevateSession(server, "sess", webauthn.SessionData{}, time.Minute, "test-mtls-admin")
	rec := doStepUpFinish(t, server, testAdminPrincipal(), "sess", nil)
	// Session is consumed by LoadAndDelete regardless; the account lookup fires first
	// since session check is after account check — wait, need to confirm order.
	// Account check is BEFORE session load in handleStepUpFinish.
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "WEB_ACCOUNT_NOT_FOUND", errCode(t, rec.Body.Bytes()))
}

func TestStepUpFinish_NoActiveSession_400(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	principal := &Principal{ID: username}
	// No session injected — begin was never called.
	rec := doStepUpFinish(t, server, principal, "sess", nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "NO_ACTIVE_ELEVATION_SESSION", errCode(t, rec.Body.Bytes()))
}

func TestStepUpFinish_SessionExpired_400(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	principal := &Principal{ID: username}
	// Inject an already-expired session.
	injectElevateSession(server, "sess", webauthn.SessionData{}, -time.Second, username)
	rec := doStepUpFinish(t, server, principal, "sess", nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "SESSION_EXPIRED", errCode(t, rec.Body.Bytes()))
}

func TestStepUpFinish_Throttled_429(t *testing.T) {
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})

	credID := []byte("throttle-test-cred")
	injectCredential(t, server, username, credID)
	principal := &Principal{ID: username}

	// Record enough failures to trigger the per-session throttle.
	const sessID = "throttle-sess"
	for i := 0; i < 4; i++ {
		server.recordElevateFailure("session:" + sessID)
	}

	// Inject a fresh (non-expired) session.
	injectElevateSession(server, sessID, webauthn.SessionData{}, time.Minute, username)

	rec := doStepUpFinish(t, server, principal, sessID, nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "THROTTLED", errCode(t, rec.Body.Bytes()))
}

// TestStepUpFinish_SignCountClone verifies that a response with a non-advancing sign count
// is rejected when either the stored or response count is nonzero.
func TestStepUpFinish_SignCountClone_400(t *testing.T) {
	server, username := setupWebAuthnServer(t, svAuthRPID, []string{svAuthOrigin})

	// Decode the NoneES256 authentication spec vector bytes.
	credIDBytes, err := hex.DecodeString(svAuthCredentialIDHex)
	require.NoError(t, err)
	pubKeyBytes, err := hex.DecodeString(svAuthPublicKeyHex)
	require.NoError(t, err)
	challengeBytes, err := hex.DecodeString(svAuthChallengeHex)
	require.NoError(t, err)
	authDataBytes, err := hex.DecodeString(svAuthAuthDataHex)
	require.NoError(t, err)
	clientDataJSONBytes, err := hex.DecodeString(svAuthClientDataJSONHex)
	require.NoError(t, err)
	sigBytes, err := hex.DecodeString(svAuthSignatureHex)
	require.NoError(t, err)

	// Inject a credential with SignCount=100 — the assertion response has SignCount=0,
	// so this triggers the "stored > response and stored > 0" clone detection.
	injectCredentialWithPublicKey(t, server, username, credIDBytes, pubKeyBytes, 100)

	// Load the account to obtain its stable UUID for the session UserID field.
	// FinishLogin checks bytes.Equal(user.WebAuthnID(), session.UserID); the user's
	// WebAuthnID is []byte(acct.ID) (a UUID, not the username).
	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)

	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)
	sd := webauthn.SessionData{
		Challenge:            challenge,
		RelyingPartyID:       svAuthRPID,
		UserID:               []byte(acct.ID),
		UserVerification:     protocol.VerificationPreferred, // spec vector has UP only; use Preferred to not block on UV
		AllowedCredentialIDs: [][]byte{credIDBytes},
		Expires:              time.Now().Add(10 * time.Minute),
	}

	const sessID = "clone-detect-sess"
	injectElevateSession(server, sessID, sd, time.Minute, username)

	body := buildAssertionBody(t, credIDBytes, authDataBytes, clientDataJSONBytes, sigBytes)
	principal := &Principal{ID: username}
	rec := doStepUpFinish(t, server, principal, sessID, body)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
}

// TestStepUpFinish_Success verifies the full step-up elevation path using the W3C
// NoneES256 authentication spec vector. This is a real assertion verification:
// the go-webauthn/webauthn library parses the response, verifies the ECDSA signature
// over SHA-256(authData + hash(clientDataJSON)), and checks challenge/origin/RP-ID.
// No mock objects are used — the test exercises the same code path as production.
//
// The spec vector's authData does not have the UV (User Verified) flag set, so the
// injected session uses VerificationPreferred to avoid the UV check. In production,
// handleStepUpBegin always sets VerificationRequired; this test verifies the
// cryptographic verification path, which is the same regardless of the UV policy.
func TestStepUpFinish_Success(t *testing.T) {
	server, username := setupWebAuthnServer(t, svAuthRPID, []string{svAuthOrigin})

	// Initialize a real webSessionManager so webSessionManager.Elevate can succeed.
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	store := session.NewMemStore(webCfg, time.Now)
	t.Cleanup(store.Close)
	server.SetWebSessionManager(session.NewManager(webCfg, store, time.Now))

	credIDBytes, err := hex.DecodeString(svAuthCredentialIDHex)
	require.NoError(t, err)
	pubKeyBytes, err := hex.DecodeString(svAuthPublicKeyHex)
	require.NoError(t, err)
	challengeBytes, err := hex.DecodeString(svAuthChallengeHex)
	require.NoError(t, err)
	authDataBytes, err := hex.DecodeString(svAuthAuthDataHex)
	require.NoError(t, err)
	clientDataJSONBytes, err := hex.DecodeString(svAuthClientDataJSONHex)
	require.NoError(t, err)
	sigBytes, err := hex.DecodeString(svAuthSignatureHex)
	require.NoError(t, err)

	// SignCount=0 in the spec vector; stored=0 → 0→0 is allowed per W3C §7.2 step 21.
	injectCredentialWithPublicKey(t, server, username, credIDBytes, pubKeyBytes, 0)

	// Load the account to obtain its stable UUID for the session UserID field.
	// FinishLogin checks bytes.Equal(user.WebAuthnID(), session.UserID); the user's
	// WebAuthnID is []byte(acct.ID) (a UUID, not the username).
	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)

	// The challenge stored in the session must match the base64url in clientDataJSON.
	// clientDataJSON decodes to: {"type":"webauthn.get","challenge":"OcDnUhQXulTUPo3JUXt0I99pvzzYBP9tZchXyav01Ag","origin":"https://example.org","crossOrigin":false}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)
	sd := webauthn.SessionData{
		Challenge:            challenge,
		RelyingPartyID:       svAuthRPID,
		UserID:               []byte(acct.ID),
		UserVerification:     protocol.VerificationPreferred,
		AllowedCredentialIDs: [][]byte{credIDBytes},
		Expires:              time.Now().Add(10 * time.Minute),
	}

	// Issue a real web session so webSessionManager.Elevate can succeed.
	_, token, issueErr := server.webSessionManager.Issue(context.Background(), username, "web-login", "default")
	require.NoError(t, issueErr)
	webSess, valErr := server.webSessionManager.Validate(context.Background(), token)
	require.NoError(t, valErr)
	realSessID := webSess.ID

	injectElevateSession(server, realSessID, sd, time.Minute, username)

	body := buildAssertionBody(t, credIDBytes, authDataBytes, clientDataJSONBytes, sigBytes)
	principal := &Principal{ID: username}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/elevate/finish", body)
	req = withPrincipal(req, principal)
	ctx := context.WithValue(req.Context(), webSessionIDContextKey, realSessID)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleStepUpFinish(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	// Response must carry assurance=strong.
	var envelope struct {
		Data StepUpElevateFinishResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	assert.Equal(t, "strong", envelope.Data.Assurance)
	assert.False(t, envelope.Data.ElevatedAt.IsZero(), "elevated_at must be set")

	// A rotated session cookie must be set.
	var newCookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieWebSession {
			newCookie = c.Value
			break
		}
	}
	assert.NotEmpty(t, newCookie, "response must set a rotated cfgms_session cookie")
	assert.NotEqual(t, token, newCookie, "cookie must be rotated (different from pre-elevation token)")

	// The new token must validate as AssuranceStrong.
	elevated, validateErr := server.webSessionManager.Validate(context.Background(), newCookie)
	require.NoError(t, validateErr)
	assert.Equal(t, session.AssuranceStrong, elevated.Assurance, "session must carry AssuranceStrong after elevation")
}

// --- TestElevateBackoff ---

func TestElevateBackoff(t *testing.T) {
	cases := []struct {
		fails int
		want  time.Duration
	}{
		{0, 0},
		{1, 0},
		{2, 0},
		{3, 10 * time.Second},
		{4, 10 * time.Second},
		{5, 30 * time.Second},
		{7, 30 * time.Second},
		{8, 2 * time.Minute},
		{11, 2 * time.Minute},
		{12, 10 * time.Minute},
		{50, 10 * time.Minute},
	}
	for _, tc := range cases {
		got := elevateBackoff(tc.fails)
		if got != tc.want {
			t.Errorf("elevateBackoff(%d) = %v, want %v", tc.fails, got, tc.want)
		}
	}
}
