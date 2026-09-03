// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3695: tests for WebAuthn operator-payload signing handlers.
//
// Coverage:
//   - handleOperatorPayloadSignBegin: not-configured, no-principal, no-session-id,
//     account-not-found, no-credentials, missing-content, missing-shell, no-targets-matched,
//     success (challenge equals operatorpayload.ChallengeHash(envelope)), differing nonce across
//     two otherwise-identical begin calls.
//   - handleOperatorPayloadSignFinish: not-configured, no-principal, no-session-id,
//     account-not-found, no-active-session, session-expired, throttle, replayed session ID
//     rejected, sign-count-clone detection, forged/unregistered-key rejection, full
//     end-to-end success with real ECDSA P-256 signature verification (no mocks).
//   - generateOperatorPayloadSignNonce: functional uniqueness/length properties, and a
//     source-level assertion that the call site reads crypto/rand (never a
//     counter/timestamp/UUID), per the Issue #3695 AC.
//
// Since the WebAuthn challenge here is derived from the envelope (not a fixed W3C spec
// vector), tests build a synthetic ECDSA P-256 authenticator: a real keypair, a COSE-encoded
// public key stored on the account, and a real ECDSA signature over authData||sha256(clientDataJSON)
// — the same bytes and algorithm production verification uses. No mock objects are used.
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// setupOperatorPayloadSignServer returns a test Server with WebAuthn configured, a
// pre-created web account, and a fleetQuery seeded with one steward so selector "all"
// resolves to a single deterministic target.
func setupOperatorPayloadSignServer(t *testing.T) (*Server, string) {
	t.Helper()
	server, username := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	server.fleetQuery = seededFleetQuery(makeSeedSteward("steward-1", "es-hv01", "linux", "amd64", "prod"))
	return server, username
}

// padCoord left-pads b to 32 bytes — the fixed EC2 coordinate length validateEC2PublicKey
// requires for P-256.
func padCoord(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// generateSyntheticCredential creates a real ECDSA P-256 keypair and returns it alongside
// the COSE-encoded public key bytes in the exact format WebAuthnCredential.PublicKey stores,
// enabling real cryptographic assertion verification in tests (no mocks).
func generateSyntheticCredential(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	coseKey := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   2, // EC2
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: padCoord(priv.X.Bytes()),
		YCoord: padCoord(priv.Y.Bytes()),
	}
	pubKeyBytes, err := webauthncbor.Marshal(coseKey)
	require.NoError(t, err)

	return priv, pubKeyBytes
}

// injectSignCredential adds a WebAuthn credential with a real public key to an account.
func injectSignCredential(t *testing.T, server *Server, username string, credID, pubKey []byte, signCount uint32) {
	t.Helper()
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct, "account %q must exist before injecting credential", username)
	acct.Credentials = append(acct.Credentials, WebAuthnCredential{
		ID:           credID,
		PublicKey:    pubKey,
		SignCount:    signCount,
		Label:        "sign-test-credential",
		RegisteredAt: time.Now(),
	})
	require.NoError(t, server.persistAccount(context.Background(), acct, "test-injector"))
	server.cacheAccount(acct)
}

// buildSignAssertionBody signs challengeB64 (the base64url challenge string the server
// issued) with priv and returns a JSON PublicKeyCredential assertion response body, using
// authenticator flags UP|UV (0x05) and the given sign count.
func buildSignAssertionBody(t *testing.T, priv *ecdsa.PrivateKey, credID []byte, rpID, origin, challengeB64 string, signCount uint32) *bytes.Reader {
	t.Helper()

	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 37)
	copy(authData[:32], rpIDHash[:])
	authData[32] = 0x05 // UP | UV
	authData[33] = byte(signCount >> 24)
	authData[34] = byte(signCount >> 16)
	authData[35] = byte(signCount >> 8)
	authData[36] = byte(signCount)

	clientData := struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}{
		Type:      "webauthn.get",
		Challenge: challengeB64,
		Origin:    origin,
	}
	clientDataJSON, err := json.Marshal(clientData)
	require.NoError(t, err)

	clientDataHash := sha256.Sum256(clientDataJSON)
	sigData := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(sigData)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	require.NoError(t, err)

	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)
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
	body := assertionCredential{
		ID: credIDB64, RawID: credIDB64, Type: "public-key",
		Response: assertionResponse{
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			Signature:         base64.RawURLEncoding.EncodeToString(sig),
		},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

func doSignBegin(t *testing.T, server *Server, principal *Principal, sessID string, body *bytes.Reader) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operator-payload/sign/begin", body)
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	if sessID != "" {
		req = req.WithContext(context.WithValue(req.Context(), webSessionIDContextKey, sessID))
	}
	rec := httptest.NewRecorder()
	server.handleOperatorPayloadSignBegin(rec, req)
	return rec
}

func doSignFinish(t *testing.T, server *Server, principal *Principal, sessID string, body *bytes.Reader) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operator-payload/sign/finish", body)
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	if sessID != "" {
		req = req.WithContext(context.WithValue(req.Context(), webSessionIDContextKey, sessID))
	}
	rec := httptest.NewRecorder()
	server.handleOperatorPayloadSignFinish(rec, req)
	return rec
}

func validBeginBody() *bytes.Reader {
	b, _ := json.Marshal(OperatorPayloadSignBeginRequest{
		Selector: "all",
		Content:  []byte("echo hello"),
		Shell:    "bash",
	})
	return bytes.NewReader(b)
}

// --- TestOperatorPayloadSignBegin ---

func TestOperatorPayloadSignBegin_NotConfigured_503(t *testing.T) {
	server := setupTestServer(t)
	rec := doSignBegin(t, server, testAdminPrincipal(), "sess", validBeginBody())
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignBegin_NoPrincipal_401(t *testing.T) {
	server, _ := setupOperatorPayloadSignServer(t)
	rec := doSignBegin(t, server, nil, "sess", validBeginBody())
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "AUTHENTICATION_REQUIRED", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignBegin_NoSessionID_400(t *testing.T) {
	server, _ := setupOperatorPayloadSignServer(t)
	rec := doSignBegin(t, server, testAdminPrincipal(), "", validBeginBody())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "SESSION_REQUIRED", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignBegin_AccountNotFound_404(t *testing.T) {
	server, _ := setupOperatorPayloadSignServer(t)
	rec := doSignBegin(t, server, testAdminPrincipal(), "sess", validBeginBody())
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "ACCOUNT_NOT_FOUND", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignBegin_NoCredentials_409(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	principal := &Principal{ID: username, Name: username}
	rec := doSignBegin(t, server, principal, "sess", validBeginBody())
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "NO_CREDENTIALS", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignBegin_MissingContent_400(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	injectSignCredential(t, server, username, []byte("cred-1"), []byte("pubkey"), 0)
	principal := &Principal{ID: username}

	b, _ := json.Marshal(OperatorPayloadSignBeginRequest{Selector: "all", Shell: "bash"})
	rec := doSignBegin(t, server, principal, "sess", bytes.NewReader(b))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "MISSING_CONTENT", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignBegin_MissingShell_400(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	injectSignCredential(t, server, username, []byte("cred-1"), []byte("pubkey"), 0)
	principal := &Principal{ID: username}

	b, _ := json.Marshal(OperatorPayloadSignBeginRequest{Selector: "all", Content: []byte("echo hi")})
	rec := doSignBegin(t, server, principal, "sess", bytes.NewReader(b))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "MISSING_SHELL", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignBegin_NoTargetsMatched_400(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	injectSignCredential(t, server, username, []byte("cred-1"), []byte("pubkey"), 0)
	principal := &Principal{ID: username}

	b, _ := json.Marshal(OperatorPayloadSignBeginRequest{
		Selector: "name:no-such-host*", Content: []byte("echo hi"), Shell: "bash",
	})
	rec := doSignBegin(t, server, principal, "sess", bytes.NewReader(b))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "NO_TARGETS_MATCHED", errCode(t, rec.Body.Bytes()))
}

// TestOperatorPayloadSignBegin_ChallengeEqualsEnvelopeHash is the core [REQUIRED TEST]:
// the challenge sent to the authenticator equals operatorpayload.ChallengeHash(envelope) of the
// exact envelope returned by begin (and, per the end-to-end finish test below, the exact
// envelope returned by finish too).
func TestOperatorPayloadSignBegin_ChallengeEqualsEnvelopeHash(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	credID := []byte("begin-hash-cred")
	_, pubKey := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, credID, pubKey, 0)
	principal := &Principal{ID: username}

	rec := doSignBegin(t, server, principal, "sess", validBeginBody())
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var envelope struct {
		Data OperatorPayloadSignBeginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))

	recomputed := operatorpayload.Envelope{
		Content:   envelope.Data.Envelope.Content,
		Shell:     envelope.Data.Envelope.Shell,
		Targets:   envelope.Data.Envelope.Targets,
		Nonce:     envelope.Data.Envelope.Nonce,
		ExpiresAt: envelope.Data.Envelope.ExpiresAt,
	}
	wantHash, err := operatorpayload.ChallengeHash(recomputed)
	require.NoError(t, err)

	assert.Equal(t, hex.EncodeToString(wantHash[:]), envelope.Data.EnvelopeHash,
		"envelope_hash must equal operatorpayload.ChallengeHash(envelope)")

	challengeBytes, err := base64.RawURLEncoding.DecodeString(envelope.Data.Assertion.Response.Challenge.String())
	require.NoError(t, err)
	assert.Equal(t, wantHash[:], challengeBytes,
		"the WebAuthn challenge must equal operatorpayload.ChallengeHash(envelope)")

	// Domain separation (W3C WebAuthn assertion-confusion defence): the challenge must
	// NOT be a bare hash of the canonical bytes, or an assertion collected during any
	// other ceremony at this relying party could be replayed as an operator
	// authorization.
	canonical, err := operatorpayload.CanonicalBytes(recomputed)
	require.NoError(t, err)
	bareHash := sha256.Sum256(canonical)
	assert.NotEqual(t, bareHash[:], challengeBytes,
		"the challenge preimage must be domain-separated, not bare CanonicalBytes")
}

// TestOperatorPayloadSignBegin_NonceDiffersAcrossCalls is the [REQUIRED TEST]: two begin
// calls for identical Content/Shell/Targets (differing only in server-generated nonce)
// produce different challenges — proving the nonce-in-hash property holds end-to-end.
func TestOperatorPayloadSignBegin_NonceDiffersAcrossCalls(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	credID := []byte("nonce-diff-cred")
	_, pubKey := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, credID, pubKey, 0)
	principal := &Principal{ID: username}

	rec1 := doSignBegin(t, server, principal, "sess-1", validBeginBody())
	require.Equal(t, http.StatusOK, rec1.Code)
	rec2 := doSignBegin(t, server, principal, "sess-2", validBeginBody())
	require.Equal(t, http.StatusOK, rec2.Code)

	var r1, r2 struct {
		Data OperatorPayloadSignBeginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &r1))
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &r2))

	assert.NotEqual(t, r1.Data.Envelope.Nonce, r2.Data.Envelope.Nonce,
		"each begin call must generate a fresh nonce")
	assert.NotEqual(t, r1.Data.EnvelopeHash, r2.Data.EnvelopeHash,
		"identical Content/Shell/Targets with differing nonce must produce different hashes")
	assert.NotEqual(t, r1.Data.Assertion.Response.Challenge.String(), r2.Data.Assertion.Response.Challenge.String(),
		"identical Content/Shell/Targets with differing nonce must produce different challenges")
}

// --- TestOperatorPayloadSignFinish ---

func TestOperatorPayloadSignFinish_NotConfigured_503(t *testing.T) {
	server := setupTestServer(t)
	rec := doSignFinish(t, server, testAdminPrincipal(), "sess", nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "WEBAUTHN_NOT_CONFIGURED", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignFinish_NoPrincipal_401(t *testing.T) {
	server, _ := setupOperatorPayloadSignServer(t)
	rec := doSignFinish(t, server, nil, "sess", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "AUTHENTICATION_REQUIRED", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignFinish_NoSessionID_400(t *testing.T) {
	server, _ := setupOperatorPayloadSignServer(t)
	rec := doSignFinish(t, server, testAdminPrincipal(), "", nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "SESSION_REQUIRED", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignFinish_AccountNotFound_404(t *testing.T) {
	server, _ := setupOperatorPayloadSignServer(t)
	rec := doSignFinish(t, server, testAdminPrincipal(), "sess", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "ACCOUNT_NOT_FOUND", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignFinish_NoActiveSession_400(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	principal := &Principal{ID: username}
	rec := doSignFinish(t, server, principal, "sess", nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "NO_ACTIVE_SIGN_SESSION", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignFinish_SessionExpired_400(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	principal := &Principal{ID: username}
	server.operatorPayloadSignSessions.Store("sess", &operatorPayloadSignSession{
		data:      webauthn.SessionData{},
		expires:   time.Now().Add(-time.Second),
		accountID: username,
	})
	rec := doSignFinish(t, server, principal, "sess", nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "SESSION_EXPIRED", errCode(t, rec.Body.Bytes()))
}

func TestOperatorPayloadSignFinish_Throttled_429(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	credID := []byte("throttle-cred")
	_, pubKey := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, credID, pubKey, 0)
	principal := &Principal{ID: username}

	const sessID = "throttle-sess"
	for i := 0; i < 4; i++ {
		server.recordSignFailure("session:" + sessID)
	}
	server.operatorPayloadSignSessions.Store(sessID, &operatorPayloadSignSession{
		data:      webauthn.SessionData{},
		expires:   time.Now().Add(time.Minute),
		accountID: username,
	})

	rec := doSignFinish(t, server, principal, sessID, nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "THROTTLED", errCode(t, rec.Body.Bytes()))
}

// TestOperatorPayloadSignFinish_ReplayedSession is the [REQUIRED TEST]: a finish call
// reusing an already-consumed session ID is rejected.
func TestOperatorPayloadSignFinish_ReplayedSession_Rejected(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	credID := []byte("replay-cred")
	priv, pubKey := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, credID, pubKey, 0)
	principal := &Principal{ID: username}

	const sessID = "replay-sess"
	beginRec := doSignBegin(t, server, principal, sessID, validBeginBody())
	require.Equal(t, http.StatusOK, beginRec.Code, "body: %s", beginRec.Body.String())
	var begin struct {
		Data OperatorPayloadSignBeginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(beginRec.Body.Bytes(), &begin))

	body := buildSignAssertionBody(t, priv, credID, tvRPID, tvOrigin,
		begin.Data.Assertion.Response.Challenge.String(), 1)
	firstRec := doSignFinish(t, server, principal, sessID, body)
	require.Equal(t, http.StatusOK, firstRec.Code, "body: %s", firstRec.Body.String())

	// Replay: same session ID, second finish attempt must be rejected — the session was
	// consumed via LoadAndDelete on the first call.
	replayBody := buildSignAssertionBody(t, priv, credID, tvRPID, tvOrigin,
		begin.Data.Assertion.Response.Challenge.String(), 2)
	replayRec := doSignFinish(t, server, principal, sessID, replayBody)
	assert.Equal(t, http.StatusBadRequest, replayRec.Code)
	assert.Equal(t, "NO_ACTIVE_SIGN_SESSION", errCode(t, replayRec.Body.Bytes()))
}

// TestOperatorPayloadSignFinish_SignCountClone_400 verifies that a response with a
// non-advancing sign count is rejected — the same discipline as handleStepUpFinish.
func TestOperatorPayloadSignFinish_SignCountClone_400(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	credID := []byte("clone-cred")
	priv, pubKey := generateSyntheticCredential(t)
	// Stored sign count 100; the assertion response below will carry 0.
	injectSignCredential(t, server, username, credID, pubKey, 100)
	principal := &Principal{ID: username}

	const sessID = "clone-sess"
	beginRec := doSignBegin(t, server, principal, sessID, validBeginBody())
	require.Equal(t, http.StatusOK, beginRec.Code, "body: %s", beginRec.Body.String())
	var begin struct {
		Data OperatorPayloadSignBeginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(beginRec.Body.Bytes(), &begin))

	body := buildSignAssertionBody(t, priv, credID, tvRPID, tvOrigin,
		begin.Data.Assertion.Response.Challenge.String(), 0)
	rec := doSignFinish(t, server, principal, sessID, body)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
}

// TestOperatorPayloadSignFinish_ForgedKey_Rejected is the [REQUIRED TEST]: a forged
// envelope — correct Targets/content, signed with a WebAuthn key not registered to any
// authorized operator account — is rejected. The server always resolves credentials from
// the authenticated caller's own account (never from client input), so a signature from an
// unregistered key can never validate regardless of how plausible the accompanying envelope
// looks.
func TestOperatorPayloadSignFinish_ForgedKey_Rejected(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	credID := []byte("forged-cred")
	_, registeredPubKey := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, credID, registeredPubKey, 0)
	principal := &Principal{ID: username}

	const sessID = "forged-sess"
	beginRec := doSignBegin(t, server, principal, sessID, validBeginBody())
	require.Equal(t, http.StatusOK, beginRec.Code, "body: %s", beginRec.Body.String())
	var begin struct {
		Data OperatorPayloadSignBeginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(beginRec.Body.Bytes(), &begin))

	// Sign with a DIFFERENT key — not the one registered to the account — but using the
	// account's real credential ID, simulating an attacker who knows the credential ID
	// (e.g. from a prior response) but does not hold the corresponding hardware-bound
	// private key.
	forgedPriv, _ := generateSyntheticCredential(t)
	body := buildSignAssertionBody(t, forgedPriv, credID, tvRPID, tvOrigin,
		begin.Data.Assertion.Response.Challenge.String(), 1)

	rec := doSignFinish(t, server, principal, sessID, body)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
}

// TestOperatorPayloadSignFinish_Success_EndToEnd verifies the full begin→finish path with a
// real ECDSA P-256 signature (no mocks), and re-confirms the [REQUIRED TEST] hash property
// against the envelope returned by finish specifically (not just begin).
func TestOperatorPayloadSignFinish_Success_EndToEnd(t *testing.T) {
	server, username := setupOperatorPayloadSignServer(t)
	credID := []byte("success-cred")
	priv, pubKey := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, credID, pubKey, 0)
	principal := &Principal{ID: username}

	const sessID = "success-sess"
	beginRec := doSignBegin(t, server, principal, sessID, validBeginBody())
	require.Equal(t, http.StatusOK, beginRec.Code, "body: %s", beginRec.Body.String())
	var begin struct {
		Data OperatorPayloadSignBeginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(beginRec.Body.Bytes(), &begin))

	body := buildSignAssertionBody(t, priv, credID, tvRPID, tvOrigin,
		begin.Data.Assertion.Response.Challenge.String(), 1)
	rec := doSignFinish(t, server, principal, sessID, body)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var finish struct {
		Data OperatorPayloadSignFinishResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &finish))

	assert.NotEmpty(t, finish.Data.AuthenticatorData)
	assert.NotEmpty(t, finish.Data.ClientDataJSON)
	assert.NotEmpty(t, finish.Data.Signature)
	assert.Equal(t, credID, finish.Data.CredentialID)
	assert.Equal(t, begin.Data.Envelope, finish.Data.Envelope,
		"finish must return the exact same envelope begin computed the challenge over")
	assert.Equal(t, begin.Data.EnvelopeHash, finish.Data.EnvelopeHash)

	recomputed := operatorpayload.Envelope{
		Content:   finish.Data.Envelope.Content,
		Shell:     finish.Data.Envelope.Shell,
		Targets:   finish.Data.Envelope.Targets,
		Nonce:     finish.Data.Envelope.Nonce,
		ExpiresAt: finish.Data.Envelope.ExpiresAt,
	}
	wantHash, err := operatorpayload.ChallengeHash(recomputed)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(wantHash[:]), finish.Data.EnvelopeHash,
		"envelope_hash returned by finish must equal ChallengeHash(the exact envelope returned in finish)")

	// The sign count must have advanced (persisted).
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.Len(t, acct.Credentials, 1)
	assert.Equal(t, uint32(1), acct.Credentials[0].SignCount)
}

// --- generateOperatorPayloadSignNonce ---

// TestGenerateOperatorPayloadSignNonce_FunctionalProperties is the [REQUIRED TEST]: nonces
// are at least 16 bytes and unique across calls.
func TestGenerateOperatorPayloadSignNonce_FunctionalProperties(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		nonce, err := generateOperatorPayloadSignNonce()
		require.NoError(t, err)
		raw, err := hex.DecodeString(nonce)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(raw), 16, "nonce must decode to at least 16 raw bytes")
		assert.False(t, seen[nonce], "nonce must not repeat across calls")
		seen[nonce] = true
	}
}

// TestGenerateOperatorPayloadSignNonce_SourceUsesCryptoRand is the [REQUIRED TEST]: the
// server-generated nonce is produced via crypto/rand — asserted directly against the
// generation call site, never a counter/timestamp/UUID.
func TestGenerateOperatorPayloadSignNonce_SourceUsesCryptoRand(t *testing.T) {
	src, err := os.ReadFile("handlers_operator_payload_sign.go")
	require.NoError(t, err)
	content := string(src)

	require.Contains(t, content, `"crypto/rand"`, "must import crypto/rand")
	require.NotContains(t, content, `"math/rand"`, "must not import the non-cryptographic math/rand")

	start := strings.Index(content, "func generateOperatorPayloadSignNonce")
	require.NotEqual(t, -1, start, "generateOperatorPayloadSignNonce must exist in this file")
	relEnd := strings.Index(content[start:], "\n}\n")
	require.NotEqual(t, -1, relEnd)
	body := content[start : start+relEnd]

	assert.Contains(t, body, "rand.Read(", "nonce generation call site must read from crypto/rand.Read")
	assert.NotContains(t, body, "time.Now(", "nonce must not derive from a timestamp")
	assert.NotContains(t, strings.ToLower(body), "uuid", "nonce must not derive from a UUID")
	assert.NotContains(t, body, "atomic.Add", "nonce must not derive from a counter")
}
