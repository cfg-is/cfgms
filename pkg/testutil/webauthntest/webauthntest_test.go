// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package webauthntest

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/softauthn"
)

const (
	testRPID   = "controller.example.test"
	testOrigin = "https://controller.example.test"
)

var testCredID = []byte("webauthntest-credential-id")

// testUser is a webauthn.User holding the credentials registered so far.
type testUser struct {
	handle []byte
	creds  []webauthn.Credential
}

func (u *testUser) WebAuthnID() []byte                         { return u.handle }
func (u *testUser) WebAuthnName() string                       { return "operator" }
func (u *testUser) WebAuthnDisplayName() string                { return "Operator" }
func (u *testUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func newRP(t *testing.T, rpID, origin string) *webauthn.WebAuthn {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: "CFGMS test", RPOrigins: []string{origin}})
	require.NoError(t, err)
	return wa
}

func finishRequest(body []byte) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
}

// registered runs a real registration ceremony through go-webauthn with the
// package's Register and returns the user holding the verified credential.
func registered(t *testing.T, wa *webauthn.WebAuthn, key *ecdsa.PrivateKey, origin string, opts ...Option) (*testUser, *webauthn.Credential) {
	t.Helper()
	user := &testUser{handle: []byte("user-handle-0123456789")}
	creation, session, err := wa.BeginRegistration(user, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
		UserVerification: protocol.VerificationRequired,
	}))
	require.NoError(t, err)
	reg := Register(t, key, testCredID, wa.Config.RPID, origin, creation.Response.Challenge.String(), opts...)
	cred, err := wa.FinishRegistration(user, *session, finishRequest(reg.Body()))
	require.NoError(t, err)
	user.creds = []webauthn.Credential{*cred}
	return user, cred
}

// login begins a login that requires user verification and returns the session
// with the challenge string the client would sign.
func login(t *testing.T, wa *webauthn.WebAuthn, user *testUser) (*webauthn.SessionData, string) {
	t.Helper()
	assertion, session, err := wa.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	require.NoError(t, err)
	return session, assertion.Response.Challenge.String()
}

func TestNewKey_COSEKeyIsAcceptedByRegistration(t *testing.T) {
	key, pub := NewKey(t)
	wa := newRP(t, testRPID, testOrigin)
	_, cred := registered(t, wa, key, testOrigin)
	assert.Equal(t, cred.PublicKey, pub, "NewKey's COSE key must match the key softauthn registers")
}

func TestRegister_DefaultAAGUIDIsZero(t *testing.T) {
	key, _ := NewKey(t)
	wa := newRP(t, testRPID, testOrigin)
	_, cred := registered(t, wa, key, testOrigin)

	assert.Equal(t, make([]byte, 16), cred.Authenticator.AAGUID, "a default registration must carry a zero AAGUID")
	assert.NotEqual(t, softauthn.AAGUID[:], cred.Authenticator.AAGUID)
	assert.True(t, cred.Flags.UserPresent)
	assert.True(t, cred.Flags.UserVerified)
	assert.Equal(t, "none", cred.AttestationFormat)
}

func TestRegister_CFGMSAAGUIDOptionSetsSoftauthnAAGUID(t *testing.T) {
	key, _ := NewKey(t)
	wa := newRP(t, testRPID, testOrigin)
	_, cred := registered(t, wa, key, testOrigin, WithCFGMSAAGUID())
	assert.Equal(t, softauthn.AAGUID[:], cred.Authenticator.AAGUID)
}

func TestRegister_ChosenAAGUID(t *testing.T) {
	other := [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6}
	key, _ := NewKey(t)
	wa := newRP(t, testRPID, testOrigin)
	_, cred := registered(t, wa, key, testOrigin, WithAAGUID(other))
	assert.Equal(t, other[:], cred.Authenticator.AAGUID)
}

func TestRegister_RecordsUserHandleAndAcceptsNonHTTPSOrigin(t *testing.T) {
	// softauthn refuses a non-https origin; the package writes it by patching.
	const origin = "http://localhost:8443"
	key, _ := NewKey(t)
	wa := newRP(t, "localhost", origin)
	_, cred := registered(t, wa, key, origin, WithUserHandle([]byte("chosen-user")))
	assert.Equal(t, testCredID, cred.ID)
}

func TestRegister_WrongOriginAndWrongCeremonyFail(t *testing.T) {
	for name, opt := range map[string]Option{
		"wrong origin":   WithOrigin("https://evil.example"),
		"wrong ceremony": WithCeremonyType(CeremonyGet),
		"wrong rp id":    WithRPID("attacker.example"),
	} {
		t.Run(name, func(t *testing.T) {
			key, _ := NewKey(t)
			wa := newRP(t, testRPID, testOrigin)
			user := &testUser{handle: []byte("user-handle-0123456789")}
			creation, session, err := wa.BeginRegistration(user)
			require.NoError(t, err)
			reg := Register(t, key, testCredID, testRPID, testOrigin, creation.Response.Challenge.String(), opt)
			_, err = wa.FinishRegistration(user, *session, finishRequest(reg.Body()))
			require.Error(t, err)
		})
	}
}

func TestAssert_DefaultPassesVerification(t *testing.T) {
	key, _ := NewKey(t)
	wa := newRP(t, testRPID, testOrigin)
	user, _ := registered(t, wa, key, testOrigin)

	session, challenge := login(t, wa, user)
	a := Assert(t, key, testCredID, testRPID, testOrigin, challenge)

	cred, err := wa.FinishLogin(user, *session, finishRequest(a.Body()))
	require.NoError(t, err)
	assert.Equal(t, testCredID, cred.ID)
	assert.Equal(t, FlagUP|FlagUV, a.AuthenticatorData[flagsOffset]&(FlagUP|FlagUV))
	assert.Zero(t, cred.Authenticator.SignCount)
}

func TestAssert_NonHTTPSOriginPassesVerification(t *testing.T) {
	const origin = "http://localhost:8443"
	key, _ := NewKey(t)
	wa := newRP(t, "localhost", origin)
	user, _ := registered(t, wa, key, origin)

	session, challenge := login(t, wa, user)
	a := Assert(t, key, testCredID, "localhost", origin, challenge)
	_, err := wa.FinishLogin(user, *session, finishRequest(a.Body()))
	require.NoError(t, err)
}

func TestAssert_NegativeOptionsFailVerification(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
	}{
		{"user presence only (no UV)", []Option{UserPresenceOnly()}},
		{"user verification only (no UP)", []Option{WithFlags(FlagUV)}},
		{"no flags", []Option{WithFlags(0)}},
		{"wrong origin", []Option{WithOrigin("https://evil.example")}},
		{"wrong RP id", []Option{WithRPID("attacker.example")}},
		{"corrupted signature", []Option{WithCorruptSignature()}},
		{"registration ceremony type", []Option{WithCeremonyType(CeremonyCreate)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, _ := NewKey(t)
			wa := newRP(t, testRPID, testOrigin)
			user, _ := registered(t, wa, key, testOrigin)

			session, challenge := login(t, wa, user)
			a := Assert(t, key, testCredID, testRPID, testOrigin, challenge, tc.opts...)
			_, err := wa.FinishLogin(user, *session, finishRequest(a.Body()))
			require.Error(t, err)
		})
	}
}

// A negative option must move only its own property: with the signature
// re-computed, a flags-only change still verifies once the verifier does not
// require UV, proving the failure above is the flag and not a broken signature.
func TestAssert_FlagChangeIsReSignedSoOnlyTheFlagIsWrong(t *testing.T) {
	key, _ := NewKey(t)
	wa := newRP(t, testRPID, testOrigin)
	user, _ := registered(t, wa, key, testOrigin)

	assertion, session, err := wa.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	require.NoError(t, err)
	a := Assert(t, key, testCredID, testRPID, testOrigin, assertion.Response.Challenge.String(), UserPresenceOnly())

	_, err = wa.FinishLogin(user, *session, finishRequest(a.Body()))
	require.NoError(t, err, "UP-only must verify when UV is not required, so the signature is valid")
}

func TestAssert_WrongKeyFailsVerification(t *testing.T) {
	key, _ := NewKey(t)
	other, _ := NewKey(t)
	wa := newRP(t, testRPID, testOrigin)
	user, _ := registered(t, wa, key, testOrigin)

	session, challenge := login(t, wa, user)
	a := Assert(t, other, testCredID, testRPID, testOrigin, challenge)
	_, err := wa.FinishLogin(user, *session, finishRequest(a.Body()))
	require.Error(t, err)
}

func TestAssert_ChosenSignCount(t *testing.T) {
	key, _ := NewKey(t)
	wa := newRP(t, testRPID, testOrigin)
	user, _ := registered(t, wa, key, testOrigin)

	session, challenge := login(t, wa, user)
	a := Assert(t, key, testCredID, testRPID, testOrigin, challenge, WithSignCount(7))

	parsed, err := protocol.ParseCredentialRequestResponseBytes(a.Body())
	require.NoError(t, err)
	assert.Equal(t, uint32(7), parsed.Response.AuthenticatorData.Counter)

	cred, err := wa.FinishLogin(user, *session, finishRequest(a.Body()))
	require.NoError(t, err, "a re-signed non-zero counter must still verify")
	assert.Equal(t, uint32(7), cred.Authenticator.SignCount)
}

func TestAssert_ChosenUserHandle(t *testing.T) {
	key, _ := NewKey(t)
	wa := newRP(t, testRPID, testOrigin)
	user, _ := registered(t, wa, key, testOrigin)

	t.Run("matching handle verifies", func(t *testing.T) {
		session, challenge := login(t, wa, user)
		a := Assert(t, key, testCredID, testRPID, testOrigin, challenge, WithUserHandle(user.handle))
		assert.Equal(t, user.handle, a.UserHandle)
		_, err := wa.FinishLogin(user, *session, finishRequest(a.Body()))
		require.NoError(t, err)
	})
	t.Run("other handle is refused", func(t *testing.T) {
		session, challenge := login(t, wa, user)
		a := Assert(t, key, testCredID, testRPID, testOrigin, challenge, WithUserHandle([]byte("someone-else")))
		parsed, err := protocol.ParseCredentialRequestResponseBytes(a.Body())
		require.NoError(t, err)
		assert.Equal(t, []byte("someone-else"), parsed.Response.UserHandle)
		_, err = wa.FinishLogin(user, *session, finishRequest(a.Body()))
		require.Error(t, err)
	})
}

func TestAssert_NonCanonicalChallengeIsWrittenVerbatim(t *testing.T) {
	key, _ := NewKey(t)
	// "unused" is not a canonical base64url encoding (trailing bits are set).
	a := Assert(t, key, testCredID, testRPID, testOrigin, "unused")
	parsed, err := protocol.ParseCredentialRequestResponseBytes(a.Body())
	require.NoError(t, err)
	assert.Equal(t, "unused", parsed.Response.CollectedClientData.Challenge)
}

// With no option set, the signed bytes are softauthn's own: the package adds
// nothing to a default response.
func TestAssert_DefaultBytesAreSoftauthns(t *testing.T) {
	key, _ := NewKey(t)
	const challenge = "AAECAwQFBgcICQoLDA0ODw"
	a := Assert(t, key, testCredID, testRPID, testOrigin, challenge)

	authn, err := softauthn.New(softauthn.Config{Signer: key, RPID: testRPID, Origin: testOrigin, CredentialID: testCredID})
	require.NoError(t, err)
	chBytes, ok := decodeCanonical(challenge)
	require.True(t, ok)
	request, err := json.Marshal(protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{Challenge: chBytes, RelyingPartyID: testRPID}})
	require.NoError(t, err)
	raw, err := authn.Assert(request)
	require.NoError(t, err)
	var want protocol.CredentialAssertionResponse
	require.NoError(t, json.Unmarshal(raw, &want))

	assert.Equal(t, []byte(want.AssertionResponse.AuthenticatorData), a.AuthenticatorData)
	assert.Equal(t, []byte(want.AssertionResponse.ClientDataJSON), a.ClientDataJSON)
	assert.Equal(t, FlagUP|FlagUV, a.AuthenticatorData[flagsOffset])
}

func TestRawAssertionBody_RoundTripsFields(t *testing.T) {
	body := RawAssertionBody([]byte("cred"), []byte("authdata"), []byte(`{"type":"webauthn.get"}`), []byte("sig"), []byte("handle"))
	var got protocol.CredentialAssertionResponse
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, []byte("cred"), []byte(got.RawID))
	assert.Equal(t, []byte("authdata"), []byte(got.AssertionResponse.AuthenticatorData))
	assert.Equal(t, []byte("sig"), []byte(got.AssertionResponse.Signature))
	assert.Equal(t, []byte("handle"), []byte(got.AssertionResponse.UserHandle))

	noHandle := RawAssertionBody([]byte("cred"), []byte("a"), []byte("{}"), []byte("s"), nil)
	assert.NotContains(t, string(noHandle), "userHandle")
}
