// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package softauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRPID   = "controller.example.test"
	testOrigin = "https://controller.example.test"
)

var testUserHandle = []byte("user-handle-0123456789")

// testUser is a webauthn.User holding the credentials registered so far.
type testUser struct {
	creds []webauthn.Credential
}

func (u *testUser) WebAuthnID() []byte                         { return testUserHandle }
func (u *testUser) WebAuthnName() string                       { return "operator" }
func (u *testUser) WebAuthnDisplayName() string                { return "Operator" }
func (u *testUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func newRP(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          testRPID,
		RPDisplayName: "CFGMS test",
		RPOrigins:     []string{testOrigin},
	})
	require.NoError(t, err)
	return wa
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func newAuth(t *testing.T, key crypto.Signer, mutate ...func(*Config)) *Authenticator {
	t.Helper()
	credID := make([]byte, 32)
	_, err := rand.Read(credID)
	require.NoError(t, err)
	cfg := Config{Signer: key, RPID: testRPID, Origin: testOrigin, CredentialID: credID}
	for _, m := range mutate {
		m(&cfg)
	}
	a, err := New(cfg)
	require.NoError(t, err)
	return a
}

func jsonRequest(body []byte) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
}

// beginRegistration mirrors the controller's begin options: resident key and
// user verification required, existing credentials excluded.
func beginRegistration(t *testing.T, wa *webauthn.WebAuthn, user *testUser) ([]byte, *webauthn.SessionData) {
	t.Helper()
	creation, session, err := wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		}),
		webauthn.WithExclusions(webauthn.Credentials(user.creds).CredentialDescriptors()),
	)
	require.NoError(t, err)
	raw, err := json.Marshal(creation)
	require.NoError(t, err)
	return raw, session
}

func register(t *testing.T, wa *webauthn.WebAuthn, a *Authenticator) (*webauthn.Credential, *testUser) {
	t.Helper()
	user := &testUser{}
	opts, session := beginRegistration(t, wa, user)
	resp, err := a.Register(opts)
	require.NoError(t, err)
	cred, err := wa.FinishRegistration(user, *session, jsonRequest(resp))
	require.NoError(t, err)
	user.creds = []webauthn.Credential{*cred}
	return cred, user
}

func beginLogin(t *testing.T, wa *webauthn.WebAuthn, user *testUser, discoverable bool) ([]byte, *webauthn.SessionData) {
	t.Helper()
	var (
		assertion *protocol.CredentialAssertion
		session   *webauthn.SessionData
		err       error
	)
	if discoverable {
		assertion, session, err = wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	} else {
		assertion, session, err = wa.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	}
	require.NoError(t, err)
	raw, err := json.Marshal(assertion)
	require.NoError(t, err)
	return raw, session
}

func discoverableHandler(user *testUser) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		if !bytes.Equal(userHandle, testUserHandle) {
			return nil, errors.New("unknown user handle")
		}
		return user, nil
	}
}

func TestNewExportsCFGMSAAGUID(t *testing.T) {
	var zero [16]byte
	assert.NotEqual(t, zero, AAGUID, "the CFGMS AAGUID must be a fixed non-zero value")
}

func TestRegistrationPassesFinishRegistration(t *testing.T) {
	wa := newRP(t)
	a := newAuth(t, newKey(t))

	cred, _ := register(t, wa, a)

	assert.Equal(t, AAGUID[:], cred.Authenticator.AAGUID, "AAGUID must be the CFGMS constant")
	assert.False(t, cred.Flags.BackupEligible, "BE must be 0")
	assert.False(t, cred.Flags.BackupState, "BS must be 0")
	assert.True(t, cred.Flags.UserVerified, "UV must be 1")
	assert.True(t, cred.Flags.UserPresent, "UP must be 1")
	assert.Equal(t, "none", cred.AttestationFormat)
	assert.Equal(t, a.CredentialID(), cred.ID)
	assert.Zero(t, cred.Authenticator.SignCount)
}

func TestRegistrationAAGUIDOverrideIsHonouredForTests(t *testing.T) {
	wa := newRP(t)
	other := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	a := newAuth(t, newKey(t), func(c *Config) { c.AAGUID = &other })

	cred, _ := register(t, wa, a)

	assert.Equal(t, other[:], cred.Authenticator.AAGUID)
	assert.NotEqual(t, AAGUID[:], cred.Authenticator.AAGUID)
}

// The server accepts a stored/response sign count of 0/0 (signCountAdvances in
// features/controller/api), and the package has no storage to persist an
// advancing counter. Every response therefore carries sign count 0, including
// repeated assertions.
func TestSignCountIsZeroOnEveryResponse(t *testing.T) {
	wa := newRP(t)
	a := newAuth(t, newKey(t))
	cred, user := register(t, wa, a)
	require.Zero(t, cred.Authenticator.SignCount)

	for i := 0; i < 3; i++ {
		opts, session := beginLogin(t, wa, user, false)
		resp, err := a.Assert(opts)
		require.NoError(t, err)

		parsed, err := protocol.ParseCredentialRequestResponseBytes(resp)
		require.NoError(t, err)
		assert.Zero(t, parsed.Response.AuthenticatorData.Counter, "assertion %d", i)

		got, err := wa.FinishLogin(user, *session, jsonRequest(resp))
		require.NoError(t, err)
		assert.Zero(t, got.Authenticator.SignCount)
	}
}

func TestAssertionPassesDiscoverableAndKnownUserLogin(t *testing.T) {
	wa := newRP(t)
	a := newAuth(t, newKey(t))
	cred, user := register(t, wa, a)

	t.Run("FinishDiscoverableLogin", func(t *testing.T) {
		opts, session := beginLogin(t, wa, user, true)
		resp, err := a.Assert(opts)
		require.NoError(t, err)
		got, err := wa.FinishDiscoverableLogin(discoverableHandler(user), *session, jsonRequest(resp))
		require.NoError(t, err)
		assert.Equal(t, cred.ID, got.ID)
		assert.True(t, got.Flags.UserVerified)
		assert.False(t, got.Flags.BackupEligible)
	})

	t.Run("FinishLogin", func(t *testing.T) {
		opts, session := beginLogin(t, wa, user, false)
		resp, err := a.Assert(opts)
		require.NoError(t, err)
		got, err := wa.FinishLogin(user, *session, jsonRequest(resp))
		require.NoError(t, err)
		assert.Equal(t, cred.ID, got.ID)
	})
}

func TestAssertionUsesSeededUserHandle(t *testing.T) {
	wa := newRP(t)
	// A fresh authenticator that never registered in this process (as after a
	// restart) takes the handle from Config.
	key := newKey(t)
	first := newAuth(t, key)
	_, user := register(t, wa, first)

	second, err := New(Config{
		Signer: key, RPID: testRPID, Origin: testOrigin,
		CredentialID: first.CredentialID(), UserHandle: testUserHandle,
	})
	require.NoError(t, err)

	opts, session := beginLogin(t, wa, user, true)
	resp, err := second.Assert(opts)
	require.NoError(t, err)
	_, err = wa.FinishDiscoverableLogin(discoverableHandler(user), *session, jsonRequest(resp))
	require.NoError(t, err)
}

func TestRegistrationRefusals(t *testing.T) {
	wa := newRP(t)
	a := newAuth(t, newKey(t))
	user := &testUser{}
	opts, _ := beginRegistration(t, wa, user)

	mutate := func(t *testing.T, f func(*protocol.CredentialCreation)) []byte {
		t.Helper()
		var c protocol.CredentialCreation
		require.NoError(t, json.Unmarshal(opts, &c))
		f(&c)
		out, err := json.Marshal(c)
		require.NoError(t, err)
		return out
	}

	cases := []struct {
		name string
		opts []byte
		want error
	}{
		{"different rpId", mutate(t, func(c *protocol.CredentialCreation) { c.Response.RelyingParty.ID = "evil.example.test" }), ErrRPIDMismatch},
		{"no ES256", mutate(t, func(c *protocol.CredentialCreation) {
			c.Response.Parameters = []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: -257}}
		}), ErrNoES256},
		{"excludes own credential", mutate(t, func(c *protocol.CredentialCreation) {
			c.Response.CredentialExcludeList = []protocol.CredentialDescriptor{
				{Type: protocol.PublicKeyCredentialType, CredentialID: a.CredentialID()},
			}
		}), ErrCredentialExcluded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := a.Register(tc.opts)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, resp, "nothing may be signed on refusal")
		})
	}

	t.Run("excluding some other credential is allowed", func(t *testing.T) {
		out := mutate(t, func(c *protocol.CredentialCreation) {
			c.Response.CredentialExcludeList = []protocol.CredentialDescriptor{
				{Type: protocol.PublicKeyCredentialType, CredentialID: []byte("someone-else")},
			}
		})
		_, err := a.Register(out)
		require.NoError(t, err)
	})

	t.Run("malformed and challengeless options", func(t *testing.T) {
		_, err := a.Register([]byte("{not json"))
		require.Error(t, err)
		_, err = a.Register([]byte(`{"publicKey":{"rp":{"id":"` + testRPID + `"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}}`))
		require.Error(t, err)
	})
}

func TestAssertionRefusals(t *testing.T) {
	wa := newRP(t)
	a := newAuth(t, newKey(t))
	_, user := register(t, wa, a)
	opts, _ := beginLogin(t, wa, user, true)

	mutate := func(t *testing.T, f func(*protocol.CredentialAssertion)) []byte {
		t.Helper()
		var c protocol.CredentialAssertion
		require.NoError(t, json.Unmarshal(opts, &c))
		f(&c)
		out, err := json.Marshal(c)
		require.NoError(t, err)
		return out
	}

	cases := []struct {
		name string
		opts []byte
		want error
	}{
		{"different rpId", mutate(t, func(c *protocol.CredentialAssertion) { c.Response.RelyingPartyID = "evil.example.test" }), ErrRPIDMismatch},
		{"allowCredentials omits own credential", mutate(t, func(c *protocol.CredentialAssertion) {
			c.Response.AllowedCredentials = []protocol.CredentialDescriptor{
				{Type: protocol.PublicKeyCredentialType, CredentialID: []byte("someone-else")},
			}
		}), ErrCredentialNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := a.Assert(tc.opts)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, resp, "nothing may be signed on refusal")
		})
	}

	t.Run("allowCredentials listing own credential is allowed", func(t *testing.T) {
		out := mutate(t, func(c *protocol.CredentialAssertion) {
			c.Response.AllowedCredentials = []protocol.CredentialDescriptor{
				{Type: protocol.PublicKeyCredentialType, CredentialID: a.CredentialID()},
			}
		})
		_, err := a.Assert(out)
		require.NoError(t, err)
	})

	t.Run("malformed and challengeless options", func(t *testing.T) {
		_, err := a.Assert([]byte("{not json"))
		require.Error(t, err)
		_, err = a.Assert([]byte(`{"publicKey":{"rpId":"` + testRPID + `"}}`))
		require.Error(t, err)
	})
}

func TestNewRefusesDifferentOrigin(t *testing.T) {
	key := newKey(t)
	for _, origin := range []string{
		"https://evil.example.org",             // unrelated host
		"https://notcontroller.example.test",   // suffix without a label boundary
		"http://controller.example.test",       // not https
		"https://controller.example.test/path", // not an origin
		"https://u@controller.example.test",    // userinfo
		"controller.example.test",              // no scheme
		"",
	} {
		_, err := New(Config{Signer: key, RPID: testRPID, Origin: origin, CredentialID: []byte("id")})
		assert.Error(t, err, "origin %q", origin)
	}

	_, err := New(Config{Signer: key, RPID: testRPID, Origin: "https://app.controller.example.test:8443", CredentialID: []byte("id")})
	assert.NoError(t, err, "a subdomain of the RP ID on a non-default port is a valid origin")
}

// An authenticator bound to an origin the relying party does not accept still
// produces a response the library rejects: the origin is verified server-side.
func TestRelyingPartyRejectsOtherOriginResponses(t *testing.T) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID: testRPID, RPDisplayName: "CFGMS test",
		RPOrigins: []string{"https://other.controller.example.test"},
	})
	require.NoError(t, err)
	a := newAuth(t, newKey(t))
	user := &testUser{}
	opts, session := beginRegistration(t, wa, user)
	resp, err := a.Register(opts)
	require.NoError(t, err)
	_, err = wa.FinishRegistration(user, *session, jsonRequest(resp))
	require.Error(t, err)
}

func TestNewValidatesConfig(t *testing.T) {
	good := Config{Signer: newKey(t), RPID: testRPID, Origin: testOrigin, CredentialID: []byte("id")}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cases := map[string]func(*Config){
		"nil signer":          func(c *Config) { c.Signer = nil },
		"non P-256 key":       func(c *Config) { c.Signer = p384 },
		"empty rp id":         func(c *Config) { c.RPID = "" },
		"empty credential":    func(c *Config) { c.CredentialID = nil },
		"oversize credential": func(c *Config) { c.CredentialID = make([]byte, maxCredentialIDLen+1) },
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := good
			m(&cfg)
			_, err := New(cfg)
			assert.Error(t, err)
		})
	}
}

// Negative controls: the library must reject a tampered assertion, proving the
// positive tests exercise real signature and challenge verification.
func TestTamperedAssertionsFailVerification(t *testing.T) {
	wa := newRP(t)
	a := newAuth(t, newKey(t))
	_, user := register(t, wa, a)

	t.Run("corrupted signature", func(t *testing.T) {
		opts, session := beginLogin(t, wa, user, false)
		resp, err := a.Assert(opts)
		require.NoError(t, err)

		var r protocol.CredentialAssertionResponse
		require.NoError(t, json.Unmarshal(resp, &r))
		sig := append([]byte(nil), r.AssertionResponse.Signature...)
		sig[len(sig)-1] ^= 0xff
		r.AssertionResponse.Signature = sig
		bad, err := json.Marshal(r)
		require.NoError(t, err)

		_, err = wa.FinishLogin(user, *session, jsonRequest(bad))
		require.Error(t, err)
	})

	t.Run("wrong challenge", func(t *testing.T) {
		opts, _ := beginLogin(t, wa, user, false)
		_, otherSession := beginLogin(t, wa, user, false)
		resp, err := a.Assert(opts)
		require.NoError(t, err)

		_, err = wa.FinishLogin(user, *otherSession, jsonRequest(resp))
		require.Error(t, err)
	})

	t.Run("signature from another key", func(t *testing.T) {
		impostor := newAuth(t, newKey(t), func(c *Config) { c.CredentialID = a.CredentialID() })
		opts, session := beginLogin(t, wa, user, false)
		resp, err := impostor.Assert(opts)
		require.NoError(t, err)

		_, err = wa.FinishLogin(user, *session, jsonRequest(resp))
		require.Error(t, err)
	})
}

// failingSigner returns an error that embeds a recognisable string; the package
// must not pass it through.
type failingSigner struct{ crypto.Signer }

func (f failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("backend leaked SECRET-DETAIL")
}

func TestNoPrivateKeyMaterialInOutputsOrErrors(t *testing.T) {
	wa := newRP(t)
	key := newKey(t)
	a := newAuth(t, key)
	secrets := [][]byte{key.D.Bytes(), []byte(key.D.Text(16)), []byte(key.D.String())}

	user := &testUser{}
	regOpts, _ := beginRegistration(t, wa, user)
	regResp, err := a.Register(regOpts)
	require.NoError(t, err)

	cred, user := register(t, wa, a)
	_ = cred
	loginOpts, _ := beginLogin(t, wa, user, true)
	loginResp, err := a.Assert(loginOpts)
	require.NoError(t, err)

	var errTexts []string
	_, rerr := a.Register([]byte("{bad"))
	errTexts = append(errTexts, rerr.Error())
	_, rerr = a.Assert([]byte("{bad"))
	errTexts = append(errTexts, rerr.Error())
	_, rerr = New(Config{Signer: key, RPID: testRPID, Origin: "https://evil.example.org", CredentialID: []byte("id")})
	errTexts = append(errTexts, rerr.Error())

	fs := failingSigner{Signer: key}
	failing := newAuth(t, fs)
	_, rerr = failing.Assert(loginOpts)
	require.Error(t, rerr)
	assert.NotContains(t, rerr.Error(), "SECRET-DETAIL", "signer errors must not be passed through")
	errTexts = append(errTexts, rerr.Error())

	for _, s := range secrets {
		for _, out := range [][]byte{regResp, loginResp} {
			assert.False(t, bytes.Contains(out, s), "response contains private scalar bytes")
		}
		for _, e := range errTexts {
			assert.False(t, strings.Contains(e, string(s)), "error contains private scalar")
		}
	}
}

// recordingAttester returns a fixed statement and records what it was asked to
// certify. The real TPM-backed Attester is exercised against a software TPM in
// pkg/softauthn/tpmkey; here only the encoding and wiring of Register are checked.
type recordingAttester struct {
	stmt           *TPMStatement
	err            error
	authData       []byte
	clientDataHash []byte
}

func (r *recordingAttester) AttestTPM(authData, clientDataHash []byte) (*TPMStatement, error) {
	r.authData = append([]byte(nil), authData...)
	r.clientDataHash = append([]byte(nil), clientDataHash...)
	return r.stmt, r.err
}

func cannedStatement() *TPMStatement {
	return &TPMStatement{
		X5C:        [][]byte{[]byte("carrier-cert"), []byte("second-cert")},
		Sig:        []byte("signature"),
		CertInfo:   []byte("cert-info"),
		PubArea:    []byte("pub-area"),
		Activation: []byte("activation-secret"),
	}
}

func registerRaw(t *testing.T, a *Authenticator) protocol.CredentialCreationResponse {
	t.Helper()
	opts, _ := beginRegistration(t, newRP(t), &testUser{})
	resp, err := a.Register(opts)
	require.NoError(t, err)
	var out protocol.CredentialCreationResponse
	require.NoError(t, json.Unmarshal(resp, &out))
	return out
}

// With no Attester the attestation object is exactly {fmt:none, attStmt:{}, authData}
// as it has always been, and it carries the CFGMS AAGUID.
func TestRegisterWithoutAttesterIsByteIdenticalFmtNone(t *testing.T) {
	a := newAuth(t, newKey(t))
	out := registerRaw(t, a)
	authData := out.AttestationResponse.AuthenticatorData

	want := []byte{0xa3}
	want = append(want, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e')
	want = append(want, 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0)
	want = append(want, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', 0x58, byte(len(authData)))
	require.Less(t, len(authData), 256)
	want = append(want, authData...)
	assert.Equal(t, want, []byte(out.AttestationResponse.AttestationObject))

	assert.Equal(t, AAGUID[:], []byte(authData[37:53]), "authData carries softauthn.AAGUID")
}

func TestRegisterWithAttesterEmitsFmtTPM(t *testing.T) {
	key := newKey(t)
	att := &recordingAttester{stmt: cannedStatement()}
	a := newAuth(t, key, func(c *Config) { c.Attester = att })

	opts, _ := beginRegistration(t, newRP(t), &testUser{})
	resp, err := a.Register(opts)
	require.NoError(t, err)

	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	require.NoError(t, err)
	obj := parsed.Response.AttestationObject
	assert.Equal(t, "tpm", obj.Format)
	assert.Equal(t, AAGUID[:], obj.AuthData.AttData.AAGUID, "an attester cannot change the AAGUID")
	assert.Equal(t, "2.0", obj.AttStatement["ver"])
	assert.EqualValues(t, -7, obj.AttStatement["alg"])
	assert.Equal(t, []any{[]byte("carrier-cert"), []byte("second-cert")}, obj.AttStatement["x5c"])
	assert.Equal(t, []byte("signature"), obj.AttStatement["sig"])
	assert.Equal(t, []byte("cert-info"), obj.AttStatement["certInfo"])
	assert.Equal(t, []byte("pub-area"), obj.AttStatement["pubArea"])
	assert.Equal(t, []byte("activation-secret"), obj.AttStatement["cfgmsActivation"])

	// The credential public key in the attestation is the signer's public key.
	k, err := webauthncose.ParsePublicKey(obj.AuthData.AttData.CredentialPublicKey)
	require.NoError(t, err)
	ec, ok := k.(webauthncose.EC2PublicKeyData)
	require.True(t, ok)
	assert.Equal(t, key.X.FillBytes(make([]byte, 32)), ec.XCoord)
	assert.Equal(t, key.Y.FillBytes(make([]byte, 32)), ec.YCoord)

	// The attester was asked to certify exactly this registration.
	assert.Equal(t, []byte(parsed.Raw.AttestationResponse.AuthenticatorData), att.authData)
	cdHash := sha256.Sum256(parsed.Raw.AttestationResponse.ClientDataJSON)
	assert.Equal(t, cdHash[:], att.clientDataHash)
}

func TestRegisterWithAttesterRefusals(t *testing.T) {
	incomplete := func(mutate func(*TPMStatement)) *TPMStatement {
		s := cannedStatement()
		mutate(s)
		return s
	}
	cases := map[string]*recordingAttester{
		"attester error": {err: errors.New("tpm unavailable")},
		"nil statement":  {},
		"no chain":       {stmt: incomplete(func(s *TPMStatement) { s.X5C = nil })},
		"no sig":         {stmt: incomplete(func(s *TPMStatement) { s.Sig = nil })},
		"no certInfo":    {stmt: incomplete(func(s *TPMStatement) { s.CertInfo = nil })},
		"no pubArea":     {stmt: incomplete(func(s *TPMStatement) { s.PubArea = nil })},
		"no activation":  {stmt: incomplete(func(s *TPMStatement) { s.Activation = nil })},
	}
	for name, att := range cases {
		t.Run(name, func(t *testing.T) {
			a := newAuth(t, newKey(t), func(c *Config) { c.Attester = att })
			opts, _ := beginRegistration(t, newRP(t), &testUser{})
			resp, err := a.Register(opts)
			require.Error(t, err)
			assert.Nil(t, resp, "a failed attestation must not yield a response that falls back to none")
		})
	}
}
