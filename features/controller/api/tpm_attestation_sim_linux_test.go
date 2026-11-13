// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux && cgo

// Issue #6227: a root agent account's registration with a genuine producer. The
// credential key, the attestation key and the activation come from the real client
// library pkg/softauthn/tpmkey running against a software TPM (tpmkeytest) provisioned
// with an endorsement certificate from a CA generated at test time, which is the one
// root the controller trusts here. There is no second attestation producer in this
// file; the negative cases use only the wrong-output helpers tpmkeytest exports.
//
// Every other component is real: the account and audit stores, the WebAuthn relying
// party and the four registration handlers.

package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/softauthn/tpmkey"
	"github.com/cfgis/cfgms/pkg/softauthn/tpmkey/tpmkeytest"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const tpmtAgent = "agent-tpm"

// tpmtRoute is one registration route: begin and finish carry a body, and a success
// emits addedAction.
type tpmtRoute struct {
	name        string
	addedAction string
	begin       func(t *testing.T, server *Server, token string, body []byte) *httptest.ResponseRecorder
	finish      func(t *testing.T, server *Server, token string, body []byte) *httptest.ResponseRecorder
}

var tpmtRoutes = []tpmtRoute{
	{
		name: "admin register route", addedAction: "account.passkey_added",
		begin: func(t *testing.T, server *Server, _ string, body []byte) *httptest.ResponseRecorder {
			t.Helper()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/accounts/"+tpmtAgent+"/webauthn/register/begin", bytes.NewReader(body))
			req = withPrincipal(withVars(req, map[string]string{"username": tpmtAgent}), testAdminPrincipal())
			rec := httptest.NewRecorder()
			server.handleWebAuthnRegisterBegin(rec, req)
			return rec
		},
		finish: func(t *testing.T, server *Server, _ string, body []byte) *httptest.ResponseRecorder {
			t.Helper()
			return doFinish(t, server, tpmtAgent, bytes.NewReader(body))
		},
	},
	{
		name: "enrollment-token route", addedAction: "account.passkey_enrolled",
		begin: func(t *testing.T, server *Server, token string, body []byte) *httptest.ResponseRecorder {
			t.Helper()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/enroll/begin", bytes.NewReader(body))
			req.Header.Set(enrollmentTokenHeader, token)
			rec := httptest.NewRecorder()
			server.handlePasskeyEnrollBegin(rec, req)
			return rec
		},
		finish: func(t *testing.T, server *Server, token string, body []byte) *httptest.ResponseRecorder {
			t.Helper()
			return doEnrollFinish(t, server, token, bytes.NewReader(body))
		},
	},
}

// tpmtFixture is a root agent account on a controller that trusts the software TPM's
// CA, and the client side: a software TPM and the Prepare result the begin body carries.
type tpmtFixture struct {
	t        *testing.T
	route    tpmtRoute
	server   *Server
	token    string
	tpm      *tpmkeytest.TPM
	prepared *tpmkey.Prepared
}

func newTPMTFixture(t *testing.T, route tpmtRoute) *tpmtFixture {
	t.Helper()
	// The root-agent setting is on: the requirement does not depend on it, but the
	// registration policy that runs after the attestation check does.
	server, token := newRootAgentPolicyServer(t, true, rootAgentSpec{username: tpmtAgent, flag: true})
	tpm := tpmkeytest.Start(t, tpmkeytest.Options{})
	pool := x509.NewCertPool()
	pool.AddCert(tpm.CA)
	server.SetRootAgentTPMRoots(pool)
	prepared, err := tpmkey.Prepare(tpm)
	require.NoError(t, err)
	return &tpmtFixture{t: t, route: route, server: server, token: token, tpm: tpm, prepared: prepared}
}

// beginBody is the begin request body a correct client sends.
func (f *tpmtFixture) beginBody() []byte {
	return f.beginBodyFor(f.prepared.AKPublic)
}

func (f *tpmtFixture) beginBodyFor(akPublic []byte) []byte {
	f.t.Helper()
	body, err := json.Marshal(map[string]any{"tpm": map[string]any{
		"ek_cert_chain": f.prepared.EKCertChain, "ak_public": akPublic,
	}})
	require.NoError(f.t, err)
	return body
}

func (f *tpmtFixture) begin(body []byte) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.route.begin(f.t, f.server, f.token, body)
}

func (f *tpmtFixture) finish(body []byte) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.route.finish(f.t, f.server, f.token, body)
}

// tpmtBegun is a successful begin: the creation options the authenticator answers and
// the controller's activation challenge.
type tpmtBegun struct {
	options   []byte
	challenge tpmChallenge
}

func (f *tpmtFixture) mustBegin() tpmtBegun {
	f.t.Helper()
	options := beginData(f.t, f.begin(f.beginBody()))
	var extra struct {
		CfgmsTpm tpmChallenge `json:"cfgmsTpm"`
	}
	require.NoError(f.t, json.Unmarshal(options, &extra))
	return tpmtBegun{options: options, challenge: extra.CfgmsTpm}
}

// tpmtRespond selects how the client answers a begin; the zero value is the correct client.
type tpmtRespond struct {
	blobs  *tpmkey.Blobs                               // credential key; nil makes a correct one
	secret []byte                                      // activation secret; nil activates the challenge
	wrap   func(softauthn.Attester) softauthn.Attester // wrong-output helper
}

// respond answers a begin with the real client library and returns the finish body.
func (f *tpmtFixture) respond(b tpmtBegun, r tpmtRespond) []byte {
	f.t.Helper()
	body, _ := f.respondAs(b, r)
	return body
}

// respondAs is respond that also returns the authenticator that registered, which holds
// the account's user handle and signs later assertions with the TPM-held key.
func (f *tpmtFixture) respondAs(b tpmtBegun, r tpmtRespond) ([]byte, *softauthn.Authenticator) {
	f.t.Helper()
	blobs := r.blobs
	if blobs == nil {
		made, _, err := tpmkey.Create(f.tpm)
		require.NoError(f.t, err)
		blobs = &made
	}
	secret := r.secret
	if secret == nil {
		var err error
		secret, err = tpmkey.Activate(f.tpm, f.prepared, b.challenge.CredentialBlob, b.challenge.EncryptedSecret)
		require.NoError(f.t, err)
	}
	signer, err := tpmkey.Open(f.tpm, *blobs)
	require.NoError(f.t, err)
	attester := tpmkey.NewAttester(f.tpm, *blobs, secret)
	if r.wrap != nil {
		attester = r.wrap(attester)
	}
	credID := make([]byte, 32)
	_, err = rand.Read(credID)
	require.NoError(f.t, err)
	a, err := softauthn.New(softauthn.Config{
		Signer: signer, RPID: aaguidRPID, Origin: aaguidOrigin, CredentialID: credID, Attester: attester,
	})
	require.NoError(f.t, err)
	body, err := a.Register(b.options)
	require.NoError(f.t, err)
	return body, a
}

// login runs the usernameless passkey login with auth and returns the finish response.
func (f *tpmtFixture) login(auth *softauthn.Authenticator) *httptest.ResponseRecorder {
	f.t.Helper()
	webCfg := session.Config{IdleTimeout: 60 * time.Minute, AbsoluteTimeout: 12 * time.Hour, GraceWindow: 30 * time.Second}
	store := session.NewMemStore(webCfg, time.Now)
	f.t.Cleanup(store.Close)
	f.server.SetWebSessionManager(session.NewManager(webCfg, store, time.Now))

	const csrf = "pre-session-csrf"
	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/begin", nil)
	beginReq.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrf})
	beginReq.Header.Set(headerCSRFToken, csrf)
	begin := httptest.NewRecorder()
	f.server.handlePasskeyLoginBegin(begin, beginReq)
	require.Equal(f.t, http.StatusOK, begin.Code, begin.Body.String())
	var ceremony *http.Cookie
	for _, c := range begin.Result().Cookies() {
		if c.Name == cookiePasskeyCeremony {
			ceremony = c
		}
	}
	require.NotNil(f.t, ceremony)
	assertion, err := auth.Assert(beginData(f.t, begin))
	require.NoError(f.t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", bytes.NewReader(assertion))
	req.AddCookie(ceremony)
	rec := httptest.NewRecorder()
	f.server.handlePasskeyLoginFinish(rec, req)
	return rec
}

func (f *tpmtFixture) credentialCount() int {
	return rootAgentCredentialCount(f.t, f.server, tpmtAgent)
}

// auditEvents returns the recorded events for action.
func tpmtAuditEvents(t *testing.T, server *Server, action string) []*business.AuditEntry {
	t.Helper()
	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{Actions: []string{action}})
	require.NoError(t, err)
	return entries
}

// requireRefused asserts a refusal: an error status, nothing stored, and a denied audit
// event under action with the named reason.
func (f *tpmtFixture) requireRefused(rec *httptest.ResponseRecorder, wantStatus int, wantCode, action, wantReason string) {
	f.t.Helper()
	assert.Equal(f.t, wantStatus, rec.Code, rec.Body.String())
	assert.Equal(f.t, wantCode, errCode(f.t, rec.Body.Bytes()))
	assert.Zero(f.t, f.credentialCount(), "nothing is stored on refusal")
	events := tpmtAuditEvents(f.t, f.server, action)
	require.NotEmpty(f.t, events, "a refusal is audited under %s", action)
	last := events[len(events)-1]
	assert.Equal(f.t, wantReason, last.Details["reason"])
	assert.Equal(f.t, business.AuditResultDenied, last.Result)
	assert.Equal(f.t, true, last.Details[auditKeyRootScope])
	assert.NotContains(f.t, rec.Body.String(), wantReason, "the response does not say which check failed")
}

func TestRootAgentRegistration_TPMAttested(t *testing.T) {
	for _, route := range tpmtRoutes {
		t.Run(route.name, func(t *testing.T) {
			f := newTPMTFixture(t, route)
			begun := f.mustBegin()

			var opts struct {
				PublicKey struct {
					Attestation string `json:"attestation"`
				} `json:"publicKey"`
			}
			require.NoError(t, json.Unmarshal(begun.options, &opts))
			assert.Equal(t, "direct", opts.PublicKey.Attestation, "direct attestation is requested for this ceremony")
			assert.NotEmpty(t, begun.challenge.CredentialBlob, "the options carry the cfgmsTpm member")
			assert.NotEmpty(t, begun.challenge.EncryptedSecret)

			body, auth := f.respondAs(begun, tpmtRespond{})
			rec := f.finish(body)
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

			stored, err := f.server.loadAccountFromStore(context.Background(), tpmtAgent, "")
			require.NoError(t, err)
			require.Len(t, stored.Credentials, 1)
			cred := stored.Credentials[0]
			assert.True(t, cred.tpmAttested())
			assert.Equal(t, "tpm", cred.AttestationFormat)
			assert.True(t, cred.isSoftwareAuthenticator())

			ekCert, err := x509.ParseCertificate(f.tpm.EKCertificate)
			require.NoError(t, err)
			der, err := x509.MarshalPKIXPublicKey(ekCert.PublicKey)
			require.NoError(t, err)
			keyHash := sha256.Sum256(der)
			rcd := cred.TPMAttestation
			require.NotNil(t, rcd)
			assert.Equal(t, tpmkeytest.Manufacturer, rcd.EKManufacturer)
			assert.Equal(t, "id:00000000", rcd.EKModel)
			assert.Equal(t, "id:20260101", rcd.EKFirmware)
			assert.Equal(t, f.tpm.CA.Subject.String(), rcd.EKIssuer)
			assert.Equal(t, ekCert.SerialNumber.Text(16), rcd.EKSerial)
			assert.Equal(t, hex.EncodeToString(keyHash[:]), rcd.EKPublicSHA256)
			assert.False(t, rcd.VerifiedAt.IsZero())

			events := tpmtAuditEvents(t, f.server, route.addedAction)
			require.Len(t, events, 1)
			d := events[0].Details
			assert.Equal(t, true, d["tpm_attested"])
			assert.Equal(t, rcd.EKManufacturer, d["ek_manufacturer"])
			assert.Equal(t, rcd.EKModel, d["ek_model"])
			assert.Equal(t, rcd.EKFirmware, d["ek_firmware"])
			assert.Equal(t, rcd.EKIssuer, d["ek_issuer"])
			assert.Equal(t, rcd.EKSerial, d["ek_serial"])
			assert.Equal(t, rcd.EKPublicSHA256, d["ek_public_sha256"])
			assert.Equal(t, "tpm", d["attestation_format"])

			// The attested credential is usable: the use-time view keeps it.
			view, err := f.server.permittedAccountView(context.Background(), stored)
			require.NoError(t, err)
			assert.Len(t, view.Credentials, 1)

			// It signs in: the TPM-held key signs the assertion the controller verifies.
			login := f.login(auth)
			assert.Equal(t, http.StatusOK, login.Code, login.Body.String())

			// The list shows it as TPM-attested.
			list := doListCredentials(t, f.server, tpmtAgent)
			require.Equal(t, http.StatusOK, list.Code, list.Body.String())
			assert.Contains(t, list.Body.String(), `"tpm_attested":true`)
		})
	}
}

func TestRootAgentRegistration_Refused(t *testing.T) {
	const (
		denied      = registrationDeniedAction
		beginDenied = registrationBeginDeniedAction
	)
	otherAAGUID := [16]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	cases := []struct {
		name string
		run  func(t *testing.T, f *tpmtFixture)
	}{
		{"no tpm body at begin (tpm_attestation_required)", func(t *testing.T, f *tpmtFixture) {
			rec := f.begin(nil)
			f.requireRefused(rec, http.StatusBadRequest, errCodeTPMAttestationRequired, beginDenied, reasonTPMAttestationRequired)
		}},
		{"an oversized body at begin (tpm_attestation_required)", func(t *testing.T, f *tpmtFixture) {
			rec := f.begin([]byte(`{"tpm":{"ek_cert_chain":["` + strings.Repeat("A", tpmBeginBodyLimit) + `"],"ak_public":"AA=="}}`))
			f.requireRefused(rec, http.StatusBadRequest, errCodeTPMAttestationRequired, beginDenied, reasonTPMAttestationRequired)
		}},
		{"attestation format none (tpm_attestation_format)", func(t *testing.T, f *tpmtFixture) {
			begun := f.mustBegin()
			resp, err := newSoftAuthenticator(t, nil).Register(begun.options)
			require.NoError(t, err)
			f.requireRefused(f.finish(resp), http.StatusForbidden, errCodeTPMAttestationRefused, denied, reasonTPMAttestationFormat)
		}},
		{"a non-CFGMS AAGUID with format none (tpm_attestation_format): the trigger is the account", func(t *testing.T, f *tpmtFixture) {
			begun := f.mustBegin()
			resp, err := newSoftAuthenticator(t, &otherAAGUID).Register(begun.options)
			require.NoError(t, err)
			f.requireRefused(f.finish(resp), http.StatusForbidden, errCodeTPMAttestationRefused, denied, reasonTPMAttestationFormat)
		}},
		{"an EK chain to a root not in the configured set (tpm_ek_chain)", func(t *testing.T, f *tpmtFixture) {
			pool := x509.NewCertPool()
			pool.AddCert(newTPMTestPKI(t).root)
			f.server.SetRootAgentTPMRoots(pool)
			f.requireRefused(f.begin(f.beginBody()), http.StatusForbidden, errCodeTPMAttestationRefused, beginDenied, reasonTPMEKChain)
		}},
		{"no trusted roots configured (tpm_no_trusted_roots)", func(t *testing.T, f *tpmtFixture) {
			f.server.SetRootAgentTPMRoots(nil)
			f.requireRefused(f.begin(f.beginBody()), http.StatusForbidden, errCodeTPMAttestationRefused, beginDenied, reasonTPMNoTrustedRoots)
		}},
		{"a wrong activation secret (tpm_activation_failed)", func(t *testing.T, f *tpmtFixture) {
			begun := f.mustBegin()
			body := f.respond(begun, tpmtRespond{wrap: tpmkeytest.TamperedActivation})
			f.requireRefused(f.finish(body), http.StatusForbidden, errCodeTPMAttestationRefused, denied, reasonTPMActivationFailed)
		}},
		{"x5c[0] holds another key than the AK sent at begin (tpm_ak_mismatch)", func(t *testing.T, f *tpmtFixture) {
			// Begin names a different, well-formed attestation key; the TPM cannot
			// activate a challenge made for it, so the client answers with a secret of
			// its own and the real attestation key. The key check comes first.
			begun := tpmtBegun{}
			rec := f.begin(f.beginBodyFor(tpmtAKPublic(t, &tpmtECKey(t).PublicKey, nil)))
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			begun.options = beginData(t, rec)
			body := f.respond(begun, tpmtRespond{secret: bytes.Repeat([]byte{5}, tpmSecretLen)})
			f.requireRefused(f.finish(body), http.StatusForbidden, errCodeTPMAttestationRefused, denied, reasonTPMAKMismatch)
		}},
		{"a certified key without fixedTPM or fixedParent (tpm_key_not_fixed)", func(t *testing.T, f *tpmtFixture) {
			begun := f.mustBegin()
			movable, err := tpmkeytest.KeyWithoutFixedTPM(f.tpm)
			require.NoError(t, err)
			body := f.respond(begun, tpmtRespond{blobs: &movable})
			f.requireRefused(f.finish(body), http.StatusForbidden, errCodeTPMAttestationRefused, denied, reasonTPMKeyNotFixed)
		}},
		{"an attestation replayed from another ceremony (tpm_attestation_invalid)", func(t *testing.T, f *tpmtFixture) {
			first := f.mustBegin()
			firstBody := f.respond(first, tpmtRespond{})
			second := f.mustBegin() // replaces the pending session
			secondBody := f.respond(second, tpmtRespond{})

			// The replay carries the second ceremony's client data (so the challenge,
			// origin and RP ID match the pending session) around the first ceremony's
			// attestation object, whose certInfo binds the first ceremony's data.
			var a, b map[string]any
			require.NoError(t, json.Unmarshal(firstBody, &a))
			require.NoError(t, json.Unmarshal(secondBody, &b))
			aResp, _ := a["response"].(map[string]any)
			bResp, _ := b["response"].(map[string]any)
			require.NotNil(t, aResp)
			require.NotNil(t, bResp)
			bResp["attestationObject"] = aResp["attestationObject"]
			replay, err := json.Marshal(b)
			require.NoError(t, err)

			f.requireRefused(f.finish(replay), http.StatusBadRequest, "WEBAUTHN_VERIFY_ERROR", denied, reasonTPMAttestationInvalid)
		}},
	}

	for _, route := range tpmtRoutes {
		for _, tt := range cases {
			t.Run(route.name+"/"+tt.name, func(t *testing.T) {
				tt.run(t, newTPMTFixture(t, route))
			})
		}
	}
}

// The same attestation presented twice: the pending session, and with it the activation
// secret, is consumed by the first finish, so the second finds none. This holds after a
// success and after a refusal.
func TestRootAgentRegistration_AttestationIsSingleUse(t *testing.T) {
	for _, route := range tpmtRoutes {
		t.Run(route.name+"/after a success", func(t *testing.T) {
			f := newTPMTFixture(t, route)
			body := f.respond(f.mustBegin(), tpmtRespond{})
			require.Equal(t, http.StatusCreated, f.finish(body).Code)

			second := f.finish(body)
			assert.Equal(t, http.StatusBadRequest, second.Code, second.Body.String())
			assert.Contains(t, []string{"NO_ACTIVE_REGISTRATION", "NO_ACTIVE_ENROLLMENT"}, errCode(t, second.Body.Bytes()))
			assert.Equal(t, 1, f.credentialCount(), "the credential was stored once")
		})
		t.Run(route.name+"/after a refusal", func(t *testing.T) {
			f := newTPMTFixture(t, route)
			begun := f.mustBegin()
			body := f.respond(begun, tpmtRespond{wrap: tpmkeytest.TamperedActivation})
			require.Equal(t, http.StatusForbidden, f.finish(body).Code)

			second := f.finish(f.respond(begun, tpmtRespond{}))
			assert.Equal(t, http.StatusBadRequest, second.Code, second.Body.String())
			assert.Contains(t, []string{"NO_ACTIVE_REGISTRATION", "NO_ACTIVE_ENROLLMENT"}, errCode(t, second.Body.Bytes()))
			assert.Zero(t, f.credentialCount())
		})
	}
}

// A root agent begin that the controller refuses starts no ceremony: nothing is pending,
// so a finish finds no session.
func TestRootAgentRegistration_RefusedBeginStartsNoCeremony(t *testing.T) {
	for _, route := range tpmtRoutes {
		t.Run(route.name, func(t *testing.T) {
			f := newTPMTFixture(t, route)
			require.Equal(t, http.StatusBadRequest, f.begin(nil).Code)

			rec := f.finish([]byte("{}"))
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, []string{"NO_ACTIVE_REGISTRATION", "NO_ACTIVE_ENROLLMENT"}, errCode(t, rec.Body.Bytes()))
			assert.Zero(t, f.credentialCount())
		})
	}
}
