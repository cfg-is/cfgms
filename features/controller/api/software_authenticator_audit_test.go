// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6144: every use of a software-authenticator credential (login, presence,
// elevation, operator-payload sign, workflow publish, run-command proof) is marked in
// the audit trail with software_authenticator, the credential ID and the AAGUID. A use
// of any other credential carries software_authenticator: false.
//
// Every component is real: the account and session stores, the audit manager, the
// WebAuthn relying party and the ceremony handlers (the enfFixture of the enforcement
// tests). The credentials are real ECDSA keys generated at test time; the "software"
// label is the AAGUID recorded on the stored credential, as at registration.

package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/testutil/webauthntest"
)

// markedEvents returns every audit event that carries the software_authenticator field.
func (f *enfFixture) markedEvents(t *testing.T) []*business.AuditEntry {
	t.Helper()
	require.NoError(t, f.server.auditManager.Flush(context.Background()))
	entries, err := f.server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{})
	require.NoError(t, err)
	var marked []*business.AuditEntry
	for _, e := range entries {
		if _, ok := e.Details[auditKeySoftwareAuthenticator]; ok {
			marked = append(marked, e)
		}
	}
	return marked
}

// auditCeremony runs one use of a credential and reports whether it was accepted; the
// credential ID is recorded in credEnc, the encoding the ceremony's event uses.
type auditCeremony struct {
	name    string
	credEnc func(id []byte) string
	run     func(t *testing.T, f *enfFixture, soft bool) bool
}

func base64URLID(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }
func hexID(id []byte) string       { return hex.EncodeToString(id) }

// runCommandDispatch posts a WebAuthn-proved run command through handlePostRunCommand.
func (f *enfFixture) runCommandDispatch(t *testing.T, soft bool) bool {
	t.Helper()
	const steward = "steward-1"
	require.NoError(t, f.server.controllerService.RegisterSteward(steward, "client-"+steward, "", "active"))
	f.server.SetRunManager(newTestRunManager(t), newTestRunQueue(t))
	f.server.fleetQuery = &staticRunFleetQuery{results: []fleet.StewardResult{{ID: steward, TenantID: enfTenant}}}
	f.server.certManager = newTLSTestCertManager(t)
	ensureSharedSigningCertificate(t, f.server.certManager)

	key, id := f.credential(soft)
	f.sess++
	env := operatorpayload.Envelope{
		Content: []byte("echo hello"), Shell: "bash", Targets: []string{steward},
		Nonce: fmt.Sprintf("audit-nonce-%d", f.sess), ExpiresAt: time.Now().Add(3 * time.Minute).Truncate(time.Second),
	}
	hash, err := operatorpayload.ChallengeHash(env)
	require.NoError(t, err)
	proof := actionProof(t, key, id, hash)
	b64 := base64.StdEncoding.EncodeToString
	body := map[string]interface{}{
		"target": "id:" + steward, "content": b64(env.Content), "shell": env.Shell,
		"webauthn": map[string]interface{}{
			"authenticator_data": b64(proof.AuthenticatorData), "client_data_json": b64(proof.ClientDataJSON),
			"signature": b64(proof.Signature), "credential_id": b64(proof.CredentialID),
		},
		"targets": env.Targets, "nonce": env.Nonce, "expires_at": env.ExpiresAt.UTC().Format(time.RFC3339),
	}
	p := &Principal{ID: f.accountID, TenantID: enfTenant, Assurance: session.AssuranceStrong, AccountBound: true}
	rec := postRunWithPrincipal(t, f.server.handlePostRunCommand, "/api/v1/runs/command", p, body)
	return rec.Code == http.StatusOK
}

func auditCeremonies() []auditCeremony {
	byName := map[string]ceremony{}
	for _, c := range enfCeremonies() {
		byName[c.name] = c
	}
	use := func(name string, enc func([]byte) string) auditCeremony {
		return auditCeremony{name: name, credEnc: enc, run: byName[name].run}
	}
	return []auditCeremony{
		use("passkey login", base64URLID),
		use("presence begin/finish", base64URLID),
		use("step-up elevate", base64URLID),
		// The sign finish and the run-command dispatch write the operator_payload.dispatch
		// event, which has always recorded its credential_id in hex.
		use("operator-payload sign", hexID),
		use("workflow publish", base64URLID),
		{name: "run-command dispatch", credEnc: hexID, run: func(t *testing.T, f *enfFixture, soft bool) bool {
			return f.runCommandDispatch(t, soft)
		}},
	}
}

// assertMarked requires exactly one event to carry the marker and returns it after
// checking the marker, the credential ID and the AAGUID.
func assertMarked(t *testing.T, events []*business.AuditEntry, wantSoftware bool, credID, wantAAGUID string) *business.AuditEntry {
	t.Helper()
	require.Len(t, events, 1, "exactly one audit event must carry software_authenticator")
	e := events[0]
	assert.Equal(t, wantSoftware, e.Details[auditKeySoftwareAuthenticator])
	assert.Equal(t, wantAAGUID, e.Details[auditKeyAAGUID])
	assert.Equal(t, credID, e.Details[auditKeyCredentialID])
	return e
}

// [REQUIRED TEST] Each use of a software credential writes exactly one event carrying
// software_authenticator: true, the credential ID and the AAGUID.
func TestSoftwareAuthenticatorAudit_SoftwareCredentialUseIsMarked(t *testing.T) {
	for _, c := range auditCeremonies() {
		t.Run(c.name, func(t *testing.T) {
			f := newEnfFixture(t, true, true)
			require.True(t, c.run(t, f, true), "the software credential must be accepted")

			e := assertMarked(t, f.markedEvents(t), true, c.credEnc(f.softID), hex.EncodeToString(softauthn.AAGUID[:]))
			assert.Equal(t, business.AuditResultSuccess, e.Result)
		})
	}
}

// [REQUIRED TEST] The same operations with a credential that does not carry the CFGMS
// AAGUID record software_authenticator: false.
func TestSoftwareAuthenticatorAudit_OtherCredentialUseIsMarkedFalse(t *testing.T) {
	for _, c := range auditCeremonies() {
		t.Run(c.name, func(t *testing.T) {
			f := newEnfFixture(t, true, true)
			require.True(t, c.run(t, f, false), "the other credential must be accepted")

			e := assertMarked(t, f.markedEvents(t), false, c.credEnc(f.hwID), hex.EncodeToString(make([]byte, 16)))
			assert.Equal(t, business.AuditResultSuccess, e.Result)
		})
	}
}

// [REQUIRED TEST] A login whose assertion carries a bad signature still writes the
// failure event, marked as a software authenticator.
func TestSoftwareAuthenticatorAudit_FailedLoginIsMarked(t *testing.T) {
	f := newEnfFixture(t, true, true)
	rec := f.passkeyLoginWith(t, true, webauthntest.WithCorruptSignature())
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	e := assertMarked(t, f.markedEvents(t), true, base64URLID(f.softID), hex.EncodeToString(softauthn.AAGUID[:]))
	assert.Equal(t, "web.passkey.login.failure", e.Action)
	assert.Equal(t, business.AuditResultFailure, e.Result)
	assert.NotContains(t, e.Details, auditKeyReason, "a bad signature is not a policy refusal")
}

// A failed login by another credential still writes the failure event, marked false.
func TestSoftwareAuthenticatorAudit_FailedLoginOtherCredentialIsMarkedFalse(t *testing.T) {
	f := newEnfFixture(t, true, true)
	rec := f.passkeyLoginWith(t, false, webauthntest.WithCorruptSignature())
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	e := assertMarked(t, f.markedEvents(t), false, base64URLID(f.hwID), hex.EncodeToString(make([]byte, 16)))
	assert.Equal(t, "web.passkey.login.failure", e.Action)
}

// [REQUIRED TEST] A use the policy refuses writes an event with software_authenticator:
// true, the credential ID, the AAGUID and a denied outcome, for login and for sign finish.
func TestSoftwareAuthenticatorAudit_PolicyRefusedUseIsDenied(t *testing.T) {
	byName := map[string]auditCeremony{}
	for _, c := range auditCeremonies() {
		byName[c.name] = c
	}
	for _, name := range []string{"passkey login", "operator-payload sign"} {
		for _, mode := range enfCeremonyModes {
			t.Run(name+"/"+mode.name, func(t *testing.T) {
				c := byName[name]
				f := newEnfFixture(t, true, true)
				mode.off(t, f)

				require.False(t, c.run(t, f, true), "the policy must refuse the software credential")

				e := assertMarked(t, f.markedEvents(t), true, c.credEnc(f.softID), hex.EncodeToString(softauthn.AAGUID[:]))
				assert.Equal(t, business.AuditResultDenied, e.Result)
				if name == "passkey login" {
					assert.Equal(t, auditReasonSoftwareAuthenticatorPolicy, e.Details[auditKeyReason])
				} else {
					// The dispatch event has always recorded why it was refused as rejection_reason.
					assert.Contains(t, e.Details["rejection_reason"], "software authenticator policy")
				}
			})
		}
	}
}

// A refused software credential is a denial even when the same account holds a working
// hardware credential, and the hardware credential's own use is not affected.
func TestSoftwareAuthenticatorAudit_RefusalDoesNotMarkTheOtherCredential(t *testing.T) {
	f := newEnfFixture(t, true, true)
	enfFlagCleared.off(t, f)

	require.True(t, auditCeremonies()[0].run(t, f, false), "the hardware credential still logs in")
	e := assertMarked(t, f.markedEvents(t), false, base64URLID(f.hwID), hex.EncodeToString(make([]byte, 16)))
	assert.Equal(t, business.AuditResultSuccess, e.Result)
}

// The ceremonies that had no failure event record one for a failed or refused software
// credential only, so what they record for other credentials does not change.
func TestSoftwareAuthenticatorAudit_NewFailureEventsAreForSoftwareCredentialsOnly(t *testing.T) {
	for _, name := range []string{"presence begin/finish", "step-up elevate", "workflow publish", "run-command dispatch"} {
		t.Run(name, func(t *testing.T) {
			var c auditCeremony
			for _, x := range auditCeremonies() {
				if x.name == name {
					c = x
				}
			}
			f := newEnfFixture(t, true, true)
			enfFlagCleared.off(t, f)

			require.False(t, c.run(t, f, true), "the policy must refuse the software credential")
			events := f.markedEvents(t)
			require.Len(t, events, 1)
			assert.Equal(t, true, events[0].Details[auditKeySoftwareAuthenticator])
			assert.Equal(t, business.AuditResultDenied, events[0].Result)
		})
	}
}

// softwareAuthenticatorAuditDetails is the one place the fields are built: it names the
// credential on the account, and nothing for one the account does not hold.
func TestSoftwareAuthenticatorAuditDetails(t *testing.T) {
	soft := WebAuthnCredential{ID: []byte("soft-id"), AAGUID: softauthn.AAGUID[:]}
	hw := WebAuthnCredential{ID: []byte("hw-id"), AAGUID: make([]byte, 16)}
	acct := &account{Credentials: []WebAuthnCredential{hw, soft}}

	got := softwareAuthenticatorAuditDetails(acct, soft.ID)
	assert.Equal(t, map[string]interface{}{
		auditKeySoftwareAuthenticator: true,
		auditKeyAAGUID:                hex.EncodeToString(softauthn.AAGUID[:]),
		auditKeyCredentialID:          base64URLID(soft.ID),
	}, got)
	assert.Equal(t, false, softwareAuthenticatorAuditDetails(acct, hw.ID)[auditKeySoftwareAuthenticator])

	assert.Nil(t, softwareAuthenticatorAuditDetails(acct, []byte("unknown")), "an unknown credential is not claimed")
	assert.Nil(t, softwareAuthenticatorAuditDetails(acct, nil))
	assert.Nil(t, softwareAuthenticatorAuditDetails(nil, soft.ID))
}

// An audit event for a credential that is not the account's carries no marker, so a
// failed login with an unknown credential never claims one.
func TestSoftwareAuthenticatorAudit_UnidentifiedCredentialIsNotMarked(t *testing.T) {
	f := newEnfFixture(t, true, true)
	f.softID = []byte("not-registered") // the assertion names a credential the account does not hold
	rec := f.passkeyLoginWith(t, true)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	assert.Empty(t, f.markedEvents(t))
}

// passkeyLoginWith is passkeyLogin with assertion options (a corrupt signature).
//
//duplication:justified features/controller/api/software_authenticator_enforcement_test.go -- enfFixture.passkeyLogin takes no assertion options and lives in a test file this story does not change
func (f *enfFixture) passkeyLoginWith(t *testing.T, soft bool, opts ...webauthntest.Option) *httptest.ResponseRecorder {
	t.Helper()
	const csrf = "pre-session-csrf"
	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/begin", nil)
	beginReq.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrf})
	beginReq.Header.Set(headerCSRFToken, csrf)
	begin := httptest.NewRecorder()
	f.server.handlePasskeyLoginBegin(begin, beginReq)
	require.Equal(t, http.StatusOK, begin.Code, begin.Body.String())
	var ceremonyCookie *http.Cookie
	for _, c := range begin.Result().Cookies() {
		if c.Name == cookiePasskeyCeremony {
			ceremonyCookie = c
		}
	}
	require.NotNil(t, ceremonyCookie)

	opts = append([]webauthntest.Option{webauthntest.WithUserHandle([]byte(f.accountID))}, opts...)
	body := f.assertion(t, soft, publicKeyChallenge(t, begin), opts...)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", body)
	req.AddCookie(ceremonyCookie)
	rec := httptest.NewRecorder()
	f.server.handlePasskeyLoginFinish(rec, req)
	return rec
}

// A step-up elevation with a bad signature records a failure for a software credential
// (not a denial: the policy permits it) and nothing for any other credential.
func TestSoftwareAuthenticatorAudit_StepUpBadSignature(t *testing.T) {
	for _, soft := range []bool{true, false} {
		t.Run(fmt.Sprintf("software=%v", soft), func(t *testing.T) {
			f := newEnfFixture(t, true, true)
			sessID := f.webSessionID(t)
			begin := doStepUpBegin(t, f.server, f.principal(), sessID)
			require.Equal(t, http.StatusOK, begin.Code, begin.Body.String())

			rec := doStepUpFinish(t, f.server, f.principal(), sessID,
				f.assertion(t, soft, publicKeyChallenge(t, begin), webauthntest.WithCorruptSignature()))
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

			events := f.markedEvents(t)
			if !soft {
				assert.Empty(t, events, "a failed use of another credential is not newly recorded")
				return
			}
			e := assertMarked(t, events, true, base64URLID(f.softID), hex.EncodeToString(softauthn.AAGUID[:]))
			assert.Equal(t, stepUpAuditActionFailure, e.Action)
			assert.Equal(t, business.AuditResultFailure, e.Result)
			assert.NotContains(t, e.Details, auditKeyReason)
		})
	}
}
