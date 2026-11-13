// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6143: use-time enforcement of the software-authenticator policy (ADR-021
// Amendment 10). A registered CFGMS software-authenticator credential stops working
// everywhere the moment softwareAuthenticatorPermitted turns false, while a credential
// with any other AAGUID on the same account is unaffected.
//
// Every component is real: the account and session stores, the tenant tree, the
// WebAuthn relying party, the ceremony handlers and the authentication middleware. The
// credentials are real ECDSA keys generated at test time; the "software" label is the
// AAGUID recorded on the stored credential, as at registration.

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/testutil/webauthntest"
)

const enfTenant = "msp-a"

// enfFixture is a server with the tenant tree, the relying party, the controller.cfg
// list naming enfTenant, and one enfTenant account (flag set) that holds the
// operator-payload and workflow-publish grants. Its credentials are injected as stored
// records: a CFGMS-AAGUID "software" credential, a zero-AAGUID "hardware" one, or both.
type enfFixture struct {
	server    *Server
	username  string
	accountID string
	rawToken  string // the account's enrollment token

	softKey, hwKey *ecdsa.PrivateKey
	softID, hwID   []byte

	counter uint32
	sess    int
	wfStore *workflow.WorkflowStore
}

func newEnfFixture(t *testing.T, withSoft, withHardware bool) *enfFixture {
	t.Helper()
	server := setupTestServer(t)
	seedTenantTree(t, server)
	wa, err := NewWebAuthnFromConfig(tvRPID, tvRPID, []string{tvOrigin})
	require.NoError(t, err)
	server.SetWebAuthn(wa)
	server.SetSoftwareAuthenticatorTenants([]string{enfTenant})
	server.fleetQuery = seededFleetQuery(makeSeedSteward("steward-1", "es-hv01", "linux", "amd64", "prod"))

	webCfg := session.Config{IdleTimeout: 60 * time.Minute, AbsoluteTimeout: 12 * time.Hour, GraceWindow: 30 * time.Second}
	webStore := session.NewMemStore(webCfg, time.Now)
	t.Cleanup(webStore.Close)
	server.SetWebSessionManager(session.NewManager(webCfg, webStore, time.Now))
	cliCfg := session.DefaultConfig()
	cliStore := session.NewMemStore(cliCfg, time.Now)
	t.Cleanup(cliStore.Close)
	server.SetSessionManager(session.NewManager(cliCfg, cliStore, time.Now))

	h, configStore := newTestWorkflowHandler(t)
	server.workflowHandler = h

	const username = "enforce-user"
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username:    username,
		TenantID:    enfTenant,
		Permissions: []string{OperatorPayloadSignGrant, workflow.PublishPermission},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "create account: %s", rec.Body.String())
	var outer APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &outer))
	rawToken, _ := outer.Data.(map[string]interface{})["enrollment_magic_link"].(string)
	require.NotEmpty(t, rawToken)

	f := &enfFixture{
		server: server, username: username, rawToken: rawToken,
		wfStore: workflow.NewWorkflowStore(configStore, enfTenant),
	}
	f.edit(t, func(a *account) {
		f.accountID = a.ID
		a.AllowSoftwareAuthenticator = true
		if withSoft {
			var pub []byte
			f.softKey, pub = webauthntest.NewKey(t)
			f.softID = []byte("enforce-soft-cred")
			a.Credentials = append(a.Credentials, WebAuthnCredential{
				ID: f.softID, PublicKey: pub, Label: "soft", RegisteredAt: time.Now(),
				AAGUID: append([]byte(nil), softauthn.AAGUID[:]...),
			})
		}
		if withHardware {
			var pub []byte
			f.hwKey, pub = webauthntest.NewKey(t)
			f.hwID = []byte("enforce-hardware-cred")
			a.Credentials = append(a.Credentials, WebAuthnCredential{
				ID: f.hwID, PublicKey: pub, Label: "hardware", RegisteredAt: time.Now(),
				AAGUID: make([]byte, 16),
			})
		}
	})
	return f
}

// edit applies mutate to the stored account as an administrator's direct record edit
// would, moving the record when the change moves it to another storage tenant, and
// drops the account cache.
func (f *enfFixture) edit(t *testing.T, mutate func(a *account)) {
	t.Helper()
	ctx := context.Background()
	a, err := f.server.loadAccountFromStore(ctx, f.username, "")
	require.NoError(t, err)
	require.NotNil(t, a)
	before := accountStorageTenant(a.TenantID)
	mutate(a)
	if after := accountStorageTenant(a.TenantID); after != before {
		require.NoError(t, f.server.secretStore.DeleteSecret(ctx, before+"/"+accountStoreKey(f.username)))
	}
	require.NoError(t, f.server.persistAccount(ctx, a, "test"))
	dropAccountCache(f.server)
}

// credential returns the key and ID of the software or the hardware credential.
func (f *enfFixture) credential(soft bool) (*ecdsa.PrivateKey, []byte) {
	if soft {
		return f.softKey, f.softID
	}
	return f.hwKey, f.hwID
}

func (f *enfFixture) principal() *Principal {
	return &Principal{ID: f.accountID, TenantID: enfTenant, Assurance: session.AssuranceStrong}
}

// signPrincipal is the principal the payload-sign ceremony runs as: the seeded steward
// belongs to no tenant, so the caller carries none (as in the other sign tests).
func (f *enfFixture) signPrincipal() *Principal {
	return &Principal{ID: f.accountID}
}

// assertion signs challenge with the chosen credential; the sign count always advances.
func (f *enfFixture) assertion(t *testing.T, soft bool, challenge string, opts ...webauthntest.Option) *bytes.Reader {
	t.Helper()
	key, id := f.credential(soft)
	f.counter++
	opts = append([]webauthntest.Option{webauthntest.WithSignCount(f.counter)}, opts...)
	return webauthntest.Assert(t, key, id, tvRPID, tvOrigin, challenge, opts...).Reader()
}

// publicKeyChallenge reads the challenge out of a begin response whose data is the
// WebAuthn request options ({"publicKey":{"challenge":...}}).
func publicKeyChallenge(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	opts, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	pk, ok := opts["publicKey"].(map[string]interface{})
	require.True(t, ok)
	challenge, _ := pk["challenge"].(string)
	require.NotEmpty(t, challenge)
	return challenge
}

// enfMode is one way the policy stops permitting the account's software credential.
// restore undoes it (nil when it cannot be undone from a test).
type enfMode struct {
	name    string
	off     func(t *testing.T, f *enfFixture)
	restore func(t *testing.T, f *enfFixture)
}

func enfRestoreShape(t *testing.T, f *enfFixture) {
	f.edit(t, func(a *account) { a.TenantID, a.RootScope = enfTenant, false })
}

var (
	enfTenantRemoved = enfMode{"tenant removed from the list",
		func(_ *testing.T, f *enfFixture) { f.server.SetSoftwareAuthenticatorTenants(nil) },
		func(_ *testing.T, f *enfFixture) { f.server.SetSoftwareAuthenticatorTenants([]string{enfTenant}) }}
	enfFlagCleared = enfMode{"account flag cleared",
		func(t *testing.T, f *enfFixture) {
			f.edit(t, func(a *account) { a.AllowSoftwareAuthenticator = false })
		},
		func(t *testing.T, f *enfFixture) { f.edit(t, func(a *account) { a.AllowSoftwareAuthenticator = true }) }}
	enfRootScope = enfMode{"account becomes root scope",
		func(t *testing.T, f *enfFixture) { f.edit(t, func(a *account) { a.TenantID, a.RootScope = "", true }) },
		enfRestoreShape}
	enfEmptyTenant = enfMode{"account tenant emptied",
		func(t *testing.T, f *enfFixture) { f.edit(t, func(a *account) { a.TenantID = "" }) },
		enfRestoreShape}
	enfRootTenant = enfMode{"account moved into the root tenant",
		func(t *testing.T, f *enfFixture) { f.edit(t, func(a *account) { a.TenantID = testRootTenantID }) },
		enfRestoreShape}
	enfRootUnresolved = enfMode{"root tenant unresolved",
		func(t *testing.T, f *enfFixture) {
			seedLegacyTopLevelTenant(t, f.server, "legacy-top")
			require.Empty(t, f.server.rootTenantID(context.Background()))
		}, nil}
)

// enfCeremonyModes are the modes every ceremony is exercised under. (An emptied tenant
// also takes away the account's own authority over the publish tenant, so it is covered
// by the session tests, where only the credential is in question.)
//
// The unresolved-root case is separate (TestSoftwareAuthenticatorEnforcement_UnresolvedRoot*):
// the tenant manager caches the root it resolved, so a server whose policy was already
// evaluated cannot be turned into one with an unresolvable root.
var enfCeremonyModes = []enfMode{enfTenantRemoved, enfFlagCleared, enfRootScope, enfRootTenant}

var enfSessionModes = []enfMode{enfTenantRemoved, enfFlagCleared, enfRootScope, enfEmptyTenant, enfRootTenant}

// ceremony runs one use of a credential and reports whether it was accepted.
type ceremony struct {
	name string
	run  func(t *testing.T, f *enfFixture, soft bool) bool
}

func (f *enfFixture) passkeyLogin(t *testing.T, soft bool) *httptest.ResponseRecorder {
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

	body := f.assertion(t, soft, publicKeyChallenge(t, begin), webauthntest.WithUserHandle([]byte(f.accountID)))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", body)
	req.AddCookie(ceremonyCookie)
	rec := httptest.NewRecorder()
	f.server.handlePasskeyLoginFinish(rec, req)
	return rec
}

func (f *enfFixture) webSessionID(t *testing.T) string {
	t.Helper()
	sess, _, err := f.server.webSessionManager.Issue(context.Background(), f.accountID, "web-login", enfTenant)
	require.NoError(t, err)
	return sess.ID
}

func (f *enfFixture) nextSessionKey() string {
	f.sess++
	return fmt.Sprintf("enforce-sess-%d", f.sess)
}

func (f *enfFixture) publishCall(t *testing.T, step, version, sessID string, body *bytes.Reader) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/publish-wf/versions/"+version+"/publish/"+step, body)
	req = withPrincipal(req, f.principal())
	req = mux.SetURLVars(req, map[string]string{"id": "publish-wf", "version": version})
	req = req.WithContext(context.WithValue(req.Context(), webSessionIDContextKey, sessID))
	rec := httptest.NewRecorder()
	if step == "begin" {
		f.server.handleWorkflowPublishBegin(rec, req)
	} else {
		f.server.handleWorkflowPublishFinish(rec, req)
	}
	return rec
}

// publish seeds a fresh workflow version and runs a publish ceremony over it with the
// chosen credential. It returns the version and whether the publish was accepted.
func (f *enfFixture) publish(t *testing.T, soft bool, version string) (*workflow.VersionedWorkflow, bool) {
	t.Helper()
	sv, err := workflow.ParseSemanticVersion(version)
	require.NoError(t, err)
	vw := &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{
			Name: "publish-wf", Version: version,
			Steps: []workflow.Step{{Name: "step1", Type: workflow.StepTypeTask}},
		},
		SemanticVersion: *sv,
	}
	require.NoError(t, f.wfStore.StoreWorkflow(context.Background(), vw))

	sessKey := f.nextSessionKey()
	begin := f.publishCall(t, "begin", version, sessKey, nil)
	if begin.Code != http.StatusOK {
		return vw, false
	}
	var resp struct {
		Data WorkflowPublishBeginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(begin.Body.Bytes(), &resp))
	challenge := resp.Data.Assertion.Response.Challenge.String()
	finish := f.publishCall(t, "finish", version, sessKey, f.assertion(t, soft, challenge, webauthntest.WithFlags(0x05)))
	if finish.Code != http.StatusOK {
		return vw, false
	}
	stored, err := f.wfStore.GetWorkflow(context.Background(), "publish-wf", *sv)
	require.NoError(t, err)
	require.NotNil(t, stored.Publication)
	return stored, true
}

func enfCeremonies() []ceremony {
	return []ceremony{
		{"passkey login", func(t *testing.T, f *enfFixture, soft bool) bool {
			return f.passkeyLogin(t, soft).Code == http.StatusOK
		}},
		{"presence begin/finish", func(t *testing.T, f *enfFixture, soft bool) bool {
			action := presenceActionBinding{
				Method: http.MethodPost, Path: "/api/v1/modules/approvals/test-address/approve",
				BodyHash: emptyBodyHashHex, PermissionID: "module:approve",
			}
			begin := doPresenceBeginWithAction(t, f.server, f.principal(), action)
			if begin.Code != http.StatusOK {
				return false
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/presence/finish",
				f.assertion(t, soft, publicKeyChallenge(t, begin)))
			req = withPrincipal(req, f.principal())
			rec := httptest.NewRecorder()
			f.server.handlePresenceFinish(rec, req)
			return rec.Code == http.StatusOK
		}},
		{"step-up elevate", func(t *testing.T, f *enfFixture, soft bool) bool {
			sessID := f.webSessionID(t)
			begin := doStepUpBegin(t, f.server, f.principal(), sessID)
			if begin.Code != http.StatusOK {
				return false
			}
			return doStepUpFinish(t, f.server, f.principal(), sessID,
				f.assertion(t, soft, publicKeyChallenge(t, begin))).Code == http.StatusOK
		}},
		{"operator-payload sign", func(t *testing.T, f *enfFixture, soft bool) bool {
			sessKey := f.nextSessionKey()
			begin := doSignBegin(t, f.server, f.signPrincipal(), sessKey, validBeginBody())
			if begin.Code != http.StatusOK {
				return false
			}
			var resp struct {
				Data OperatorPayloadSignBeginResponse `json:"data"`
			}
			require.NoError(t, json.Unmarshal(begin.Body.Bytes(), &resp))
			challenge := resp.Data.Assertion.Response.Challenge.String()
			return doSignFinish(t, f.server, f.signPrincipal(), sessKey,
				f.assertion(t, soft, challenge)).Code == http.StatusOK
		}},
		{"workflow publish", func(t *testing.T, f *enfFixture, soft bool) bool {
			f.sess++
			_, ok := f.publish(t, soft, fmt.Sprintf("1.%d.0", f.sess))
			return ok
		}},
		{"run-command WebAuthn proof (VerifyAssertion)", func(t *testing.T, f *enfFixture, soft bool) bool {
			key, id := f.credential(soft)
			exp := time.Now().Add(3 * time.Minute)
			env := operatorpayload.Envelope{
				Content: []byte("echo hello"), Shell: "bash", Targets: []string{"steward-1"},
				Nonce: "enforce-nonce", ExpiresAt: exp,
			}
			hash, err := operatorpayload.ChallengeHash(env)
			require.NoError(t, err)
			proof := actionProof(t, key, id, hash)
			ctx := context.WithValue(context.Background(), principalContextKey, f.principal())
			_, err = f.server.verifyCommandWebAuthn(ctx, env.Content, env.Shell, env.Targets, env.Nonce, exp, proof)
			return err == nil
		}},
		{"steward roster manifest", func(t *testing.T, f *enfFixture, soft bool) bool {
			_, id := f.credential(soft)
			entries, err := f.server.buildAuthorizedWebAuthnCredentials(context.Background())
			require.NoError(t, err)
			for _, e := range entries {
				if bytes.Equal(e.CredentialID, id) {
					return true
				}
			}
			return false
		}},
	}
}

// [REQUIRED TEST] With the policy on a software credential works in every ceremony;
// after the policy turns off the same call is refused (or the credential is absent from
// the roster), and a credential with another AAGUID on the same account is unaffected.
func TestSoftwareAuthenticatorEnforcement_CeremoniesRefuseTheCredentialOnceThePolicyIsOff(t *testing.T) {
	for _, c := range enfCeremonies() {
		for _, mode := range enfCeremonyModes {
			t.Run(c.name+"/"+mode.name, func(t *testing.T) {
				f := newEnfFixture(t, true, true)
				require.True(t, c.run(t, f, true), "precondition: the software credential works while the policy is on")
				require.True(t, c.run(t, f, false), "precondition: the other credential works while the policy is on")

				mode.off(t, f)

				assert.False(t, c.run(t, f, true), "the software credential must be refused")
				assert.True(t, c.run(t, f, false), "a credential with another AAGUID must keep working")
			})
		}
	}
}

// [REQUIRED TEST] Unresolved root tenant: the software credential is refused in every
// ceremony, other credentials are unaffected.
func TestSoftwareAuthenticatorEnforcement_UnresolvedRootFailsClosed(t *testing.T) {
	for _, c := range enfCeremonies() {
		t.Run(c.name, func(t *testing.T) {
			f := newEnfFixture(t, true, true)
			enfRootUnresolved.off(t, f)

			assert.False(t, c.run(t, f, true), "the software credential must be refused")
			assert.True(t, c.run(t, f, false), "a credential with another AAGUID must keep working")
		})
	}
}

// [REQUIRED TEST] Unresolved root tenant, sessions: a web session and a CLI-login
// session that rest on the software credential end; sessions resting on another
// credential of the same account do not.
func TestSoftwareAuthenticatorEnforcement_UnresolvedRootEndsSoftwareSessions(t *testing.T) {
	f := newEnfFixture(t, true, true)
	ctx := context.Background()
	acct := f.storedAccount(t)
	softCookie := sessEndLogin(t, f.server.webSessionManager, acct, f.softID)
	hwCookie := sessEndLogin(t, f.server.webSessionManager, acct, f.hwID)
	_, softCLI, err := f.server.sessionManager.IssueBound(ctx, f.accountID, cliLoginConnectionName, enfTenant, false, f.softID, nil)
	require.NoError(t, err)
	_, hwCLI, err := f.server.sessionManager.IssueBound(ctx, f.accountID, cliLoginConnectionName, enfTenant, false, f.hwID, nil)
	require.NoError(t, err)
	enfRootUnresolved.off(t, f)

	requireSessionRevoked(t, sessEndRequest(t, f.server, softCookie))
	requireSessionRevoked(t, cliBindRequest(t, f.server, softCLI))
	assert.Equal(t, http.StatusOK, sessEndRequest(t, f.server, hwCookie).Code)
	assert.Equal(t, http.StatusOK, cliBindRequest(t, f.server, hwCLI).Code)
}

// A software-only account is refused outright (not even a NO_CREDENTIALS bypass).
func TestSoftwareAuthenticatorEnforcement_SoftwareOnlyAccountRefusedAtBegin(t *testing.T) {
	f := newEnfFixture(t, true, false)
	enfFlagCleared.off(t, f)

	rec := doStepUpBegin(t, f.server, f.principal(), f.webSessionID(t))
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Equal(t, "NO_CREDENTIALS", errCode(t, rec.Body.Bytes()))

	rec = doPresenceBeginWithAction(t, f.server, f.principal(), presenceActionBinding{
		Method: http.MethodPost, Path: "/api/v1/x", BodyHash: emptyBodyHashHex, PermissionID: "module:approve"})
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	rec = doSignBegin(t, f.server, f.signPrincipal(), f.nextSessionKey(), validBeginBody())
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
}

// [REQUIRED TEST] A web session created by a software-authenticator login, and a
// CLI-login Bearer session approved with one, each end on their next request after the
// policy turns false. A web session proved with another credential survives.
func TestSoftwareAuthenticatorEnforcement_SessionsEndWhenThePolicyTurnsOff(t *testing.T) {
	for _, mode := range enfSessionModes {
		t.Run("web session/"+mode.name, func(t *testing.T) {
			f := newEnfFixture(t, true, true)
			login := f.passkeyLogin(t, true)
			require.Equal(t, http.StatusOK, login.Code, login.Body.String())
			var cookie *http.Cookie
			for _, c := range login.Result().Cookies() {
				if c.Name == cookieWebSession {
					cookie = c
				}
			}
			require.NotNil(t, cookie)
			acct, err := f.server.getAccountByID(context.Background(), f.accountID)
			require.NoError(t, err)
			hwCookie := sessEndLogin(t, f.server.webSessionManager, acct, f.hwID)
			require.Equal(t, http.StatusOK, sessEndRequest(t, f.server, cookie).Code, "precondition: the session works")

			mode.off(t, f)

			requireSessionRevoked(t, sessEndRequest(t, f.server, cookie))
			_, err = f.server.webSessionManager.Validate(context.Background(), cookie.Value)
			assert.Error(t, err, "the refused session must be revoked, not just refused once")
			assert.Equal(t, http.StatusOK, sessEndRequest(t, f.server, hwCookie).Code,
				"a session proved with another credential keeps working")
		})

		t.Run("cli-login session/"+mode.name, func(t *testing.T) {
			f := newEnfFixture(t, true, true)
			ctx := context.Background()
			_, soft, err := f.server.sessionManager.IssueBound(ctx, f.accountID, cliLoginConnectionName, enfTenant, false, f.softID, nil)
			require.NoError(t, err)
			_, hw, err := f.server.sessionManager.IssueBound(ctx, f.accountID, cliLoginConnectionName, enfTenant, false, f.hwID, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, cliBindRequest(t, f.server, soft).Code, "precondition: the session works")

			mode.off(t, f)

			requireSessionRevoked(t, cliBindRequest(t, f.server, soft))
			_, err = f.server.sessionManager.Validate(ctx, soft)
			assert.Error(t, err, "the refused CLI session must be revoked")
			assert.Equal(t, http.StatusOK, cliBindRequest(t, f.server, hw).Code,
				"a CLI session approved with another credential keeps working")
		})
	}
}

// [REQUIRED TEST] A software-only account whose policy is off cannot enroll a new
// credential through the zero-authenticator exemption and keeps an authenticator count
// of 0, which confines a cookie session to the routes the confinement exempts.
func TestSoftwareAuthenticatorEnforcement_SoftwareOnlyAccountDoesNotOpenTheZeroAuthenticatorPath(t *testing.T) {
	f := newEnfFixture(t, true, false)
	enfFlagCleared.off(t, f)

	t.Run("enrollment-token route", func(t *testing.T) {
		begin := doEnrollBegin(t, f.server, f.rawToken)
		if begin.Code != http.StatusOK {
			return // refused before the ceremony: nothing was enrolled either
		}
		key, _ := webauthntest.NewKey(t)
		reg := webauthntest.Register(t, key, []byte("enforce-new-cred"), tvRPID, tvOrigin, publicKeyChallenge(t, begin))
		rec := doEnrollFinish(t, f.server, f.rawToken, reg.Reader())
		assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
		assert.Equal(t, "ALREADY_ENROLLED", errCode(t, rec.Body.Bytes()))

		stored := f.storedAccount(t)
		assert.Len(t, stored.Credentials, 1, "no credential was added")
	})

	t.Run("authenticator count and confinement", func(t *testing.T) {
		acct, err := f.server.getAccountByID(context.Background(), f.accountID)
		require.NoError(t, err)
		require.Len(t, acct.Credentials, 1, "the stored credential is untouched")

		refreshed, ok := f.server.sessionPrincipalRefresh(&Principal{ID: f.accountID, AccountBound: true}, false)(context.Background())
		require.True(t, ok)
		assert.Zero(t, refreshed.AuthenticatorCount)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		ctx := context.WithValue(req.Context(), principalContextKey, refreshed)
		ctx = context.WithValue(ctx, cookieAuthContextKey, true)
		rec := httptest.NewRecorder()
		reached := false
		f.server.enrollmentConfinementMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reached = true
		})).ServeHTTP(rec, req.WithContext(ctx))
		assert.False(t, reached)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, "ENROLLMENT_REQUIRED", errCode(t, rec.Body.Bytes()))
	})

	t.Run("another credential on the account still counts", func(t *testing.T) {
		g := newEnfFixture(t, true, true)
		enfFlagCleared.off(t, g)
		refreshed, ok := g.server.sessionPrincipalRefresh(&Principal{ID: g.accountID, AccountBound: true}, false)(context.Background())
		require.True(t, ok)
		assert.Equal(t, 1, refreshed.AuthenticatorCount)
	})
}

func (f *enfFixture) storedAccount(t *testing.T) *account {
	t.Helper()
	a, err := f.server.loadAccountFromStore(context.Background(), f.username, "")
	require.NoError(t, err)
	require.NotNil(t, a)
	return a
}

// [REQUIRED TEST] A stored workflow publication signed by a software credential stops
// verifying when the policy is off, and verifies again when it is back on.
func TestSoftwareAuthenticatorEnforcement_StoredPublicationFollowsThePolicy(t *testing.T) {
	for _, mode := range []enfMode{enfTenantRemoved, enfFlagCleared, enfRootScope, enfRootTenant} {
		t.Run(mode.name, func(t *testing.T) {
			f := newEnfFixture(t, true, true)
			soft, ok := f.publish(t, true, "1.0.0")
			require.True(t, ok)
			hw, ok := f.publish(t, false, "1.1.0")
			require.True(t, ok)
			verify := func(vw *workflow.VersionedWorkflow) error {
				return f.server.VerifyWorkflowPublication(context.Background(), enfTenant, vw)
			}
			require.NoError(t, verify(soft), "precondition: verifies while the policy is on")
			require.NoError(t, verify(hw))

			mode.off(t, f)
			assert.Error(t, verify(soft), "a publication signed by the software credential stops verifying")
			assert.NoError(t, verify(hw), "a publication signed by another credential keeps verifying")

			mode.restore(t, f)
			assert.NoError(t, verify(soft), "it verifies again when the policy is back on")
		})
	}
}

// [REQUIRED TEST] An account that registered a software credential while tenant-scoped
// and is then changed to a shape the policy never permits loses use of it at once and
// its sessions end.
func TestSoftwareAuthenticatorEnforcement_AccountShapeChangeEndsUse(t *testing.T) {
	for _, mode := range []enfMode{enfRootScope, enfEmptyTenant, enfRootTenant} {
		t.Run(mode.name, func(t *testing.T) {
			f := newEnfFixture(t, true, false)
			login := f.passkeyLogin(t, true)
			require.Equal(t, http.StatusOK, login.Code, login.Body.String())
			var cookie *http.Cookie
			for _, c := range login.Result().Cookies() {
				if c.Name == cookieWebSession {
					cookie = c
				}
			}
			require.NotNil(t, cookie)

			mode.off(t, f)

			requireSessionRevoked(t, sessEndRequest(t, f.server, cookie))
			assert.NotEqual(t, http.StatusOK, f.passkeyLogin(t, true).Code, "the credential cannot log in again")
		})
	}
}

// The credential is still listed and can still be revoked while the policy is off.
func TestSoftwareAuthenticatorEnforcement_StillListedAndRevocableWhilePolicyIsOff(t *testing.T) {
	f := newEnfFixture(t, true, true)
	enfTenantRemoved.off(t, f)

	rec := doListCredentials(t, f.server, f.username)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	b64 := base64.RawURLEncoding.EncodeToString
	assert.Contains(t, rec.Body.String(), b64(f.softID), "the software credential is still listed")
	assert.Contains(t, rec.Body.String(), b64(f.hwID))

	rec = doRevokeCredential(t, f.server, f.username, b64(f.softID))
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	stored := f.storedAccount(t)
	require.Len(t, stored.Credentials, 1)
	assert.Equal(t, f.hwID, stored.Credentials[0].ID)
}

// The stored credential is never deleted by a refusal: a use that is refused, and a use
// by another credential that persists the sign count, both leave it on the account.
func TestSoftwareAuthenticatorEnforcement_RefusalAndPersistKeepTheStoredCredential(t *testing.T) {
	f := newEnfFixture(t, true, true)
	enfFlagCleared.off(t, f)

	require.NotEqual(t, http.StatusOK, f.passkeyLogin(t, true).Code)
	sessKey := f.nextSessionKey()
	begin := doSignBegin(t, f.server, f.signPrincipal(), sessKey, validBeginBody())
	require.Equal(t, http.StatusOK, begin.Code, begin.Body.String())
	var resp struct {
		Data OperatorPayloadSignBeginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(begin.Body.Bytes(), &resp))
	finish := doSignFinish(t, f.server, f.signPrincipal(), sessKey,
		f.assertion(t, false, resp.Data.Assertion.Response.Challenge.String()))
	require.Equal(t, http.StatusOK, finish.Code, finish.Body.String())

	stored := f.storedAccount(t)
	require.Len(t, stored.Credentials, 2, "the sign-count write kept the software credential")
	assert.True(t, stored.hasSoftwareCredential())
	assert.False(t, stored.AllowSoftwareAuthenticator, "the write did not touch the administrator's flag")

	enfFlagCleared.restore(t, f)
	// The refused login above counted against the throttles; clear them so only the
	// policy decides.
	f.server.passkeyLoginThrottle.Range(func(k, _ any) bool {
		f.server.passkeyLoginThrottle.Delete(k)
		return true
	})
	login := f.passkeyLogin(t, true)
	assert.Equal(t, http.StatusOK, login.Code, "the credential works again when the policy is back on: %s", login.Body.String())
}

func TestPermittedAccountView(t *testing.T) {
	ctx := context.Background()
	f := newEnfFixture(t, true, true)
	acct := f.storedAccount(t)

	t.Run("permitted: the account itself", func(t *testing.T) {
		view, err := f.server.permittedAccountView(ctx, acct)
		require.NoError(t, err)
		assert.Same(t, acct, view)
	})

	t.Run("not permitted: a copy without software credentials, original untouched", func(t *testing.T) {
		f.server.SetSoftwareAuthenticatorTenants(nil)
		view, err := f.server.permittedAccountView(ctx, acct)
		require.NoError(t, err)
		require.NotSame(t, acct, view)
		require.Len(t, view.Credentials, 1)
		assert.Equal(t, f.hwID, view.Credentials[0].ID)
		assert.Len(t, acct.Credentials, 2, "the original keeps both credentials")
	})

	t.Run("unresolved root: fails closed with the error", func(t *testing.T) {
		g := newEnfFixture(t, true, true)
		enfRootUnresolved.off(t, g)
		view, err := g.server.permittedAccountView(ctx, g.storedAccount(t))
		assert.ErrorIs(t, err, errRootTenantUnresolved)
		require.Len(t, view.Credentials, 1)
		assert.False(t, view.Credentials[0].isSoftwareAuthenticator())
	})

	t.Run("no software credential: no policy lookup, same account", func(t *testing.T) {
		g := newEnfFixture(t, false, true)
		enfRootUnresolved.off(t, g)
		a := g.storedAccount(t)
		view, err := g.server.permittedAccountView(ctx, a)
		require.NoError(t, err, "an account without a software credential never reaches the root lookup")
		assert.Same(t, a, view)
	})

	t.Run("nil account", func(t *testing.T) {
		view, err := f.server.permittedAccountView(ctx, nil)
		require.NoError(t, err)
		assert.Nil(t, view)
	})
}

// --- Issue #6225: a software authenticator on a dedicated root-scope agent account
// (ADR-021 Amendment 11) ---

// newAgentFixture is the enforcement fixture with its account turned into a root-scope
// agent account: root scope, the flag set, one CFGMS software credential, the root-agent
// setting on. A second, tenant-scoped software account is not part of it; see
// TestRootAgentEnforcement_TenantSoftwareAccountIsUnaffectedByTheSetting.
func newAgentFixture(t *testing.T) *enfFixture {
	t.Helper()
	f := newEnfFixture(t, true, false)
	f.edit(t, func(a *account) {
		a.TenantID, a.RootScope = "", true
		a.Permissions = nil
	})
	f.server.SetSoftwareAuthenticatorRootAgentAccounts(true)
	return f
}

// agentPrincipal is the principal the presence and step-up handlers see for the agent.
func (f *enfFixture) agentPrincipal() *Principal {
	return &Principal{ID: f.accountID, GlobalScope: true, RootScoped: true, AccountBound: true, RootAgent: true, Assurance: session.AssuranceStrong}
}

// presenceToken runs the presence ceremony for action with the agent's software
// credential and returns the response; the token is in the body of a 200.
func (f *enfFixture) presenceFinish(t *testing.T, action presenceActionBinding, soft bool) *httptest.ResponseRecorder {
	t.Helper()
	begin := doPresenceBeginWithAction(t, f.server, f.agentPrincipal(), action)
	if begin.Code != http.StatusOK {
		return begin
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/presence/finish",
		f.assertion(t, soft, publicKeyChallenge(t, begin)))
	req = withPrincipal(req, f.agentPrincipal())
	rec := httptest.NewRecorder()
	f.server.handlePresenceFinish(rec, req)
	return rec
}

var agentModuleApproveAction = presenceActionBinding{
	Method: http.MethodPost, Path: "/api/v1/modules/approvals/test-address/approve",
	BodyHash: emptyBodyHashHex, PermissionID: "module:approve",
}

// agentBearer issues a CLI-login Bearer session bound to the agent's software credential
// and elevates it with that credential, so it carries phishing-resistant assurance.
func (f *enfFixture) agentBearer(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	sess, _, err := f.server.sessionManager.IssueBound(ctx, f.accountID, cliLoginConnectionName, "", false, f.softID, nil)
	require.NoError(t, err)
	_, token, err := f.server.sessionManager.Elevate(ctx, sess.ID, f.softID, "")
	require.NoError(t, err)
	return token
}

// agentRequest sends one request through the real router as the agent.
func (f *enfFixture) agentRequest(t *testing.T, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)
	return rec
}

// [REQUIRED TEST] The agent logs in by passkey, completes the presence ceremony and
// receives a presence token; a presence-gated request without the token gets the 401
// presence challenge.
func TestRootAgentEnforcement_LoginPresenceAndGatedRoute(t *testing.T) {
	f := newAgentFixture(t)

	login := f.passkeyLogin(t, true)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())

	rec := f.presenceFinish(t, agentModuleApproveAction, true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	token, _ := resp.Data["presence_token"].(string)
	assert.NotEmpty(t, token, "a presence token is returned")

	bearer := f.agentBearer(t)
	gated := f.agentRequest(t, bearer, http.MethodPost, "/api/v1/modules/approvals/test-address/approve", "")
	require.Equal(t, http.StatusUnauthorized, gated.Code, gated.Body.String())
	assert.Contains(t, gated.Header().Get("WWW-Authenticate"), `presence="required"`)
	assert.Contains(t, gated.Header().Get("WWW-Authenticate"), `permission="module:approve"`)

	// With the token the request passes the presence gate: module:approve is in the
	// allowlist, so it is neither 401 nor 403. (The approval itself is proven by #6151.)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/modules/approvals/test-address/approve", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set(presenceTokenHeader, token)
	out := httptest.NewRecorder()
	f.server.router.ServeHTTP(out, req)
	assert.NotEqual(t, http.StatusUnauthorized, out.Code, out.Body.String())
	assert.NotEqual(t, http.StatusForbidden, out.Code, out.Body.String())
}

// [REQUIRED TEST] Every way the policy can stop permitting the agent's credential
// refuses the next login and presence attempt, audited as denied with the policy
// reason; the stored credential stays.
func TestRootAgentEnforcement_RevocationRefusesNextUse(t *testing.T) {
	modes := []enfMode{
		{"setting switched off",
			func(_ *testing.T, f *enfFixture) { f.server.SetSoftwareAuthenticatorRootAgentAccounts(false) },
			func(_ *testing.T, f *enfFixture) { f.server.SetSoftwareAuthenticatorRootAgentAccounts(true) }},
		enfFlagCleared,
		{"non-software credential added",
			func(t *testing.T, f *enfFixture) {
				f.edit(t, func(a *account) {
					_, pub := webauthntest.NewKey(t)
					a.Credentials = append(a.Credentials, WebAuthnCredential{
						ID: []byte("added-human"), PublicKey: pub, Label: "hardware", RegisteredAt: time.Now(), AAGUID: make([]byte, 16),
					})
				})
			}, nil},
		{"admin certificate bound",
			func(t *testing.T, f *enfFixture) {
				f.edit(t, func(a *account) { a.CertBindings = []CertBinding{{Serial: "77", Fingerprint: "fp"}} })
			}, nil},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			f := newAgentFixture(t)
			require.Equal(t, http.StatusOK, f.passkeyLogin(t, true).Code, "precondition: login works")
			require.Equal(t, http.StatusOK, f.presenceFinish(t, agentModuleApproveAction, true).Code, "precondition: presence works")

			mode.off(t, f)

			assert.NotEqual(t, http.StatusOK, f.passkeyLogin(t, true).Code, "the next login is refused")
			assert.NotEqual(t, http.StatusOK, f.presenceFinish(t, agentModuleApproveAction, true).Code, "the next presence attempt is refused")

			var denied int
			for _, e := range f.markedEvents(t) {
				if e.Result == business.AuditResultDenied && e.Details[auditKeyReason] == auditReasonSoftwareAuthenticatorPolicy {
					denied++
					assert.Equal(t, true, e.Details[auditKeyRootScope], "a root agent's refusal is told from tenant use")
				}
			}
			assert.GreaterOrEqual(t, denied, 1, "the refusal is audited as denied with the policy reason")

			stored := f.storedAccount(t)
			require.Len(t, stored.Credentials, map[bool]int{true: 2, false: 1}[mode.name == "non-software credential added"])
			assert.True(t, stored.hasSoftwareCredential(), "the stored software credential is not deleted")
		})
	}
}

// With the setting turned off and on again the same credential works again.
func TestRootAgentEnforcement_SettingBackOnRestoresUse(t *testing.T) {
	f := newAgentFixture(t)
	f.server.SetSoftwareAuthenticatorRootAgentAccounts(false)
	assert.NotEqual(t, http.StatusOK, f.passkeyLogin(t, true).Code)
	f.server.SetSoftwareAuthenticatorRootAgentAccounts(true)
	assert.Equal(t, http.StatusOK, f.passkeyLogin(t, true).Code)
}

// A tenant-scoped software account follows the tenant list and the flag only: the
// root-agent setting is not consulted in either direction.
func TestRootAgentEnforcement_TenantSoftwareAccountIsUnaffectedByTheSetting(t *testing.T) {
	for _, setting := range []bool{true, false} {
		t.Run(fmt.Sprintf("root agent setting %v", setting), func(t *testing.T) {
			f := newEnfFixture(t, true, false)
			f.server.SetSoftwareAuthenticatorRootAgentAccounts(setting)
			assert.Equal(t, http.StatusOK, f.passkeyLogin(t, true).Code)
			begin := doPresenceBeginWithAction(t, f.server, f.principal(), agentModuleApproveAction)
			assert.Equal(t, http.StatusOK, begin.Code, begin.Body.String())

			enfTenantRemoved.off(t, f)
			f.server.SetSoftwareAuthenticatorRootAgentAccounts(!setting)
			assert.NotEqual(t, http.StatusOK, f.passkeyLogin(t, true).Code, "the tenant list still governs a tenant account")
		})
	}
}

// [REQUIRED TEST] Through the real router a flagged root agent session is refused
// (403, audited with the software-authenticator marker, root_scope and a reason) on the
// routes outside the allowlist and succeeds on an allowlisted one.
func TestRootAgentEnforcement_RouterRefusesOutsideTheAllowlist(t *testing.T) {
	f := newAgentFixture(t)
	bearer := f.agentBearer(t)

	refused := []struct {
		name, method, path, body string
	}{
		{"set the software-authenticator flag", http.MethodPut, "/api/v1/accounts/other-user/software-authenticator", `{"enabled":false}`},
		{"register a credential", http.MethodPost, "/api/v1/accounts/other-user/webauthn/register/begin", ""},
		{"approve a credential request with the root-scope marker", http.MethodPost, "/api/v1/credential-requests/req-1/approve", `{"grant_root_scope_marker":true}`},
		{"grant a tenant crossing", http.MethodPost, "/api/v1/tenants/msp-a/access-grants", `{}`},
		{"create an API key", http.MethodPost, "/api/v1/api-keys", `{"name":"k","permissions":["steward:list"]}`},
		{"create an RBAC role", http.MethodPost, "/api/v1/rbac/roles", `{"name":"r"}`},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			rec := f.agentRequest(t, bearer, tt.method, tt.path, tt.body)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Equal(t, "INSUFFICIENT_PERMISSIONS", errCode(t, rec.Body.Bytes()))
		})
	}

	// One audit event per refusal, each marked.
	var events []*business.AuditEntry
	require.NoError(t, f.server.auditManager.Flush(context.Background()))
	all, err := f.server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{Actions: []string{"authorization.root_agent_denied"}})
	require.NoError(t, err)
	events = append(events, all...)
	require.Len(t, events, len(refused))
	for _, e := range events {
		assert.Equal(t, business.AuditResultDenied, e.Result)
		assert.Equal(t, true, e.Details[auditKeySoftwareAuthenticator], "the session was opened with a software credential")
		assert.Equal(t, true, e.Details[auditKeyRootScope])
		assert.Equal(t, reasonRootAgentPermissionNotAllowed, e.Details[auditKeyReason])
		assert.NotEmpty(t, e.Details["permission_id"])
	}

	t.Run("an allowlisted route succeeds", func(t *testing.T) {
		rec := f.agentRequest(t, bearer, http.MethodPost, "/api/v1/tenants",
			`{"id":"agent-tenant","name":"agent-tenant","parent_id":"`+testRootTenantID+`"}`)
		assert.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		list := f.agentRequest(t, bearer, http.MethodGet, "/api/v1/tenants", "")
		assert.Equal(t, http.StatusOK, list.Code, list.Body.String())
	})

	t.Run("the allowlist does not skip the tenant crossing boundary", func(t *testing.T) {
		rec := f.agentRequest(t, bearer, http.MethodPost, "/api/v1/tenants",
			`{"id":"agent-below","name":"agent-below","parent_id":"msp-a"}`)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "tenant_crossing_required", "creating below root needs a crossing")
	})
}

// A human root account (no flag) on the same router keeps full admin: the route that
// refuses the agent for lack of the permission is not refused for that reason here.
func TestRootAgentEnforcement_HumanRootAccountOnTheSameRoutesIsNotLimited(t *testing.T) {
	f := newEnfFixture(t, false, true)
	f.edit(t, func(a *account) {
		a.TenantID, a.RootScope, a.AllowSoftwareAuthenticator = "", true, false
		a.Permissions = nil
	})
	ctx := context.Background()
	sess, _, err := f.server.sessionManager.IssueBound(ctx, f.accountID, cliLoginConnectionName, "", false, f.hwID, nil)
	require.NoError(t, err)
	_, token, err := f.server.sessionManager.Elevate(ctx, sess.ID, f.hwID, "")
	require.NoError(t, err)

	for _, path := range []string{"/api/v1/api-keys", "/api/v1/rbac/roles"} {
		rec := f.agentRequest(t, token, http.MethodPost, path, `{"name":"r","permissions":["steward:list"]}`)
		assert.NotEqual(t, http.StatusForbidden, rec.Code, "%s: %s", path, rec.Body.String())
	}
	list := f.agentRequest(t, token, http.MethodGet, "/api/v1/tenants", "")
	assert.Equal(t, http.StatusOK, list.Code, list.Body.String())
}

// [REQUIRED TEST] POST /accounts through the real router: a root agent creates a new
// tenant-scoped account where it needs no crossing, and a tenant below root still gets
// the tenant-crossing challenge (the allowlist does not skip crossing).
func TestRootAgentEnforcement_AccountCreateThroughTheRouter(t *testing.T) {
	f := newAgentFixture(t)
	bearer := f.agentBearer(t)

	ok := f.agentRequest(t, bearer, http.MethodPost, "/api/v1/accounts",
		`{"username":"agent-made","tenant_id":"`+testRootTenantID+`","permissions":["steward:list"]}`)
	require.Equal(t, http.StatusCreated, ok.Code, ok.Body.String())
	assert.Contains(t, ok.Body.String(), "enrollment_magic_link")

	below := f.agentRequest(t, bearer, http.MethodPost, "/api/v1/accounts",
		`{"username":"agent-made-below","tenant_id":"client-1"}`)
	assert.Equal(t, http.StatusUnauthorized, below.Code, below.Body.String())
	assert.Contains(t, below.Body.String(), "tenant_crossing_required")

	minted := f.agentRequest(t, bearer, http.MethodPost, "/api/v1/accounts", `{"username":"agent-root-2","root_scope":true}`)
	assert.Equal(t, http.StatusForbidden, minted.Code, minted.Body.String())
	assert.Equal(t, errCodeRootAgentLimited, errCode(t, minted.Body.Bytes()))
}

// A successful use of the agent's software credential is marked and carries
// root_scope: true, so root agent use is told from tenant use in the audit trail.
func TestRootAgentEnforcement_SuccessfulUseIsMarkedRootScope(t *testing.T) {
	f := newAgentFixture(t)
	require.Equal(t, http.StatusOK, f.passkeyLogin(t, true).Code)
	require.Equal(t, http.StatusOK, f.presenceFinish(t, agentModuleApproveAction, true).Code)

	var presence *business.AuditEntry
	for _, e := range f.markedEvents(t) {
		if e.Action == presenceAuditActionSuccess {
			presence = e
		}
	}
	require.NotNil(t, presence)
	assert.Equal(t, true, presence.Details[auditKeySoftwareAuthenticator])
	assert.Equal(t, true, presence.Details[auditKeyRootScope])

	// A tenant account's event carries no root_scope.
	tenantFixture := newEnfFixture(t, true, false)
	require.Equal(t, http.StatusOK, tenantFixture.passkeyLogin(t, true).Code)
	for _, e := range tenantFixture.markedEvents(t) {
		assert.NotContains(t, e.Details, auditKeyRootScope)
	}
}
