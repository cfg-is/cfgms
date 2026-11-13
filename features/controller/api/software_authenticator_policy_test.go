// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6140: software-authenticator policy at registration (ADR-021 Amendment 10).

package api

import (
	"bytes"
	"context"
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

	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	policyUser         = "policy-user"
	policyDeniedAction = "account.passkey_registration_denied"
)

type policyAccountSpec struct {
	tenantID  string
	rootScope bool
	flag      bool // AllowSoftwareAuthenticator, set on the stored record directly
}

// newPolicyServer builds a server with the WebAuthn relying party, the tenant tree
// (root > msp-a > client-1, root > msp-b), the given controller.cfg tenant list and
// one account. It returns the server and the account's enrollment token.
func newPolicyServer(t *testing.T, listed []string, spec policyAccountSpec) (*Server, string) {
	t.Helper()
	server := setupTestServer(t)
	seedTenantTree(t, server)
	wa, err := NewWebAuthnFromConfig(aaguidRPID, aaguidRPID, []string{aaguidOrigin})
	require.NoError(t, err)
	server.SetWebAuthn(wa)
	server.SetSoftwareAuthenticatorTenants(listed)

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: policyUser, TenantID: spec.tenantID, RootScope: spec.rootScope,
	})
	require.Equal(t, http.StatusCreated, rec.Code, "create account: %s", rec.Body.String())
	var outer APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &outer))
	rawToken, _ := outer.Data.(map[string]interface{})["enrollment_magic_link"].(string)
	require.NotEmpty(t, rawToken)

	if spec.flag {
		ctx := context.Background()
		acct, err := server.loadAccountFromStore(ctx, policyUser, accountStorageTenant(spec.tenantID))
		require.NoError(t, err)
		require.NotNil(t, acct)
		acct.AllowSoftwareAuthenticator = true
		require.NoError(t, server.persistAccount(ctx, acct, "test"))
		dropAccountCache(server)
	}
	return server, rawToken
}

// registerRoute runs one full registration ceremony and returns the finish response.
type registerRoute struct {
	name string
	run  func(t *testing.T, server *Server, rawToken string, aaguid *[16]byte) *httptest.ResponseRecorder
}

// creationOptions returns the creation options for a registration on one route. A root
// agent account's begin refuses a request that carries no TPM material (Issue #6227,
// TPM_ATTESTATION_REQUIRED), so for such an account the pending session is stored
// directly, as a begin for any other account would have stored it. That lets these tests
// reach the finish-side policy with a credential that carries no TPM attestation; the
// attested path is TestRootAgentRegistration_TPMAttested.
func creationOptions(t *testing.T, server *Server, username string, begin *httptest.ResponseRecorder, store func(webauthn.SessionData)) []byte {
	t.Helper()
	if begin.Code == http.StatusOK {
		return beginData(t, begin)
	}
	require.Equal(t, http.StatusBadRequest, begin.Code, begin.Body.String())
	require.Equal(t, errCodeTPMAttestationRequired, errCode(t, begin.Body.Bytes()))
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	creation, session, err := server.getWebAuthn().BeginRegistration(buildWebauthnUser(acct),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		}))
	require.NoError(t, err)
	store(*session)
	raw, err := json.Marshal(creation)
	require.NoError(t, err)
	return raw
}

var registerRoutes = []registerRoute{
	{"admin register route", func(t *testing.T, server *Server, _ string, aaguid *[16]byte) *httptest.ResponseRecorder {
		opts := creationOptions(t, server, policyUser, doBegin(t, server, policyUser), func(sd webauthn.SessionData) {
			injectSession(server, policyUser, sd, 10*time.Minute)
		})
		resp, err := newSoftAuthenticator(t, aaguid).Register(opts)
		require.NoError(t, err)
		return doFinish(t, server, policyUser, bytes.NewReader(resp))
	}},
	{"enrollment-token route", func(t *testing.T, server *Server, rawToken string, aaguid *[16]byte) *httptest.ResponseRecorder {
		opts := creationOptions(t, server, policyUser, doEnrollBegin(t, server, rawToken), func(sd webauthn.SessionData) {
			injectEnrollSession(server, rawToken, sd, 10*time.Minute)
		})
		resp, err := newSoftAuthenticator(t, aaguid).Register(opts)
		require.NoError(t, err)
		return doEnrollFinish(t, server, rawToken, bytes.NewReader(resp))
	}},
}

// storedState reads the account from the durable store and returns it with its
// registered credential count.
func storedState(t *testing.T, server *Server, tenantID string) (*account, int) {
	t.Helper()
	fresh, err := server.loadAccountFromStore(context.Background(), policyUser, accountStorageTenant(tenantID))
	require.NoError(t, err)
	require.NotNil(t, fresh)
	return fresh, len(fresh.Credentials)
}

func TestSoftwareAuthenticatorPermitted_Decision(t *testing.T) {
	ctx := context.Background()
	server := setupTestServer(t)
	seedTenantTree(t, server)
	server.SetSoftwareAuthenticatorTenants([]string{"msp-a", testRootTenantID})

	tests := []struct {
		name string
		acct *account
		want bool
	}{
		{"listed tenant and flag", &account{TenantID: "msp-a", AllowSoftwareAuthenticator: true}, true},
		{"listed tenant, flag off", &account{TenantID: "msp-a"}, false},
		{"flag on, tenant not listed", &account{TenantID: "msp-b", AllowSoftwareAuthenticator: true}, false},
		{"child of a listed tenant is not covered", &account{TenantID: "client-1", AllowSoftwareAuthenticator: true}, false},
		{"root-scope account", &account{TenantID: "msp-a", RootScope: true, AllowSoftwareAuthenticator: true}, false},
		{"empty tenant", &account{TenantID: "", AllowSoftwareAuthenticator: true}, false},
		{"root tenant, even when listed", &account{TenantID: testRootTenantID, AllowSoftwareAuthenticator: true}, false},
		{"nil account", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := server.softwareAuthenticatorPermitted(ctx, tt.acct)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("empty list is off", func(t *testing.T) {
		server.SetSoftwareAuthenticatorTenants(nil)
		got, err := server.softwareAuthenticatorPermitted(ctx, &account{TenantID: "msp-a", AllowSoftwareAuthenticator: true})
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("a blank list entry never matches an empty tenant", func(t *testing.T) {
		server.SetSoftwareAuthenticatorTenants([]string{""})
		got, err := server.softwareAuthenticatorPermitted(ctx, &account{TenantID: "", AllowSoftwareAuthenticator: true})
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("unresolved root fails closed", func(t *testing.T) {
		// A fresh server: the tenant manager may cache the root it resolved above.
		server := setupTestServer(t)
		seedTenantTree(t, server)
		server.SetSoftwareAuthenticatorTenants([]string{"msp-a"})
		seedLegacyTopLevelTenant(t, server, "legacy-top")
		require.Empty(t, server.rootTenantID(ctx))
		got, err := server.softwareAuthenticatorPermitted(ctx, &account{TenantID: "msp-a", AllowSoftwareAuthenticator: true})
		assert.ErrorIs(t, err, errRootTenantUnresolved)
		assert.False(t, got)
	})
}

func TestSoftwareAuthenticatorPolicy_RefusedAtRegistration(t *testing.T) {
	tests := []struct {
		name   string
		listed []string
		spec   policyAccountSpec
	}{
		{"tenant list empty, flag on", nil, policyAccountSpec{tenantID: "msp-a", flag: true}},
		{"tenant listed, flag off", []string{"msp-a"}, policyAccountSpec{tenantID: "msp-a"}},
		{"flag on, tenant not listed", []string{"msp-b"}, policyAccountSpec{tenantID: "msp-a", flag: true}},
		{"parent listed, child tenant unlisted", []string{"msp-a"}, policyAccountSpec{tenantID: "client-1", flag: true}},
		{"root-scope account", []string{"msp-a", testRootTenantID}, policyAccountSpec{rootScope: true, flag: true}},
		{"account in the root tenant", []string{testRootTenantID}, policyAccountSpec{tenantID: testRootTenantID, flag: true}},
	}
	for _, route := range registerRoutes {
		for _, tt := range tests {
			t.Run(route.name+"/"+tt.name, func(t *testing.T) {
				server, rawToken := newPolicyServer(t, tt.listed, tt.spec)

				rec := route.run(t, server, rawToken, nil)
				assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
				assert.Equal(t, errCodeSoftwareAuthenticatorNotAllowed, errCode(t, rec.Body.Bytes()))

				acct, creds := storedState(t, server, tt.spec.tenantID)
				assert.Zero(t, creds, "nothing is stored on refusal")
				assert.False(t, acct.EnrollmentLinkRevoked, "a refused registration does not consume the enrollment token")

				details := auditDetailsFor(t, server, policyDeniedAction)
				assert.Equal(t, acct.ID, details["account_id"])
				assert.Equal(t, acct.TenantID, details["tenant_id"])
				assert.Equal(t, hex.EncodeToString(softauthn.AAGUID[:]), details["aaguid"])
			})
		}
	}
}

func TestSoftwareAuthenticatorPolicy_RefusalAuditEventIsDenied(t *testing.T) {
	server, rawToken := newPolicyServer(t, nil, policyAccountSpec{tenantID: "msp-a", flag: true})
	rec := registerRoutes[1].run(t, server, rawToken, nil)
	require.Equal(t, http.StatusForbidden, rec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{Actions: []string{policyDeniedAction}})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, business.AuditResultDenied, entries[0].Result)
	assert.Equal(t, "msp-a", entries[0].TenantID)
}

func TestSoftwareAuthenticatorPolicy_UnresolvedRootRefusesRegistration(t *testing.T) {
	for _, route := range registerRoutes {
		t.Run(route.name, func(t *testing.T) {
			server, rawToken := newPolicyServer(t, []string{"msp-a"}, policyAccountSpec{tenantID: "msp-a", flag: true})
			seedLegacyTopLevelTenant(t, server, "legacy-top")
			require.Empty(t, server.rootTenantID(context.Background()))

			rec := route.run(t, server, rawToken, nil)
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())

			_, creds := storedState(t, server, "msp-a")
			assert.Zero(t, creds)
			details := auditDetailsFor(t, server, policyDeniedAction)
			assert.Equal(t, "root_tenant_unresolved", details["reason"])
		})
	}
}

func TestSoftwareAuthenticatorPolicy_PermittedRegisters(t *testing.T) {
	for _, route := range registerRoutes {
		t.Run(route.name, func(t *testing.T) {
			server, rawToken := newPolicyServer(t, []string{"msp-a"}, policyAccountSpec{tenantID: "msp-a", flag: true})

			rec := route.run(t, server, rawToken, nil)
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

			acct, creds := storedState(t, server, "msp-a")
			require.Equal(t, 1, creds)
			assert.True(t, acct.Credentials[0].isSoftwareAuthenticator())
			assert.True(t, acct.AllowSoftwareAuthenticator, "the flag survives the credential write")
		})
	}
}

// A credential that does not carry the CFGMS AAGUID is outside this policy: it
// registers for an account the policy would refuse, and is recorded as not
// software, so nothing downstream treats it differently either way.
func TestSoftwareAuthenticatorPolicy_NonCFGMSAAGUIDRegistersRegardless(t *testing.T) {
	other := [16]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	for _, route := range registerRoutes {
		t.Run(route.name, func(t *testing.T) {
			server, rawToken := newPolicyServer(t, nil, policyAccountSpec{rootScope: true})

			rec := route.run(t, server, rawToken, &other)
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

			acct, creds := storedState(t, server, "")
			require.Equal(t, 1, creds)
			assert.Equal(t, other[:], acct.Credentials[0].AAGUID)
			assert.False(t, acct.Credentials[0].isSoftwareAuthenticator())
			assert.False(t, acct.AllowSoftwareAuthenticator)
		})
	}
}

func TestAccount_AllowSoftwareAuthenticatorPersists(t *testing.T) {
	server, _ := newPolicyServer(t, nil, policyAccountSpec{tenantID: "msp-a", flag: true})
	dropAccountCache(server)
	acct, _ := storedState(t, server, "msp-a")
	assert.True(t, acct.AllowSoftwareAuthenticator)

	off, _ := newPolicyServer(t, nil, policyAccountSpec{tenantID: "msp-a"})
	acct, _ = storedState(t, off, "msp-a")
	assert.False(t, acct.AllowSoftwareAuthenticator, "absent key means off")
}

// A reset re-provisions the account to zero authenticators and must not keep the
// flag that let it hold a software one.
func TestAccount_ResetClearsAllowSoftwareAuthenticator(t *testing.T) {
	server, _ := newPolicyServer(t, []string{"msp-a"}, policyAccountSpec{tenantID: "msp-a", flag: true})

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: policyUser, TenantID: "msp-a", ResetCredentials: true,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	acct, _ := storedState(t, server, "msp-a")
	assert.False(t, acct.AllowSoftwareAuthenticator)
}

func TestSetSoftwareAuthenticatorTenants_ExactMatchAndReplace(t *testing.T) {
	server := setupTestServer(t)
	in := []string{"msp-a"}
	server.SetSoftwareAuthenticatorTenants(in)
	in[0] = "msp-b"
	assert.True(t, server.SoftwareAuthenticatorTenantListed("msp-a"), "the list is copied")
	assert.False(t, server.SoftwareAuthenticatorTenantListed("msp-b"))
	assert.False(t, server.SoftwareAuthenticatorTenantListed("msp-a/client-1"))
	assert.False(t, server.SoftwareAuthenticatorTenantListed("MSP-A"))

	server.SetSoftwareAuthenticatorTenants(nil)
	assert.False(t, server.SoftwareAuthenticatorTenantListed("msp-a"))
}

// --- Issue #6225: root-scope agent accounts (ADR-021 Amendment 11) ---

// rootAgentSpec is one root-scope account for the root-agent registration tests.
type rootAgentSpec struct {
	username string
	flag     bool
	cert     bool // a bound admin certificate
	human    bool // an existing non-software credential
}

// newRootAgentPolicyServer builds the policy server with the root-agent setting at
// setting, and one root-scope account shaped by spec. It returns the server and the
// account's enrollment token.
func newRootAgentPolicyServer(t *testing.T, setting bool, spec rootAgentSpec) (*Server, string) {
	t.Helper()
	server := setupTestServer(t)
	seedTenantTree(t, server)
	wa, err := NewWebAuthnFromConfig(aaguidRPID, aaguidRPID, []string{aaguidOrigin})
	require.NoError(t, err)
	server.SetWebAuthn(wa)
	server.SetSoftwareAuthenticatorRootAgentAccounts(setting)

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: spec.username, RootScope: true})
	require.Equal(t, http.StatusCreated, rec.Code, "create account: %s", rec.Body.String())
	var outer APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &outer))
	rawToken, _ := outer.Data.(map[string]interface{})["enrollment_magic_link"].(string)
	require.NotEmpty(t, rawToken)

	ctx := context.Background()
	acct, err := server.loadAccountFromStore(ctx, spec.username, "")
	require.NoError(t, err)
	require.NotNil(t, acct)
	acct.AllowSoftwareAuthenticator = spec.flag
	if spec.cert {
		acct.CertBindings = []CertBinding{{Serial: "4242", Fingerprint: "fp"}}
	}
	if spec.human {
		acct.Credentials = append(acct.Credentials, WebAuthnCredential{
			ID: []byte("human-credential"), PublicKey: []byte("pk"), Label: "hardware",
			AAGUID: make([]byte, 16),
		})
		// A credential on the account closes the enrollment link; the admin register
		// route does not use it.
	}
	require.NoError(t, server.persistAccount(ctx, acct, "test"))
	dropAccountCache(server)
	return server, rawToken
}

// rootAgentRegister runs the admin registration ceremony for username.
func rootAgentRegister(t *testing.T, server *Server, username string) *httptest.ResponseRecorder {
	t.Helper()
	opts := creationOptions(t, server, username, doBegin(t, server, username), func(sd webauthn.SessionData) {
		injectSession(server, username, sd, 10*time.Minute)
	})
	resp, err := newSoftAuthenticator(t, nil).Register(opts)
	require.NoError(t, err)
	return doFinish(t, server, username, bytes.NewReader(resp))
}

func rootAgentCredentialCount(t *testing.T, server *Server, username string) int {
	t.Helper()
	fresh, err := server.loadAccountFromStore(context.Background(), username, "")
	require.NoError(t, err)
	require.NotNil(t, fresh)
	return len(fresh.Credentials)
}

func TestSoftwareAuthenticatorPolicy_RootAgentSettingOffRefusesRegistration(t *testing.T) {
	server, _ := newRootAgentPolicyServer(t, false, rootAgentSpec{username: "agent-off", flag: true})

	rec := rootAgentRegister(t, server, "agent-off")
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, errCodeSoftwareAuthenticatorNotAllowed, errCode(t, rec.Body.Bytes()))
	assert.Zero(t, rootAgentCredentialCount(t, server, "agent-off"), "nothing is stored on refusal")

	details := auditDetailsFor(t, server, policyDeniedAction)
	assert.Equal(t, reasonRootAgentSettingOff, details["reason"])
	assert.Equal(t, true, details["root_scope"], "a root-scope refusal is told from a tenant one")
	assert.Equal(t, hex.EncodeToString(softauthn.AAGUID[:]), details["aaguid"])

	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{Actions: []string{policyDeniedAction}})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, business.AuditResultDenied, entries[0].Result)
}

func TestSoftwareAuthenticatorPolicy_RootAgentRegistrationRefusals(t *testing.T) {
	tests := []struct {
		name   string
		spec   rootAgentSpec
		reason string
	}{
		{"root account without the flag", rootAgentSpec{username: "agent-noflag"}, reasonRootAgentFlagUnset},
		{"the cfgms-admin account carrying the flag", rootAgentSpec{username: "cfgms-admin", flag: true}, reasonRootAgentSystemAdmin},
		{"a bound admin certificate", rootAgentSpec{username: "agent-cert", flag: true, cert: true}, reasonRootAgentCertBound},
		{"an existing non-software credential", rootAgentSpec{username: "agent-human", flag: true, human: true}, reasonRootAgentHumanCredential},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, _ := newRootAgentPolicyServer(t, true, tt.spec)
			before := rootAgentCredentialCount(t, server, tt.spec.username)

			rec := rootAgentRegister(t, server, tt.spec.username)
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Equal(t, errCodeSoftwareAuthenticatorNotAllowed, errCode(t, rec.Body.Bytes()))
			assert.Equal(t, before, rootAgentCredentialCount(t, server, tt.spec.username), "nothing is stored on refusal")

			details := auditDetailsFor(t, server, policyDeniedAction)
			assert.Equal(t, tt.reason, details["reason"])
			assert.Equal(t, true, details["root_scope"])
		})
	}
}

// A root agent account that is eligible under every Issue #6225 condition still cannot
// register a credential without a verified TPM attestation (Issue #6227): begin refuses a
// request with no TPM material, and a finish with a "none" attestation is refused, on
// both routes. The attested registration is TestRootAgentRegistration_TPMAttested.
func TestSoftwareAuthenticatorPolicy_RootAgentWithoutTPMIsRefused(t *testing.T) {
	t.Run("admin register route", func(t *testing.T) {
		server, _ := newRootAgentPolicyServer(t, true, rootAgentSpec{username: "agent-ok", flag: true})
		begin := doBegin(t, server, "agent-ok")
		require.Equal(t, http.StatusBadRequest, begin.Code, begin.Body.String())
		assert.Equal(t, errCodeTPMAttestationRequired, errCode(t, begin.Body.Bytes()))

		rec := rootAgentRegister(t, server, "agent-ok")
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Equal(t, errCodeTPMAttestationRequired, errCode(t, rec.Body.Bytes()))
		assert.Zero(t, rootAgentCredentialCount(t, server, "agent-ok"), "nothing is stored on refusal")
	})
	t.Run("enrollment-token route", func(t *testing.T) {
		server, rawToken := newRootAgentPolicyServer(t, true, rootAgentSpec{username: "agent-enroll", flag: true})
		begin := doEnrollBegin(t, server, rawToken)
		require.Equal(t, http.StatusBadRequest, begin.Code, begin.Body.String())
		assert.Equal(t, errCodeTPMAttestationRequired, errCode(t, begin.Body.Bytes()))
		assert.Zero(t, rootAgentCredentialCount(t, server, "agent-enroll"))
	})
}

func TestSoftwareAuthenticatorPermitted_RootAgentDecision(t *testing.T) {
	ctx := context.Background()
	server := setupTestServer(t)
	seedTenantTree(t, server)
	soft := WebAuthnCredential{ID: []byte("s"), AAGUID: append([]byte(nil), softauthn.AAGUID[:]...)}
	hardware := WebAuthnCredential{ID: []byte("h"), AAGUID: make([]byte, 16)}

	tests := []struct {
		name    string
		setting bool
		acct    *account
		want    bool
		reason  string
	}{
		{"eligible, no credential yet", true, &account{Username: "a", RootScope: true, AllowSoftwareAuthenticator: true}, true, ""},
		{"eligible, software credentials only", true, &account{Username: "a", RootScope: true, AllowSoftwareAuthenticator: true, Credentials: []WebAuthnCredential{soft, soft}}, true, ""},
		{"setting off", false, &account{Username: "a", RootScope: true, AllowSoftwareAuthenticator: true}, false, reasonRootAgentSettingOff},
		{"flag off", true, &account{Username: "a", RootScope: true}, false, reasonRootAgentFlagUnset},
		{"system admin name", true, &account{Username: systemAdminAccountName, RootScope: true, AllowSoftwareAuthenticator: true}, false, reasonRootAgentSystemAdmin},
		{"bound certificate", true, &account{Username: "a", RootScope: true, AllowSoftwareAuthenticator: true, CertBindings: []CertBinding{{Serial: "1"}}}, false, reasonRootAgentCertBound},
		{"one hardware credential among software ones", true, &account{Username: "a", RootScope: true, AllowSoftwareAuthenticator: true, Credentials: []WebAuthnCredential{soft, hardware}}, false, reasonRootAgentHumanCredential},
		{"root scope with a tenant id is still judged as root", true, &account{Username: "a", TenantID: "msp-a", RootScope: true, AllowSoftwareAuthenticator: true}, true, ""},
		{"tenant account unaffected by the setting on", true, &account{Username: "a", TenantID: "msp-a", AllowSoftwareAuthenticator: true}, false, reasonPolicy},
		{"empty tenant, not root scope, setting on", true, &account{Username: "a", AllowSoftwareAuthenticator: true}, false, reasonPolicy},
		{"root tenant account, setting on", true, &account{Username: "a", TenantID: testRootTenantID, AllowSoftwareAuthenticator: true}, false, reasonPolicy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.SetSoftwareAuthenticatorRootAgentAccounts(tt.setting)
			got, reason, err := server.softwareAuthenticatorDecision(ctx, tt.acct)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.reason, reason)
			wrapped, err := server.softwareAuthenticatorPermitted(ctx, tt.acct)
			require.NoError(t, err)
			assert.Equal(t, tt.want, wrapped)
		})
	}

	t.Run("a tenant account listed in the tenant path is unaffected by the setting in both directions", func(t *testing.T) {
		server.SetSoftwareAuthenticatorTenants([]string{"msp-a"})
		acct := &account{Username: "t", TenantID: "msp-a", AllowSoftwareAuthenticator: true}
		for _, setting := range []bool{true, false} {
			server.SetSoftwareAuthenticatorRootAgentAccounts(setting)
			got, err := server.softwareAuthenticatorPermitted(ctx, acct)
			require.NoError(t, err)
			assert.True(t, got)
		}
	})

	t.Run("the root-agent path needs no resolvable root tenant", func(t *testing.T) {
		server := setupTestServerWithoutRootTenant(t)
		server.SetSoftwareAuthenticatorRootAgentAccounts(true)
		got, err := server.softwareAuthenticatorPermitted(ctx, &account{Username: "a", RootScope: true, AllowSoftwareAuthenticator: true})
		require.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("nil account", func(t *testing.T) {
		got, err := server.softwareAuthenticatorPermitted(ctx, nil)
		require.NoError(t, err)
		assert.False(t, got)
	})
}

func TestSetSoftwareAuthenticatorRootAgentAccounts_DefaultsOffAndReplaces(t *testing.T) {
	server := setupTestServer(t)
	assert.False(t, server.SoftwareAuthenticatorRootAgentAccounts(), "absent means off")
	server.SetSoftwareAuthenticatorRootAgentAccounts(true)
	assert.True(t, server.SoftwareAuthenticatorRootAgentAccounts())
	server.SetSoftwareAuthenticatorRootAgentAccounts(false)
	assert.False(t, server.SoftwareAuthenticatorRootAgentAccounts())
}
