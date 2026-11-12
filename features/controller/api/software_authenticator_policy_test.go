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

var registerRoutes = []registerRoute{
	{"admin register route", func(t *testing.T, server *Server, _ string, aaguid *[16]byte) *httptest.ResponseRecorder {
		resp, err := newSoftAuthenticator(t, aaguid).Register(beginData(t, doBegin(t, server, policyUser)))
		require.NoError(t, err)
		return doFinish(t, server, policyUser, bytes.NewReader(resp))
	}},
	{"enrollment-token route", func(t *testing.T, server *Server, rawToken string, aaguid *[16]byte) *httptest.ResponseRecorder {
		resp, err := newSoftAuthenticator(t, aaguid).Register(beginData(t, doEnrollBegin(t, server, rawToken)))
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
