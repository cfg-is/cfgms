// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6141: PUT /api/v1/accounts/{username}/software-authenticator.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	flagPerm  = "account:set-software-authenticator"
	flagUser  = "flag-user"
	flagAudit = "account.software_authenticator_flag_changed"
)

type flagFixture struct {
	tb  *testing.T
	srv *Server
	mux *mux.Router
}

// newFlagFixture wires the real route behind the real requirePermission middleware on
// a server with the tenant tree (root > msp-a > client-1, root > msp-b), a durable
// secret store and an audit manager.
func newFlagFixture(t *testing.T) *flagFixture {
	t.Helper()
	srv := setupTestServer(t)
	seedTenantTree(t, srv)
	r := mux.NewRouter()
	registerSoftwareAuthenticatorFlagRoutes(srv, r.PathPrefix("/api/v1").Subrouter())
	return &flagFixture{tb: t, srv: srv, mux: r}
}

// rootCaller is a human root-scope administrator holding the flag permission.
func rootCaller() *Principal {
	return &Principal{ID: "root-admin", Assurance: session.AssuranceStrong, Permissions: []string{flagPerm}}
}

// tenantCaller is a human administrator of one tenant holding the flag permission.
func tenantCaller(tenantID string) *Principal {
	return &Principal{ID: "tenant-admin-" + tenantID, Assurance: session.AssuranceStrong, TenantID: tenantID, Permissions: []string{flagPerm}}
}

func (f *flagFixture) createAccount(username, tenantID string) {
	f.tb.Helper()
	rec := postAccount(f.tb, f.srv, testAdminPrincipal(), AccountRequest{Username: username, TenantID: tenantID})
	require.Equal(f.tb, http.StatusCreated, rec.Code, rec.Body.String())
}

func (f *flagFixture) put(username, body string, p *Principal, presence bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/v1/accounts/"+username+"/software-authenticator", strings.NewReader(body))
	req = withPrincipal(req, p)
	if presence {
		req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(f.tb, f.srv, p.ID, req, flagPerm))
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

// flag reads the stored flag, bypassing the cache.
func (f *flagFixture) flag(username, tenantID string) bool {
	f.tb.Helper()
	dropAccountCache(f.srv)
	acct, err := f.srv.loadAccountFromStore(context.Background(), username, accountStorageTenant(tenantID))
	require.NoError(f.tb, err)
	require.NotNil(f.tb, acct)
	return acct.AllowSoftwareAuthenticator
}

// setFlag writes the flag on the stored record directly, as a prior tap would have.
func (f *flagFixture) setFlag(username, tenantID string, v bool) {
	f.tb.Helper()
	ctx := context.Background()
	acct, err := f.srv.loadAccountFromStore(ctx, username, accountStorageTenant(tenantID))
	require.NoError(f.tb, err)
	require.NotNil(f.tb, acct)
	acct.AllowSoftwareAuthenticator = v
	require.NoError(f.tb, f.srv.persistAccount(ctx, acct, "test"))
	dropAccountCache(f.srv)
}

func (f *flagFixture) auditEntries() []*business.AuditEntry {
	return auditEntriesByAction(f.tb, f.srv, flagAudit)
}

// The route is on the live router, and an API-key principal is refused there even
// when the key carries the permission.
func TestSoftwareAuthenticatorFlagRouteIsLive(t *testing.T) {
	srv := setupTestServer(t)

	var match mux.RouteMatch
	req := httptest.NewRequest(http.MethodPut, "/api/v1/accounts/someone/software-authenticator", nil)
	require.True(t, srv.router.Match(req, &match), "PUT /accounts/{username}/software-authenticator must be registered")
	assert.Equal(t, "someone", match.Vars["username"])

	key := NewTestKey(t, srv, []string{flagPerm})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/accounts/someone/software-authenticator", strings.NewReader(`{"enabled":true}`))
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "a machine principal is refused: %s", rec.Body.String())
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"), "refusal, not a step-up challenge")
}

func TestSoftwareAuthenticatorFlag_TapMachineAndTenantRefusals(t *testing.T) {
	f := newFlagFixture(t)
	f.createAccount(flagUser, "client-1")

	t.Run("no presence token gets the step-up challenge", func(t *testing.T) {
		rec := f.put(flagUser, `{"enabled":true}`, rootCaller(), false)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`)
		assert.False(t, f.flag(flagUser, "client-1"))
		assert.Empty(t, f.auditEntries(), "a challenged request leaves no audit record")
	})

	t.Run("machine principal is refused", func(t *testing.T) {
		machine := &Principal{ID: "key-1", Assurance: session.AssuranceMachine, Permissions: []string{flagPerm}}
		rec := f.put(flagUser, `{"enabled":true}`, machine, true)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.False(t, f.flag(flagUser, "client-1"))
	})

	t.Run("caller without the permission is refused", func(t *testing.T) {
		p := rootCaller()
		p.Permissions = []string{"account:update"}
		rec := f.put(flagUser, `{"enabled":true}`, p, true)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.False(t, f.flag(flagUser, "client-1"))
	})

	t.Run("caller outside the account's tenant is refused", func(t *testing.T) {
		f.setFlag(flagUser, "client-1", true)
		for name, body := range map[string]string{"enable": `{"enabled":true}`, "clear": `{"enabled":false}`} {
			rec := f.put(flagUser, body, tenantCaller("msp-b"), true)
			assert.Equal(t, http.StatusNotFound, rec.Code, "%s: %s", name, rec.Body.String())
		}
		assert.True(t, f.flag(flagUser, "client-1"), "an outside caller cannot clear it either")
		assert.Empty(t, f.auditEntries())
	})
}

func TestSoftwareAuthenticatorFlag_RootEnablesAndClearsWithAudit(t *testing.T) {
	f := newFlagFixture(t)
	f.createAccount(flagUser, "msp-a")
	root := rootCaller()

	rec := f.put(flagUser, `{"enabled":true}`, root, true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data SoftwareAuthenticatorFlagResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, flagUser, resp.Data.Username)
	assert.Equal(t, "msp-a", resp.Data.TenantID)
	assert.True(t, resp.Data.AllowSoftwareAuthenticator)
	assert.True(t, f.flag(flagUser, "msp-a"), "the flag is durable")

	entries := f.auditEntries()
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, "root-admin", e.UserID)
	assert.Equal(t, "msp-a", e.TenantID)
	assert.Equal(t, business.AuditResultSuccess, e.Result)
	assert.Equal(t, flagUser, e.Details["account"])
	assert.Equal(t, "msp-a", e.Details["tenant"])
	assert.Equal(t, "root-admin", e.Details["principal"])
	assert.Equal(t, false, e.Details["previous"])
	assert.Equal(t, true, e.Details["new"])

	rec = f.put(flagUser, `{"enabled":false}`, root, true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.False(t, f.flag(flagUser, "msp-a"))
	entries = f.auditEntries()
	require.Len(t, entries, 2, "each change leaves one audit record")
	var sawClear bool
	for _, e := range entries {
		if e.Details["previous"] == true && e.Details["new"] == false {
			sawClear = true
		}
	}
	assert.True(t, sawClear, "the clear records true -> false")
}

func TestSoftwareAuthenticatorFlag_TenantCallerCanOnlyClear(t *testing.T) {
	f := newFlagFixture(t)
	f.createAccount(flagUser, "client-1")
	msp := tenantCaller("msp-a") // client-1's parent: allowed to manage it, not to enable

	rec := f.put(flagUser, `{"enabled":true}`, msp, true)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.False(t, f.flag(flagUser, "client-1"))
	assert.Empty(t, f.auditEntries(), "a refused enable leaves no change record")

	f.setFlag(flagUser, "client-1", true)
	rec = f.put(flagUser, `{"enabled":false}`, msp, true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.False(t, f.flag(flagUser, "client-1"))
	require.Len(t, f.auditEntries(), 1)

	// The account's own tenant may clear it as well.
	f.setFlag(flagUser, "client-1", true)
	require.Equal(t, http.StatusOK, f.put(flagUser, `{"enabled":false}`, tenantCaller("client-1"), true).Code)
	assert.False(t, f.flag(flagUser, "client-1"))
}

func TestSoftwareAuthenticatorFlag_EnableRefusedForRootShapes(t *testing.T) {
	f := newFlagFixture(t)
	root := rootCaller()

	// A RootScope account.
	rootScoped := postAccount(t, f.srv, testAdminPrincipal(), AccountRequest{Username: "root-scoped", RootScope: true})
	require.Equal(t, http.StatusCreated, rootScoped.Code, rootScoped.Body.String())
	// An account in the root tenant.
	f.createAccount("root-tenant-user", testRootTenantID)
	// An account with an empty TenantID that is not RootScope. A store record cannot
	// load that shape (an empty tenant is stored under a sentinel), so it is injected
	// through the account cache, which getAccount falls back to.
	f.srv.cacheAccount(&account{ID: "empty-id", Username: "empty-tenant", TenantID: ""})

	shapes := []struct{ username, storeTenant string }{
		{"root-scoped", ""},
		{"root-tenant-user", testRootTenantID},
		{"empty-tenant", ""},
	}
	for _, sh := range shapes {
		t.Run(sh.username, func(t *testing.T) {
			rec := f.put(sh.username, `{"enabled":true}`, root, true)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), errCodeSoftwareAuthenticatorNotAllowed)
		})
	}
	assert.Empty(t, f.auditEntries(), "a refused enable leaves no change record")

	// Clearing is always allowed, including for the shapes that cannot be enabled.
	f.setFlag("root-tenant-user", testRootTenantID, true)
	f.setFlag("root-scoped", "", true)
	f.srv.cacheAccount(&account{ID: "empty-id", Username: "empty-tenant", TenantID: "", AllowSoftwareAuthenticator: true}) // setFlag dropped the cache
	for _, sh := range shapes {
		t.Run("clear "+sh.username, func(t *testing.T) {
			rec := f.put(sh.username, `{"enabled":false}`, root, true)
			assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		})
	}
	assert.False(t, f.flag("root-tenant-user", testRootTenantID))
	assert.False(t, f.flag("root-scoped", ""))
	assert.Len(t, f.auditEntries(), 3)
}

func TestSoftwareAuthenticatorFlag_EnableFailsClosedWithoutRootTenant(t *testing.T) {
	srv := setupTestServerWithoutRootTenant(t)
	f := &flagFixture{tb: t, srv: srv, mux: mux.NewRouter()}
	registerSoftwareAuthenticatorFlagRoutes(srv, f.mux.PathPrefix("/api/v1").Subrouter())
	srv.cacheAccount(&account{ID: "acct-id", Username: flagUser, TenantID: "msp-a"})

	rec := f.put(flagUser, `{"enabled":true}`, rootCaller(), true)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Empty(t, f.auditEntries())
}

func TestSoftwareAuthenticatorFlag_AuditUnavailableLeavesFlagUnchanged(t *testing.T) {
	f := newFlagFixture(t)
	f.createAccount(flagUser, "msp-a")
	root := rootCaller()

	t.Run("audit manager cannot record", func(t *testing.T) {
		mgr, err := audit.NewManager(newTestFailingAuditStore(t, assert.AnError), "controller")
		require.NoError(t, err)
		require.NoError(t, mgr.Stop(context.Background()))
		live := f.srv.auditManager
		f.srv.auditManager = mgr
		t.Cleanup(func() { f.srv.auditManager = live })

		rec := f.put(flagUser, `{"enabled":true}`, root, true)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "AUDIT_UNAVAILABLE")
		assert.False(t, f.flag(flagUser, "msp-a"))
	})

	t.Run("no audit manager", func(t *testing.T) {
		live := f.srv.auditManager
		f.srv.auditManager = nil
		t.Cleanup(func() { f.srv.auditManager = live })

		assert.Equal(t, http.StatusServiceUnavailable, f.put(flagUser, `{"enabled":true}`, root, true).Code)
		assert.False(t, f.flag(flagUser, "msp-a"))
	})

	t.Run("a stopped audit manager also blocks a clear", func(t *testing.T) {
		f.setFlag(flagUser, "msp-a", true)
		live := f.srv.auditManager
		f.srv.auditManager = nil
		t.Cleanup(func() { f.srv.auditManager = live })

		assert.Equal(t, http.StatusServiceUnavailable, f.put(flagUser, `{"enabled":false}`, root, true).Code)
		assert.True(t, f.flag(flagUser, "msp-a"), "no audit, no change, in either direction")
	})
}

func TestSoftwareAuthenticatorFlag_RejectsBadRequests(t *testing.T) {
	f := newFlagFixture(t)
	f.createAccount(flagUser, "msp-a")
	root := rootCaller()

	for name, body := range map[string]string{
		"missing enabled": `{}`,
		"not a bool":      `{"enabled":"yes"}`,
		"null":            `{"enabled":null}`,
		"not json":        `enabled=true`,
		"unknown field":   `{"enabled":true,"tenant_id":"msp-b"}`,
		"trailing value":  `{"enabled":true}{"enabled":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.put(flagUser, body, root, true)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.False(t, f.flag(flagUser, "msp-a"))
		})
	}
	assert.Empty(t, f.auditEntries())

	assert.Equal(t, http.StatusNotFound, f.put("no-such-user", `{"enabled":true}`, root, true).Code)
	assert.Equal(t, http.StatusBadRequest, f.put("a", `{"enabled":true}`, root, true).Code, "username fails validation")
}

// postAccountRaw posts a raw JSON body to handleCreateAccount, so a field AccountRequest
// does not declare can be sent.
func postAccountRaw(t *testing.T, srv *Server, p *Principal, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := withPrincipal(httptest.NewRequest(http.MethodPost, "/api/v1/accounts", bytes.NewBufferString(body)), p)
	rec := httptest.NewRecorder()
	srv.handleCreateAccount(rec, req)
	return rec
}

func putAccountFlagBody(t *testing.T, srv *Server, p *Principal, username, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/accounts/"+username, bytes.NewBufferString(body))
	req = withVars(withPrincipal(req, p), map[string]string{"username": username})
	rec := httptest.NewRecorder()
	srv.handleUpdateAccount(rec, req)
	return rec
}

// The ordinary account write paths cannot set the flag, whoever calls them, and an
// unknown allow_software_authenticator body field is ignored.
func TestSoftwareAuthenticatorFlag_OrdinaryWritePathsCannotSet(t *testing.T) {
	callers := map[string]*Principal{
		"root caller":   testAdminPrincipal(),
		"tenant caller": {ID: "msp-admin", Assurance: session.AssuranceStrong, TenantID: "msp-a", Permissions: []string{"account:create", "account:update"}},
	}
	for name, caller := range callers {
		t.Run(name, func(t *testing.T) {
			f := newFlagFixture(t)

			// Create with the field in the body.
			rec := postAccountRaw(t, f.srv, caller, `{"username":"`+flagUser+`","tenant_id":"client-1","allow_software_authenticator":true}`)
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
			assert.False(t, f.flag(flagUser, "client-1"), "create ignores the field")

			// Upsert (reset without reset_credentials) with the field in the body.
			rec = postAccountRaw(t, f.srv, caller, `{"username":"`+flagUser+`","allow_software_authenticator":true}`)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.False(t, f.flag(flagUser, "client-1"), "upsert ignores the field")

			// Upsert with reset_credentials and the field.
			rec = postAccountRaw(t, f.srv, caller, `{"username":"`+flagUser+`","reset_credentials":true,"allow_software_authenticator":true}`)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.False(t, f.flag(flagUser, "client-1"), "a reset does not set it")

			// Update route with the field.
			rec = putAccountFlagBody(t, f.srv, caller, flagUser, `{"disabled":false,"allow_software_authenticator":true}`)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.False(t, f.flag(flagUser, "client-1"), "update ignores the field")
		})
	}
}

// Both ordinary paths leave an enabled flag as it was, except that reset_credentials
// clears it; a move to another tenant clears it too.
func TestSoftwareAuthenticatorFlag_OrdinaryWritePathsLeaveItUnlessReset(t *testing.T) {
	admin := testAdminPrincipal()

	t.Run("upsert and update leave it enabled", func(t *testing.T) {
		f := newFlagFixture(t)
		f.createAccount(flagUser, "msp-a")
		f.setFlag(flagUser, "msp-a", true)

		rec := postAccountRaw(t, f.srv, admin, `{"username":"`+flagUser+`","permissions":["steward:list"]}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.True(t, f.flag(flagUser, "msp-a"), "upsert leaves the flag")

		rec = putAccountFlagBody(t, f.srv, admin, flagUser, `{"permissions":["steward:read"],"disabled":false}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.True(t, f.flag(flagUser, "msp-a"), "update leaves the flag")
	})

	t.Run("upsert reset_credentials clears it", func(t *testing.T) {
		f := newFlagFixture(t)
		f.createAccount(flagUser, "msp-a")
		f.setFlag(flagUser, "msp-a", true)

		rec := postAccountRaw(t, f.srv, admin, `{"username":"`+flagUser+`","reset_credentials":true}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.False(t, f.flag(flagUser, "msp-a"))
		reset := auditEntriesByAction(t, f.srv, "account.reset")
		require.NotEmpty(t, reset)
		assert.Equal(t, "allow_software_authenticator", reset[len(reset)-1].Details["flag_cleared"])
	})

	t.Run("update reset_credentials clears it", func(t *testing.T) {
		f := newFlagFixture(t)
		f.createAccount(flagUser, "msp-a")
		f.setFlag(flagUser, "msp-a", true)

		rec := putAccountFlagBody(t, f.srv, admin, flagUser, `{"reset_credentials":true}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.False(t, f.flag(flagUser, "msp-a"))
		entries := auditEntriesByAction(t, f.srv, "account.credentials_reset")
		require.Len(t, entries, 1)
		assert.Equal(t, "allow_software_authenticator", entries[0].Details["flag_cleared"])
	})

	t.Run("a move to another tenant clears it", func(t *testing.T) {
		f := newFlagFixture(t)
		f.createAccount(flagUser, "msp-a")
		f.setFlag(flagUser, "msp-a", true)

		rec := postAccountRaw(t, f.srv, admin, `{"username":"`+flagUser+`","tenant_id":"msp-b"}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.False(t, f.flag(flagUser, "msp-b"))
	})
}
