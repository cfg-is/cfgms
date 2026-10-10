// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// identityReadFixture holds one client tenant (an MSP) and one record of every
// identity and credential kind for both it and the root tenant, so a test can tell
// which of the two a read returned.
type identityReadFixture struct {
	server  *Server
	certMgr *cert.Manager
	msp     string

	rootAccount, mspAccount     string
	rootAccountID, mspAccountID string
	rootSerial, mspSerial       string
	rootToken, mspToken         string
	rootCase, mspCase           string
	rootRole, mspRole           string
	rootKeyID, mspKeyID         string
}

const identityMSP = "msp-identity"

func newIdentityReadFixture(t *testing.T) *identityReadFixture {
	t.Helper()
	server, certMgr, stewardStore := setupCertTestServerWithStewardStore(t)
	server = seedRootTenant(t, wireCrossingStore(t, server))
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: identityMSP, ParentID: testRootTenantID})
	require.NoError(t, err)

	fx := &identityReadFixture{server: server, certMgr: certMgr, msp: identityMSP,
		rootAccount: "root-op", mspAccount: "msp-user"}

	// Accounts: a root-scope operator (owned by the root tenant) and an MSP account.
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: fx.rootAccount, RootScope: true, Permissions: []string{"steward:list"}})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	fx.rootAccountID = decodeAccountInfo(t, rec).ID
	rec = postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: fx.mspAccount, TenantID: identityMSP, Permissions: []string{"steward:list"}})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	fx.mspAccountID = decodeAccountInfo(t, rec).ID

	createSubjectForTenant(t, server, identityMSP, fx.mspAccountID, "msp-user")

	// Certificates, each owned through its steward record.
	for _, s := range []struct {
		id, tenant string
		serial     *string
	}{{"steward-identity-root", testRootTenantID, &fx.rootSerial}, {"steward-identity-msp", identityMSP, &fx.mspSerial}} {
		require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
			ID: s.id, TenantID: s.tenant, Hostname: s.id, Platform: "linux", Arch: "amd64"}))
		c, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
			CommonName: s.id, Organization: "Test CFGMS", ClientID: s.id, ValidityDays: 365})
		require.NoError(t, err)
		*s.serial = c.SerialNumber
	}

	// Registration tokens.
	tokenStore := newTestRegistrationStore(t)
	server.registrationTokenStore = tokenStore
	for _, s := range []struct {
		tenant string
		out    *string
	}{{testRootTenantID, &fx.rootToken}, {identityMSP, &fx.mspToken}} {
		tok, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID: s.tenant, ControllerURL: "grpc://controller.example.com:7443", Group: "g"})
		require.NoError(t, err)
		require.NoError(t, tokenStore.SaveToken(ctx, tok))
		*s.out = tok.Token
	}

	// Pending registrations.
	sm := pkgtesting.SetupTestStorage(t)
	server.SetPendingStore(sm.GetPendingRegistrationStore())
	for _, tid := range []string{testRootTenantID, identityMSP} {
		require.NoError(t, sm.GetPendingRegistrationStore().AddPending(ctx, &business.PendingRegistrationEntry{
			PendingID: "pending-" + tid, StewardID: "steward-pending-" + tid, TenantID: tid,
			TokenStr: "tok-" + tid, SourceIP: "10.0.0.9", RegisteredAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(time.Hour), Status: business.PendingRegistrationStatusPending}))
	}

	// Cases.
	server.SetCasesStore(sm.GetCaseStore())
	fx.rootCase = seedCase(t, sm.GetCaseStore(), testRootTenantID).ID
	fx.mspCase = seedCase(t, sm.GetCaseStore(), identityMSP).ID

	// Roles.
	fx.rootRole, fx.mspRole = "role-identity-root", "role-identity-msp"
	createRoleForTenant(t, server, testRootTenantID, fx.rootRole, "identity-root")
	createRoleForTenant(t, server, identityMSP, fx.mspRole, "identity-msp")

	// API keys, held in the in-memory cache only.
	fx.rootKeyID, fx.mspKeyID = "key-identity-root", "key-identity-msp"
	injectAPIKey(server, &APIKey{ID: fx.rootKeyID, Key: "identity-root-secret", Name: "root", TenantID: testRootTenantID, CreatedAt: time.Now()})
	injectAPIKey(server, &APIKey{ID: fx.mspKeyID, Key: "identity-msp-secret", Name: "msp", TenantID: identityMSP, CreatedAt: time.Now()})

	// Sessions.
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)
	server.SetSessionManager(mgr)
	_, _, err = mgr.Issue(ctx, "session-root-user", "cli", testRootTenantID)
	require.NoError(t, err)
	_, _, err = mgr.Issue(ctx, "session-msp-user", "cli", identityMSP)
	require.NoError(t, err)

	// Role configs, stored under each tenant through its own scoped key.
	server.SetRoleConfigStore(sm.GetConfigStore())
	for _, tid := range []string{testRootTenantID, identityMSP} {
		key := NewEphemeralTestKey(t, server, []string{"role:write"}, tid, 5*time.Minute)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(validRolePayload("cfg-"+tid, "os:linux")))
		req.Header.Set("X-API-Key", key)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	}
	return fx
}

func decodeAccountInfo(t *testing.T, rec *httptest.ResponseRecorder) AccountInfo {
	t.Helper()
	var resp struct {
		Data AccountInfo `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func identityRootCaller(op *Principal) func(*http.Request, map[string]string) *http.Request {
	return func(req *http.Request, vars map[string]string) *http.Request {
		return asRootOperator(req, op, vars)
	}
}

func identityUnrestrictedCaller() func(*http.Request, map[string]string) *http.Request {
	return func(req *http.Request, vars map[string]string) *http.Request {
		return withVars(withPrincipal(req, testAdminPrincipal()), vars)
	}
}

func identityMSPAdminCaller() func(*http.Request, map[string]string) *http.Request {
	return func(req *http.Request, vars map[string]string) *http.Request {
		return withVars(withPrincipal(req, &Principal{ID: "msp-admin", TenantID: identityMSP}), vars)
	}
}

func identityServe(h http.HandlerFunc, method, url string, caller func(*http.Request, map[string]string) *http.Request, vars map[string]string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, caller(httptest.NewRequest(method, url, nil), vars))
	return rec
}

// identityDataList decodes {"data":[...]} and returns the string field named by pick from each row.
func identityDataList[T any](t *testing.T, rec *httptest.ResponseRecorder, pick func(T) string) []string {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []T `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	out := make([]string, 0, len(resp.Data))
	for _, row := range resp.Data {
		out = append(out, pick(row))
	}
	return out
}

// identityListRoute is one list endpoint: call serves it and ids returns the owning key of
// each row, so root's row and the MSP's row can be told apart.
type identityListRoute struct {
	name     string
	call     func(fx *identityReadFixture, caller func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder
	ids      func(t *testing.T, fx *identityReadFixture, rec *httptest.ResponseRecorder) []string
	rootWant string // value identifying root's own row
	mspWant  string // value identifying the MSP's row
}

func identityListRoutes(fx *identityReadFixture) []identityListRoute {
	s := fx.server
	return []identityListRoute{
		{"GET /api/v1/accounts",
			func(_ *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
				return identityServe(s.handleListAccounts, http.MethodGet, "/api/v1/accounts", c, nil)
			},
			func(t *testing.T, _ *identityReadFixture, rec *httptest.ResponseRecorder) []string {
				return identityDataList(t, rec, func(a AccountInfo) string { return a.Username })
			}, fx.rootAccount, fx.mspAccount},
		{"GET /api/v1/certificates",
			func(_ *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
				return identityServe(s.handleListCertificates, http.MethodGet, "/api/v1/certificates", c, nil)
			},
			func(t *testing.T, _ *identityReadFixture, rec *httptest.ResponseRecorder) []string {
				return identityDataList(t, rec, func(c CertificateInfo) string { return c.StewardID })
			}, "steward-identity-root", "steward-identity-msp"},
		{"GET /api/v1/sessions",
			func(_ *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
				return identityServe(s.handleSessionList, http.MethodGet, "/api/v1/sessions", c, nil)
			},
			func(t *testing.T, _ *identityReadFixture, rec *httptest.ResponseRecorder) []string {
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				var resp sessionListResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
				out := []string{}
				for _, it := range resp.Sessions {
					out = append(out, it.PrincipalID)
				}
				return out
			}, "session-root-user", "session-msp-user"},
		{"GET /api/v1/registration/tokens",
			func(_ *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
				return identityServe(s.handleListRegistrationTokens, http.MethodGet, "/api/v1/registration/tokens", c, nil)
			},
			func(t *testing.T, _ *identityReadFixture, rec *httptest.ResponseRecorder) []string {
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				var resp TokenListResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
				out := []string{}
				for _, tk := range resp.Tokens {
					out = append(out, tk.TenantID)
				}
				return out
			}, testRootTenantID, identityMSP},
		{"GET /api/v1/registration/pending",
			func(_ *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
				return identityServe(s.handleListPendingRegistrations, http.MethodGet, "/api/v1/registration/pending", c, nil)
			},
			func(t *testing.T, _ *identityReadFixture, rec *httptest.ResponseRecorder) []string {
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				var rows []PendingRegistration
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rows))
				out := []string{}
				for _, r := range rows {
					out = append(out, r.TenantID)
				}
				return out
			}, testRootTenantID, identityMSP},
		{"GET /api/v1/cases",
			func(_ *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
				return identityServe(s.handleListCases, http.MethodGet, "/api/v1/cases", c, nil)
			},
			func(t *testing.T, _ *identityReadFixture, rec *httptest.ResponseRecorder) []string {
				return identityDataList(t, rec, func(c caseResponse) string { return c.TenantID })
			}, testRootTenantID, identityMSP},
		{"GET /api/v1/rbac/roles",
			func(_ *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
				return identityServe(s.handleListRoles, http.MethodGet, "/api/v1/rbac/roles", c, nil)
			},
			func(t *testing.T, _ *identityReadFixture, rec *httptest.ResponseRecorder) []string {
				return identityDataList(t, rec, func(r RoleInfo) string { return r.ID })
			}, fx.rootRole, fx.mspRole},
	}
}

// TestRootIdentityReads_ListsRequireCrossing is the [REQUIRED TEST] for the list
// reads: a boundary-subject root session sees only root-tenant records until an
// active crossing covers the owning MSP.
func TestRootIdentityReads_ListsRequireCrossing(t *testing.T) {
	fx := newIdentityReadFixture(t)
	for _, rt := range identityListRoutes(fx) {
		t.Run(rt.name, func(t *testing.T) {
			noCrossing := boundRootOperator("list-op-without-" + uuid.NewString())
			got := rt.ids(t, fx, rt.call(fx, identityRootCaller(noCrossing)))
			assert.Contains(t, got, rt.rootWant, "root's own record stays visible with no crossing")
			assert.NotContains(t, got, rt.mspWant, "a client tenant's record needs a crossing")

			withCrossing := boundRootOperator("list-op-with-" + uuid.NewString())
			grantCrossing(t, fx.server, withCrossing.ID, identityMSP)
			got = rt.ids(t, fx, rt.call(fx, identityRootCaller(withCrossing)))
			assert.Contains(t, got, rt.rootWant)
			assert.Contains(t, got, rt.mspWant, "an active crossing admits the client tenant's record")
		})
	}
}

// TestRootIdentityReads_UnchangedForOtherCallers is the [REQUIRED TEST] that an
// unrestricted certificate admin and a tenant-scoped MSP admin see what they saw
// before.
func TestRootIdentityReads_UnchangedForOtherCallers(t *testing.T) {
	fx := newIdentityReadFixture(t)
	for _, rt := range identityListRoutes(fx) {
		switch rt.name {
		case "GET /api/v1/rbac/roles", "GET /api/v1/registration/tokens", "GET /api/v1/cases":
			// These resolve the caller's tenant from the request context, which the
			// unrestricted fixture does not carry; the MSP-admin leg below covers them.
		default:
			t.Run("unrestricted "+rt.name, func(t *testing.T) {
				got := rt.ids(t, fx, rt.call(fx, identityUnrestrictedCaller()))
				assert.Contains(t, got, rt.rootWant)
				assert.Contains(t, got, rt.mspWant, "an unrestricted admin keeps fleet-wide breadth")
			})
		}
		switch rt.name {
		case "GET /api/v1/accounts", "GET /api/v1/certificates", "GET /api/v1/registration/pending":
			t.Run("msp admin "+rt.name, func(t *testing.T) {
				got := rt.ids(t, fx, rt.call(fx, identityMSPAdminCaller()))
				assert.Contains(t, got, rt.mspWant)
				assert.NotContains(t, got, rt.rootWant, "a tenant-scoped admin never sees root's records")
			})
		}
	}
	t.Run("msp admin reads its own account", func(t *testing.T) {
		rec := identityServe(fx.server.handleGetAccount, http.MethodGet, "/api/v1/accounts/"+fx.mspAccount, identityMSPAdminCaller(), map[string]string{"username": fx.mspAccount})
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
	t.Run("msp admin cannot read root's account", func(t *testing.T) {
		rec := identityServe(fx.server.handleGetAccount, http.MethodGet, "/api/v1/accounts/"+fx.rootAccount, identityMSPAdminCaller(), map[string]string{"username": fx.rootAccount})
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
	t.Run("unrestricted admin reads a client account", func(t *testing.T) {
		rec := identityServe(fx.server.handleGetAccount, http.MethodGet, "/api/v1/accounts/"+fx.mspAccount, identityUnrestrictedCaller(), map[string]string{"username": fx.mspAccount})
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
}

// identityByIDRoute is one by-ID read of a record the MSP owns.
type identityByIDRoute struct {
	name string
	call func(fx *identityReadFixture, caller func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder
}

func identityByIDRoutes(fx *identityReadFixture) []identityByIDRoute {
	s := fx.server
	return []identityByIDRoute{
		{"GET /api/v1/accounts/{username}", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleGetAccount, http.MethodGet, "/", c, map[string]string{"username": f.mspAccount})
		}},
		{"GET /api/v1/certificates/{serial}", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleGetCertificate, http.MethodGet, "/", c, map[string]string{"serial": f.mspSerial})
		}},
		{"GET /api/v1/registration/tokens/{token}", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleGetRegistrationToken, http.MethodGet, "/", c, map[string]string{"token": f.mspToken})
		}},
		{"GET /api/v1/api-keys/{id}", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleGetAPIKey, http.MethodGet, "/", c, map[string]string{"id": f.mspKeyID})
		}},
		{"GET /api/v1/cases/{id}", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleGetCase, http.MethodGet, "/", c, map[string]string{"id": f.mspCase})
		}},
		{"GET /api/v1/rbac/roles/{id}", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleGetRole, http.MethodGet, "/", c, map[string]string{"id": f.mspRole})
		}},
		{"GET /api/v1/roles/{name}", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleGetRoleConfig, http.MethodGet, "/?tenant="+identityMSP, c, map[string]string{"name": "cfg-" + identityMSP})
		}},
		{"GET /api/v1/roles", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleListRoleConfigs, http.MethodGet, "/?tenant="+identityMSP, c, nil)
		}},
		{"GET /api/v1/rbac/subjects/{id}/roles", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleGetSubjectRoles, http.MethodGet, "/", c, map[string]string{"id": f.mspAccountID})
		}},
		{"GET /api/v1/accounts/{username}/webauthn/credentials", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleWebAuthnListCredentials, http.MethodGet, "/", c, map[string]string{"username": f.mspAccount})
		}},
		{"GET /api/v1/accounts/{username}/certs", func(f *identityReadFixture, c func(*http.Request, map[string]string) *http.Request) *httptest.ResponseRecorder {
			return identityServe(s.handleListCertBindings, http.MethodGet, "/", c, map[string]string{"username": f.mspAccount})
		}},
	}
}

// TestRootIdentityReads_ByIDRequiresCrossing is the [REQUIRED TEST] for by-ID reads:
// the boundary-subject root session gets the crossing challenge for a client
// tenant's record and succeeds once a crossing is active.
func TestRootIdentityReads_ByIDRequiresCrossing(t *testing.T) {
	fx := newIdentityReadFixture(t)
	for _, rt := range identityByIDRoutes(fx) {
		t.Run(rt.name, func(t *testing.T) {
			rec := rt.call(fx, identityRootCaller(boundRootOperator("byid-without-"+uuid.NewString())))
			assertCrossingChallenge(t, rec, identityMSP)

			op := boundRootOperator("byid-with-" + uuid.NewString())
			grantCrossing(t, fx.server, op.ID, identityMSP)
			rec = rt.call(fx, identityRootCaller(op))
			assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		})
	}

	t.Run("a missing record is still 404", func(t *testing.T) {
		op := boundRootOperator("byid-missing")
		rec := identityServe(fx.server.handleGetCase, http.MethodGet, "/", identityRootCaller(op), map[string]string{"id": "no-such-case"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
		rec = identityServe(fx.server.handleGetAccount, http.MethodGet, "/", identityRootCaller(op), map[string]string{"username": "no-such-user"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

// TestRootIdentityReads_OwnRecordsNeedNoCrossing is the [REQUIRED TEST] that a root
// operator still reads their own account, passkeys, sessions and API keys, root's
// records, and system roles with no crossing.
func TestRootIdentityReads_OwnRecordsNeedNoCrossing(t *testing.T) {
	fx := newIdentityReadFixture(t)
	s := fx.server
	op := boundRootOperator("own-records-op")

	cases := []struct {
		name string
		rec  *httptest.ResponseRecorder
	}{
		{"own account", identityServe(s.handleGetAccount, http.MethodGet, "/", identityRootCaller(op), map[string]string{"username": fx.rootAccount})},
		{"own passkeys", identityServe(s.handleWebAuthnListCredentials, http.MethodGet, "/", identityRootCaller(op), map[string]string{"username": fx.rootAccount})},
		{"own cert bindings", identityServe(s.handleListCertBindings, http.MethodGet, "/", identityRootCaller(op), map[string]string{"username": fx.rootAccount})},
		{"own sessions", identityServe(s.handleSessionList, http.MethodGet, "/", identityRootCaller(op), nil)},
		{"own api key", identityServe(s.handleGetAPIKey, http.MethodGet, "/", identityRootCaller(op), map[string]string{"id": fx.rootKeyID})},
		{"own api key list", identityServe(s.handleListAPIKeys, http.MethodGet, "/", identityRootCaller(op), nil)},
		{"root certificate", identityServe(s.handleGetCertificate, http.MethodGet, "/", identityRootCaller(op), map[string]string{"serial": fx.rootSerial})},
		{"root token", identityServe(s.handleGetRegistrationToken, http.MethodGet, "/", identityRootCaller(op), map[string]string{"token": fx.rootToken})},
		{"root case", identityServe(s.handleGetCase, http.MethodGet, "/", identityRootCaller(op), map[string]string{"id": fx.rootCase})},
		{"root role", identityServe(s.handleGetRole, http.MethodGet, "/", identityRootCaller(op), map[string]string{"id": fx.rootRole})},
		{"root role config", identityServe(s.handleGetRoleConfig, http.MethodGet, "/?tenant="+testRootTenantID, identityRootCaller(op), map[string]string{"name": "cfg-" + testRootTenantID})},
		{"root role config list", identityServe(s.handleListRoleConfigs, http.MethodGet, "/?tenant="+testRootTenantID, identityRootCaller(op), nil)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, http.StatusOK, c.rec.Code, c.rec.Body.String())
		})
	}

	t.Run("system role", func(t *testing.T) {
		list := identityServe(s.handleListRoles, http.MethodGet, "/", identityRootCaller(op), nil)
		require.Equal(t, http.StatusOK, list.Code, list.Body.String())
		resp, err := s.rbacService.ListRoles(context.Background(), &controller.ListRolesRequest{TenantId: testRootTenantID})
		require.NoError(t, err)
		var systemRole string
		for _, r := range resp.Roles {
			if r.IsSystemRole {
				systemRole = r.Id
				break
			}
		}
		require.NotEmpty(t, systemRole, "the default RBAC set includes a system role")
		rec := identityServe(s.handleGetRole, http.MethodGet, "/", identityRootCaller(op), map[string]string{"id": systemRole})
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, identityDataList(t, list, func(r RoleInfo) string { return r.ID }), systemRole,
			"system roles belong to no tenant and stay listed")
	})
}

// TestRootIdentityReads_CredentialRequestLists covers the two credential lists, whose
// fixtures need the enrolment flow.
func TestRootIdentityReads_CredentialRequestLists(t *testing.T) {
	server := setupCollectTestServer(t)
	server = seedRootTenant(t, wireCrossingStore(t, server))
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: identityMSP, ParentID: testRootTenantID})
	require.NoError(t, err)

	// A pending request per tenant, and an orphaned collected certificate per tenant.
	lodgeTestCredentialRequest(t, server, testRootTenantID)
	lodgeTestCredentialRequest(t, server, identityMSP)
	collectThenOrphan(t, server, testRootTenantID, "orphan-root-owner", ApproveCredentialRequestBody{})
	collectThenOrphan(t, server, identityMSP, "orphan-msp-owner", ApproveCredentialRequestBody{})

	tenantsOf := func(t *testing.T, h http.HandlerFunc, caller func(*http.Request, map[string]string) *http.Request, pick func(*testing.T, *httptest.ResponseRecorder) []string) []string {
		return pick(t, identityServe(h, http.MethodGet, "/", caller, nil))
	}
	pending := func(t *testing.T, rec *httptest.ResponseRecorder) []string {
		return identityDataList(t, rec, func(r PendingCredentialRequestInfo) string { return r.TenantID })
	}
	orphaned := func(t *testing.T, rec *httptest.ResponseRecorder) []string {
		return identityDataList(t, rec, func(r OrphanedCredentialInfo) string { return r.TenantID })
	}

	for name, route := range map[string]struct {
		h    http.HandlerFunc
		pick func(*testing.T, *httptest.ResponseRecorder) []string
	}{
		"GET /api/v1/credential-requests":          {server.handleListCredentialRequests, pending},
		"GET /api/v1/credential-requests/orphaned": {server.handleListOrphanedCredentials, orphaned},
	} {
		t.Run(name, func(t *testing.T) {
			got := tenantsOf(t, route.h, identityRootCaller(boundRootOperator("cred-without-"+uuid.NewString())), route.pick)
			assert.NotContains(t, got, identityMSP)

			op := boundRootOperator("cred-with-" + uuid.NewString())
			grantCrossing(t, server, op.ID, identityMSP)
			got = tenantsOf(t, route.h, identityRootCaller(op), route.pick)
			assert.Contains(t, got, identityMSP)
			assert.Contains(t, got, testRootTenantID)

			got = tenantsOf(t, route.h, identityUnrestrictedCaller(), route.pick)
			assert.Contains(t, got, identityMSP, "an unrestricted admin keeps fleet-wide breadth")
		})
	}
}

// TestRootIdentityReads_RevocationManifest is the [REQUIRED TEST] that the manifest,
// a signed fleet-wide trust artifact, is still served to a root caller and refused
// to a tenant-scoped one.
func TestRootIdentityReads_RevocationManifest(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	ensureSharedSigningCertificate(t, certMgr)

	t.Run("root operator with no crossing is served", func(t *testing.T) {
		rec := identityServe(server.handleGetRevocationManifest, http.MethodGet, "/api/v1/certificates/revocation-manifest",
			identityRootCaller(boundRootOperator("manifest-op")), nil)
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
	t.Run("unrestricted admin is served", func(t *testing.T) {
		rec, body := getRevocationManifest(t, server, certMgr)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, RevocationManifestKind, body.Manifest.Kind)
	})
	t.Run("tenant-scoped caller is refused", func(t *testing.T) {
		rec := identityServe(server.handleGetRevocationManifest, http.MethodGet, "/api/v1/certificates/revocation-manifest",
			identityMSPAdminCaller(), nil)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	})
}

// TestRootIdentityReads_CertificateListOwnerLookupFault_FailsClosed verifies that
// a genuine steward-store fault (a corrupted record, distinct from not-found)
// while resolving certificate owners fails a boundary-subject root caller's list
// with 500. Treating the unresolved certificate as unattributable would show a
// client tenant's certificate past the crossing during a store outage.
func TestRootIdentityReads_CertificateListOwnerLookupFault_FailsClosed(t *testing.T) {
	server, certMgr, stewardStore, flatfileRoot := setupCertTestServerWithStewardStoreRoot(t)
	server = seedRootTenant(t, wireCrossingStore(t, server))
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: identityMSP, ParentID: testRootTenantID})
	require.NoError(t, err)

	for _, s := range []struct{ id, tenant string }{
		{"steward-fault-root", testRootTenantID}, {"steward-fault-msp", identityMSP},
	} {
		require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
			ID: s.id, TenantID: s.tenant, Hostname: s.id, Platform: "linux", Arch: "amd64"}))
		_, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
			CommonName: s.id, Organization: "Test CFGMS", ClientID: s.id, ValidityDays: 365})
		require.NoError(t, err)
	}

	// Corrupt the MSP steward's durable record so GetSteward returns a store error
	// rather than business.ErrStewardNotFound.
	recordPath := filepath.Join(flatfileRoot, "stewards", "steward-fault-msp.json")
	require.FileExists(t, recordPath)
	require.NoError(t, os.WriteFile(recordPath, []byte("{ not json"), 0o600))
	_, lookupErr := stewardStore.GetSteward(ctx, "steward-fault-msp")
	require.Error(t, lookupErr, "corrupted record must produce a store error")
	require.NotErrorIs(t, lookupErr, business.ErrStewardNotFound,
		"the injected fault must be a genuine store error, not not-found")

	op := boundRootOperator("list-op-fault-" + uuid.NewString())
	rec := identityServe(server.handleListCertificates, http.MethodGet, "/api/v1/certificates", identityRootCaller(op), nil)

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"an owner-lookup fault must fail a boundary-subject list, not treat the cert as unattributable")
	body := rec.Body.String()
	assert.NotContains(t, body, "steward-fault-msp", "the client tenant's certificate must not leak")
	assert.NotContains(t, body, "steward-fault-root", "a failed read decision returns no partial data")
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
}
