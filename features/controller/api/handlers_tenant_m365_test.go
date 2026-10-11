// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const m365TestSecret = "Zq9-super-secret-value-7731"

// m365Route pairs a route with the handler and permission registerTenantRoutes uses.
type m365Route struct {
	method, suffix, resource, action string
	handler                          func(*Server) http.HandlerFunc
}

var (
	m365RoutePut = m365Route{http.MethodPut, "/m365-connection", "tenant", "manage",
		func(s *Server) http.HandlerFunc { return s.handlePutTenantM365Connection }}
	m365RouteGet = m365Route{http.MethodGet, "/m365-connection", "tenant", "read",
		func(s *Server) http.HandlerFunc { return s.handleGetTenantM365Connection }}
	m365RouteDelete = m365Route{http.MethodDelete, "/m365-connection", "tenant", "manage",
		func(s *Server) http.HandlerFunc { return s.handleDeleteTenantM365Connection }}
	m365RouteCustomers = m365Route{http.MethodPost, "/m365-gdap-customers", "tenant", "manage",
		func(s *Server) http.HandlerFunc { return s.handleM365GDAPCustomers }}
	m365RouteLinks = m365Route{http.MethodPost, "/m365-gdap-links", "tenant", "manage",
		func(s *Server) http.HandlerFunc { return s.handleM365GDAPLinks }}
	m365AllRoutes = []m365Route{m365RoutePut, m365RouteGet, m365RouteDelete, m365RouteCustomers, m365RouteLinks}
)

func m365AdminPrincipal() *Principal {
	return &Principal{
		ID: "admin-1", Name: "mtls-admin:admin-1", Assurance: session.AssuranceStrong,
		GlobalScope: true, CertSerial: "m365-test-serial", ImplicitAdmin: true,
	}
}

// m365Do runs the route through its permission middleware (as registered) as principal.
func m365Do(t *testing.T, server *Server, p *Principal, rt m365Route, id string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(rt.method, "/api/v1/tenants/"+id+rt.suffix, &buf)
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": id})
	ctx := context.WithValue(req.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, p.TenantID)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scopeForVerifiedAdminCert(p.TenantID))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.requirePermission(rt.resource, rt.action)(rt.handler(server)).ServeHTTP(rec, req)
	return rec
}

// m365Env is a server with root -> msp-a (client-a1..a3, gc-a1 below client-a1) and
// root -> msp-b (client-b1), plus a Partner Center test server for customers cust-1..cust-4.
type m365Env struct {
	server *Server
	cs     *auth.SecretStoreCredentialStore
}

func newM365Env(t *testing.T) *m365Env {
	t.Helper()
	return newM365EnvWithServer(t, setupCrossingTestServer(t))
}

func newM365EnvWithServer(t *testing.T, server *Server) *m365Env {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, ensureTestRootTenant(ctx, server.tenantManager))
	for _, tr := range []*tenant.TenantRequest{
		{ID: "msp-a", Name: "MSP-A", ParentID: "root"},
		{ID: "client-a1", Name: "Client-A1", ParentID: "msp-a"},
		{ID: "client-a2", Name: "Client-A2", ParentID: "msp-a"},
		{ID: "client-a3", Name: "Client-A3", ParentID: "msp-a"},
		{ID: "gc-a1", Name: "Grandchild-A1", ParentID: "client-a1"},
		{ID: "msp-b", Name: "MSP-B", ParentID: "root"},
		{ID: "client-b1", Name: "Client-B1", ParentID: "msp-b"},
	} {
		_, err := server.tenantManager.CreateTenant(ctx, tr)
		require.NoError(t, err)
	}

	pc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/partner-1/oauth2/v2.0/token" {
			_ = r.ParseForm()
			if r.PostForm.Get("client_secret") != m365TestSecret {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "pc", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		var items []map[string]interface{}
		for _, c := range []string{"cust-1", "cust-2", "cust-3", "cust-4"} {
			items = append(items, map[string]interface{}{
				"id": "rel-" + c, "status": "active",
				"customer":    map[string]string{"tenantId": c, "displayName": "Customer " + c},
				"endDateTime": time.Now().Add(48 * time.Hour).Format(time.RFC3339),
				"details":     map[string]interface{}{"unifiedRoles": []map[string]string{{"roleDefinitionId": "r1", "roleName": "User Administrator"}}},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items})
	}))
	t.Cleanup(pc.Close)
	prev := m365PartnerEndpoints
	m365PartnerEndpoints.partnerCenterBaseURL, m365PartnerEndpoints.loginBaseURL = pc.URL, pc.URL
	t.Cleanup(func() { m365PartnerEndpoints = prev })

	require.NotNil(t, server.secretStore)
	return &m365Env{server: server, cs: auth.NewSecretStoreCredentialStore(server.secretStore)}
}

func (e *m365Env) set(t *testing.T, id string, replace bool) *httptest.ResponseRecorder {
	return m365Do(t, e.server, m365AdminPrincipal(), m365RoutePut, id, map[string]interface{}{
		"app_id": "app-1", "m365_tenant_id": "dir-1", "client_secret": m365TestSecret, "replace": replace,
	})
}

func (e *m365Env) partnerBody(extra map[string]interface{}) map[string]interface{} {
	b := map[string]interface{}{"partner_tenant_id": "partner-1", "app_id": "papp", "client_secret": m365TestSecret}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func (e *m365Env) link(t *testing.T, replace bool, links ...[2]string) *httptest.ResponseRecorder {
	ls := make([]map[string]string, 0, len(links))
	for _, l := range links {
		ls = append(ls, map[string]string{"customer_tenant_id": l[0], "tenant_id": l[1]})
	}
	return m365Do(t, e.server, m365AdminPrincipal(), m365RouteLinks, "msp-a",
		e.partnerBody(map[string]interface{}{"links": ls, "replace": replace, "gdap_roles": []string{"User-Administrator"}}))
}

func (e *m365Env) secretKeys(t *testing.T) []string {
	t.Helper()
	metas, err := e.server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{})
	require.NoError(t, err)
	keys := make([]string, 0, len(metas))
	for _, m := range metas {
		keys = append(keys, m.Key)
	}
	sort.Strings(keys)
	return keys
}

func (e *m365Env) tenantIDs(t *testing.T) []string {
	t.Helper()
	all, err := e.server.tenantManager.ListTenants(context.Background(), &business.TenantFilter{})
	require.NoError(t, err)
	ids := make([]string, 0, len(all))
	for _, td := range all {
		ids = append(ids, td.ID)
	}
	sort.Strings(ids)
	return ids
}

func m365Data(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func TestM365Connection_DirectSetStoresConfigReadByCredentialStore(t *testing.T) {
	env := newM365Env(t)
	rec := env.set(t, "client-a1", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	cfg, err := auth.NewSecretStoreCredentialStore(env.server.secretStore).GetConfig("client-a1")
	require.NoError(t, err)
	assert.Equal(t, &auth.OAuth2Config{ClientID: "app-1", ClientSecret: m365TestSecret, TenantID: "dir-1", UseClientCredentials: true}, cfg)
}

func TestM365Connection_OnlyExistingClientTenantsAccepted(t *testing.T) {
	env := newM365Env(t)
	before := env.secretKeys(t)

	for _, id := range []string{"root", "msp-a", "does-not-exist", "gc-a1"} {
		rec := env.set(t, id, true)
		assert.GreaterOrEqual(t, rec.Code, 400, "%s: %s", id, rec.Body.String())
		assert.Less(t, rec.Code, 500, id)
	}
	// A client tenant of a different MSP is refused on the gdap-links route.
	rec := env.link(t, true, [2]string{"cust-1", "client-b1"})
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	// An MSP tenant or a client tenant is not a valid {id} for the GDAP routes' MSP.
	rec = m365Do(t, env.server, m365AdminPrincipal(), m365RouteLinks, "client-a1",
		env.partnerBody(map[string]interface{}{"links": []map[string]string{{"customer_tenant_id": "cust-1", "tenant_id": "client-a1"}}}))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	assert.Equal(t, before, env.secretKeys(t), "no secret may be written for a refused target")
}

func TestM365Routes_NeverCreateTenants(t *testing.T) {
	env := newM365Env(t)
	before := env.tenantIDs(t)
	admin := m365AdminPrincipal()

	_ = env.set(t, "client-a1", false)
	_ = env.set(t, "client-a1", false) // 409
	_ = env.set(t, "msp-a", false)
	_ = env.set(t, "ghost", false)
	_ = m365Do(t, env.server, admin, m365RouteGet, "client-a1", nil)
	_ = m365Do(t, env.server, admin, m365RouteCustomers, "msp-a", env.partnerBody(nil))
	_ = env.link(t, false, [2]string{"cust-1", "client-a2"}, [2]string{"cust-2", "client-a3"})
	_ = env.link(t, false, [2]string{"cust-9", "client-a2"})
	_ = env.link(t, false, [2]string{"cust-3", "ghost"})
	_ = m365Do(t, env.server, admin, m365RouteDelete, "client-a1", nil)
	_ = m365Do(t, env.server, admin, m365RouteDelete, "ghost", nil)

	assert.Equal(t, before, env.tenantIDs(t))
}

func TestM365Routes_SecretNeverEchoed(t *testing.T) {
	capLog := &auditCapturingLogger{}
	env := newM365EnvWithServer(t, setupCrossingTestServerWithLogger(t, capLog))
	admin := m365AdminPrincipal()

	var bodies []string
	add := func(rec *httptest.ResponseRecorder) { bodies = append(bodies, rec.Body.String()) }
	add(env.set(t, "client-a1", false))
	add(env.set(t, "client-a1", false))
	add(env.set(t, "msp-a", false))
	add(m365Do(t, env.server, admin, m365RouteGet, "client-a1", nil))
	add(m365Do(t, env.server, admin, m365RouteCustomers, "msp-a", env.partnerBody(nil)))
	add(env.link(t, false, [2]string{"cust-1", "client-a2"}))
	add(env.link(t, false, [2]string{"cust-9", "client-a3"}))
	add(m365Do(t, env.server, admin, m365RouteDelete, "client-a1", nil))
	// A wrong secret takes the Partner Center failure path.
	add(m365Do(t, env.server, admin, m365RouteCustomers, "msp-a",
		env.partnerBody(map[string]interface{}{"client_secret": "wrong-secret-4455"})))
	for _, b := range bodies {
		assert.NotContains(t, b, m365TestSecret)
		assert.NotContains(t, b, "wrong-secret-4455")
	}

	require.NoError(t, env.server.auditManager.Flush(context.Background()))
	var found int
	for _, tid := range []string{"client-a1", "client-a2"} {
		entries, err := env.server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: tid})
		require.NoError(t, err)
		for _, e := range entries {
			raw, err := json.Marshal(e)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), m365TestSecret)
			if e.Action == "m365.connection.set" || e.Action == "m365.connection.delete" || e.Action == "m365.gdap.link" {
				found++
				assert.Contains(t, string(raw), "app_id")
			}
		}
	}
	assert.GreaterOrEqual(t, found, 3, "set, delete and gdap.link each emit an audit event")

	logs := capLog.formattedOutput()
	assert.NotContains(t, logs, m365TestSecret)
	assert.NotContains(t, logs, "wrong-secret-4455")
}

func TestM365Connection_GetAndDelete(t *testing.T) {
	env := newM365Env(t)
	admin := m365AdminPrincipal()

	rec := m365Do(t, env.server, admin, m365RouteGet, "client-a1", nil)
	require.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "M365_CONNECTION_NOT_FOUND")

	require.Equal(t, http.StatusOK, env.set(t, "client-a1", false).Code)
	rec = m365Do(t, env.server, admin, m365RouteGet, "client-a1", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	d := m365Data(t, rec)
	assert.Equal(t, "direct", d["mode"])
	assert.Equal(t, "app-1", d["app_id"])
	assert.Equal(t, "dir-1", d["m365_tenant_id"])
	assert.Equal(t, true, d["has_client_secret"])

	require.NoError(t, env.cs.StoreToken("client-a1", &auth.AccessToken{Token: "t", ExpiresAt: time.Now().Add(time.Hour)}))
	rec = m365Do(t, env.server, admin, m365RouteDelete, "client-a1", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	_, err := env.cs.GetConfig("client-a1")
	assert.ErrorIs(t, err, secretsif.ErrSecretNotFound)
	_, err = env.cs.GetToken("client-a1")
	assert.ErrorIs(t, err, secretsif.ErrSecretNotFound)
}

func TestM365Connection_ReplaceRequired(t *testing.T) {
	env := newM365Env(t)
	require.Equal(t, http.StatusOK, env.set(t, "client-a1", false).Code)

	rec := m365Do(t, env.server, m365AdminPrincipal(), m365RoutePut, "client-a1", map[string]interface{}{
		"app_id": "app-2", "m365_tenant_id": "dir-2", "client_secret": "other-secret"})
	require.Equal(t, http.StatusConflict, rec.Code)
	cfg, err := env.cs.GetConfig("client-a1")
	require.NoError(t, err)
	assert.Equal(t, "app-1", cfg.ClientID)

	rec = m365Do(t, env.server, m365AdminPrincipal(), m365RoutePut, "client-a1", map[string]interface{}{
		"app_id": "app-2", "m365_tenant_id": "dir-2", "client_secret": "other-secret", "replace": true})
	require.Equal(t, http.StatusOK, rec.Code)
	cfg, err = env.cs.GetConfig("client-a1")
	require.NoError(t, err)
	assert.Equal(t, "app-2", cfg.ClientID)
	assert.Equal(t, "dir-2", cfg.TenantID)
}

func TestM365Connection_InvalidInputAndNoSecretStore(t *testing.T) {
	env := newM365Env(t)
	admin := m365AdminPrincipal()
	for _, body := range []map[string]interface{}{
		{"app_id": "", "m365_tenant_id": "d", "client_secret": "s"},
		{"app_id": "a b", "m365_tenant_id": "d", "client_secret": "s"},
		{"app_id": "a", "m365_tenant_id": "..", "client_secret": "s"},
		{"app_id": "a", "m365_tenant_id": "", "client_secret": "s"},
		{"app_id": "a", "m365_tenant_id": "d", "client_secret": ""},
		{"app_id": "a", "m365_tenant_id": "d", "client_secret": "s", "extra": 1},
	} {
		rec := m365Do(t, env.server, admin, m365RoutePut, "client-a1", body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "%v", body)
	}
	assert.Empty(t, env.secretKeys(t))

	saved := env.server.secretStore
	env.server.secretStore = nil
	defer func() { env.server.secretStore = saved }()
	for _, rt := range m365AllRoutes {
		rec := m365Do(t, env.server, admin, rt, "client-a1", map[string]interface{}{})
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rt.method+rt.suffix)
	}
}

func TestM365GDAPCustomers_ListsLinkState(t *testing.T) {
	env := newM365Env(t)
	require.NoError(t, env.cs.StoreConfig("client-a2", &auth.OAuth2Config{
		ClientID: "papp", ClientSecret: "x", TenantID: "cust-2", PartnerDelegated: true,
		PartnerTenantID: "partner-1", CustomerTenantID: "cust-2"}))
	before := env.secretKeys(t)

	rec := m365Do(t, env.server, m365AdminPrincipal(), m365RouteCustomers, "msp-a", env.partnerBody(nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data struct {
			Customers []m365GDAPCustomerRow `json:"customers"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Data.Customers, 4)
	for _, row := range resp.Data.Customers {
		if row.CustomerTenantID == "cust-2" {
			assert.Equal(t, "client-a2", row.LinkedTo)
			assert.Equal(t, "linked", row.LinkState)
		} else {
			assert.Equal(t, "unlinked", row.LinkState)
			assert.Empty(t, row.LinkedTo)
		}
		assert.Equal(t, "active", row.Status)
		assert.Equal(t, []string{"User Administrator"}, row.Roles)
	}
	assert.Equal(t, before, env.secretKeys(t), "listing writes nothing")

	// An MSP's customers are not shown linked to another MSP's tenants.
	rec = m365Do(t, env.server, m365AdminPrincipal(), m365RouteCustomers, "msp-b", env.partnerBody(nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "client-a2")
}

func TestM365GDAPLinks_LinksManyCustomers(t *testing.T) {
	env := newM365Env(t)
	rec := env.link(t, false, [2]string{"cust-1", "client-a1"}, [2]string{"cust-2", "client-a2"}, [2]string{"cust-3", "client-a3"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	for cust, tid := range map[string]string{"cust-1": "client-a1", "cust-2": "client-a2", "cust-3": "client-a3"} {
		cfg, err := env.cs.GetConfig(tid)
		require.NoError(t, err)
		assert.Equal(t, &auth.OAuth2Config{
			ClientID: "papp", ClientSecret: m365TestSecret, TenantID: cust, PartnerDelegated: true,
			PartnerTenantID: "partner-1", CustomerTenantID: cust, GDAPRequiredRoles: []string{"User-Administrator"},
		}, cfg)
	}
	// Partner credentials are not stored on the MSP or under the partner tenant.
	for _, k := range []string{"msp-a", "partner-1", "root"} {
		_, err := env.cs.GetConfig(k)
		assert.ErrorIs(t, err, secretsif.ErrSecretNotFound, k)
	}
}

func TestM365GDAPLinks_AllOrNothingValidation(t *testing.T) {
	env := newM365Env(t)
	require.NoError(t, env.cs.StoreConfig("client-a3", &auth.OAuth2Config{
		ClientID: "papp", ClientSecret: "x", TenantID: "cust-4", PartnerDelegated: true,
		PartnerTenantID: "partner-1", CustomerTenantID: "cust-4"}))
	require.NoError(t, env.cs.StoreConfig("client-a2", &auth.OAuth2Config{ClientID: "d", ClientSecret: "x", TenantID: "dir", UseClientCredentials: true}))
	before := env.secretKeys(t)
	good := [2]string{"cust-1", "client-a1"}

	cases := map[string]struct {
		links  [][2]string
		status int
	}{
		"customer not in GDAP list":         {[][2]string{{"cust-nope", "client-a1"}}, http.StatusBadRequest},
		"target of a different MSP":         {[][2]string{{"cust-2", "client-b1"}}, http.StatusBadRequest},
		"target below a client":             {[][2]string{{"cust-2", "gc-a1"}}, http.StatusBadRequest},
		"target is the MSP":                 {[][2]string{{"cust-2", "msp-a"}}, http.StatusBadRequest},
		"missing target":                    {[][2]string{{"cust-2", "ghost"}}, http.StatusNotFound},
		"duplicate customer":                {[][2]string{{"cust-1", "client-a1"}, {"cust-1", "client-a2"}}, http.StatusBadRequest},
		"duplicate target":                  {[][2]string{{"cust-1", "client-a1"}, {"cust-2", "client-a1"}}, http.StatusBadRequest},
		"customer already linked elsewhere": {[][2]string{{"cust-4", "client-a1"}}, http.StatusConflict},
		"existing connection no replace":    {[][2]string{{"cust-2", "client-a2"}}, http.StatusConflict},
	}
	for name, c := range cases {
		links := append([][2]string{good}, c.links...)
		for _, l := range c.links {
			if l == good || l[1] == good[1] || l[0] == good[0] {
				links = c.links
			}
		}
		rec := env.link(t, false, links...)
		assert.Equal(t, c.status, rec.Code, "%s: %s", name, rec.Body.String())
		assert.Equal(t, before, env.secretKeys(t), "%s must write nothing", name)
	}
	cfg, err := env.cs.GetConfig("client-a2")
	require.NoError(t, err)
	assert.Equal(t, "dir", cfg.TenantID)

	// With replace the existing direct connection is overwritten.
	rec := env.link(t, true, [2]string{"cust-2", "client-a2"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	cfg, err = env.cs.GetConfig("client-a2")
	require.NoError(t, err)
	assert.True(t, cfg.PartnerDelegated)
}

func TestM365Routes_TenantBoundary(t *testing.T) {
	env := newM365Env(t)
	server := env.server
	root := boundaryTestPrincipal("root-op-m365")
	linkBody := env.partnerBody(map[string]interface{}{
		"links": []map[string]string{{"customer_tenant_id": "cust-1", "tenant_id": "client-a1"}}})
	bodyFor := func(rt m365Route) interface{} {
		switch rt.suffix + rt.method {
		case m365RoutePut.suffix + m365RoutePut.method:
			return map[string]interface{}{"app_id": "a", "m365_tenant_id": "d", "client_secret": "s"}
		case m365RouteCustomers.suffix + m365RouteCustomers.method:
			return env.partnerBody(nil)
		case m365RouteLinks.suffix + m365RouteLinks.method:
			return linkBody
		}
		return nil
	}
	target := func(rt m365Route) string {
		if rt.suffix != "/m365-connection" {
			return "msp-a"
		}
		return "client-a1"
	}

	// Root-scoped without a crossing: the challenge on all five routes.
	for _, rt := range m365AllRoutes {
		rec := m365Do(t, server, root, rt, "msp-a", bodyFor(rt))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, rt.method+rt.suffix)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`, rt.method+rt.suffix)
	}
	assert.Empty(t, env.secretKeys(t))

	// With an active MSP grant the caller may list and link.
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(context.Background(), &business.TenantCrossing{
		ID: "grant-m365-1", TenantID: "msp-a", Kind: business.TenantCrossingKindGrant, GrantedBy: "msp-a-admin",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
	rec := m365Do(t, server, root, m365RouteCustomers, "msp-a", env.partnerBody(nil))
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = m365Do(t, server, root, m365RouteLinks, "msp-a", linkBody)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = m365Do(t, server, root, m365RouteGet, "client-a1", nil)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// A tenant-bound principal of a different MSP sees 404 on all five routes.
	other := &Principal{ID: "msp-b-admin", Name: "msp-b-admin", Assurance: session.AssuranceStrong,
		TenantID: "msp-b", ImplicitAdmin: true, CertSerial: "m365-test-serial"}
	for _, rt := range m365AllRoutes {
		rec := m365Do(t, server, other, rt, target(rt), bodyFor(rt))
		assert.Equal(t, http.StatusNotFound, rec.Code, rt.method+rt.suffix+": "+rec.Body.String())
	}
	// ... and a link naming another MSP's client tenant in its own MSP is refused.
	rec = m365Do(t, server, other, m365RouteLinks, "msp-b", env.partnerBody(map[string]interface{}{
		"links": []map[string]string{{"customer_tenant_id": "cust-2", "tenant_id": "client-a2"}}}))
	assert.Contains(t, []int{http.StatusNotFound, http.StatusBadRequest}, rec.Code)
	_, err := env.cs.GetConfig("client-a2")
	assert.ErrorIs(t, err, secretsif.ErrSecretNotFound)
}
