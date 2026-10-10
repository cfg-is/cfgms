// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// contactsTestTree seeds root > msp-a > client-a1 > site-a1 and root > msp-b.
func contactsTestTree(t *testing.T) *Server {
	t.Helper()
	server := seedRootTenant(t, setupCrossingTestServer(t))
	ctx := context.Background()
	for _, r := range []*tenant.TenantRequest{
		{ID: "msp-a", ParentID: testRootTenantID},
		{ID: "client-a1", ParentID: "msp-a"},
		{ID: "site-a1", ParentID: "client-a1"},
		{ID: "msp-b", ParentID: testRootTenantID},
	} {
		_, err := server.tenantManager.CreateTenant(ctx, r)
		require.NoError(t, err)
	}
	return server
}

func contactsAdmin(tenantID string) *Principal {
	return &Principal{ID: tenantID + "-admin", TenantID: tenantID, Assurance: session.AssuranceStrong}
}

func callContacts(t *testing.T, server *Server, method, tenantID string, p *Principal, body string) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	req := requestAsPrincipal(t, method, "/api/v1/tenants/"+tenantID+"/admin-contacts", tenantID, p, b)
	rec := httptest.NewRecorder()
	if method == http.MethodGet {
		server.handleGetTenantAdminContacts(rec, req)
	} else {
		server.handlePutTenantAdminContacts(rec, req)
	}
	return rec
}

func decodeContacts(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var env struct {
		Data tenantAdminContactsBody `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	return env.Data.Contacts
}

func TestAdminContacts_MSPAdminSetReadReplace(t *testing.T) {
	server := contactsTestTree(t)
	admin := contactsAdmin("msp-a")

	rec := callContacts(t, server, http.MethodGet, "msp-a", admin, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, decodeContacts(t, rec))

	rec = callContacts(t, server, http.MethodPut, "msp-a", admin, `{"contacts":["Ops@Example.com","sec@example.com","ops@example.com"]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"ops@example.com", "sec@example.com"}, decodeContacts(t, rec))

	rec = callContacts(t, server, http.MethodGet, "msp-a", admin, "")
	assert.Equal(t, []string{"ops@example.com", "sec@example.com"}, decodeContacts(t, rec))

	rec = callContacts(t, server, http.MethodPut, "msp-a", admin, `{"contacts":["new@example.com"]}`)
	require.Equal(t, http.StatusOK, rec.Code)
	rec = callContacts(t, server, http.MethodGet, "msp-a", admin, "")
	assert.Equal(t, []string{"new@example.com"}, decodeContacts(t, rec))

	// The MSP admin may also edit a descendant's contacts.
	rec = callContacts(t, server, http.MethodPut, "client-a1", admin, `{"contacts":["c@example.com"]}`)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Empty list is allowed.
	rec = callContacts(t, server, http.MethodPut, "msp-a", admin, `{"contacts":[]}`)
	require.Equal(t, http.StatusOK, rec.Code)
	rec = callContacts(t, server, http.MethodGet, "msp-a", admin, "")
	assert.Empty(t, decodeContacts(t, rec))
}

func TestAdminContacts_InvalidRejected(t *testing.T) {
	server := contactsTestTree(t)
	admin := contactsAdmin("msp-a")

	var many []string
	for i := 0; i <= tenant.MaxAdminContacts; i++ {
		many = append(many, "u"+string(rune('a'+i%26))+strings.Repeat("x", i)+"@example.com")
	}
	manyJSON, _ := json.Marshal(map[string]any{"contacts": many})

	for name, body := range map[string]string{
		"not an address": `{"contacts":["nope"]}`,
		"display name":   `{"contacts":["Ops <ops@example.com>"]}`,
		"crlf":           `{"contacts":["a@example.com\r\nBcc: b@example.com"]}`,
		"too many":       string(manyJSON),
		"missing field":  `{}`,
		"bad json":       `{`,
	} {
		rec := callContacts(t, server, http.MethodPut, "msp-a", admin, body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, name)
	}
	rec := callContacts(t, server, http.MethodGet, "msp-a", admin, "")
	assert.Empty(t, decodeContacts(t, rec), "rejected writes leave contacts unchanged")
}

func TestAdminContacts_RootScopedCaller(t *testing.T) {
	server := contactsTestTree(t)
	ctx := context.Background()
	_, err := server.tenantManager.SetAdminContacts(ctx, "msp-a", []string{"ops@example.com"})
	require.NoError(t, err)
	root := rootScopedPrincipal("root-op-1")

	// No crossing: the crossing challenge, for read and write alike.
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		rec := callContacts(t, server, method, "msp-a", root, `{"contacts":["evil@example.com"]}`)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, method)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "tenant-crossing")
	}

	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "grant-1", TenantID: "msp-a", Kind: business.TenantCrossingKindGrant,
		GrantedBy: "msp-a-admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))

	rec := callContacts(t, server, http.MethodPut, "msp-a", root, `{"contacts":["evil@example.com"]}`)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "ROOT_SCOPED_CANNOT_EDIT_CONTACTS")

	got, err := server.tenantManager.GetAdminContacts(ctx, "msp-a")
	require.NoError(t, err)
	assert.Equal(t, []string{"ops@example.com"}, got, "contacts unchanged")
}

func TestAdminContacts_TenantIsolation(t *testing.T) {
	server := contactsTestTree(t)
	ctx := context.Background()
	_, err := server.tenantManager.SetAdminContacts(ctx, "msp-b", []string{"b@example.com"})
	require.NoError(t, err)
	_, err = server.tenantManager.SetAdminContacts(ctx, "msp-a", []string{"a@example.com"})
	require.NoError(t, err)

	adminA := contactsAdmin("msp-a")
	assert.Equal(t, http.StatusNotFound, callContacts(t, server, http.MethodGet, "msp-b", adminA, "").Code)
	assert.Equal(t, http.StatusNotFound, callContacts(t, server, http.MethodPut, "msp-b", adminA, `{"contacts":[]}`).Code)

	// A client-tenant admin cannot reach its parent MSP's contacts.
	client := contactsAdmin("client-a1")
	assert.Equal(t, http.StatusNotFound, callContacts(t, server, http.MethodPut, "msp-a", client, `{"contacts":["x@example.com"]}`).Code)
	assert.Equal(t, http.StatusNotFound, callContacts(t, server, http.MethodGet, "msp-a", client, "").Code)

	// Unknown tenant is indistinguishable.
	assert.Equal(t, http.StatusNotFound, callContacts(t, server, http.MethodGet, "no-such", adminA, "").Code)

	for id, want := range map[string][]string{"msp-a": {"a@example.com"}, "msp-b": {"b@example.com"}} {
		got, err := server.tenantManager.GetAdminContacts(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
}

func TestAdminContacts_GenericTenantEndpointsKeepAndRejectReservedKey(t *testing.T) {
	server := contactsTestTree(t)
	ctx := context.Background()
	_, err := server.tenantManager.SetAdminContacts(ctx, "msp-a", []string{"a@example.com"})
	require.NoError(t, err)

	// Update omitting metadata, and with other metadata, keeps the contacts.
	for _, body := range []string{`{"name":"msp-a"}`, `{"name":"msp-a","metadata":{"k":"v"}}`} {
		rec := putTenantAsScopedCaller(t, server, "msp-a", "msp-a", []byte(body))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		got, _ := server.tenantManager.GetAdminContacts(ctx, "msp-a")
		assert.Equal(t, []string{"a@example.com"}, got)
	}

	// Supplying the reserved key on update is a 400.
	rec := putTenantAsScopedCaller(t, server, "msp-a", "msp-a",
		[]byte(`{"name":"msp-a","metadata":{"cfgms.admin_contacts":"[\"evil@example.com\"]"}}`))
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	got, _ := server.tenantManager.GetAdminContacts(ctx, "msp-a")
	assert.Equal(t, []string{"a@example.com"}, got)

	// And on create.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(
		`{"id":"msp-c","parent_id":"msp-a","metadata":{"cfgms.admin_contacts":"[\"evil@example.com\"]"}}`))
	req.Header.Set("Content-Type", "application/json")
	admin := contactsAdmin("msp-a")
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, admin))
	crec := httptest.NewRecorder()
	server.handleCreateTenant(crec, req)
	assert.Equal(t, http.StatusBadRequest, crec.Code, crec.Body.String())
}

func TestAdminContacts_AuditCarriesCountNotAddresses(t *testing.T) {
	server := contactsTestTree(t)
	ctx := context.Background()
	require.NotNil(t, server.auditManager)

	rec := callContacts(t, server, http.MethodPut, "msp-a", contactsAdmin("msp-a"),
		`{"contacts":["secret-person@example.com","other@example.com"]}`)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, server.auditManager.Flush(ctx))

	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "msp-a", Actions: []string{"tenant.admin_contacts_updated"}})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, business.AuditSeverityHigh, entries[0].Severity)
	raw, _ := json.Marshal(entries[0])
	assert.NotContains(t, string(raw), "secret-person@example.com")
	assert.Contains(t, string(raw), "contact_count")
}
