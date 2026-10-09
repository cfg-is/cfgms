// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	boundaryClientName     = "Distinctive-Client-Zq7"
	boundaryGrandchildName = "Distinctive-Grandchild-Zq8"
)

// seedBoundaryTree builds root -> msp-a -> client-a1 -> grandchild-a1x and root -> msp-b,
// with a distinctive name on the client and grandchild, and returns the client's
// billing label.
func seedBoundaryTree(t *testing.T, server *Server) (clientLabel string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, ensureTestRootTenant(ctx, server.tenantManager))
	for _, tr := range []*tenant.TenantRequest{
		{ID: "msp-a", Name: "MSP-Alpha", ParentID: "root"},
		{ID: "client-a1", Name: boundaryClientName, ParentID: "msp-a"},
		{ID: "grandchild-a1x", Name: boundaryGrandchildName, ParentID: "client-a1"},
		{ID: "msp-b", Name: "MSP-Beta", ParentID: "root"},
	} {
		_, err := server.tenantManager.CreateTenant(ctx, tr)
		require.NoError(t, err)
	}
	st := newTestSQLiteStewardStore(t)
	server.SetStewardStore(st)
	seedSteward(t, st, &business.StewardRecord{ID: "sa-own", TenantID: "msp-a", Status: business.StewardStatusActive})
	seedSteward(t, st, &business.StewardRecord{ID: "sa-client", TenantID: "client-a1", Status: business.StewardStatusActive})
	seedSteward(t, st, &business.StewardRecord{ID: "sa-gone", TenantID: "client-a1", Status: business.StewardStatusDeregistered})
	seedSteward(t, st, &business.StewardRecord{ID: "sa-gc", TenantID: "grandchild-a1x", Status: business.StewardStatusActive})
	td, err := server.tenantManager.GetTenant(ctx, "client-a1")
	require.NoError(t, err)
	return td.BillingLabel
}

func listAsPrincipal(t *testing.T, server *Server, p *Principal) []map[string]any {
	t.Helper()
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants", "", p, nil)
	rec := httptest.NewRecorder()
	server.handleListTenants(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func rowsByID(rows []map[string]any) map[string][]map[string]any {
	m := map[string][]map[string]any{}
	for _, r := range rows {
		id, _ := r["id"].(string)
		m[id] = append(m[id], r)
	}
	return m
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestHandleListTenants_RootScoped_WalledOffMSPsAreBoundaryRows(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBoundaryTree(t, server)

	rows := listAsPrincipal(t, server, rootScopedPrincipal("root-op-boundary-1"))
	byID := rowsByID(rows)

	for _, id := range []string{"msp-a", "msp-b"} {
		require.Len(t, byID[id], 1, "exactly one row for %s", id)
		assert.Equal(t, true, byID[id][0]["boundary"])
		assert.Equal(t, false, byID[id][0]["accessible"])
	}
	a := byID["msp-a"][0]
	assert.Equal(t, "MSP-Alpha", a["name"])
	assert.Equal(t, "root", a["parent_id"])
	assert.Equal(t, "active", a["status"])
	assert.EqualValues(t, 3, a["device_count"], "terminal-state steward excluded; client and grandchild rolled in")
	assert.EqualValues(t, 1, a["client_count"])
	assert.EqualValues(t, 0, a["tech_count"])

	// Key-set assertion: exactly the documented keys, so a TenantData field cannot leak.
	assert.Equal(t,
		[]string{"accessible", "boundary", "client_count", "device_count", "id", "name", "parent_id", "status", "tech_count"},
		sortedKeys(a))

	rootRow := byID["root"]
	require.Len(t, rootRow, 1)
	assert.Equal(t, false, rootRow[0]["boundary"])
	assert.Equal(t, true, rootRow[0]["accessible"])
}

func TestHandleListTenants_RootScoped_NoClientBytesLeak(t *testing.T) {
	server := setupCrossingTestServer(t)
	label := seedBoundaryTree(t, server)
	require.NotEmpty(t, label)

	caller := rootScopedPrincipal("root-op-boundary-2")
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants", "", caller, nil)
	rec := httptest.NewRecorder()
	server.handleListTenants(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assertNoClientBytes(t, rec.Body.String(), label)

	byID := rowsByID(listAsPrincipal(t, server, caller))
	assert.Empty(t, byID["client-a1"])
	assert.Empty(t, byID["grandchild-a1x"])

	// GET of a client below a walled-off MSP: crossing challenge, naming only the requested ID.
	getReq := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/client-a1", "client-a1", caller, nil)
	getRec := httptest.NewRecorder()
	server.handleGetTenant(getRec, getReq)
	assert.Contains(t, []int{http.StatusNotFound, http.StatusUnauthorized}, getRec.Code)
	body := getRec.Body.String()
	assert.NotContains(t, body, boundaryClientName)
	assert.NotContains(t, body, boundaryGrandchildName)
	assert.NotContains(t, body, "grandchild-a1x")
	assert.NotContains(t, body, label)
	assert.NotContains(t, body, "msp-a")
	assert.NotContains(t, body, "msp-b")
}

func assertNoClientBytes(t *testing.T, body, label string) {
	t.Helper()
	for _, s := range []string{boundaryClientName, boundaryGrandchildName, "client-a1", "grandchild-a1x", label} {
		assert.NotContains(t, body, s)
	}
}

func TestHandleListTenants_RootScoped_GrantYieldsOneFullRow(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBoundaryTree(t, server)
	caller := rootScopedPrincipal("root-op-boundary-3")
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(context.Background(), &business.TenantCrossing{
		ID: "grant-boundary-1", TenantID: "msp-a",
		Kind: business.TenantCrossingKindGrant, GrantedBy: "msp-a-admin",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))

	byID := rowsByID(listAsPrincipal(t, server, caller))
	require.Len(t, byID["msp-a"], 1, "a walled-off MSP with a grant never yields two rows")
	assert.Equal(t, false, byID["msp-a"][0]["boundary"])
	assert.Equal(t, true, byID["msp-a"][0]["accessible"])
	assert.Contains(t, byID["msp-a"][0], "created_at", "the full row is returned")
	require.Len(t, byID["client-a1"], 1, "client below an accessible MSP is a normal row")

	require.Len(t, byID["msp-b"], 1)
	assert.Equal(t, true, byID["msp-b"][0]["boundary"])
}

func TestHandleListTenants_MSPAdmin_NoBoundaryRows(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBoundaryTree(t, server)

	caller := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rows := listAsPrincipal(t, server, caller)
	byID := rowsByID(rows)
	assert.Empty(t, byID["msp-b"], "another MSP must not appear, even as a boundary row")
	assert.Empty(t, byID["root"])
	require.Len(t, byID["msp-a"], 1)
	for _, r := range rows {
		assert.Equal(t, false, r["boundary"])
		assert.Equal(t, true, r["accessible"])
	}
}

func TestHandleGetTenant_BoundaryRowMSP_StillReturnsChallenge(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBoundaryTree(t, server)
	caller := rootScopedPrincipal("root-op-boundary-4")

	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a", "msp-a", caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.NotContains(t, rec.Body.String(), "MSP-Alpha")
	assert.NotContains(t, rec.Body.String(), "created_at")
}
