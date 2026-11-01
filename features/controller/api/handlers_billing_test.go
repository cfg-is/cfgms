// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	billingHostSecret = "host-secret-zq9.example.internal"
	billingIPSecret   = "203.0.113.77"
)

// seedBillingReportTree extends seedBoundaryTree with a client under msp-b, hostnames and
// IPs on the client stewards, and returns the labels of client-a1 and client-b1.
func seedBillingReportTree(t *testing.T, server *Server) (labelA1, labelB1 string) {
	t.Helper()
	ctx := context.Background()
	labelA1 = seedBoundaryTree(t, server)
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "client-b1", Name: "Distinctive-ClientB-Zq9", ParentID: "msp-b"})
	require.NoError(t, err)
	td, err := server.tenantManager.GetTenant(ctx, "client-b1")
	require.NoError(t, err)
	labelB1 = td.BillingLabel
	require.NotEmpty(t, labelA1)
	require.NotEmpty(t, labelB1)
	require.NotEqual(t, labelA1, labelB1)

	st := newTestSQLiteStewardStore(t)
	server.SetStewardStore(st)
	for _, rec := range []*business.StewardRecord{
		{ID: "bill-sa-own", TenantID: "msp-a", Status: business.StewardStatusActive, Platform: "linux", Version: "1.0"},
		{ID: "bill-sa-client", TenantID: "client-a1", Status: business.StewardStatusActive, Platform: "windows", Version: "1.0", Hostname: billingHostSecret, IPAddress: billingIPSecret},
		{ID: "bill-sa-gc", TenantID: "grandchild-a1x", Status: business.StewardStatusLost, Platform: "linux", Version: "2.0", Hostname: billingHostSecret, IPAddress: billingIPSecret},
		{ID: "bill-sb-client", TenantID: "client-b1", Status: business.StewardStatusActive, Platform: "darwin", Version: "1.0", Hostname: billingHostSecret, IPAddress: billingIPSecret},
	} {
		seedSteward(t, st, rec)
	}
	seedBillingAccount(t, server, "bill-tech-a1", "client-a1", false, false)
	seedBillingAccount(t, server, "bill-tech-msp-a", "msp-a", false, false)
	return labelA1, labelB1
}

func mspAdminPrincipal(id, tenantID string) *Principal {
	return &Principal{ID: id, Name: id, Assurance: session.AssuranceStrong, TenantID: tenantID,
		Permissions: []string{"tenant:billing-read", "tenant:read"}}
}

// legacyCertPrincipal is an unscoped, certificate-authenticated, non-root-scoped admin.
func legacyCertPrincipal(perms ...string) *Principal {
	return &Principal{ID: "legacy-cert", Name: "legacy-cert", Assurance: session.AssuranceStrong,
		GlobalScope: true, TenantID: "", CertSerial: "serial-legacy", Permissions: perms}
}

func callRootBilling(t *testing.T, server *Server, p *Principal) *httptest.ResponseRecorder {
	t.Helper()
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/billing/report", "", p, nil)
	rec := httptest.NewRecorder()
	server.requirePermission("tenant", "billing-read")(http.HandlerFunc(server.handleRootBillingReport)).ServeHTTP(rec, req)
	return rec
}

func callTenantBilling(t *testing.T, server *Server, p *Principal, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/"+id+"/billing-report", id, p, nil)
	rec := httptest.NewRecorder()
	server.requirePermission("tenant", "billing-read")(http.HandlerFunc(server.handleTenantBillingReport)).ServeHTTP(rec, req)
	return rec
}

type rootReportEnvelope struct {
	Data rootBillingReport `json:"data"`
}

type tenantReportEnvelope struct {
	Data tenantBillingReport `json:"data"`
}

func decodeRootReport(t *testing.T, rec *httptest.ResponseRecorder) rootBillingReport {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var env rootReportEnvelope
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	return env.Data
}

func decodeTenantReport(t *testing.T, rec *httptest.ResponseRecorder) tenantBillingReport {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var env tenantReportEnvelope
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	return env.Data
}

func TestRootBillingReport_ShapeAndNoClientIdentity(t *testing.T) {
	server := setupCrossingTestServer(t)
	labelA1, labelB1 := seedBillingReportTree(t, server)

	rec := callRootBilling(t, server, rootScopedPrincipal("root-op-bill-1"))
	report := decodeRootReport(t, rec)

	byID := map[string]rootBillingMSP{}
	for _, m := range report.MSPs {
		byID[m.ID] = m
	}
	require.Len(t, byID, 2)
	a := byID["msp-a"]
	assert.Equal(t, "MSP-Alpha", a.Name)
	assert.Equal(t, 3, a.EndpointCount, "own + client + grandchild")
	assert.Equal(t, 2, a.TechCount)
	assert.Equal(t, 1, a.ClientCount)
	assert.Equal(t, billingOwnCounts{TechCount: 1, EndpointCount: 1}, a.MSPOwn)
	assert.Equal(t, 2, a.Metrics.EndpointsOnline, "msp-a own + client-a1")
	assert.Equal(t, 1, a.Metrics.EndpointsOffline, "grandchild")
	require.Len(t, a.Clients, 1)
	assert.Equal(t, rootBillingClient{Label: labelA1, EndpointCount: 2, TechCount: 1}, a.Clients[0])
	require.Len(t, byID["msp-b"].Clients, 1)
	assert.Equal(t, labelB1, byID["msp-b"].Clients[0].Label)

	body := rec.Body.String()
	for _, secret := range []string{
		boundaryClientName, boundaryGrandchildName, "Distinctive-ClientB-Zq9",
		"client-a1", "client-b1", "grandchild-a1x",
		billingHostSecret, billingIPSecret, "bill-sa-client", "bill-sb-client", "ip_address", "hostname",
	} {
		assert.NotContains(t, body, secret)
	}

	// Client rows carry exactly label, endpoint_count and tech_count.
	var raw struct {
		Data struct {
			MSPs []struct {
				Clients []map[string]any `json:"clients"`
			} `json:"msps"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	for _, m := range raw.Data.MSPs {
		for _, c := range m.Clients {
			assert.Equal(t, []string{"endpoint_count", "label", "tech_count"}, sortedKeys(c))
		}
	}
}

func TestRootBillingReport_ErrorBodiesLeakNothing(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBillingReportTree(t, server)

	bodies := []string{
		callRootBilling(t, server, mspAdminPrincipal("msp-admin", "msp-a")).Body.String(),
		callRootBilling(t, server, legacyCertPrincipal()).Body.String(),
		callRootBilling(t, server, &Principal{ID: "nobody"}).Body.String(),
	}
	for _, body := range bodies {
		for _, secret := range []string{boundaryClientName, "client-a1", "msp-a", "msp-b", "MSP-Alpha", billingHostSecret, billingIPSecret, "bill-sa-client"} {
			assert.NotContains(t, body, secret)
		}
	}
}

func TestRootBillingReport_MSPAdminGets403BillingRootOnly(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBillingReportTree(t, server)

	rec := callRootBilling(t, server, mspAdminPrincipal("msp-admin", "msp-a"))
	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "BILLING_ROOT_ONLY")
	assert.NotContains(t, rec.Body.String(), "msp-a")
	assert.NotContains(t, rec.Body.String(), `"msps"`)
}

func TestRootBillingReport_LegacyCertificate(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBillingReportTree(t, server)

	with := callRootBilling(t, server, legacyCertPrincipal("tenant:billing-read"))
	assert.Len(t, decodeRootReport(t, with).MSPs, 2, "an unscoped certificate holding the permission reads the report")

	without := callRootBilling(t, server, legacyCertPrincipal("tenant:read"))
	assert.Equal(t, http.StatusForbidden, without.Code, "a certificate authenticates, it does not authorize")
	assert.NotContains(t, without.Body.String(), `"msps"`)
}

func TestRootBillingReport_RootTenantBoundPrincipal(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBillingReportTree(t, server)

	rec := callRootBilling(t, server, mspAdminPrincipal("root-bound", "root"))
	assert.Len(t, decodeRootReport(t, rec).MSPs, 2)
}

func TestRootBillingReport_NoAuditEvent(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBillingReportTree(t, server)
	require.NotNil(t, server.auditManager)
	ctx := context.Background()

	require.NoError(t, server.auditManager.Flush(ctx))
	before, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{})
	require.NoError(t, err)

	rec := callRootBilling(t, server, rootScopedPrincipal("root-op-bill-audit"))
	require.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, server.auditManager.Flush(ctx))
	after, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{})
	require.NoError(t, err)
	assert.Len(t, after, len(before), "a root billing read adds no audit event (A6.3)")
}

func TestTenantBillingReport_MSPIsolation(t *testing.T) {
	server := setupCrossingTestServer(t)
	labelA1, _ := seedBillingReportTree(t, server)
	adminA := mspAdminPrincipal("admin-a", "msp-a")

	report := decodeTenantReport(t, callTenantBilling(t, server, adminA, "msp-a"))
	assert.Equal(t, "msp-a", report.ID)
	assert.Equal(t, "MSP-Alpha", report.Name)
	require.Len(t, report.Clients, 1)
	assert.Equal(t, tenantBillingClient{ID: "client-a1", Name: boundaryClientName, EndpointCount: 2, TechCount: 1}, report.Clients[0])

	rec := callTenantBilling(t, server, adminA, "msp-a")
	for _, other := range []string{"msp-b", "client-b1", "Distinctive-ClientB-Zq9", "MSP-Beta"} {
		assert.NotContains(t, rec.Body.String(), other)
	}
	assert.NotContains(t, rec.Body.String(), labelA1, "the label is root-report output only")

	denied := callTenantBilling(t, server, adminA, "msp-b")
	assert.Equal(t, http.StatusNotFound, denied.Code)
	assert.NotContains(t, denied.Body.String(), "Distinctive-ClientB-Zq9")
}

func TestTenantBillingReport_ClientScopedSeesOnlyItself(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBillingReportTree(t, server)
	_, err := server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ID: "client-a2", Name: "Distinctive-Sibling-Zq5", ParentID: "msp-a"})
	require.NoError(t, err)
	client := mspAdminPrincipal("client-admin", "client-a1")

	rec := callTenantBilling(t, server, client, "client-a1")
	report := decodeTenantReport(t, rec)
	require.Len(t, report.Clients, 1)
	assert.Equal(t, "grandchild-a1x", report.Clients[0].ID)
	assert.NotContains(t, rec.Body.String(), "Distinctive-Sibling-Zq5")

	assert.Equal(t, http.StatusNotFound, callTenantBilling(t, server, client, "client-a2").Code)
	assert.Equal(t, http.StatusNotFound, callTenantBilling(t, server, client, "msp-a").Code)
}

func TestTenantBillingReport_RootScopedNeedsCrossing(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBillingReportTree(t, server)

	rec := callTenantBilling(t, server, rootScopedPrincipal("root-op-bill-2"), "msp-a")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
	assert.NotContains(t, rec.Body.String(), boundaryClientName)
}

func TestRootScopedGetClientBelowWalledOffMSP_NoClientName(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedBillingReportTree(t, server)

	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/client-a1", "client-a1", rootScopedPrincipal("root-op-bill-3"), nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)
	assert.Contains(t, []int{http.StatusNotFound, http.StatusUnauthorized}, rec.Code)
	assert.NotContains(t, rec.Body.String(), boundaryClientName)
}

func TestBillingLabelIsNotATenantID(t *testing.T) {
	server := setupCrossingTestServer(t)
	labelA1, _ := seedBillingReportTree(t, server)
	root := rootScopedPrincipal("root-op-bill-4")

	for name, h := range map[string]http.HandlerFunc{
		"get tenant":     server.handleGetTenant,
		"billing report": server.handleTenantBillingReport,
		"list crossings": server.handleListTenantCrossings,
		"suspend":        server.handleSuspendTenant,
	} {
		req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/"+labelA1, labelA1, root, nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code, name)
		assert.NotContains(t, rec.Body.String(), boundaryClientName, name)
	}
}

func TestBillingReports_RootAndMSPAgree(t *testing.T) {
	server := setupCrossingTestServer(t)
	labelA1, _ := seedBillingReportTree(t, server)
	root := rootScopedPrincipal("root-op-bill-5")

	first := decodeRootReport(t, callRootBilling(t, server, root))
	second := decodeRootReport(t, callRootBilling(t, server, root))
	assert.Equal(t, first, second)

	for _, m := range first.MSPs {
		msp := decodeTenantReport(t, callTenantBilling(t, server, mspAdminPrincipal("admin-"+m.ID, m.ID), m.ID))
		assert.Equal(t, m.TechCount, msp.TechCount, m.ID)
		assert.Equal(t, m.EndpointCount, msp.EndpointCount, m.ID)
		assert.Equal(t, m.ClientCount, msp.ClientCount, m.ID)
		assert.Equal(t, m.Metrics, msp.Metrics, m.ID)
		assert.Equal(t, m.MSPOwn, msp.MSPOwn, m.ID)
		require.Len(t, m.Clients, len(msp.Clients), m.ID)
		for i, c := range m.Clients {
			assert.Equal(t, msp.Clients[i].EndpointCount, c.EndpointCount)
			assert.Equal(t, msp.Clients[i].TechCount, c.TechCount)
		}
	}
	var gotA string
	for _, m := range first.MSPs {
		if m.ID == "msp-a" {
			gotA = m.Clients[0].Label
		}
	}
	assert.Equal(t, labelA1, gotA)
}
