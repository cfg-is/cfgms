// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	reportsprovider "github.com/cfgis/cfgms/features/reports/provider"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// Issue #4715: a root caller subject to the ADR-025 boundary needs a crossing to
// read a client tenant's stewards, fleet lists, connections, compliance and live
// telemetry. Lists silently omit what it cannot read; by-ID reads answer the
// crossing challenge.

const (
	stewardReadMSP     = "msp-steward-read"
	stewardReadClient  = "client-steward-read"
	stewardReadOtherMS = "msp-steward-other"
)

type stewardReadFixture struct {
	server        *Server
	rootSteward   string
	clientSteward string
	durableOnly   string // owned by the client tenant, known only to the durable store
}

func newStewardReadFixture(t *testing.T) *stewardReadFixture {
	t.Helper()
	server := seedRootTenant(t, setupCrossingTestServer(t))
	ctx := context.Background()
	for _, tr := range []*tenant.TenantRequest{
		{ID: stewardReadMSP, ParentID: testRootTenantID},
		{ID: stewardReadClient, ParentID: stewardReadMSP},
		{ID: stewardReadOtherMS, ParentID: testRootTenantID},
	} {
		_, err := server.tenantManager.CreateTenant(ctx, tr)
		require.NoError(t, err)
	}

	f := &stewardReadFixture{
		server:        server,
		rootSteward:   registerStewardUnderTenant(t, server, testRootTenantID, "root-host"),
		clientSteward: registerStewardUnderTenant(t, server, stewardReadClient, "client-host"),
		durableOnly:   "durable-client-steward",
	}
	server.stewardStore = &fleetViewStore{records: []*business.StewardRecord{
		{ID: f.durableOnly, TenantID: stewardReadClient, Status: business.StewardStatusActive, LastSeen: time.Now().UTC()},
	}}

	now := time.Now()
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: []fleet.StewardData{
		{ID: f.rootSteward, TenantID: testRootTenantID, Status: "active", LastHeartbeat: now,
			DNAAttributes: map[string]string{"hostname": "root-host", "os": "linux", "steward.version": "v1.0"}},
		{ID: f.clientSteward, TenantID: stewardReadClient, Status: "active", LastHeartbeat: now,
			DNAAttributes: map[string]string{"hostname": "client-host", "os": "windows", "steward.version": "v2.0"}},
		{ID: "client-lost", TenantID: stewardReadClient, Status: "lost", LastHeartbeat: now.Add(-time.Hour),
			DNAAttributes: map[string]string{"hostname": "client-lost-host", "os": "darwin", "steward.version": "v2.0"}},
	}})

	// Backing services the by-ID reads need before they reach the tenant decision.
	server.SetScriptModule(newTestScriptTracker(t), script.NewAuditLogger(1000), script.NewExecutionMonitor())
	egProvider, err := egsqlite.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = egProvider.Close() })
	server.SetDataProvider(reportsprovider.New(egProvider, logging.NewNoopLogger()))
	server.SetCommandStore(pkgtesting.SetupTestStorage(t).GetCommandStore())

	reg := registry.NewRegistry()
	registerTestConnection(t, reg, f.rootSteward)
	registerTestConnection(t, reg, f.clientSteward)
	server.SetRegistry(reg)
	return f
}

func (f *stewardReadFixture) get(t *testing.T, handler http.HandlerFunc, operator *Principal, path string, vars map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler(rec, asRootOperator(httptest.NewRequest(http.MethodGet, path, nil), operator, vars))
	return rec
}

func decodeData[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var env struct {
		Data T `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&env), rec.Body.String())
	return env.Data
}

func TestRootStewardReads_ByIDCrossingBoundary(t *testing.T) {
	f := newStewardReadFixture(t)
	s := f.server

	routes := []struct {
		name    string
		handler http.HandlerFunc
		// steward is the steward ID the route is asked about.
		steward string
		// ok reports whether a status is an acceptable answer once the caller may read:
		// anything but the challenge or a refusal.
		ok func(int) bool
	}{
		{"GET /stewards/{id}", s.handleGetSteward, f.clientSteward, func(c int) bool { return c == http.StatusOK }},
		{"GET /stewards/{id} (durable record)", s.handleGetSteward, f.durableOnly, func(c int) bool { return c == http.StatusOK }},
		{"GET /stewards/{id}/dna", s.handleGetStewardDNA, f.clientSteward, func(c int) bool { return c == http.StatusOK }},
		{"GET /stewards/{id}/logs", s.handleGetStewardLogs, f.clientSteward, func(c int) bool { return c == http.StatusOK }},
		{"GET /stewards/{id}/modules", s.handleGetStewardModules, f.clientSteward, func(c int) bool { return c != http.StatusNotFound }},
		{"GET /stewards/{id}/config", s.handleGetStewardConfig, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
		{"GET /stewards/{id}/config/effective", s.handleGetEffectiveConfig, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
		{"GET /stewards/{id}/connection", s.handleGetStewardConnection, f.clientSteward, func(c int) bool { return c == http.StatusOK }},
		{"GET /stewards/{id}/scripts/executions", s.handleGetScriptExecutions, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
		{"GET /stewards/{id}/scripts/executions/{execution_id}", s.handleGetScriptExecution, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
		{"GET /stewards/{id}/scripts/metrics", s.handleGetScriptMetrics, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
		{"GET /stewards/{id}/scripts/status", s.handleGetScriptStatus, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
		{"GET /stewards/{id}/tags", s.handleListStewardTags, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
		{"GET /stewards/{id}/compliance", s.handleGetStewardCompliance, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
		{"GET /stewards/{id}/compliance/report", s.handleGetStewardComplianceReport, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
		{"GET /stewards/{id}/reboot-window", s.handleGetStewardRebootWindow, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
		{"GET /stewards/{id}/pending-deliveries", s.handleListPendingDeliveries, f.clientSteward, func(c int) bool { return c != http.StatusUnauthorized }},
	}

	for i, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			path := "/api/v1/stewards/" + rt.steward
			vars := map[string]string{"id": rt.steward, "execution_id": "exec-none"}

			t.Run("no crossing", func(t *testing.T) {
				rec := f.get(t, rt.handler, boundRootOperator("steward-read-no-"+string(rune('a'+i))), path, vars)
				assertCrossingChallenge(t, rec, stewardReadClient)
			})
			t.Run("active crossing on the owning MSP", func(t *testing.T) {
				operator := boundRootOperator("steward-read-msp-" + string(rune('a'+i)))
				grantCrossing(t, s, operator.ID, stewardReadMSP)
				rec := f.get(t, rt.handler, operator, path, vars)
				assert.True(t, rt.ok(rec.Code), "unexpected %d: %s", rec.Code, rec.Body.String())
			})
			t.Run("active crossing on the client", func(t *testing.T) {
				operator := boundRootOperator("steward-read-client-" + string(rune('a'+i)))
				grantCrossing(t, s, operator.ID, stewardReadClient)
				rec := f.get(t, rt.handler, operator, path, vars)
				assert.True(t, rt.ok(rec.Code), "unexpected %d: %s", rec.Code, rec.Body.String())
			})
		})
	}

	t.Run("an unknown steward stays 404 for a boundary-subject root caller", func(t *testing.T) {
		rec := f.get(t, s.handleGetSteward, boundRootOperator("steward-read-unknown"),
			"/api/v1/stewards/no-such", map[string]string{"id": "no-such"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("a root-tenant steward needs no crossing", func(t *testing.T) {
		rec := f.get(t, s.handleGetSteward, boundRootOperator("steward-read-own"),
			"/api/v1/stewards/"+f.rootSteward, map[string]string{"id": f.rootSteward})
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
}

func TestRootStewardReads_ListsOmitClientTenants(t *testing.T) {
	f := newStewardReadFixture(t)
	s := f.server

	idsOf := func(list []StewardInfo) []string {
		out := make([]string, 0, len(list))
		for _, st := range list {
			out = append(out, st.ID)
		}
		return out
	}

	t.Run("GET /stewards without a crossing lists only root-tenant stewards", func(t *testing.T) {
		rec := f.get(t, s.handleListStewards, boundRootOperator("list-none"), "/api/v1/stewards", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.ElementsMatch(t, []string{f.rootSteward}, idsOf(decodeData[[]StewardInfo](t, rec)))
	})

	t.Run("pagination total counts visible rows only", func(t *testing.T) {
		rec := f.get(t, s.handleListStewards, boundRootOperator("list-page"), "/api/v1/stewards?limit=10&offset=0", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		page := decodeData[StewardListPage](t, rec)
		assert.Equal(t, 1, page.Total)
		assert.Len(t, page.Stewards, 1)
	})

	t.Run("selector search path omits client tenants", func(t *testing.T) {
		rec := f.get(t, s.handleListStewards, boundRootOperator("list-q"), "/api/v1/stewards?q=all&limit=10", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		page := decodeData[StewardListPage](t, rec)
		assert.Equal(t, 1, page.Total)
		assert.Equal(t, []string{f.rootSteward}, idsOf(page.Stewards))
	})

	t.Run("filtered path omits client tenants", func(t *testing.T) {
		rec := f.get(t, s.handleListStewards, boundRootOperator("list-os"), "/api/v1/stewards?os=windows", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Empty(t, decodeData[[]StewardInfo](t, rec))
	})

	t.Run("an active grant on the MSP adds its client stewards", func(t *testing.T) {
		operator := boundRootOperator("list-granted")
		grantCrossing(t, s, operator.ID, stewardReadMSP)
		rec := f.get(t, s.handleListStewards, operator, "/api/v1/stewards?limit=10", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		page := decodeData[StewardListPage](t, rec)
		assert.Equal(t, 3, page.Total)
		assert.ElementsMatch(t, []string{f.rootSteward, f.clientSteward, f.durableOnly}, idsOf(page.Stewards))
	})

	t.Run("an unrestricted certificate admin sees every tenant", func(t *testing.T) {
		admin := &Principal{ID: "cert-admin", GlobalScope: true, CertSerial: "01"}
		rec := f.get(t, s.handleListStewards, admin, "/api/v1/stewards", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.ElementsMatch(t, []string{f.rootSteward, f.clientSteward, f.durableOnly}, idsOf(decodeData[[]StewardInfo](t, rec)))
	})

	t.Run("a tenant-scoped MSP admin sees its subtree as before", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		ctx := context.WithValue(req.Context(), principalContextKey, &Principal{ID: "msp-admin", TenantID: stewardReadMSP})
		ctx = context.WithValue(ctx, ctxkeys.TenantID, stewardReadMSP)
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(stewardReadMSP))
		rec := httptest.NewRecorder()
		s.handleListStewards(rec, req.WithContext(ctx))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.ElementsMatch(t, []string{f.clientSteward, "client-lost"}, idsOf(decodeData[[]StewardInfo](t, rec)))
	})
}

func TestRootStewardReads_ConnectionsAllAndResolve(t *testing.T) {
	f := newStewardReadFixture(t)
	s := f.server

	t.Run("connections/all omits client-tenant connections without a crossing", func(t *testing.T) {
		rec := f.get(t, s.handleListAllConnections, boundRootOperator("conn-none"), "/api/v1/stewards/connections/all", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		body := decodeData[struct {
			Connections []StewardConnectionItem `json:"connections"`
		}](t, rec)
		require.Len(t, body.Connections, 1)
		assert.Equal(t, f.rootSteward, body.Connections[0].StewardID)
	})

	t.Run("connections/all includes them under a crossing", func(t *testing.T) {
		operator := boundRootOperator("conn-granted")
		grantCrossing(t, s, operator.ID, stewardReadMSP)
		rec := f.get(t, s.handleListAllConnections, operator, "/api/v1/stewards/connections/all", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		body := decodeData[struct {
			Connections []StewardConnectionItem `json:"connections"`
		}](t, rec)
		assert.Len(t, body.Connections, 2)
	})

	resolve := func(operator *Principal) []StewardInfo {
		req := asRootOperator(httptest.NewRequest(http.MethodPost, "/api/v1/fleet/resolve",
			strings.NewReader(`{"selector":"all"}`)), operator, nil)
		rec := httptest.NewRecorder()
		s.handleResolveSelector(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		return decodeData[[]StewardInfo](t, rec)
	}

	t.Run("selector resolve returns no client-tenant rows without a crossing", func(t *testing.T) {
		got := resolve(boundRootOperator("resolve-none"))
		require.Len(t, got, 1)
		assert.Equal(t, f.rootSteward, got[0].ID)
	})

	t.Run("selector resolve includes them under a crossing", func(t *testing.T) {
		operator := boundRootOperator("resolve-granted")
		grantCrossing(t, s, operator.ID, stewardReadClient)
		assert.Len(t, resolve(operator), 3)
	})
}

func TestRootStewardReads_FleetHealthAnonymizesWalledOffTenants(t *testing.T) {
	f := newStewardReadFixture(t)
	s := f.server

	t.Run("without a crossing, client tenants appear only as the anonymized set", func(t *testing.T) {
		rec := f.get(t, s.handleFleetHealth, boundRootOperator("health-none"), "/api/v1/fleet/health", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		resp := decodeData[FleetHealthResponse](t, rec)
		assert.Equal(t, 1, resp.Healthy, "only the root-tenant steward is counted in the visible fields")
		assert.Equal(t, 0, resp.Unreachable)
		require.NotNil(t, resp.WalledOff)
		assert.Equal(t, 1, resp.WalledOff.Online)
		assert.Equal(t, 1, resp.WalledOff.Offline)
		assert.Equal(t, 1, resp.WalledOff.Platform.Windows)
		assert.Equal(t, 1, resp.WalledOff.Platform.Darwin)
		assert.Equal(t, map[string]int{"v2.0": 2}, resp.WalledOff.Versions)

		raw := rec.Body.String()
		for _, leaked := range []string{f.clientSteward, "client-lost", "client-host", stewardReadClient} {
			assert.NotContains(t, raw, leaked, "the walled-off aggregate must carry no identifier")
		}
	})

	t.Run("under a crossing, client stewards are counted as visible rows", func(t *testing.T) {
		operator := boundRootOperator("health-granted")
		grantCrossing(t, s, operator.ID, stewardReadMSP)
		rec := f.get(t, s.handleFleetHealth, operator, "/api/v1/fleet/health", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		resp := decodeData[FleetHealthResponse](t, rec)
		assert.Equal(t, 2, resp.Healthy)
		assert.Equal(t, 1, resp.Unreachable)
		assert.Nil(t, resp.WalledOff)
	})

	t.Run("an unrestricted certificate admin sees the full counts and no aggregate", func(t *testing.T) {
		rec := f.get(t, s.handleFleetHealth, &Principal{ID: "cert-admin", GlobalScope: true, CertSerial: "01"}, "/api/v1/fleet/health", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		resp := decodeData[FleetHealthResponse](t, rec)
		assert.Equal(t, 2, resp.Healthy)
		assert.Equal(t, 1, resp.Unreachable)
		assert.Nil(t, resp.WalledOff)
	})
}

func TestRootStewardReads_ComplianceSummary(t *testing.T) {
	f := newStewardReadFixture(t)
	s := f.server

	tenantsOf := func(operator *Principal) map[string]bool {
		rec := f.get(t, s.handleGetComplianceSummary, operator, "/api/v1/compliance/summary", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		out := map[string]bool{}
		for _, bt := range resp.ByTenant {
			out[bt.TenantID] = true
		}
		return out
	}

	assert.Equal(t, map[string]bool{testRootTenantID: true}, tenantsOf(boundRootOperator("summary-none")))

	granted := boundRootOperator("summary-granted")
	grantCrossing(t, s, granted.ID, stewardReadMSP)
	assert.Equal(t, map[string]bool{testRootTenantID: true, stewardReadClient: true}, tenantsOf(granted))

	assert.Equal(t, map[string]bool{testRootTenantID: true, stewardReadClient: true},
		tenantsOf(&Principal{ID: "cert-admin", GlobalScope: true, CertSerial: "01"}))
}

func TestRootStewardReads_PendingRefreshes(t *testing.T) {
	f := newStewardReadFixture(t)
	s := f.server
	ctx := context.Background()

	s.stewardStore = nil // hostname enrichment is not under test
	store := pkgtesting.SetupTestStorage(t).GetPendingRefreshStore()
	require.NotNil(t, store, "test storage must provide a real PendingRefreshStore")
	s.SetPendingRefreshStore(store)
	now := time.Now().UTC()
	for _, e := range []*business.PendingRefreshEntry{
		{PendingID: "p-root", DeviceID: "d-root", TenantID: testRootTenantID, Status: business.PendingRefreshStatusPending, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
		{PendingID: "p-client", DeviceID: "d-client", TenantID: stewardReadClient, Status: business.PendingRefreshStatusPending, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
	} {
		require.NoError(t, store.AddPendingRefresh(ctx, e))
	}

	pendingIDs := func(operator *Principal) []string {
		rec := httptest.NewRecorder()
		s.handleListPendingRefreshes(rec, asRootOperator(httptest.NewRequest(http.MethodGet, "/api/v1/stewards/refresh/pending", nil), operator, nil))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var out []APIPendingRefreshEntry
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
		ids := make([]string, 0, len(out))
		for _, e := range out {
			ids = append(ids, e.PendingID)
		}
		return ids
	}

	assert.Equal(t, []string{"p-root"}, pendingIDs(boundRootOperator("refresh-none")))

	granted := boundRootOperator("refresh-granted")
	grantCrossing(t, s, granted.ID, stewardReadMSP)
	assert.ElementsMatch(t, []string{"p-root", "p-client"}, pendingIDs(granted))

	assert.ElementsMatch(t, []string{"p-root", "p-client"}, pendingIDs(&Principal{ID: "cert-admin", GlobalScope: true, CertSerial: "01"}))
}

func TestRootStewardReads_TelemetryStream(t *testing.T) {
	f := newStewardReadFixture(t)
	s := f.server

	reached := false
	wrapped := s.tenantScopedTelemetryWrapper(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	call := func(operator *Principal, stewardID string) *httptest.ResponseRecorder {
		reached = false
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, asRootOperator(httptest.NewRequest(http.MethodGet, "/api/v1/telemetry/ws/"+stewardID, nil), operator, map[string]string{"id": stewardID}))
		return rec
	}

	t.Run("refused with the challenge without a crossing", func(t *testing.T) {
		rec := call(boundRootOperator("telemetry-none"), f.clientSteward)
		assertCrossingChallenge(t, rec, stewardReadClient)
		assert.False(t, reached, "the stream handler must not run")
	})

	t.Run("delivered with a crossing", func(t *testing.T) {
		operator := boundRootOperator("telemetry-granted")
		grantCrossing(t, s, operator.ID, stewardReadMSP)
		rec := call(operator, f.clientSteward)
		assert.Equal(t, http.StatusSwitchingProtocols, rec.Code)
		assert.True(t, reached)
	})

	t.Run("a root-tenant steward needs no crossing", func(t *testing.T) {
		rec := call(boundRootOperator("telemetry-own"), f.rootSteward)
		assert.Equal(t, http.StatusSwitchingProtocols, rec.Code)
	})

	t.Run("an unknown steward is 404", func(t *testing.T) {
		rec := call(boundRootOperator("telemetry-unknown"), "no-such")
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}
