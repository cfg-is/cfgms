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

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	reportapi "github.com/cfgis/cfgms/features/reports/api"
	reportscache "github.com/cfgis/cfgms/features/reports/cache"
	reportsengine "github.com/cfgis/cfgms/features/reports/engine"
	reportsexporters "github.com/cfgis/cfgms/features/reports/exporters"
	reportsprovider "github.com/cfgis/cfgms/features/reports/provider"
	reportstemplates "github.com/cfgis/cfgms/features/reports/templates"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Issue #4720: report, drift, compliance and dashboard reads by a root caller
// subject to the ADR-025 boundary need a crossing for client tenants. The
// anonymized A6.1 aggregate stays visible; /health and /monitoring stay reachable.

const (
	reportReadMSP    = "msp-report-read"
	reportReadClient = "client-report-read"
)

type reportReadFixture struct {
	server        *Server
	router        *mux.Router
	rootSteward   string
	clientSteward string
}

func newReportReadFixture(t *testing.T) *reportReadFixture {
	t.Helper()
	server := seedRootTenant(t, setupCrossingTestServer(t))
	ctx := context.Background()
	for _, tr := range []*tenant.TenantRequest{
		{ID: reportReadMSP, ParentID: testRootTenantID},
		{ID: reportReadClient, ParentID: reportReadMSP},
	} {
		_, err := server.tenantManager.CreateTenant(ctx, tr)
		require.NoError(t, err)
	}
	f := &reportReadFixture{
		server:        server,
		rootSteward:   registerStewardUnderTenant(t, server, testRootTenantID, "root-report-host"),
		clientSteward: registerStewardUnderTenant(t, server, reportReadClient, "client-report-host"),
	}

	now := time.Now()
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: []fleet.StewardData{
		{ID: f.rootSteward, TenantID: testRootTenantID, Status: "active", LastHeartbeat: now,
			DNAAttributes: map[string]string{"hostname": "root-report-host", "os": "linux", "steward.version": "v1.0"}},
		{ID: f.clientSteward, TenantID: reportReadClient, Status: "active", LastHeartbeat: now,
			DNAAttributes: map[string]string{"hostname": "client-report-host", "os": "windows", "steward.version": "v2.0"}},
		{ID: "client-report-lost", TenantID: reportReadClient, Status: "lost", LastHeartbeat: now.Add(-time.Hour),
			DNAAttributes: map[string]string{"hostname": "client-report-lost-host", "os": "darwin", "steward.version": "v2.0"}},
	}})

	logger := logging.NewNoopLogger()
	egProvider, err := egsqlite.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = egProvider.Close() })
	storeOwnedHost(t, egProvider, f.rootSteward, testRootTenantID)
	storeOwnedHost(t, egProvider, f.clientSteward, reportReadClient)

	engine := reportsengine.New(reportsprovider.New(egProvider, logger), reportstemplates.New(logger),
		reportsexporters.New(logger), reportscache.NewMemoryCache(), logger)
	handler := reportapi.New(engine, reportsexporters.New(logger), server.controllerService, nil, logger)
	handler.SetTenantAncestry(func(ctx context.Context, ancestor, descendant string) (bool, error) {
		return server.tenantSubtreeContains(ctx, ancestor, descendant), nil
	})
	handler.SetTenantReadScope(server.reportsTenantReadScope)
	f.router = mux.NewRouter()
	handler.RegisterRoutes(f.router.PathPrefix("/api/v1/reports").Subrouter())
	return f
}

func storeOwnedHost(t *testing.T, eg *egsqlite.SQLiteEntityGraphProvider, deviceID, tenantID string) {
	t.Helper()
	at := time.Now()
	eid, err := egtypes.NewEID("host", deviceID, "")
	require.NoError(t, err)
	require.NoError(t, eg.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: deviceID,
		Observations: []egtypes.Observation{{
			Source: deviceID, ObservedAt: at, RecordedAt: at, Subject: eid.String(),
			Kind: egtypes.ObservationKindState, Confidence: egtypes.ConfidenceHigh,
			Payload: map[string]interface{}{
				"entity_kind": "host", "owning_tenant": tenantID, "observed_at": at.Format(time.RFC3339Nano),
			},
		}},
	}))
}

func (f *reportReadFixture) do(operator *Principal, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, asRootOperator(req, operator, nil))
	return rec
}

func (f *reportReadFixture) generateBody(tenants, devices []string) string {
	b, _ := json.Marshal(map[string]any{
		"type": "compliance", "template": "compliance-summary", "format": "json",
		"tenant_ids": tenants, "device_ids": devices,
		"time_range": map[string]any{"start": time.Now().Add(-time.Hour), "end": time.Now().Add(time.Minute)},
	})
	return string(b)
}

func devicesAnalyzed(t *testing.T, rec *httptest.ResponseRecorder) float64 {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		Compliance map[string]any `json:"compliance"`
		Drift      map[string]any `json:"drift_summary"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	n, _ := body.Compliance["devices_analyzed"].(float64)
	return n
}

func TestRootReportReads_TenantSelection(t *testing.T) {
	f := newReportReadFixture(t)

	t.Run("compliance and drift with no tenant named cover root-tenant data only", func(t *testing.T) {
		op := boundRootOperator("report-none")
		assert.EqualValues(t, 1, devicesAnalyzed(t, f.do(op, http.MethodGet, "/api/v1/reports/compliance/status", "")))
		rec := f.do(op, http.MethodGet, "/api/v1/reports/drift/summary", "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), f.clientSteward)
	})

	for _, path := range []string{
		"/api/v1/reports/compliance/status?tenant_id=" + reportReadClient,
		"/api/v1/reports/drift/summary?tenant_id=" + reportReadClient,
		"/api/v1/reports/dashboard/overview?tenant_id=" + reportReadClient,
		"/api/v1/reports/dashboard/trends?tenant_id=" + reportReadClient,
		"/api/v1/reports/dashboard/alerts?tenant_id=" + reportReadClient,
	} {
		t.Run("naming a client tenant answers the challenge: "+path, func(t *testing.T) {
			assertCrossingChallenge(t, f.do(boundRootOperator("report-named"), http.MethodGet, path, ""), reportReadClient)
		})
	}

	t.Run("generate naming a client tenant answers the challenge", func(t *testing.T) {
		rec := f.do(boundRootOperator("report-gen"), http.MethodPost, "/api/v1/reports/generate",
			f.generateBody([]string{reportReadClient}, nil))
		assertCrossingChallenge(t, rec, reportReadClient)
	})

	t.Run("an active grant on the MSP returns the client data", func(t *testing.T) {
		op := boundRootOperator("report-granted")
		grantCrossing(t, f.server, op.ID, reportReadMSP)
		assert.EqualValues(t, 2, devicesAnalyzed(t, f.do(op, http.MethodGet, "/api/v1/reports/compliance/status", "")))
		assert.EqualValues(t, 1, devicesAnalyzed(t, f.do(op, http.MethodGet, "/api/v1/reports/compliance/status?tenant_id="+reportReadClient, "")))
	})
}

func TestRootReportReads_DeviceSelection(t *testing.T) {
	f := newReportReadFixture(t)
	generate := func(op *Principal, device string) *httptest.ResponseRecorder {
		return f.do(op, http.MethodPost, "/api/v1/reports/generate", f.generateBody(nil, []string{device}))
	}

	t.Run("a client device is refused with the challenge without a crossing", func(t *testing.T) {
		op := boundRootOperator("report-dev-none")
		assertCrossingChallenge(t, generate(op, f.clientSteward), reportReadClient)
		assertCrossingChallenge(t, f.do(op, http.MethodGet, "/api/v1/reports/compliance/status?device_id="+f.clientSteward, ""), reportReadClient)
		assertCrossingChallenge(t, f.do(op, http.MethodGet, "/api/v1/reports/dashboard/alerts?device_id="+f.clientSteward, ""), reportReadClient)
	})
	t.Run("a client device is generated with a crossing", func(t *testing.T) {
		op := boundRootOperator("report-dev-granted")
		grantCrossing(t, f.server, op.ID, reportReadClient)
		assert.Equal(t, http.StatusOK, generate(op, f.clientSteward).Code)
	})
	t.Run("a root-tenant device needs no crossing", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, generate(boundRootOperator("report-dev-root"), f.rootSteward).Code)
	})
	t.Run("an unknown device is not found", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, generate(boundRootOperator("report-dev-unknown"), "no-such-device").Code)
	})
}

func TestRootReportReads_DashboardAnonymizedAggregate(t *testing.T) {
	f := newReportReadFixture(t)
	op := boundRootOperator("report-dash")

	for _, path := range []string{"/api/v1/reports/dashboard/overview", "/api/v1/reports/dashboard/trends"} {
		t.Run(path, func(t *testing.T) {
			rec := f.do(op, http.MethodGet, path, "")
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var body struct {
				Fleet *FleetAnonymizedMetrics `json:"anonymized_fleet"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.NotNil(t, body.Fleet, "client-tenant counts stay visible")
			assert.Equal(t, 1, body.Fleet.Online)
			assert.Equal(t, 1, body.Fleet.Offline)
			assert.Equal(t, 1, body.Fleet.Platform.Windows)
			assert.Equal(t, 1, body.Fleet.Platform.Darwin)
			assert.Equal(t, 0, body.Fleet.Platform.Linux, "root-tenant stewards are readable rows, not part of the aggregate")
			assert.Equal(t, map[string]int{"v2.0": 2}, body.Fleet.Versions)
			for _, leaked := range []string{f.clientSteward, "client-report-lost", "client-report-host", "client-report-lost-host"} {
				assert.NotContains(t, rec.Body.String(), leaked)
			}
		})
	}

	t.Run("alerts return no client-tenant device alerts without a crossing", func(t *testing.T) {
		rec := f.do(op, http.MethodGet, "/api/v1/reports/dashboard/alerts", "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), f.clientSteward)
		assert.NotContains(t, rec.Body.String(), "anonymized_fleet")
	})
}

func TestRootReportReads_UnchangedCallers(t *testing.T) {
	f := newReportReadFixture(t)

	t.Run("an unrestricted certificate admin keeps all-tenant reach", func(t *testing.T) {
		admin := &Principal{ID: "cert-admin", GlobalScope: true, CertSerial: "01"}
		rec := f.do(admin, http.MethodGet, "/api/v1/reports/compliance/status?tenant_id="+reportReadClient, "")
		assert.EqualValues(t, 1, devicesAnalyzed(t, rec))
		rec = f.do(admin, http.MethodGet, "/api/v1/reports/dashboard/overview?tenant_id="+reportReadClient, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), "anonymized_fleet")
	})

	t.Run("a tenant-scoped MSP admin sees its subtree as before", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/compliance/status", nil)
		ctx := context.WithValue(req.Context(), principalContextKey, &Principal{ID: "msp-admin", TenantID: reportReadMSP})
		ctx = context.WithValue(ctx, ctxkeys.TenantID, reportReadMSP)
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(reportReadMSP))
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, req.WithContext(ctx))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), "anonymized_fleet")
	})
}

func TestRootReportReads_HealthAndMonitoringStayReachable(t *testing.T) {
	server := seedRootTenant(t, setupCrossingTestServer(t))
	for name, handler := range map[string]http.HandlerFunc{
		"/api/v1/health":            server.handleHealth,
		"/api/v1/monitoring/health": server.handleSystemHealth,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, asRootOperator(httptest.NewRequest(http.MethodGet, name, nil), boundRootOperator("report-health"), nil))
			assert.NotEqual(t, http.StatusUnauthorized, rec.Code, "platform signals need no crossing: %s", rec.Body.String())
			assert.NotContains(t, rec.Header().Get("WWW-Authenticate"), "tenant-crossing")
		})
	}
}
