// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	reportscache "github.com/cfgis/cfgms/features/reports/cache"
	reportsengine "github.com/cfgis/cfgms/features/reports/engine"
	"github.com/cfgis/cfgms/features/reports/exporters"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/features/reports/provider"
	"github.com/cfgis/cfgms/features/reports/templates"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// reportsStack is the reports stack the controller wires in production
// (features/controller/server/server.go: initializeReportsHandler), built from
// real CFGMS components only: a real SQLite-backed entity graph provider
// (ADR-022) on a per-test database, data provider, template processor,
// exporter, report cache and report engine, plus the real steward registry
// that is the device→tenant authority. alertStore is a real flatfile-backed
// AlertStore. Nothing is substituted.
type reportsStack struct {
	handler    *Handler
	registry   *service.ControllerService
	egProvider *egsqlite.SQLiteEntityGraphProvider
	alertStore business.AlertStore
}

func newReportsStack(t *testing.T) *reportsStack {
	t.Helper()
	logger := logging.NewNoopLogger()

	egProvider := newTestEGProvider(t)
	registry := service.NewControllerService(logger)
	alertStore := newTestAlertStore(t)

	return &reportsStack{
		handler:    New(newEngine(t, egProvider, logger), exporters.New(logger), registry, alertStore, logger),
		registry:   registry,
		egProvider: egProvider,
		alertStore: alertStore,
	}
}

// newTestEGProvider creates a real SQLite-backed entity graph provider (ADR-022)
// on a t.TempDir()-isolated database — no mocks, real component.
func newTestEGProvider(t *testing.T) *egsqlite.SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := egsqlite.NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err, "real entity graph provider must initialize")
	t.Cleanup(func() {
		if closeErr := p.Close(); closeErr != nil {
			t.Logf("closing entity graph provider: %v", closeErr)
		}
	})
	return p
}

// newEngine assembles the real report engine over the given entity graph provider.
func newEngine(t *testing.T, egProvider eginterfaces.EntityGraphProvider, logger logging.Logger) *reportsengine.Engine {
	t.Helper()
	return reportsengine.New(
		provider.New(egProvider, logger),
		templates.New(logger),
		exporters.New(logger),
		reportscache.NewMemoryCache(),
		logger,
	)
}

// storeHostEntity records a state observation for the bare host entity
// host:<deviceID> at the given time, giving the device an observation history
// GetDNAData/GetDeviceStats can read. The payload embeds "at" so repeated calls
// for the same device don't collide under ReportObservations' content-hash dedup.
func storeHostEntity(t *testing.T, egp eginterfaces.EntityGraphProvider, deviceID string, at time.Time) {
	t.Helper()
	eid, err := egtypes.NewEID("host", deviceID, "")
	require.NoError(t, err)
	err = egp.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: deviceID,
		Observations: []egtypes.Observation{
			{
				Source:     deviceID,
				ObservedAt: at,
				RecordedAt: at,
				Subject:    eid.String(),
				Kind:       egtypes.ObservationKindState,
				Confidence: egtypes.ConfidenceHigh,
				Payload: map[string]interface{}{
					"entity_kind": "host",
					"observed_at": at.Format(time.RFC3339Nano),
				},
			},
		},
	})
	require.NoError(t, err, "storing host entity observation must succeed")
}

// storeDriftDiff records a drift-diff observation (ADR-022) for deviceID's
// fragment entity host:<deviceID>/<fragmentID>, changing it from prevVal to
// currVal. This is the entity graph shape the migrated DataProvider reads via
// ListDrifted. fragmentID doubles as the drift field's attribute name, so a
// security-category name (e.g. "auth:enabled") classifies critical via
// drift.CategorizeAttributeSeverity, and a network-category name (e.g.
// "host:hostname") classifies warning — matching the pre-migration flat-store
// detector's keyword classification.
func storeDriftDiff(t *testing.T, egp eginterfaces.EntityGraphProvider, deviceID, fragmentID, prevVal, currVal string) {
	t.Helper()
	eid, err := egtypes.NewEID("host", deviceID, fragmentID)
	require.NoError(t, err)

	now := time.Now()
	err = egp.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: deviceID,
		Observations: []egtypes.Observation{
			{
				Source:     deviceID,
				ObservedAt: now,
				RecordedAt: now,
				Subject:    eid.String(),
				Kind:       egtypes.ObservationKindDriftDiff,
				Confidence: egtypes.ConfidenceHigh,
				Payload: map[string]interface{}{
					"config_revision": "rev-1",
					"fields": []interface{}{
						map[string]interface{}{
							"attribute": fragmentID,
							"desired":   prevVal,
							"actual":    currVal,
							"matching":  false,
						},
					},
				},
			},
		},
	})
	require.NoError(t, err, "failed to store drift-diff observation")
}

// addDeviceWithDrift registers a device and stores drift-diff observations for
// each attribute that differs between attrs1 and attrs2, so the entity graph's
// drift projection has at least one event to serve. attrs1 and attrs2 are
// fragment-ID → state maps; any key whose value differs between the two maps
// registers as a drift event.
func (s *reportsStack) addDeviceWithDrift(t *testing.T, deviceID, tenantID string, attrs1, attrs2 map[string]string) {
	t.Helper()
	require.NoError(t, s.registry.RegisterSteward(deviceID, tenantID, "127.0.0.1:8443", "online"))

	storeHostEntity(t, s.egProvider, deviceID, time.Now())
	for attr, prevVal := range attrs1 {
		storeDriftDiff(t, s.egProvider, deviceID, attr, prevVal, attrs2[attr])
	}
}

// addDevice registers a steward in the real registry under tenantID and stores a
// real host-entity observation for it, so the device is both authorizable and
// carries data.
func (s *reportsStack) addDevice(t *testing.T, deviceID, tenantID string) {
	t.Helper()
	require.NoError(t, s.registry.RegisterSteward(deviceID, tenantID, "127.0.0.1:8443", "online"))
	storeHostEntity(t, s.egProvider, deviceID, time.Now())
}

// addTenantOwnedDevice registers a steward and stores its host entity with an
// owning_tenant, which is the entity graph's only access-control axis (ADR-023).
// Only such a device is discoverable by a report that names no device_id: that
// path resolves hosts through EntityFilter.TenantFilter, which matches on the
// entity index's owning_tenant.
func (s *reportsStack) addTenantOwnedDevice(t *testing.T, deviceID, tenantID string) {
	t.Helper()
	require.NoError(t, s.registry.RegisterSteward(deviceID, tenantID, "127.0.0.1:8443", "online"))

	at := time.Now()
	eid, err := egtypes.NewEID("host", deviceID, "")
	require.NoError(t, err)
	require.NoError(t, s.egProvider.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: deviceID,
		Observations: []egtypes.Observation{
			{
				Source:     deviceID,
				ObservedAt: at,
				RecordedAt: at,
				Subject:    eid.String(),
				Kind:       egtypes.ObservationKindState,
				Confidence: egtypes.ConfidenceHigh,
				Payload: map[string]interface{}{
					"entity_kind":   "host",
					"owning_tenant": tenantID,
					"observed_at":   at.Format(time.RFC3339Nano),
				},
			},
		},
	}), "storing the tenant-owned host entity must succeed")
}

// request builds a request carrying the authenticated caller's tenant exactly as
// the API auth middleware supplies it. An empty callerTenant models a
// root/unscoped caller; a nil body builds a GET-style request.
func request(method, target, callerTenant string, body []byte) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	if callerTenant != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, callerTenant))
	}
	return req
}

// testTimeRange is a 1-day range, well inside the engine's 30-day limit, that
// covers DNA records stored during the test.
func testTimeRange() interfaces.TimeRange {
	return interfaces.TimeRange{Start: time.Now().Add(-24 * time.Hour), End: time.Now()}
}

// deviceScopedRoutes are the report endpoints that accept a device selector and
// therefore must authorize it against the caller's tenant.
var deviceScopedRoutes = []struct {
	name    string
	path    string
	handler func(*Handler) http.HandlerFunc
}{
	{"dashboard/overview", "/reports/dashboard/overview", func(h *Handler) http.HandlerFunc { return h.getDashboardOverview }},
	{"dashboard/trends", "/reports/dashboard/trends", func(h *Handler) http.HandlerFunc { return h.getDashboardTrends }},
	{"dashboard/alerts", "/reports/dashboard/alerts", func(h *Handler) http.HandlerFunc { return h.getDashboardAlerts }},
	{"compliance/status", "/reports/compliance/status", func(h *Handler) http.HandlerFunc { return h.getComplianceStatus }},
	{"drift/summary", "/reports/drift/summary", func(h *Handler) http.HandlerFunc { return h.getDriftSummary }},
}

// TestParseTenantIDs verifies the caller-tenant scoping logic directly: a
// tenant-scoped caller is forced to its own tenant regardless of query params.
func TestParseTenantIDs(t *testing.T) {
	h := newReportsStack(t).handler

	t.Run("scoped caller ignores tenant_id query param", func(t *testing.T) {
		ids := h.parseTenantIDs(request("GET", "/?tenant_id=tenant-b", "tenant-a", nil))
		assert.Equal(t, []string{"tenant-a"}, ids,
			"scoped caller must receive only their own tenant, not the query param")
	})

	t.Run("scoped caller with no param returns own tenant", func(t *testing.T) {
		ids := h.parseTenantIDs(request("GET", "/", "tenant-a", nil))
		assert.Equal(t, []string{"tenant-a"}, ids)
	})

	t.Run("root caller passes through single tenant_id query param", func(t *testing.T) {
		ids := h.parseTenantIDs(request("GET", "/?tenant_id=tenant-b", "", nil))
		assert.Equal(t, []string{"tenant-b"}, ids)
	})

	t.Run("root caller with no param returns nil", func(t *testing.T) {
		ids := h.parseTenantIDs(request("GET", "/", "", nil))
		assert.Nil(t, ids)
	})

	t.Run("root caller honors multiple tenant_id params", func(t *testing.T) {
		ids := h.parseTenantIDs(request("GET", "/?tenant_id=tenant-b&tenant_id=tenant-c", "", nil))
		assert.ElementsMatch(t, []string{"tenant-b", "tenant-c"}, ids)
	})
}

// TestGetTemplates exercises GET /reports/templates against the real engine.
func TestGetTemplates(t *testing.T) {
	h := newReportsStack(t).handler

	rec := httptest.NewRecorder()
	h.getTemplates(rec, request("GET", "/reports/templates", "tenant-a", nil))

	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Templates []interfaces.TemplateInfo `json:"templates"`
		Count     int                       `json:"count"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.Templates, "the real engine must advertise templates")
	require.Equal(t, len(body.Templates), body.Count)

	names := make([]string, 0, len(body.Templates))
	for _, tmpl := range body.Templates {
		names = append(names, tmpl.Name)
	}
	assert.Contains(t, names, "compliance-summary")
	assert.Contains(t, names, "executive-dashboard")
	assert.Contains(t, names, "drift-analysis")
}

// TestGetTemplate exercises GET /reports/templates/{template}.
func TestGetTemplate(t *testing.T) {
	h := newReportsStack(t).handler

	t.Run("known template returns its info", func(t *testing.T) {
		req := request("GET", "/reports/templates/compliance-summary", "tenant-a", nil)
		req = mux.SetURLVars(req, map[string]string{"template": "compliance-summary"})
		rec := httptest.NewRecorder()
		h.getTemplate(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var tmpl interfaces.TemplateInfo
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tmpl))
		assert.Equal(t, "compliance-summary", tmpl.Name)
		assert.Equal(t, interfaces.ReportTypeCompliance, tmpl.Type)
		assert.NotEmpty(t, tmpl.Formats)
	})

	t.Run("unknown template returns 404", func(t *testing.T) {
		req := request("GET", "/reports/templates/no-such-template", "tenant-a", nil)
		req = mux.SetURLVars(req, map[string]string{"template": "no-such-template"})
		rec := httptest.NewRecorder()
		h.getTemplate(rec, req)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("missing template name returns 400", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.getTemplate(rec, request("GET", "/reports/templates/", "tenant-a", nil))
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// TestGenerateReport exercises POST /reports/generate end to end: body decode,
// engine generation, export, and the format-specific response headers.
func TestGenerateReport(t *testing.T) {
	stack := newReportsStack(t)
	stack.addDevice(t, "steward-a1", "tenant-a")

	t.Run("json request returns the exported report", func(t *testing.T) {
		body, err := json.Marshal(interfaces.ReportRequest{
			Type:      interfaces.ReportTypeCompliance,
			Template:  "compliance-summary",
			TimeRange: testTimeRange(),
			DeviceIDs: []string{"steward-a1"},
			Format:    interfaces.FormatJSON,
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		stack.handler.generateReport(rec, request("POST", "/reports/generate", "tenant-a", body))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))

		var report interfaces.Report
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &report))
		assert.Equal(t, interfaces.ReportTypeCompliance, report.Type)
		assert.NotEmpty(t, report.ID)
		assert.NotEmpty(t, report.Sections, "compliance-summary must produce sections")
		assert.Equal(t, 1, report.Summary.DevicesAnalyzed,
			"the DNA record stored for the requested device must reach the report")
	})

	t.Run("csv request returns a csv attachment", func(t *testing.T) {
		body, err := json.Marshal(interfaces.ReportRequest{
			Type:      interfaces.ReportTypeDrift,
			Template:  "drift-analysis",
			TimeRange: testTimeRange(),
			DeviceIDs: []string{"steward-a1"},
			Format:    interfaces.FormatCSV,
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		stack.handler.generateReport(rec, request("POST", "/reports/generate", "tenant-a", body))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/csv", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Header().Get("Content-Disposition"), `attachment; filename="report_`)
		assert.NotEmpty(t, rec.Body.Bytes(), "the CSV export must have content")
	})

	t.Run("omitted format defaults to json", func(t *testing.T) {
		body, err := json.Marshal(interfaces.ReportRequest{
			Type:      interfaces.ReportTypeCompliance,
			Template:  "compliance-summary",
			TimeRange: testTimeRange(),
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		stack.handler.generateReport(rec, request("POST", "/reports/generate", "tenant-a", body))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	})

	t.Run("malformed body returns 400", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.generateReport(rec,
			request("POST", "/reports/generate", "tenant-a", []byte("not json")))
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("request rejected by the engine returns 500", func(t *testing.T) {
		body, err := json.Marshal(interfaces.ReportRequest{
			Type:      interfaces.ReportTypeCompliance,
			Template:  "", // engine.ValidateRequest requires a template
			TimeRange: testTimeRange(),
			Format:    interfaces.FormatJSON,
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		stack.handler.generateReport(rec, request("POST", "/reports/generate", "tenant-a", body))
		require.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

// TestGenerateReport_TenantScope proves POST /reports/generate cannot be used to
// escape the tenant boundary enforced on the GET endpoints: body-supplied
// TenantIDs are overridden and body-supplied DeviceIDs are authorized.
func TestGenerateReport_TenantScope(t *testing.T) {
	generateBody := func(t *testing.T, tenantIDs, deviceIDs []string) []byte {
		t.Helper()
		body, err := json.Marshal(interfaces.ReportRequest{
			Type:      interfaces.ReportTypeCompliance,
			Template:  "compliance-summary",
			TimeRange: testTimeRange(),
			DeviceIDs: deviceIDs,
			TenantIDs: tenantIDs,
			Format:    interfaces.FormatJSON,
		})
		require.NoError(t, err)
		return body
	}

	t.Run("scoped caller cannot request another tenant's device", func(t *testing.T) {
		stack := newReportsStack(t)
		stack.addDevice(t, "steward-a1", "tenant-a")
		stack.addDevice(t, "steward-b1", "tenant-b")

		rec := httptest.NewRecorder()
		stack.handler.generateReport(rec, request("POST", "/reports/generate", "tenant-a",
			generateBody(t, []string{"tenant-b"}, []string{"steward-b1"})))

		require.Equal(t, http.StatusNotFound, rec.Code,
			"tenant-a must not be able to export tenant-b device data")
		assert.NotContains(t, rec.Body.String(), "steward-b1",
			"the error must not echo the requested device ID")
	})

	t.Run("scoped caller may request its own device", func(t *testing.T) {
		stack := newReportsStack(t)
		stack.addDevice(t, "steward-a1", "tenant-a")
		stack.addDevice(t, "steward-b1", "tenant-b")

		rec := httptest.NewRecorder()
		stack.handler.generateReport(rec, request("POST", "/reports/generate", "tenant-a",
			generateBody(t, []string{"tenant-b"}, []string{"steward-a1"})))

		require.Equal(t, http.StatusOK, rec.Code)
		var report interfaces.Report
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &report))
		assert.Equal(t, 1, report.Summary.DevicesAnalyzed)
	})

	t.Run("scoped caller may request a descendant tenant's device", func(t *testing.T) {
		stack := newReportsStack(t)
		stack.addDevice(t, "steward-child", "tenant-a/client-1")

		rec := httptest.NewRecorder()
		stack.handler.generateReport(rec, request("POST", "/reports/generate", "tenant-a",
			generateBody(t, nil, []string{"steward-child"})))

		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped caller cannot request an unknown device", func(t *testing.T) {
		stack := newReportsStack(t)
		stack.addDevice(t, "steward-a1", "tenant-a")

		rec := httptest.NewRecorder()
		stack.handler.generateReport(rec, request("POST", "/reports/generate", "tenant-a",
			generateBody(t, nil, []string{"steward-unknown"})))

		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("root caller may request any device", func(t *testing.T) {
		stack := newReportsStack(t)
		stack.addDevice(t, "steward-b1", "tenant-b")

		rec := httptest.NewRecorder()
		stack.handler.generateReport(rec, request("POST", "/reports/generate", "",
			generateBody(t, []string{"tenant-b"}, []string{"steward-b1"})))

		require.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestDeviceScope_CrossTenantRejected proves device_id/device_ids cannot be used
// as a cross-tenant selector on any device-accepting report endpoint. The device
// ID — not TenantIDs — is what the data path actually selects on, so this is the
// load-bearing tenant check.
func TestDeviceScope_CrossTenantRejected(t *testing.T) {
	for _, route := range deviceScopedRoutes {
		t.Run(route.name, func(t *testing.T) {
			stack := newReportsStack(t)
			stack.addDevice(t, "steward-a1", "tenant-a")
			stack.addDevice(t, "steward-b1", "tenant-b")
			handler := route.handler(stack.handler)

			t.Run("device_id from another tenant returns 404", func(t *testing.T) {
				rec := httptest.NewRecorder()
				handler(rec, request("GET", route.path+"?device_id=steward-b1", "tenant-a", nil))
				require.Equal(t, http.StatusNotFound, rec.Code,
					"tenant-a must not read tenant-b device data")
				assert.NotContains(t, rec.Body.String(), "steward-b1")
			})

			t.Run("device_ids list containing another tenant returns 404", func(t *testing.T) {
				rec := httptest.NewRecorder()
				handler(rec, request("GET",
					route.path+`?device_ids=["steward-a1","steward-b1"]`, "tenant-a", nil))
				require.Equal(t, http.StatusNotFound, rec.Code,
					"a mixed device list must be rejected, not partially served")
			})

			t.Run("unknown device_id returns 404", func(t *testing.T) {
				rec := httptest.NewRecorder()
				handler(rec, request("GET", route.path+"?device_id=steward-nope", "tenant-a", nil))
				require.Equal(t, http.StatusNotFound, rec.Code)
			})

			t.Run("own device_id succeeds", func(t *testing.T) {
				rec := httptest.NewRecorder()
				handler(rec, request("GET", route.path+"?device_id=steward-a1", "tenant-a", nil))
				require.Equal(t, http.StatusOK, rec.Code)
			})

			t.Run("root caller may select any device", func(t *testing.T) {
				rec := httptest.NewRecorder()
				handler(rec, request("GET", route.path+"?device_id=steward-b1", "", nil))
				require.Equal(t, http.StatusOK, rec.Code)
			})
		})
	}
}

// TestDeviceScope_FailsClosedWithoutResolver verifies that a deployment without a
// device→tenant authority refuses device-scoped requests from scoped callers
// rather than serving them unauthorized.
func TestDeviceScope_FailsClosedWithoutResolver(t *testing.T) {
	logger := logging.NewNoopLogger()
	egProvider := newTestEGProvider(t)
	unresolvable := New(newEngine(t, egProvider, logger), exporters.New(logger), nil, nil, logger)

	t.Run("scoped caller with a device selector is refused", func(t *testing.T) {
		rec := httptest.NewRecorder()
		unresolvable.getDashboardOverview(rec,
			request("GET", "/reports/dashboard/overview?device_id=steward-a1", "tenant-a", nil))
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})

	t.Run("scoped caller without a device selector still works", func(t *testing.T) {
		rec := httptest.NewRecorder()
		unresolvable.getDashboardOverview(rec,
			request("GET", "/reports/dashboard/overview", "tenant-a", nil))
		require.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestDashboardOverview verifies the overview handler's response shape and that
// tenant scoping propagates through the full handler path.
func TestDashboardOverview(t *testing.T) {
	stack := newReportsStack(t)
	stack.addDevice(t, "steward-a1", "tenant-a")

	t.Run("scoped caller ignores tenant_id query param", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDashboardOverview(rec,
			request("GET", "/reports/dashboard/overview?tenant_id=tenant-b", "tenant-a", nil))

		require.Equal(t, http.StatusOK, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Contains(t, body, "summary")
		assert.Contains(t, body, "metadata")
		assert.Contains(t, body, "time_range")
		assert.Contains(t, body, "kpis")
	})

	t.Run("invalid time range returns 400", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDashboardOverview(rec,
			request("GET", "/reports/dashboard/overview?start=not-a-time", "tenant-a", nil))
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("root caller passes through tenant_id query param", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDashboardOverview(rec,
			request("GET", "/reports/dashboard/overview?tenant_id=tenant-b", "", nil))
		require.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestDashboardOverview_NoDeviceSelector_DiscoversOnlyCallerTenantHosts covers the
// fleet-wide path end to end through the real stack: with no device_id, the engine
// has no device selector, so hosts are discovered through the entity graph under
// the caller's tenant subtree. The KPI device count must therefore cover exactly
// the caller tenant's hosts — another tenant's host must never be counted, and its
// existence must not be inferable from the response.
func TestDashboardOverview_NoDeviceSelector_DiscoversOnlyCallerTenantHosts(t *testing.T) {
	stack := newReportsStack(t)
	stack.addTenantOwnedDevice(t, "owned-a1", "tenant-a")
	stack.addTenantOwnedDevice(t, "owned-a2", "tenant-a")
	stack.addTenantOwnedDevice(t, "owned-b1", "tenant-b")

	kpiDeviceCount := func(t *testing.T, rec *httptest.ResponseRecorder) float64 {
		t.Helper()
		var body struct {
			KPIs map[string]any `json:"kpis"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		count, ok := body.KPIs["total_devices"].(float64)
		require.True(t, ok, "kpis.total_devices must be present: %v", body.KPIs)
		return count
	}

	t.Run("scoped caller sees only its own tenant's hosts", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDashboardOverview(rec,
			request("GET", "/reports/dashboard/overview", "tenant-a", nil))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, float64(2), kpiDeviceCount(t, rec),
			"discovery must cover tenant-a's two hosts and never tenant-b's")
		assert.NotContains(t, rec.Body.String(), "owned-b1",
			"another tenant's device must not appear anywhere in the response")
	})

	t.Run("root caller scoped by tenant_id sees only that tenant's hosts", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDashboardOverview(rec,
			request("GET", "/reports/dashboard/overview?tenant_id=tenant-b", "", nil))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, float64(1), kpiDeviceCount(t, rec),
			"an unscoped caller naming tenant-b sees tenant-b's single host")
	})

	t.Run("caller naming neither tenant nor device is refused", func(t *testing.T) {
		// An unscoped caller with no tenant_id and no device_id names no
		// authorization cut at all. The provider refuses rather than discovering
		// every host in every tenant, and the engine surfaces that as a failed
		// report rather than an empty one.
		rec := httptest.NewRecorder()
		stack.handler.getDashboardOverview(rec,
			request("GET", "/reports/dashboard/overview", "", nil))

		require.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.NotContains(t, rec.Body.String(), "owned-a1",
			"a refused report must disclose no device data")
		assert.NotContains(t, rec.Body.String(), "owned-b1",
			"a refused report must disclose no device data")
	})
}

// TestDashboardTrends verifies the trends handler's response shape.
func TestDashboardTrends(t *testing.T) {
	stack := newReportsStack(t)
	stack.addDevice(t, "steward-a1", "tenant-a")

	rec := httptest.NewRecorder()
	stack.handler.getDashboardTrends(rec,
		request("GET", "/reports/dashboard/trends?tenant_id=tenant-b", "tenant-a", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Contains(t, body, "charts")
	assert.Contains(t, body, "time_range")
	assert.Contains(t, body, "generated_at")
}

// TestDashboardAlerts verifies the alerts handler's response shape.
func TestDashboardAlerts(t *testing.T) {
	stack := newReportsStack(t)
	stack.addDevice(t, "steward-a1", "tenant-a")

	rec := httptest.NewRecorder()
	stack.handler.getDashboardAlerts(rec,
		request("GET", "/reports/dashboard/alerts?tenant_id=tenant-b", "tenant-a", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Alerts      []map[string]any `json:"alerts"`
		TotalAlerts int              `json:"total_alerts"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, len(body.Alerts), body.TotalAlerts)
}

// TestDashboardAlerts_IDField verifies that each alert in the dashboard/alerts
// response carries an "id" matching deriveAlertID(deviceID, description) — the
// convention the frontend's Acknowledge/Silence buttons rely on to target their
// POST calls without re-deriving the hash client-side.
//
// [REQUIRED TEST] AC: alert "id" field is present and equals
// deriveAlertID(device_id, description) for the fixture data.
func TestDashboardAlerts_IDField(t *testing.T) {
	stack := newReportsStack(t)

	stack.addDeviceWithDrift(t, "id-device", "tenant-id",
		map[string]string{"host:hostname": "before"},
		map[string]string{"host:hostname": "after"},
	)

	rec := httptest.NewRecorder()
	stack.handler.getDashboardAlerts(rec,
		request("GET", "/reports/dashboard/alerts?device_id=id-device", "tenant-id", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Alerts []map[string]interface{} `json:"alerts"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.Alerts, "must have at least one alert to verify the id field")

	for _, alert := range body.Alerts {
		deviceID, _ := alert["device_id"].(string)
		description, _ := alert["description"].(string)
		id, _ := alert["id"].(string)

		require.NotEmpty(t, id, "alert must carry a non-empty id field")
		assert.Equal(t, deriveAlertID(deviceID, description), id,
			"alert id must match deriveAlertID(device_id, description)")
	}
}

// TestComplianceStatus verifies the compliance status handler's response shape.
func TestComplianceStatus(t *testing.T) {
	stack := newReportsStack(t)
	stack.addDevice(t, "steward-a1", "tenant-a")

	rec := httptest.NewRecorder()
	stack.handler.getComplianceStatus(rec,
		request("GET", "/reports/compliance/status?tenant_id=tenant-b", "tenant-a", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Compliance map[string]any `json:"compliance"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Contains(t, body.Compliance, "score")
	assert.Contains(t, body.Compliance, "devices_analyzed")
	assert.Contains(t, body.Compliance, "critical_issues")
}

// TestDriftSummary verifies the drift summary handler's response shape.
func TestDriftSummary(t *testing.T) {
	stack := newReportsStack(t)
	stack.addDevice(t, "steward-a1", "tenant-a")

	t.Run("returns the drift summary", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDriftSummary(rec, request("GET", "/reports/drift/summary", "tenant-a", nil))

		require.Equal(t, http.StatusOK, rec.Code)
		var body struct {
			DriftSummary map[string]any `json:"drift_summary"`
			TimeRange    map[string]any `json:"time_range"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Contains(t, body.DriftSummary, "total_events")
		assert.NotEmpty(t, body.TimeRange)
	})

	t.Run("invalid time range returns 400", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDriftSummary(rec,
			request("GET", "/reports/drift/summary?end=nonsense", "tenant-a", nil))
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// TestRegisterRoutes verifies every registered report route is served through
// the router the controller mounts.
func TestRegisterRoutes(t *testing.T) {
	stack := newReportsStack(t)
	stack.addDevice(t, "steward-a1", "tenant-a")

	router := mux.NewRouter()
	stack.handler.RegisterRoutes(router.PathPrefix("/api/v1/reports").Subrouter())

	paths := []string{
		"/api/v1/reports/templates",
		"/api/v1/reports/templates/compliance-summary",
		"/api/v1/reports/dashboard/overview",
		"/api/v1/reports/dashboard/trends",
		"/api/v1/reports/dashboard/alerts",
		"/api/v1/reports/compliance/status",
		"/api/v1/reports/drift/summary",
	}

	for _, path := range paths {
		t.Run("GET "+path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, request("GET", path, "tenant-a", nil))
			require.Equal(t, http.StatusOK, rec.Code)
		})
	}

	t.Run("POST /api/v1/reports/generate", func(t *testing.T) {
		body, err := json.Marshal(interfaces.ReportRequest{
			Type:      interfaces.ReportTypeCompliance,
			Template:  "compliance-summary",
			TimeRange: testTimeRange(),
			Format:    interfaces.FormatJSON,
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, request("POST", "/api/v1/reports/generate", "tenant-a", body))
		require.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestDashboardAlerts_SeverityFilter verifies that getDashboardAlerts uses the
// severity query parameter to filter alerts, and that the default (no param) is
// warning+critical — NOT critical-only.
//
// [REQUIRED TEST] AC: default request (no severity param) includes a
// warning-severity fixture alert, not just critical.
func TestDashboardAlerts_SeverityFilter(t *testing.T) {
	stack := newReportsStack(t)

	// Device A: network-attribute change → SeverityWarning (hostname is a network keyword).
	stack.addDeviceWithDrift(t, "warn-device", "tenant-filter",
		map[string]string{"host:hostname": "before"},
		map[string]string{"host:hostname": "after"},
	)

	// Device B: security-attribute change → SeverityCritical (auth is a security keyword).
	stack.addDeviceWithDrift(t, "crit-device", "tenant-filter",
		map[string]string{"auth:enabled": "true"},
		map[string]string{"auth:enabled": "false"},
	)

	// Both devices must be registered in the resolver so the tenant-scoped caller
	// can select them via the device_id query parameter.
	makeReq := func(path string) *http.Request {
		// Explicit device IDs: this fixture's drift is stored without an
		// owning_tenant, so it is reachable through the device selector — the
		// authorization cut the API boundary verifies — rather than through
		// tenant-subtree discovery, which resolves hosts by owning_tenant.
		return request("GET", path+"&device_id=warn-device&device_id=crit-device", "tenant-filter", nil)
	}

	alertSeverities := func(t *testing.T, rec *httptest.ResponseRecorder) []string {
		t.Helper()
		var body struct {
			Alerts []map[string]interface{} `json:"alerts"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		var severities []string
		for _, a := range body.Alerts {
			if s, ok := a["severity"].(string); ok {
				severities = append(severities, s)
			}
		}
		return severities
	}

	t.Run("default (no param) returns warning and critical", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDashboardAlerts(rec, makeReq("/reports/dashboard/alerts?"))
		require.Equal(t, http.StatusOK, rec.Code)

		severities := alertSeverities(t, rec)
		assert.Contains(t, severities, "warning",
			"default severity must include warning — not critical-only")
		assert.Contains(t, severities, "critical",
			"default severity must include critical")
	})

	t.Run("severity=critical returns only critical alerts", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDashboardAlerts(rec, makeReq("/reports/dashboard/alerts?severity=critical"))
		require.Equal(t, http.StatusOK, rec.Code)

		severities := alertSeverities(t, rec)
		assert.Contains(t, severities, "critical")
		assert.NotContains(t, severities, "warning")
	})

	t.Run("severity=warning returns only warning alerts", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDashboardAlerts(rec, makeReq("/reports/dashboard/alerts?severity=warning"))
		require.Equal(t, http.StatusOK, rec.Code)

		severities := alertSeverities(t, rec)
		assert.Contains(t, severities, "warning")
		assert.NotContains(t, severities, "critical")
	})

	t.Run("severity=warning,critical returns both", func(t *testing.T) {
		rec := httptest.NewRecorder()
		stack.handler.getDashboardAlerts(rec, makeReq("/reports/dashboard/alerts?severity=warning,critical"))
		require.Equal(t, http.StatusOK, rec.Code)

		severities := alertSeverities(t, rec)
		assert.Contains(t, severities, "warning")
		assert.Contains(t, severities, "critical")
	})
}

// TestDashboardAlerts_AckSilence verifies that the dashboard-alerts handler
// annotates each alert with its AlertStore state and excludes actively silenced
// alerts.
//
// [REQUIRED TEST] AC: a silenced alert is absent from the response until
// SilencedUntil passes; an acknowledged-but-not-silenced alert remains present
// with acknowledged: true.
func TestDashboardAlerts_AckSilence(t *testing.T) {
	stack := newReportsStack(t)

	// Use a warning drift event (hostname change) so severity=warning filter works.
	stack.addDeviceWithDrift(t, "ack-device", "tenant-acks",
		map[string]string{"host:hostname": "old"},
		map[string]string{"host:hostname": "new"},
	)

	// Include the device ID explicitly: device discovery via tenant scanning is not
	// yet supported (GetDNAData with no DeviceIDs returns nothing by design).
	makeReq := func(params string) *http.Request {
		return request("GET", "/reports/dashboard/alerts?device_id=ack-device&"+params, "tenant-acks", nil)
	}

	// Fetch alerts once to get the stable alertID for our fixture device.
	rec := httptest.NewRecorder()
	stack.handler.getDashboardAlerts(rec, makeReq("severity=warning"))
	require.Equal(t, http.StatusOK, rec.Code)

	var initial struct {
		Alerts []map[string]interface{} `json:"alerts"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &initial))
	require.NotEmpty(t, initial.Alerts, "must have at least one warning alert to test ack/silence")

	// Pick the first alert and derive its stable alertID.
	firstAlert := initial.Alerts[0]
	deviceID, _ := firstAlert["device_id"].(string)
	description, _ := firstAlert["description"].(string)
	alertID := deriveAlertID(deviceID, description)

	ctx := context.Background()
	tenantID := "tenant-acks"

	t.Run("acknowledged alert remains present with acknowledged=true", func(t *testing.T) {
		require.NoError(t, stack.alertStore.AcknowledgeAlert(ctx, tenantID, alertID, "test-principal", time.Now()))

		rec := httptest.NewRecorder()
		stack.handler.getDashboardAlerts(rec, makeReq("severity=warning"))
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Alerts []map[string]interface{} `json:"alerts"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.NotEmpty(t, body.Alerts, "acknowledged alert must remain in the response")

		var found bool
		for _, a := range body.Alerts {
			if a["device_id"] == deviceID {
				found = true
				assert.Equal(t, true, a["acknowledged"],
					"acknowledged alert must carry acknowledged=true")
				assert.Equal(t, false, a["silenced"],
					"non-silenced alert must carry silenced=false")
			}
		}
		assert.True(t, found, "the acknowledged device's alert must appear in the response")
	})

	t.Run("actively silenced alert is excluded from the response", func(t *testing.T) {
		// Silence until future time → should be excluded.
		silenceUntil := time.Now().Add(24 * time.Hour)
		require.NoError(t, stack.alertStore.SilenceAlert(ctx, tenantID, alertID, "test-principal", silenceUntil))

		rec := httptest.NewRecorder()
		stack.handler.getDashboardAlerts(rec, makeReq("severity=warning"))
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Alerts []map[string]interface{} `json:"alerts"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

		for _, a := range body.Alerts {
			assert.NotEqual(t, deviceID, a["device_id"],
				"actively silenced alert must be excluded from the response")
		}
	})

	t.Run("alert with expired silence window is included", func(t *testing.T) {
		// Use a different device so we're not affected by the previous sub-test's silence.
		stack.addDeviceWithDrift(t, "expired-device", "tenant-acks",
			map[string]string{"host:hostname": "exp-old"},
			map[string]string{"host:hostname": "exp-new"},
		)

		// Request both devices; expired-device is now registered in the resolver.
		makeExpiredReq := func(params string) *http.Request {
			return request("GET",
				"/reports/dashboard/alerts?device_id=ack-device&device_id=expired-device&"+params,
				"tenant-acks", nil)
		}

		// Fetch to get the alertID for expired-device.
		rec := httptest.NewRecorder()
		stack.handler.getDashboardAlerts(rec, makeExpiredReq("severity=warning"))
		require.Equal(t, http.StatusOK, rec.Code)

		var body1 struct {
			Alerts []map[string]interface{} `json:"alerts"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body1))

		var expiredDeviceAlertID string
		for _, a := range body1.Alerts {
			if a["device_id"] == "expired-device" {
				d, _ := a["description"].(string)
				expiredDeviceAlertID = deriveAlertID("expired-device", d)
				break
			}
		}
		require.NotEmpty(t, expiredDeviceAlertID, "expired-device must appear in the alert list")

		// Set a silence window that has already expired.
		pastTime := time.Now().Add(-1 * time.Hour)
		require.NoError(t, stack.alertStore.SilenceAlert(ctx, tenantID, expiredDeviceAlertID, "test-principal", pastTime))

		// The expired-silence alert must be present.
		rec2 := httptest.NewRecorder()
		stack.handler.getDashboardAlerts(rec2, makeExpiredReq("severity=warning"))
		require.Equal(t, http.StatusOK, rec2.Code)

		var body2 struct {
			Alerts []map[string]interface{} `json:"alerts"`
		}
		require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &body2))

		var found bool
		for _, a := range body2.Alerts {
			if a["device_id"] == "expired-device" {
				found = true
			}
		}
		assert.True(t, found, "alert with an expired silence window must appear in the response")
	})
}

// TestDashboardAlerts_AlertStateUnavailable verifies the failure path of the
// AlertStore lookup in getDashboardAlerts: when GetAlertState returns an error
// the handler must fail closed with 503 rather than serve alerts whose
// acknowledgement and silence state is unknown (an actively silenced alert would
// otherwise reappear, and an operator would see it as un-acknowledged).
//
// The failure is injected at the filesystem, not by substituting the store: the
// real flat-file AlertStore is pointed at a corrupt alert_states.json, so the
// production parser produces the error.
func TestDashboardAlerts_AlertStateUnavailable(t *testing.T) {
	logger := logging.NewNoopLogger()
	egProvider := newTestEGProvider(t)
	registry := service.NewControllerService(logger)
	alertStore := newUnreadableTestAlertStore(t)

	stack := &reportsStack{
		handler:    New(newEngine(t, egProvider, logger), exporters.New(logger), registry, alertStore, logger),
		registry:   registry,
		egProvider: egProvider,
		alertStore: alertStore,
	}

	// Seed a real warning-severity drift event so the handler reaches the
	// AlertStore lookup; with no alert rows the branch is never entered.
	stack.addDeviceWithDrift(t, "unavailable-device", "tenant-unavailable",
		map[string]string{"host:hostname": "old"},
		map[string]string{"host:hostname": "new"},
	)

	// Confirm the injected fault is real at the store boundary, so a later change
	// that makes the store tolerate a corrupt file turns this test red instead of
	// silently leaving the handler branch uncovered.
	_, storeErr := alertStore.GetAlertState(context.Background(), "tenant-unavailable", "any-alert")
	require.Error(t, storeErr, "corrupt alert state file must make GetAlertState fail")

	rec := httptest.NewRecorder()
	stack.handler.getDashboardAlerts(rec,
		request("GET", "/reports/dashboard/alerts?device_id=unavailable-device", "tenant-unavailable", nil))

	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"a failing AlertStore lookup must fail the request closed with 503")

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "Alert state unavailable", body["error"])
	assert.NotContains(t, body, "details",
		"the store error must not be echoed to the client")
	assert.NotContains(t, rec.Body.String(), "alert_states.json",
		"internal storage paths must not leak in the error response")
	assert.NotContains(t, body, "alerts",
		"no alert list may be served when ack/silence state is unknown")
}

// TestDashboardAlerts_NilAlertStore verifies that getDashboardAlerts degrades
// gracefully when no AlertStore is wired: alerts are returned without ack/silence
// data and the handler does not return 503 for the whole response.
func TestDashboardAlerts_NilAlertStore(t *testing.T) {
	logger := logging.NewNoopLogger()
	egProvider := newTestEGProvider(t)
	registry := service.NewControllerService(logger)
	// Explicitly pass nil alertStore — degrade path.
	stack := &reportsStack{
		handler:    New(newEngine(t, egProvider, logger), exporters.New(logger), registry, nil, logger),
		registry:   registry,
		egProvider: egProvider,
	}

	// Seed a real warning-severity drift event (hostname is a network keyword) so
	// the degrade path actually has an alert to return; asserting over an empty
	// list would be vacuous.
	stack.addDeviceWithDrift(t, "nil-store-device", "tenant-a",
		map[string]string{"host:hostname": "old"},
		map[string]string{"host:hostname": "new"},
	)

	rec := httptest.NewRecorder()
	stack.handler.getDashboardAlerts(rec,
		request("GET", "/reports/dashboard/alerts?device_id=nil-store-device", "tenant-a", nil))
	require.Equal(t, http.StatusOK, rec.Code,
		"nil alertStore must not cause a 503 for the whole dashboard alerts response")

	var body struct {
		Alerts      []map[string]interface{} `json:"alerts"`
		TotalAlerts int                      `json:"total_alerts"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.Alerts,
		"drift for the seeded device must still be reported when no AlertStore is wired")
	assert.Equal(t, len(body.Alerts), body.TotalAlerts,
		"total_alerts must match the returned alert list")

	for _, a := range body.Alerts {
		assert.Equal(t, "nil-store-device", a["device_id"])
		assert.Equal(t, false, a["acknowledged"],
			"acknowledged must default to false when no AlertStore is wired")
		assert.Equal(t, false, a["silenced"],
			"silenced must default to false when no AlertStore is wired")
	}
}
