// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	fleetstorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/controller/service"
	reportscache "github.com/cfgis/cfgms/features/reports/cache"
	reportsengine "github.com/cfgis/cfgms/features/reports/engine"
	"github.com/cfgis/cfgms/features/reports/exporters"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/features/reports/provider"
	"github.com/cfgis/cfgms/features/reports/templates"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	dnadrift "github.com/cfgis/cfgms/pkg/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
)

// reportsStack is the reports stack the controller wires in production
// (features/controller/server/server.go: initializeReportsHandler), built from
// real CFGMS components only: DNA fleet storage on a per-test SQLite database,
// the real drift detector, data provider, template processor, exporter, report
// cache and report engine, plus the real steward registry that is the
// device→tenant authority. Nothing is substituted.
type reportsStack struct {
	handler  *Handler
	registry *service.ControllerService
	storage  *fleetstorage.Manager
}

func newReportsStack(t *testing.T) *reportsStack {
	t.Helper()
	logger := logging.NewNoopLogger()

	store := newDNAStorage(t, logger)
	registry := service.NewControllerService(logger)

	return &reportsStack{
		handler:  New(newEngine(t, store, logger), exporters.New(logger), registry, logger),
		registry: registry,
		storage:  store,
	}
}

// newDNAStorage creates the real fleet DNA store on a temp SQLite database.
func newDNAStorage(t *testing.T, logger logging.Logger) *fleetstorage.Manager {
	t.Helper()
	cfg := fleetstorage.DefaultConfig()
	cfg.Backend = fleetstorage.BackendSQLite
	cfg.DataDir = t.TempDir()

	store, err := fleetstorage.NewManager(cfg, logger)
	require.NoError(t, err, "real DNA storage must initialize")
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Logf("closing DNA storage: %v", closeErr)
		}
	})
	return store
}

// newEngine assembles the real report engine over the given DNA store.
func newEngine(t *testing.T, store *fleetstorage.Manager, logger logging.Logger) *reportsengine.Engine {
	t.Helper()
	detector, err := dnadrift.NewDetector(nil, logger)
	require.NoError(t, err, "real drift detector must initialize")

	return reportsengine.New(
		provider.New(store, detector, logger),
		templates.New(logger),
		exporters.New(logger),
		reportscache.NewMemoryCache(),
		logger,
	)
}

// addDevice registers a steward in the real registry under tenantID and stores a
// real DNA record for it, so the device is both authorizable and carries data.
func (s *reportsStack) addDevice(t *testing.T, deviceID, tenantID string) {
	t.Helper()
	require.NoError(t, s.registry.RegisterSteward(deviceID, tenantID, "127.0.0.1:8443", "online"))

	dna := &commonpb.DNA{
		Id:              deviceID,
		Attributes:      map[string]string{"hostname": deviceID, "os": "linux"},
		LastUpdated:     timestamppb.New(time.Now()),
		ConfigHash:      "config-hash-" + deviceID,
		LastSyncTime:    timestamppb.New(time.Now()),
		AttributeCount:  2,
		SyncFingerprint: "fingerprint-" + deviceID,
	}
	require.NoError(t, s.storage.Store(context.Background(), deviceID, dna,
		&fleetstorage.StoreOptions{TenantID: tenantID, Status: "online"}))
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
	store := newDNAStorage(t, logger)
	unresolvable := New(newEngine(t, store, logger), exporters.New(logger), nil, logger)

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
