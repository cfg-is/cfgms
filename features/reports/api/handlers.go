// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// DeviceTenantResolver resolves the tenant that owns a device. A report device
// ID is a steward ID, so the controller's steward registry satisfies this
// interface; it is declared here, at the point of use, so the reports feature
// stays independent of the controller packages.
type DeviceTenantResolver interface {
	// TenantForDevice returns the tenant ID owning deviceID. known is false
	// when the device is not present in the registry.
	TenantForDevice(deviceID string) (tenantID string, known bool)
}

// Device-scope failures. The device ID is deliberately absent from both: the
// response must not confirm or deny the existence of another tenant's device.
var (
	// errDeviceOutsideTenant means a scoped caller asked for a device that is
	// unknown or owned by a tenant outside the caller's subtree.
	errDeviceOutsideTenant = errors.New("device is not within the caller's tenant")
	// errDeviceScopeUnverifiable means no DeviceTenantResolver is wired, so
	// device ownership cannot be checked. Requests fail closed.
	errDeviceScopeUnverifiable = errors.New("device tenant ownership cannot be verified")
)

// Handler implements HTTP handlers for the reports API
type Handler struct {
	engine        interfaces.ReportEngine
	exporter      interfaces.Exporter
	devices       DeviceTenantResolver
	alertStore    business.AlertStore
	logger        logging.Logger
	requirePermFn func(resourceType, action string) func(http.Handler) http.Handler
}

// New creates a new reports API handler. devices resolves device ownership for
// the tenant boundary enforced on every device-selecting endpoint; when it is
// nil, tenant-scoped callers cannot select devices at all (fail closed).
// alertStore supplies alert acknowledgement and silence state for the dashboard
// alerts feed; when nil, ack/silence annotation is skipped and alerts render
// without state data.
func New(engine interfaces.ReportEngine, exporter interfaces.Exporter, devices DeviceTenantResolver, alertStore business.AlertStore, logger logging.Logger) *Handler {
	return &Handler{
		engine:     engine,
		exporter:   exporter,
		devices:    devices,
		alertStore: alertStore,
		logger:     logger,
	}
}

// SetRequirePermFn wires the server's permission-check factory into Handler so
// RegisterRoutes can gate each route without importing the concrete Server type (Issue #3282).
func (h *Handler) SetRequirePermFn(fn func(resourceType, action string) func(http.Handler) http.Handler) {
	h.requirePermFn = fn
}

// deriveAlertID returns a stable opaque identifier for (deviceID, description)
// so the same logical alert maps to the same key in AlertStore across report
// generations. It is a full hex-encoded SHA-256, matching the derivation
// documented in docs/api/rest-api.md for the dashboard/alerts feed.
func deriveAlertID(deviceID, description string) string {
	h := sha256.Sum256([]byte(deviceID + "|" + description))
	return hex.EncodeToString(h[:])
}

// RegisterRoutes registers the reports API routes on the provided subrouter.
// The router should already be scoped to the reports path prefix.
// When SetRequirePermFn has been called, each route is wrapped with the appropriate
// permission gate: report:read for all GET endpoints, report:generate for POST /generate
// (Issue #3282). Without a wired permission function (unit-test scenarios) routes are ungated.
func (h *Handler) RegisterRoutes(router *mux.Router) {
	gate := h.requirePermFn
	wrap := func(action string, fn http.HandlerFunc) http.Handler {
		if gate == nil {
			return fn
		}
		return gate("report", action)(fn)
	}

	// POST /generate is write-shaped (produces and may persist a report) and requires
	// report:generate — a separate, stricter permission than report:read so that
	// read-only principals cannot trigger generation.
	router.Handle("/generate", wrap("generate", h.generateReport)).Methods("POST")
	router.Handle("/templates", wrap("read", h.getTemplates)).Methods("GET")
	router.Handle("/templates/{template}", wrap("read", h.getTemplate)).Methods("GET")
	router.Handle("/dashboard/overview", wrap("read", h.getDashboardOverview)).Methods("GET")
	router.Handle("/dashboard/trends", wrap("read", h.getDashboardTrends)).Methods("GET")
	router.Handle("/dashboard/alerts", wrap("read", h.getDashboardAlerts)).Methods("GET")
	router.Handle("/compliance/status", wrap("read", h.getComplianceStatus)).Methods("GET")
	router.Handle("/drift/summary", wrap("read", h.getDriftSummary)).Methods("GET")

	h.logger.Info("registered reports API routes")
}

// generateReport handles POST /api/v1/reports/generate
func (h *Handler) generateReport(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Report engine not available", nil)
		return
	}
	var req interfaces.ReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Set default format if not specified
	if req.Format == "" {
		req.Format = interfaces.FormatJSON
	}

	// Tenant scope: the request body is caller-controlled, so its TenantIDs are
	// advisory only — a scoped caller is pinned to its own tenant — and its
	// DeviceIDs are authorized against that tenant before reaching the engine.
	// Without this, generate would bypass the scoping enforced on the GET
	// endpoints, since the exported report carries per-device rows.
	if callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string); callerTenant != "" {
		req.TenantIDs = []string{callerTenant}
	}
	if _, err := h.enforceDeviceTenant(r.Context(), req.DeviceIDs); err != nil {
		h.writeDeviceScopeError(w, err)
		return
	}

	// Generate the report
	report, err := h.engine.GenerateReport(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to generate report", "error", logging.SanitizeLogValue(err.Error()), "format", logging.SanitizeLogValue(string(req.Format)))
		h.writeError(w, http.StatusInternalServerError, "Failed to generate report", err)
		return
	}

	// Export in requested format
	exportData, err := h.exporter.Export(r.Context(), report, req.Format)
	if err != nil {
		h.logger.Error("failed to export report", "error", logging.SanitizeLogValue(err.Error()), "format", logging.SanitizeLogValue(string(req.Format)))
		h.writeError(w, http.StatusInternalServerError, "Failed to export report", err)
		return
	}

	// Set appropriate content type and headers (nosniff prevents MIME-type sniffing XSS)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.setExportHeaders(w, req.Format, report.ID)
	if _, err := w.Write(exportData); err != nil {
		h.logger.Error("failed to write export data", "error", logging.SanitizeLogValue(err.Error()))
		// Can't return error to client at this point as headers are already sent
	}

	h.logger.Info("report generated successfully",
		"report_id", logging.SanitizeLogValue(report.ID),
		"type", logging.SanitizeLogValue(string(report.Type)),
		"format", logging.SanitizeLogValue(string(req.Format)),
		"generation_ms", report.Metadata.GenerationMS)
}

// getTemplates handles GET /api/v1/reports/templates
func (h *Handler) getTemplates(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Report engine not available", nil)
		return
	}
	templates := h.engine.GetAvailableTemplates()

	response := map[string]interface{}{
		"templates": templates,
		"count":     len(templates),
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getTemplate handles GET /api/v1/reports/templates/{template}
func (h *Handler) getTemplate(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Report engine not available", nil)
		return
	}
	vars := mux.Vars(r)
	templateName := vars["template"]

	if templateName == "" {
		h.writeError(w, http.StatusBadRequest, "Template name is required", nil)
		return
	}

	// Validate template exists
	if err := h.engine.ValidateTemplate(templateName); err != nil {
		h.writeError(w, http.StatusNotFound, "Template not found", err)
		return
	}

	// Get template info from available templates
	templates := h.engine.GetAvailableTemplates()
	for _, template := range templates {
		if template.Name == templateName {
			h.writeJSON(w, http.StatusOK, template)
			return
		}
	}

	h.writeError(w, http.StatusNotFound, "Template not found", nil)
}

// getDashboardOverview handles GET /api/v1/reports/dashboard/overview
func (h *Handler) getDashboardOverview(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Report engine not available", nil)
		return
	}
	// Parse query parameters
	timeRange, err := h.parseTimeRange(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid time range", err)
		return
	}

	deviceIDs, err := h.scopedDeviceIDs(r)
	if err != nil {
		h.writeDeviceScopeError(w, err)
		return
	}
	tenantIDs := h.parseTenantIDs(r)

	// Generate executive dashboard report
	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeExecutive,
		Template:  "executive-dashboard",
		TimeRange: timeRange,
		DeviceIDs: deviceIDs,
		TenantIDs: tenantIDs,
		Format:    interfaces.FormatJSON,
		Parameters: map[string]any{
			"include_charts": false, // Just data for API
		},
	}

	report, err := h.engine.GenerateReport(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to generate dashboard overview", "error", logging.SanitizeLogValue(err.Error()))
		h.writeError(w, http.StatusInternalServerError, "Failed to generate dashboard overview", err)
		return
	}

	// Return the report summary and key sections
	response := map[string]interface{}{
		"summary":      report.Summary,
		"metadata":     report.Metadata,
		"time_range":   report.TimeRange,
		"generated_at": report.GeneratedAt,
	}

	// Add KPI section if available
	for _, section := range report.Sections {
		if section.ID == "kpis" {
			response["kpis"] = section.Content
			break
		}
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getDashboardTrends handles GET /api/v1/reports/dashboard/trends
func (h *Handler) getDashboardTrends(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Report engine not available", nil)
		return
	}
	timeRange, err := h.parseTimeRange(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid time range", err)
		return
	}

	deviceIDs, err := h.scopedDeviceIDs(r)
	if err != nil {
		h.writeDeviceScopeError(w, err)
		return
	}
	tenantIDs := h.parseTenantIDs(r)

	// Generate executive dashboard with charts
	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeExecutive,
		Template:  "executive-dashboard",
		TimeRange: timeRange,
		DeviceIDs: deviceIDs,
		TenantIDs: tenantIDs,
		Format:    interfaces.FormatJSON,
		Parameters: map[string]any{
			"include_charts": true,
		},
	}

	report, err := h.engine.GenerateReport(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to generate trends data", "error", logging.SanitizeLogValue(err.Error()))
		h.writeError(w, http.StatusInternalServerError, "Failed to generate trends data", err)
		return
	}

	// Return charts and trend analysis
	response := map[string]interface{}{
		"charts":       report.Charts,
		"time_range":   report.TimeRange,
		"generated_at": report.GeneratedAt,
	}

	// Add trends section if available
	for _, section := range report.Sections {
		if section.ID == "trends" {
			response["trend_analysis"] = section.Content
			break
		}
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getDashboardAlerts handles GET /api/v1/reports/dashboard/alerts
//
// Query parameters:
//   - severity: comma-separated severity filter (critical, warning, info).
//     Defaults to "warning,critical" when absent.
//
// Each alert row is annotated with acknowledged/silenced booleans sourced from
// AlertStore. Alerts whose silence window has not yet expired are excluded.
// When AlertStore is nil, annotation is skipped and all matching alerts are
// returned without ack/silence data.
func (h *Handler) getDashboardAlerts(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Report engine not available", nil)
		return
	}
	timeRange, err := h.parseTimeRange(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid time range", err)
		return
	}
	// Drift events are computed on-demand and stamped with time.Now() at detection
	// time, which is always slightly after parseTimeRange's end. Add a 1-minute
	// buffer so the provider's [start,end] filter never excludes events produced
	// during this request.
	if r.URL.Query().Get("end") == "" {
		timeRange.End = timeRange.End.Add(time.Minute)
	}

	deviceIDs, err := h.scopedDeviceIDs(r)
	if err != nil {
		h.writeDeviceScopeError(w, err)
		return
	}
	tenantIDs := h.parseTenantIDs(r)

	// severity query param; default to warning+critical for the alert center.
	severity := r.URL.Query().Get("severity")
	if severity == "" {
		severity = "warning,critical"
	}

	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeDrift,
		Template:  "drift-analysis",
		TimeRange: timeRange,
		DeviceIDs: deviceIDs,
		TenantIDs: tenantIDs,
		Format:    interfaces.FormatJSON,
		Parameters: map[string]any{
			"severity_filter": severity,
		},
	}

	report, err := h.engine.GenerateReport(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to generate alerts data", "error", logging.SanitizeLogValue(err.Error()))
		h.writeError(w, http.StatusInternalServerError, "Failed to generate alerts data", err)
		return
	}

	// resolveAlertTenant returns the tenant ID to use for alert state lookup for
	// a given deviceID. For a single scoped tenant, tenantIDs[0] is authoritative.
	// For root/unscoped callers, we derive the tenant from the device resolver.
	resolveAlertTenant := func(deviceID string) string {
		if len(tenantIDs) == 1 {
			return tenantIDs[0]
		}
		if h.devices != nil {
			if t, known := h.devices.TenantForDevice(deviceID); known {
				return t
			}
		}
		return ""
	}

	now := time.Now()
	alerts := make([]map[string]interface{}, 0)

	for _, section := range report.Sections {
		if section.Type == interfaces.SectionTypeAlert || section.ID == "drift-events" {
			if tableData, ok := section.Content.(map[string]interface{}); ok {
				if rows, ok := tableData["rows"].([][]interface{}); ok {
					for _, row := range rows {
						if len(row) < 4 {
							continue
						}
						deviceID, _ := row[1].(string)
						description, _ := row[3].(string)

						alert := map[string]interface{}{
							"timestamp":    row[0],
							"device_id":    row[1],
							"severity":     row[2],
							"description":  row[3],
							"acknowledged": false,
							"silenced":     false,
						}

						if h.alertStore != nil {
							tenantID := resolveAlertTenant(deviceID)
							alertID := deriveAlertID(deviceID, description)
							state, stateErr := h.alertStore.GetAlertState(r.Context(), tenantID, alertID)
							if stateErr != nil {
								h.logger.Error("failed to get alert state",
									"error", logging.SanitizeLogValue(stateErr.Error()),
									"alert_id", logging.SanitizeLogValue(alertID))
								h.writeError(w, http.StatusServiceUnavailable, "Alert state unavailable", nil)
								return
							}
							if state != nil {
								activelySilenced := state.Silenced && state.SilencedUntil.After(now)
								if activelySilenced {
									continue // exclude actively silenced alerts
								}
								alert["acknowledged"] = state.Acknowledged
								alert["silenced"] = false // silence window expired
							}
						}

						alerts = append(alerts, alert)
					}
				}
			}
		}
	}

	response := map[string]interface{}{
		"alerts":       alerts,
		"total_alerts": len(alerts),
		"summary":      report.Summary,
		"time_range":   report.TimeRange,
		"generated_at": report.GeneratedAt,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getComplianceStatus handles GET /api/v1/reports/compliance/status
func (h *Handler) getComplianceStatus(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Report engine not available", nil)
		return
	}
	timeRange, err := h.parseTimeRange(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid time range", err)
		return
	}

	deviceIDs, err := h.scopedDeviceIDs(r)
	if err != nil {
		h.writeDeviceScopeError(w, err)
		return
	}
	tenantIDs := h.parseTenantIDs(r)

	// Generate compliance summary report
	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeCompliance,
		Template:  "compliance-summary",
		TimeRange: timeRange,
		DeviceIDs: deviceIDs,
		TenantIDs: tenantIDs,
		Format:    interfaces.FormatJSON,
		Parameters: map[string]any{
			"include_details": false,
		},
	}

	report, err := h.engine.GenerateReport(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to generate compliance status", "error", logging.SanitizeLogValue(err.Error()))
		h.writeError(w, http.StatusInternalServerError, "Failed to generate compliance status", err)
		return
	}

	// Extract compliance information
	compliance := map[string]interface{}{
		"score":            report.Summary.ComplianceScore,
		"trend":            report.Summary.TrendDirection,
		"critical_issues":  report.Summary.CriticalIssues,
		"devices_analyzed": report.Summary.DevicesAnalyzed,
	}

	// Add section data
	for _, section := range report.Sections {
		if section.ID == "compliance-overview" {
			if kpiData, ok := section.Content.(map[string]interface{}); ok {
				for key, value := range kpiData {
					compliance[key] = value
				}
			}
		}
	}

	response := map[string]interface{}{
		"compliance":   compliance,
		"time_range":   report.TimeRange,
		"generated_at": report.GeneratedAt,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getDriftSummary handles GET /api/v1/reports/drift/summary
func (h *Handler) getDriftSummary(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Report engine not available", nil)
		return
	}
	timeRange, err := h.parseTimeRange(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid time range", err)
		return
	}

	deviceIDs, err := h.scopedDeviceIDs(r)
	if err != nil {
		h.writeDeviceScopeError(w, err)
		return
	}
	tenantIDs := h.parseTenantIDs(r)

	// Generate drift analysis report
	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeDrift,
		Template:  "drift-analysis",
		TimeRange: timeRange,
		DeviceIDs: deviceIDs,
		TenantIDs: tenantIDs,
		Format:    interfaces.FormatJSON,
	}

	report, err := h.engine.GenerateReport(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to generate drift summary", "error", logging.SanitizeLogValue(err.Error()))
		h.writeError(w, http.StatusInternalServerError, "Failed to generate drift summary", err)
		return
	}

	// Extract drift summary information
	driftSummary := map[string]interface{}{
		"total_events": report.Summary.DriftEventsTotal,
	}

	// Add section data
	for _, section := range report.Sections {
		if section.ID == "drift-overview" {
			if kpiData, ok := section.Content.(map[string]interface{}); ok {
				for key, value := range kpiData {
					driftSummary[key] = value
				}
			}
		}
	}

	response := map[string]interface{}{
		"drift_summary": driftSummary,
		"charts":        report.Charts,
		"time_range":    report.TimeRange,
		"generated_at":  report.GeneratedAt,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// Helper methods

func (h *Handler) parseTimeRange(r *http.Request) (interfaces.TimeRange, error) {
	// Default to last 24 hours
	end := time.Now()
	start := end.Add(-24 * time.Hour)

	if startStr := r.URL.Query().Get("start"); startStr != "" {
		if parsedStart, err := time.Parse(time.RFC3339, startStr); err == nil {
			start = parsedStart
		} else {
			return interfaces.TimeRange{}, fmt.Errorf("invalid start time format: %s", html.EscapeString(startStr))
		}
	}

	if endStr := r.URL.Query().Get("end"); endStr != "" {
		if parsedEnd, err := time.Parse(time.RFC3339, endStr); err == nil {
			end = parsedEnd
		} else {
			return interfaces.TimeRange{}, fmt.Errorf("invalid end time format: %s", html.EscapeString(endStr))
		}
	}

	// Handle relative time ranges
	if hours := r.URL.Query().Get("hours"); hours != "" {
		if h, err := strconv.Atoi(hours); err == nil {
			end = time.Now()
			start = end.Add(-time.Duration(h) * time.Hour)
		}
	}

	if days := r.URL.Query().Get("days"); days != "" {
		if d, err := strconv.Atoi(days); err == nil {
			end = time.Now()
			start = end.Add(-time.Duration(d) * 24 * time.Hour)
		}
	}

	return interfaces.TimeRange{Start: start, End: end}, nil
}

func (h *Handler) parseDeviceIDs(r *http.Request) []string {
	deviceIDs := r.URL.Query()["device_id"]
	if deviceIDsStr := r.URL.Query().Get("device_ids"); deviceIDsStr != "" {
		// Support comma-separated device IDs
		var ids []string
		if err := json.Unmarshal([]byte(deviceIDsStr), &ids); err == nil {
			deviceIDs = append(deviceIDs, ids...)
		}
	}
	return deviceIDs
}

// scopedDeviceIDs parses the requested device IDs and enforces the caller's
// tenant boundary on them.
func (h *Handler) scopedDeviceIDs(r *http.Request) ([]string, error) {
	return h.enforceDeviceTenant(r.Context(), h.parseDeviceIDs(r))
}

// enforceDeviceTenant verifies that every requested device belongs to the
// calling tenant's subtree. TenantIDs alone is not a filter on the data path —
// DataProvider.GetDNAData and storage.GetHistory select purely on device ID —
// so device IDs are the actual cross-tenant selector and must be authorized
// here, at the boundary, before they reach the engine.
func (h *Handler) enforceDeviceTenant(ctx context.Context, deviceIDs []string) ([]string, error) {
	callerTenant, _ := ctx.Value(ctxkeys.TenantID).(string)
	if callerTenant == "" || len(deviceIDs) == 0 {
		// Root/unscoped caller, or no device selector to authorize.
		return deviceIDs, nil
	}

	if h.devices == nil {
		return nil, errDeviceScopeUnverifiable
	}

	for _, deviceID := range deviceIDs {
		owner, known := h.devices.TenantForDevice(deviceID)
		if !known || !tenantWithinSubtree(owner, callerTenant) {
			return nil, errDeviceOutsideTenant
		}
	}

	return deviceIDs, nil
}

// tenantWithinSubtree reports whether deviceTenant is callerTenant or one of
// its descendants in the path-based tenant hierarchy (root/msp-a/client-1).
func tenantWithinSubtree(deviceTenant, callerTenant string) bool {
	return deviceTenant == callerTenant || strings.HasPrefix(deviceTenant, callerTenant+"/")
}

// writeDeviceScopeError renders a device-scope failure. An unknown or
// out-of-tenant device returns 404 rather than 403 so the response does not
// disclose the existence of another tenant's device — matching the steward
// compliance endpoints.
func (h *Handler) writeDeviceScopeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errDeviceScopeUnverifiable) {
		h.logger.Error("refusing device-scoped report request: no device tenant resolver wired")
		h.writeError(w, http.StatusServiceUnavailable, "Device tenant verification unavailable", nil)
		return
	}

	h.writeError(w, http.StatusNotFound, "Device not found", nil)
}

func (h *Handler) parseTenantIDs(r *http.Request) []string {
	// A tenant-scoped caller may only see their own tenant's data. The caller's
	// tenant is authoritative; any query param is ignored to prevent cross-tenant
	// data access. Root/unscoped callers retain query-param-driven filtering.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
		return []string{callerTenant}
	}
	// Root/unscoped caller: honor query params.
	tenantIDs := r.URL.Query()["tenant_id"]
	if tenantIDsStr := r.URL.Query().Get("tenant_ids"); tenantIDsStr != "" {
		var ids []string
		if err := json.Unmarshal([]byte(tenantIDsStr), &ids); err == nil {
			tenantIDs = append(tenantIDs, ids...)
		}
	}
	return tenantIDs
}

func (h *Handler) setExportHeaders(w http.ResponseWriter, format interfaces.ExportFormat, reportID string) {
	switch format {
	case interfaces.FormatJSON:
		w.Header().Set("Content-Type", "application/json")
	case interfaces.FormatCSV:
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"report_%s.csv\"", reportID))
	case interfaces.FormatHTML:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"report_%s.html\"", reportID))
	case interfaces.FormatPDF:
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"report_%s.pdf\"", reportID))
	case interfaces.FormatExcel:
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"report_%s.xlsx\"", reportID))
	}
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

func (h *Handler) writeError(w http.ResponseWriter, status int, message string, err error) {
	response := map[string]interface{}{
		"error":     message,
		"status":    status,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err != nil {
		response["details"] = err.Error()
	}

	h.writeJSON(w, status, response)
}
