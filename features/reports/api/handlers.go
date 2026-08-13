// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
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
	engine   interfaces.ReportEngine
	exporter interfaces.Exporter
	devices  DeviceTenantResolver
	logger   logging.Logger
}

// New creates a new reports API handler. devices resolves device ownership for
// the tenant boundary enforced on every device-selecting endpoint; when it is
// nil, tenant-scoped callers cannot select devices at all (fail closed).
func New(engine interfaces.ReportEngine, exporter interfaces.Exporter, devices DeviceTenantResolver, logger logging.Logger) *Handler {
	return &Handler{
		engine:   engine,
		exporter: exporter,
		devices:  devices,
		logger:   logger,
	}
}

// RegisterRoutes registers the reports API routes on the provided subrouter.
// The router should already be scoped to the reports path prefix.
func (h *Handler) RegisterRoutes(router *mux.Router) {
	// Report generation and management
	router.HandleFunc("/generate", h.generateReport).Methods("POST")
	router.HandleFunc("/templates", h.getTemplates).Methods("GET")
	router.HandleFunc("/templates/{template}", h.getTemplate).Methods("GET")

	// Dashboard endpoints
	router.HandleFunc("/dashboard/overview", h.getDashboardOverview).Methods("GET")
	router.HandleFunc("/dashboard/trends", h.getDashboardTrends).Methods("GET")
	router.HandleFunc("/dashboard/alerts", h.getDashboardAlerts).Methods("GET")

	// Specific report types
	router.HandleFunc("/compliance/status", h.getComplianceStatus).Methods("GET")
	router.HandleFunc("/drift/summary", h.getDriftSummary).Methods("GET")

	h.logger.Info("registered reports API routes")
}

// generateReport handles POST /api/v1/reports/generate
func (h *Handler) generateReport(w http.ResponseWriter, r *http.Request) {
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
	templates := h.engine.GetAvailableTemplates()

	response := map[string]interface{}{
		"templates": templates,
		"count":     len(templates),
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getTemplate handles GET /api/v1/reports/templates/{template}
func (h *Handler) getTemplate(w http.ResponseWriter, r *http.Request) {
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
func (h *Handler) getDashboardAlerts(w http.ResponseWriter, r *http.Request) {
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

	// Generate drift analysis report filtered to critical/warning events
	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeDrift,
		Template:  "drift-analysis",
		TimeRange: timeRange,
		DeviceIDs: deviceIDs,
		TenantIDs: tenantIDs,
		Format:    interfaces.FormatJSON,
		Parameters: map[string]any{
			"severity_filter": "critical", // Focus on critical events for alerts
		},
	}

	report, err := h.engine.GenerateReport(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to generate alerts data", "error", logging.SanitizeLogValue(err.Error()))
		h.writeError(w, http.StatusInternalServerError, "Failed to generate alerts data", err)
		return
	}

	// Extract alert information
	alerts := make([]map[string]interface{}, 0)

	for _, section := range report.Sections {
		if section.Type == interfaces.SectionTypeAlert || section.ID == "drift-events" {
			if tableData, ok := section.Content.(map[string]interface{}); ok {
				if rows, ok := tableData["rows"].([][]interface{}); ok {
					for _, row := range rows {
						if len(row) >= 4 {
							alert := map[string]interface{}{
								"timestamp":   row[0],
								"device_id":   row[1],
								"severity":    row[2],
								"description": row[3],
							}
							alerts = append(alerts, alert)
						}
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
