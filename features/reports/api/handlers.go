// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Handler implements HTTP handlers for the reports API
type Handler struct {
	engine   interfaces.ReportEngine
	exporter interfaces.Exporter
	logger   logging.Logger
}

// New creates a new reports API handler
func New(engine interfaces.ReportEngine, exporter interfaces.Exporter, logger logging.Logger) *Handler {
	return &Handler{
		engine:   engine,
		exporter: exporter,
		logger:   logger,
	}
}

// RegisterRoutes registers the reports API routes
func (h *Handler) RegisterRoutes(router *mux.Router) {
	reportsRouter := router.PathPrefix("/api/v1/reports").Subrouter()

	// Report generation and management
	reportsRouter.HandleFunc("/generate", h.generateReport).Methods("POST")
	reportsRouter.HandleFunc("/templates", h.getTemplates).Methods("GET")
	reportsRouter.HandleFunc("/templates/{template}", h.getTemplate).Methods("GET")

	// Dashboard endpoints
	reportsRouter.HandleFunc("/dashboard/overview", h.getDashboardOverview).Methods("GET")
	reportsRouter.HandleFunc("/dashboard/trends", h.getDashboardTrends).Methods("GET")
	reportsRouter.HandleFunc("/dashboard/alerts", h.getDashboardAlerts).Methods("GET")

	// Specific report types
	reportsRouter.HandleFunc("/compliance/status", h.getComplianceStatus).Methods("GET")
	reportsRouter.HandleFunc("/drift/summary", h.getDriftSummary).Methods("GET")

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

	// Generate the report
	report, err := h.engine.GenerateReport(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to generate report", "error", err, "request", req)
		h.writeError(w, http.StatusInternalServerError, "Failed to generate report", err)
		return
	}

	// Export in requested format
	exportData, err := h.exporter.Export(r.Context(), report, req.Format)
	if err != nil {
		h.logger.Error("failed to export report", "error", err, "format", req.Format)
		h.writeError(w, http.StatusInternalServerError, "Failed to export report", err)
		return
	}

	// Set appropriate content type and headers
	h.setExportHeaders(w, req.Format, report.ID)
	if _, err := w.Write(exportData); err != nil {
		h.logger.Error("failed to write export data", "error", err)
		// Can't return error to client at this point as headers are already sent
	}

	h.logger.Info("report generated successfully",
		"report_id", report.ID,
		"type", report.Type,
		"format", req.Format,
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

	deviceIDs := h.parseDeviceIDs(r)
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
		h.logger.Error("failed to generate dashboard overview", "error", err)
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

	deviceIDs := h.parseDeviceIDs(r)
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
		h.logger.Error("failed to generate trends data", "error", err)
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

	deviceIDs := h.parseDeviceIDs(r)
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
		h.logger.Error("failed to generate alerts data", "error", err)
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

	deviceIDs := h.parseDeviceIDs(r)
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
		h.logger.Error("failed to generate compliance status", "error", err)
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

	deviceIDs := h.parseDeviceIDs(r)
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
		h.logger.Error("failed to generate drift summary", "error", err)
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
			return interfaces.TimeRange{}, fmt.Errorf("invalid start time format: %s", startStr)
		}
	}

	if endStr := r.URL.Query().Get("end"); endStr != "" {
		if parsedEnd, err := time.Parse(time.RFC3339, endStr); err == nil {
			end = parsedEnd
		} else {
			return interfaces.TimeRange{}, fmt.Errorf("invalid end time format: %s", endStr)
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

func (h *Handler) parseTenantIDs(r *http.Request) []string {
	tenantIDs := r.URL.Query()["tenant_id"]
	if tenantIDsStr := r.URL.Query().Get("tenant_ids"); tenantIDsStr != "" {
		// Support comma-separated tenant IDs
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
		h.logger.Error("failed to encode JSON response", "error", err)
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
