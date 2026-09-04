// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	reportinterfaces "github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ComplianceStatusResponse represents the compliance status of a steward.
// Status derives from real drift/convergence signal (DNA delta detection), not
// agent liveness. ConnectionStatus carries the liveness/connectivity state
// separately so operators can distinguish "drifted but online" from "offline."
type ComplianceStatusResponse struct {
	DeviceID         string `json:"device_id"`
	DeviceName       string `json:"device_name"`
	Status           string `json:"status"`            // "compliant", "warning", "critical" — from drift signal
	ConnectionStatus string `json:"connection_status"` // "online", "offline", etc. — liveness only
	DaysUntilBreach  int    `json:"days_until_breach"`
	LastChecked      string `json:"last_checked"` // ISO 8601 timestamp
	AlertLevel       string `json:"alert_level"`  // "info", "warning", "critical"
}

// ComplianceReportResponse represents detailed compliance information.
// Status derives from real drift/convergence signal; ConnectionStatus carries
// liveness separately.
type ComplianceReportResponse struct {
	DeviceID          string                     `json:"device_id"`
	DeviceName        string                     `json:"device_name"`
	Status            string                     `json:"status"`            // from drift signal
	ConnectionStatus  string                     `json:"connection_status"` // liveness only
	DaysUntilBreach   int                        `json:"days_until_breach"`
	MissingPatches    []MissingPatchResponse     `json:"missing_patches"`
	OSVersion         string                     `json:"os_version"`
	LastPatchDate     string                     `json:"last_patch_date"` // ISO 8601
	ReportGeneratedAt string                     `json:"report_generated_at"`
	Policy            PatchPolicyResponse        `json:"policy"`
	CompatibilityInfo *CompatibilityInfoResponse `json:"compatibility_info,omitempty"`
}

// MissingPatchResponse represents a missing patch
type MissingPatchResponse struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	ReleaseDate  string `json:"release_date"` // ISO 8601
	DaysOverdue  int    `json:"days_overdue"`
	DaysUntilDue int    `json:"days_until_due"`
}

// PatchPolicyResponse represents the applied patch policy
type PatchPolicyResponse struct {
	CriticalDeadlineDays         int  `json:"critical_deadline_days"`
	ImportantDeadlineDays        int  `json:"important_deadline_days"`
	ModerateDeadlineDays         int  `json:"moderate_deadline_days"`
	LowDeadlineDays              int  `json:"low_deadline_days"`
	WarningThresholdDays         int  `json:"warning_threshold_days"`
	CriticalThresholdDays        int  `json:"critical_threshold_days"`
	MaintenanceWindowsConfigured bool `json:"maintenance_windows_configured"`
}

// CompatibilityInfoResponse represents Windows 11 upgrade compatibility
type CompatibilityInfoResponse struct {
	Windows11Compatible bool     `json:"windows11_compatible"`
	MissingRequirements []string `json:"missing_requirements"`
	Warnings            []string `json:"warnings,omitempty"`
	LastChecked         string   `json:"last_checked"` // ISO 8601
}

// ComplianceSummaryResponse represents system-wide compliance status
type ComplianceSummaryResponse struct {
	TotalDevices     int                      `json:"total_devices"`
	CompliantDevices int                      `json:"compliant_devices"`
	WarningDevices   int                      `json:"warning_devices"`
	CriticalDevices  int                      `json:"critical_devices"`
	BreachedDevices  int                      `json:"breached_devices"`
	ByTenant         []TenantComplianceStatus `json:"by_tenant"`
	GeneratedAt      string                   `json:"generated_at"`
}

// TenantComplianceStatus represents compliance status for a tenant
type TenantComplianceStatus struct {
	TenantID         string `json:"tenant_id"`
	TenantName       string `json:"tenant_name"`
	TotalDevices     int    `json:"total_devices"`
	CompliantDevices int    `json:"compliant_devices"`
	WarningDevices   int    `json:"warning_devices"`
	CriticalDevices  int    `json:"critical_devices"`
	BreachedDevices  int    `json:"breached_devices"`
}

// complianceDashboardWindow is the default look-back window for compliance
// queries. Matches the reports engine dashboard default.
const complianceDashboardWindow = 24 * time.Hour

// complianceTimeBuffer is added to the range End so drift events computed
// immediately after the handler captures "now" still fall within the range.
// DetectDrift sets event.Timestamp = time.Now() at detection time, which is
// always after the handler's snapshot of "now"; without this buffer the filter
// inside GetDriftEvents would drop those events.
const complianceTimeBuffer = time.Minute

// riskLevelToCompliance maps a DeviceStats.RiskLevel directly to the
// compliance status and alert-level strings the API returns.
// Reading RiskLevel directly (rather than re-deriving from ComplianceScore)
// preserves calculateRiskLevel's critical-event override:
//
//	criticalCount > 0 || complianceScore < 0.3  →  Critical
//
// A score-only threshold would silently drop that override.
func riskLevelToCompliance(level reportinterfaces.RiskLevel) (status, alertLevel string) {
	switch level {
	case reportinterfaces.RiskLevelLow:
		return "compliant", "info"
	case reportinterfaces.RiskLevelMedium:
		return "warning", "warning"
	default: // RiskLevelHigh and RiskLevelCritical
		return "critical", "critical"
	}
}

// handleGetStewardCompliance returns the compliance status for a specific steward.
//
// GET /api/v1/stewards/{id}/compliance
//
// Compliance status is derived from the real drift/convergence signal produced
// by GetDeviceStats, not from the steward's connection status. Connection
// status is included separately as connection_status.
// Returns 503 when the data provider is unavailable.
func (s *Server) handleGetStewardCompliance(w http.ResponseWriter, r *http.Request) {
	if s.dataProvider == nil {
		http.Error(w, "compliance data unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		http.Error(w, "steward ID is required", http.StatusBadRequest)
		return
	}

	stewardInfo, found := s.controllerService.GetStewardInfo(stewardID)
	if !found {
		http.Error(w, "steward not found", http.StatusNotFound)
		return
	}

	// Cross-tenant guard: a caller scoped to tenant A must not see tenant B's
	// steward compliance data. 404 (not 403) avoids disclosing steward existence
	// across tenants — matching tenantScopedTerminalWrapper behavior.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
		stewardTenant := stewardInfo.TenantID
		sameTenant := stewardTenant == callerTenant
		descendantTenant := strings.HasPrefix(stewardTenant, callerTenant+"/")
		if !sameTenant && !descendantTenant {
			http.Error(w, "steward not found", http.StatusNotFound)
			return
		}
	}

	now := time.Now().UTC()
	timeRange := reportinterfaces.TimeRange{
		Start: now.Add(-complianceDashboardWindow),
		End:   now.Add(complianceTimeBuffer),
	}

	statsMap, err := s.dataProvider.GetDeviceStats(r.Context(), []string{stewardID}, timeRange)
	if err != nil {
		s.logger.Error("Failed to get device stats for compliance",
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// A DataProvider omits any device whose stats it could not compute: a storage
	// read failure is logged and the device skipped, so one unreadable device never
	// fails a fleet-wide query. For a single explicitly-requested steward that
	// omission IS the failure — indexing the map anyway yields a zero-value
	// DeviceStats whose empty RiskLevel maps to "critical", turning a storage
	// outage into a fabricated compliance verdict. Fail loudly instead.
	stats, ok := statsMap[stewardID]
	if !ok {
		s.logger.Error("No compliance stats returned for steward",
			"steward_id", logging.SanitizeLogValue(stewardID))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	complianceStatus, alertLevel := riskLevelToCompliance(stats.RiskLevel)

	lastChecked := stats.LastSeen.UTC().Format(time.RFC3339)
	if stats.LastSeen.IsZero() {
		lastChecked = stewardInfo.LastHeartbeat.UTC().Format(time.RFC3339)
	}

	response := ComplianceStatusResponse{
		DeviceID:         stewardID,
		DeviceName:       stewardID,
		Status:           complianceStatus,
		ConnectionStatus: stewardInfo.Status,
		DaysUntilBreach:  0,
		LastChecked:      lastChecked,
		AlertLevel:       alertLevel,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode compliance status response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

// handleGetStewardComplianceReport returns detailed compliance report for a steward.
//
// GET /api/v1/stewards/{id}/compliance/report
//
// Compliance status is derived from the real drift/convergence signal; connection
// status is present as a separate connection_status field.
// Returns 503 when the data provider is unavailable.
func (s *Server) handleGetStewardComplianceReport(w http.ResponseWriter, r *http.Request) {
	if s.dataProvider == nil {
		http.Error(w, "compliance data unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		http.Error(w, "steward ID is required", http.StatusBadRequest)
		return
	}

	stewardInfo, found := s.controllerService.GetStewardInfo(stewardID)
	if !found {
		http.Error(w, "steward not found", http.StatusNotFound)
		return
	}

	// Cross-tenant guard: mirroring tenantScopedTerminalWrapper — 404 to avoid
	// disclosing steward existence across tenants.
	callerTenantR, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenantR != "" {
		stewardTenant := stewardInfo.TenantID
		sameTenant := stewardTenant == callerTenantR
		descendantTenant := strings.HasPrefix(stewardTenant, callerTenantR+"/")
		if !sameTenant && !descendantTenant {
			http.Error(w, "steward not found", http.StatusNotFound)
			return
		}
	}

	now := time.Now().UTC()
	timeRange := reportinterfaces.TimeRange{
		Start: now.Add(-complianceDashboardWindow),
		End:   now.Add(complianceTimeBuffer),
	}

	statsMap, err := s.dataProvider.GetDeviceStats(r.Context(), []string{stewardID}, timeRange)
	if err != nil {
		s.logger.Error("Failed to get device stats for compliance report",
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// See handleGetStewardCompliance: a missing entry for the one requested
	// steward means its stats could not be computed (storage failure), not that
	// it is compliant. Reporting the zero-value stats would fabricate a verdict.
	stats, ok := statsMap[stewardID]
	if !ok {
		s.logger.Error("No compliance stats returned for steward report",
			"steward_id", logging.SanitizeLogValue(stewardID))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	complianceStatus, _ := riskLevelToCompliance(stats.RiskLevel)

	lastPatchDate := stats.LastSeen.UTC().Format(time.RFC3339)
	if stats.LastSeen.IsZero() {
		lastPatchDate = stewardInfo.LastHeartbeat.UTC().Format(time.RFC3339)
	}

	// Return real steward data; patch details require patch module integration
	response := ComplianceReportResponse{
		DeviceID:          stewardID,
		DeviceName:        stewardID,
		Status:            complianceStatus,
		ConnectionStatus:  stewardInfo.Status,
		DaysUntilBreach:   0,
		MissingPatches:    []MissingPatchResponse{},
		OSVersion:         "",
		LastPatchDate:     lastPatchDate,
		ReportGeneratedAt: now.Format(time.RFC3339),
		Policy: PatchPolicyResponse{
			CriticalDeadlineDays:         7,
			ImportantDeadlineDays:        14,
			ModerateDeadlineDays:         30,
			LowDeadlineDays:              60,
			WarningThresholdDays:         7,
			CriticalThresholdDays:        1,
			MaintenanceWindowsConfigured: false,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode compliance report response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

// handleGetComplianceSummary returns system-wide compliance summary.
//
// GET /api/v1/compliance/summary
//
// Query parameters:
// - tenant_id: Filter by specific tenant (optional, root/unscoped callers only)
//
// Compliance buckets are derived from DeviceStats.RiskLevel (drift signal),
// not from steward connection status.
// Returns 503 when the data provider is unavailable.
func (s *Server) handleGetComplianceSummary(w http.ResponseWriter, r *http.Request) {
	if s.dataProvider == nil {
		http.Error(w, "compliance data unavailable", http.StatusServiceUnavailable)
		return
	}

	// TenantID is always taken from the authenticated context for scoped callers;
	// unscoped admins (callerTenant == "") may use the tenant_id query param to filter.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	tenantFilter := r.URL.Query().Get("tenant_id")

	// Collect steward IDs while applying tenant scoping from the steward registry.
	stewardsByTenant := make(map[string][]string) // tenantID → steward IDs
	for _, st := range s.controllerService.ListFleetStewards(r.Context()) {
		if callerTenant != "" {
			sameTenant := st.TenantID == callerTenant
			descendantTenant := strings.HasPrefix(st.TenantID, callerTenant+"/")
			if !sameTenant && !descendantTenant {
				continue
			}
		} else if tenantFilter != "" && st.TenantID != tenantFilter {
			continue
		}
		stewardsByTenant[st.TenantID] = append(stewardsByTenant[st.TenantID], st.ID)
	}

	// Gather all steward IDs for a single bulk DeviceStats call.
	var allIDs []string
	for _, ids := range stewardsByTenant {
		allIDs = append(allIDs, ids...)
	}

	var statsMap map[string]reportinterfaces.DeviceStats
	if len(allIDs) > 0 {
		now := time.Now().UTC()
		timeRange := reportinterfaces.TimeRange{
			Start: now.Add(-complianceDashboardWindow),
			End:   now.Add(complianceTimeBuffer),
		}
		var err error
		statsMap, err = s.dataProvider.GetDeviceStats(r.Context(), allIDs, timeRange)
		if err != nil {
			s.logger.Error("Failed to get device stats for compliance summary",
				"error", logging.SanitizeLogValue(err.Error()))
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// Any requested steward missing from the result had its stats calculation
		// fail (storage error), which the provider logs and skips. Counting those
		// zero-value stats would silently bucket them as "critical" and publish
		// aggregate totals that do not describe the fleet. Fail the summary instead.
		for _, id := range allIDs {
			if _, ok := statsMap[id]; !ok {
				s.logger.Error("Incomplete device stats for compliance summary",
					"steward_id", logging.SanitizeLogValue(id))
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
		}
	}

	// Aggregate per-tenant compliance counts from drift-based RiskLevel.
	tenantStats := make(map[string]*TenantComplianceStatus)
	for tenantID, ids := range stewardsByTenant {
		tcs, ok := tenantStats[tenantID]
		if !ok {
			tcs = &TenantComplianceStatus{
				TenantID:   tenantID,
				TenantName: tenantID,
			}
			tenantStats[tenantID] = tcs
		}
		for _, id := range ids {
			tcs.TotalDevices++
			status, _ := riskLevelToCompliance(statsMap[id].RiskLevel)
			switch status {
			case "compliant":
				tcs.CompliantDevices++
			case "warning":
				tcs.WarningDevices++
			default: // "critical"
				tcs.CriticalDevices++
			}
		}
	}

	// Aggregate totals
	totalDevices := 0
	compliantDevices := 0
	warningDevices := 0
	criticalDevices := 0
	byTenant := make([]TenantComplianceStatus, 0, len(tenantStats))

	for _, tcs := range tenantStats {
		totalDevices += tcs.TotalDevices
		compliantDevices += tcs.CompliantDevices
		warningDevices += tcs.WarningDevices
		criticalDevices += tcs.CriticalDevices
		byTenant = append(byTenant, *tcs)
	}

	response := ComplianceSummaryResponse{
		TotalDevices:     totalDevices,
		CompliantDevices: compliantDevices,
		WarningDevices:   warningDevices,
		CriticalDevices:  criticalDevices,
		BreachedDevices:  0, // Requires patch module integration
		ByTenant:         byTenant,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode compliance summary response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
