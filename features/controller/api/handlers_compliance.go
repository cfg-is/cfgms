// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// ComplianceStatusResponse represents the compliance status of a steward
type ComplianceStatusResponse struct {
	DeviceID        string `json:"device_id"`
	DeviceName      string `json:"device_name"`
	Status          string `json:"status"` // "compliant", "warning", "critical", "non_compliant"
	DaysUntilBreach int    `json:"days_until_breach"`
	LastChecked     string `json:"last_checked"` // ISO 8601 timestamp
	AlertLevel      string `json:"alert_level"`  // "info", "warning", "critical", "breach"
}

// ComplianceReportResponse represents detailed compliance information
type ComplianceReportResponse struct {
	DeviceID          string                     `json:"device_id"`
	DeviceName        string                     `json:"device_name"`
	Status            string                     `json:"status"`
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

// handleGetStewardCompliance returns the compliance status for a specific steward
//
// GET /api/v1/stewards/{id}/compliance
//
// Response:
//
//	{
//	  "device_id": "steward-123",
//	  "device_name": "DESKTOP-WIN11",
//	  "status": "warning",
//	  "days_until_breach": 4,
//	  "last_checked": "2024-01-15T10:30:00Z",
//	  "alert_level": "warning"
//	}
func (s *Server) handleGetStewardCompliance(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		http.Error(w, "steward ID is required", http.StatusBadRequest)
		return
	}

	// TODO: Integrate with patch module to get actual compliance status
	// For now, return placeholder response showing the API structure
	response := ComplianceStatusResponse{
		DeviceID:        stewardID,
		DeviceName:      "DESKTOP-WIN11",
		Status:          "warning",
		DaysUntilBreach: 4,
		LastChecked:     "2024-01-15T10:30:00Z",
		AlertLevel:      "warning",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode compliance status response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

// handleGetStewardComplianceReport returns detailed compliance report for a steward
//
// GET /api/v1/stewards/{id}/compliance/report
//
// Response:
//
//	{
//	  "device_id": "steward-123",
//	  "device_name": "DESKTOP-WIN11",
//	  "status": "warning",
//	  "days_until_breach": 4,
//	  "missing_patches": [
//	    {
//	      "id": "KB8888888",
//	      "title": "Critical Security Update",
//	      "severity": "critical",
//	      "category": "security",
//	      "release_date": "2024-01-10T00:00:00Z",
//	      "days_overdue": 0,
//	      "days_until_due": 4
//	    }
//	  ],
//	  "os_version": "Windows 11 23H2",
//	  "last_patch_date": "2024-01-01T12:00:00Z",
//	  "report_generated_at": "2024-01-15T10:30:00Z",
//	  "policy": {
//	    "critical_deadline_days": 7,
//	    "important_deadline_days": 14,
//	    "moderate_deadline_days": 30,
//	    "low_deadline_days": 60,
//	    "warning_threshold_days": 7,
//	    "critical_threshold_days": 1,
//	    "maintenance_windows_configured": true
//	  },
//	  "compatibility_info": {
//	    "windows11_compatible": true,
//	    "missing_requirements": [],
//	    "last_checked": "2024-01-15T09:00:00Z"
//	  }
//	}
func (s *Server) handleGetStewardComplianceReport(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		http.Error(w, "steward ID is required", http.StatusBadRequest)
		return
	}

	// TODO: Integrate with patch module to get actual compliance report
	// For now, return placeholder response showing the API structure
	response := ComplianceReportResponse{
		DeviceID:        stewardID,
		DeviceName:      "DESKTOP-WIN11",
		Status:          "warning",
		DaysUntilBreach: 4,
		MissingPatches: []MissingPatchResponse{
			{
				ID:           "KB8888888",
				Title:        "Critical Security Update",
				Severity:     "critical",
				Category:     "security",
				ReleaseDate:  "2024-01-10T00:00:00Z",
				DaysOverdue:  0,
				DaysUntilDue: 4,
			},
		},
		OSVersion:         "Windows 11 23H2",
		LastPatchDate:     "2024-01-01T12:00:00Z",
		ReportGeneratedAt: "2024-01-15T10:30:00Z",
		Policy: PatchPolicyResponse{
			CriticalDeadlineDays:         7,
			ImportantDeadlineDays:        14,
			ModerateDeadlineDays:         30,
			LowDeadlineDays:              60,
			WarningThresholdDays:         7,
			CriticalThresholdDays:        1,
			MaintenanceWindowsConfigured: true,
		},
		CompatibilityInfo: &CompatibilityInfoResponse{
			Windows11Compatible: true,
			MissingRequirements: []string{},
			LastChecked:         "2024-01-15T09:00:00Z",
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

// handleGetComplianceSummary returns system-wide compliance summary
//
// GET /api/v1/compliance/summary
//
// Query parameters:
// - tenant_id: Filter by specific tenant (optional)
//
// Response:
//
//	{
//	  "total_devices": 100,
//	  "compliant_devices": 75,
//	  "warning_devices": 15,
//	  "critical_devices": 8,
//	  "breached_devices": 2,
//	  "by_tenant": [
//	    {
//	      "tenant_id": "tenant-1",
//	      "tenant_name": "Acme Corp",
//	      "total_devices": 50,
//	      "compliant_devices": 40,
//	      "warning_devices": 7,
//	      "critical_devices": 2,
//	      "breached_devices": 1
//	    }
//	  ],
//	  "generated_at": "2024-01-15T10:30:00Z"
//	}
func (s *Server) handleGetComplianceSummary(w http.ResponseWriter, r *http.Request) {
	// Get optional tenant_id filter from query params
	tenantID := r.URL.Query().Get("tenant_id")

	// TODO: Integrate with patch module and steward registry to get actual compliance summary
	// For now, return placeholder response showing the API structure
	response := ComplianceSummaryResponse{
		TotalDevices:     100,
		CompliantDevices: 75,
		WarningDevices:   15,
		CriticalDevices:  8,
		BreachedDevices:  2,
		ByTenant: []TenantComplianceStatus{
			{
				TenantID:         "tenant-1",
				TenantName:       "Acme Corp",
				TotalDevices:     50,
				CompliantDevices: 40,
				WarningDevices:   7,
				CriticalDevices:  2,
				BreachedDevices:  1,
			},
			{
				TenantID:         "tenant-2",
				TenantName:       "Beta Inc",
				TotalDevices:     50,
				CompliantDevices: 35,
				WarningDevices:   8,
				CriticalDevices:  6,
				BreachedDevices:  1,
			},
		},
		GeneratedAt: "2024-01-15T10:30:00Z",
	}

	// Filter by tenant if requested
	if tenantID != "" {
		filtered := make([]TenantComplianceStatus, 0)
		for _, tenant := range response.ByTenant {
			if tenant.TenantID == tenantID {
				filtered = append(filtered, tenant)
			}
		}
		response.ByTenant = filtered

		// Recalculate totals for filtered tenant
		if len(filtered) == 1 {
			response.TotalDevices = filtered[0].TotalDevices
			response.CompliantDevices = filtered[0].CompliantDevices
			response.WarningDevices = filtered[0].WarningDevices
			response.CriticalDevices = filtered[0].CriticalDevices
			response.BreachedDevices = filtered[0].BreachedDevices
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode compliance summary response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
