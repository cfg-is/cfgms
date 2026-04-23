// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGetStewardCompliance(t *testing.T) {
	t.Run("steward not found returns 404", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		req := httptest.NewRequest("GET", "/api/v1/stewards/nonexistent/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("online steward returns compliant", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "tenant-1", "addr-1", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-1/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceStatusResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "steward-1", resp.DeviceID)
		assert.Equal(t, "compliant", resp.Status)
		assert.Equal(t, "info", resp.AlertLevel)
	})

	t.Run("offline steward returns critical", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "tenant-1", "addr-1", "offline"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-1/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceStatusResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "critical", resp.Status)
		assert.Equal(t, "critical", resp.AlertLevel)
	})

	t.Run("registered steward returns compliant with non-zero last_checked", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "tenant-1", "addr-1", "registered"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-1/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceStatusResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "compliant", resp.Status)
		assert.NotEmpty(t, resp.LastChecked)
	})
}

func TestHandleGetStewardComplianceReport(t *testing.T) {
	t.Run("steward not found returns 404", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		req := httptest.NewRequest("GET", "/api/v1/stewards/nonexistent/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("online steward returns compliant report", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "tenant-1", "addr-1", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-1/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceReportResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "steward-1", resp.DeviceID)
		assert.Equal(t, "compliant", resp.Status)
		assert.NotEmpty(t, resp.LastPatchDate)
		assert.NotEmpty(t, resp.ReportGeneratedAt)
	})

	t.Run("registered steward returns non-zero last_patch_date", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "tenant-1", "addr-1", "registered"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-1/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceReportResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.LastPatchDate)
	})

	t.Run("offline steward returns critical status", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "tenant-1", "addr-1", "offline"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-1/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceReportResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "critical", resp.Status)
	})
}

func TestHandleGetComplianceSummary(t *testing.T) {
	t.Run("no stewards returns zero counts", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"compliance:read-summary"})

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 0, resp.TotalDevices)
		assert.Equal(t, 0, resp.CompliantDevices)
		assert.Equal(t, 0, resp.WarningDevices)
		assert.Equal(t, 0, resp.CriticalDevices)
		assert.Empty(t, resp.ByTenant)
	})

	t.Run("multiple stewards with mixed status aggregates correctly", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"compliance:read-summary"})

		require.NoError(t, server.controllerService.RegisterSteward("s1", "tenant-1", "addr-1", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s2", "tenant-1", "addr-2", "offline"))
		require.NoError(t, server.controllerService.RegisterSteward("s3", "tenant-2", "addr-3", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s4", "tenant-2", "addr-4", "unknown"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 4, resp.TotalDevices)
		assert.Equal(t, 2, resp.CompliantDevices)
		assert.Equal(t, 1, resp.WarningDevices)
		assert.Equal(t, 1, resp.CriticalDevices)
		assert.Len(t, resp.ByTenant, 2)
	})

	t.Run("tenant filter returns matching stewards only", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"compliance:read-summary"})

		require.NoError(t, server.controllerService.RegisterSteward("s1", "tenant-1", "addr-1", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s2", "tenant-2", "addr-2", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary?tenant_id=tenant-1", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 1, resp.TotalDevices)
		assert.Equal(t, 1, resp.CompliantDevices)
		assert.Len(t, resp.ByTenant, 1)
		assert.Equal(t, "tenant-1", resp.ByTenant[0].TenantID)
	})

	t.Run("tenant filter with no match returns zero counts", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"compliance:read-summary"})

		require.NoError(t, server.controllerService.RegisterSteward("s1", "tenant-1", "addr-1", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary?tenant_id=nonexistent", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 0, resp.TotalDevices)
		assert.Empty(t, resp.ByTenant)
	})
}
