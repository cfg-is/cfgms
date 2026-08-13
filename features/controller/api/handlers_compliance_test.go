// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
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

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "test-tenant", "addr-1", "online"))

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

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "test-tenant", "addr-1", "offline"))

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

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "test-tenant", "addr-1", "registered"))

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

func TestHandleGetStewardCompliance_TenantIsolation(t *testing.T) {
	t.Run("tenant-A caller gets 404 for tenant-B steward", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-compliance"}, "tenant-a", 5*time.Minute)

		require.NoError(t, server.controllerService.RegisterSteward("steward-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-b/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("tenant-A caller can see own steward", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-compliance"}, "tenant-a", 5*time.Minute)

		require.NoError(t, server.controllerService.RegisterSteward("steward-a", "tenant-a", "addr-a", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-a/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("tenant-A caller can see descendant-tenant steward", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-compliance"}, "tenant-a", 5*time.Minute)

		// Register a steward under tenant-a/child (descendant)
		require.NoError(t, server.controllerService.RegisterSteward("steward-child", "tenant-a/child", "addr-c", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-child/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	// Calling handler directly to test context injection pattern (matches tests in
	// handlers_fleet_test.go and handlers_registration_tenant_scope_test.go).
	t.Run("scoped context blocks cross-tenant access", func(t *testing.T) {
		server := setupTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("steward-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-b/compliance", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "steward-b"})
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetStewardCompliance(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
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

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "test-tenant", "addr-1", "online"))

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

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "test-tenant", "addr-1", "registered"))

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

		require.NoError(t, server.controllerService.RegisterSteward("steward-1", "test-tenant", "addr-1", "offline"))

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

func TestHandleGetStewardComplianceReport_TenantIsolation(t *testing.T) {
	t.Run("tenant-A caller gets 404 for tenant-B steward report", func(t *testing.T) {
		server := setupTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("steward-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-b/compliance/report", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "steward-b"})
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetStewardComplianceReport(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("tenant-A caller can see own steward report", func(t *testing.T) {
		server := setupTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("steward-a", "tenant-a", "addr-a", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-a/compliance/report", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "steward-a"})
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetStewardComplianceReport(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
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

	// Root/unscoped callers (no TenantID in context) see all tenants' stewards.
	// Calling the handler directly (no router) to inject an empty-tenant context,
	// which the API key system doesn't support but the authentication middleware
	// does set for mTLS admin sessions.
	t.Run("root caller sees multiple stewards with mixed status", func(t *testing.T) {
		server := setupTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s1", "tenant-1", "addr-1", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s2", "tenant-1", "addr-2", "offline"))
		require.NoError(t, server.controllerService.RegisterSteward("s3", "tenant-2", "addr-3", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s4", "tenant-2", "addr-4", "unknown"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		// No TenantID in context simulates root/admin caller (e.g. mTLS admin session).
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

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

	// Root/admin callers can use tenant_id query param to filter.
	t.Run("root caller tenant filter returns matching stewards only", func(t *testing.T) {
		server := setupTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s1", "tenant-1", "addr-1", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s2", "tenant-2", "addr-2", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary?tenant_id=tenant-1", nil)
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 1, resp.TotalDevices)
		assert.Equal(t, 1, resp.CompliantDevices)
		assert.Len(t, resp.ByTenant, 1)
		assert.Equal(t, "tenant-1", resp.ByTenant[0].TenantID)
	})

	// Root/admin callers: filter with no matching stewards returns zero counts.
	t.Run("root caller tenant filter with no match returns zero counts", func(t *testing.T) {
		server := setupTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s1", "tenant-1", "addr-1", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary?tenant_id=nonexistent", nil)
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 0, resp.TotalDevices)
		assert.Empty(t, resp.ByTenant)
	})
}

func TestHandleGetComplianceSummary_TenantIsolation(t *testing.T) {
	// [REQUIRED TEST]: a tenant-A caller hitting /api/v1/compliance/summary never
	// sees tenant-B's by_tenant entry, even when no tenant_id param is supplied.
	t.Run("tenant-A caller never sees tenant-B data in by_tenant", func(t *testing.T) {
		server := setupTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s-a", "tenant-a", "addr-a", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		// Only tenant-a's steward is visible.
		assert.Equal(t, 1, resp.TotalDevices)
		require.Len(t, resp.ByTenant, 1)
		assert.Equal(t, "tenant-a", resp.ByTenant[0].TenantID)
	})

	t.Run("tenant-A caller with tenant_id=tenant-B param still only sees tenant-A data", func(t *testing.T) {
		server := setupTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s-a", "tenant-a", "addr-a", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary?tenant_id=tenant-b", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		// Query param must be ignored; caller's own tenant scoping is enforced.
		assert.Equal(t, 1, resp.TotalDevices)
		require.Len(t, resp.ByTenant, 1)
		assert.Equal(t, "tenant-a", resp.ByTenant[0].TenantID)
	})

	t.Run("tenant-A caller sees descendant tenant stewards", func(t *testing.T) {
		server := setupTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s-a", "tenant-a", "addr-a", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s-child", "tenant-a/child", "addr-c", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		// tenant-a and tenant-a/child are visible; tenant-b is not.
		assert.Equal(t, 2, resp.TotalDevices)
		assert.Len(t, resp.ByTenant, 2)
		tenantIDs := make(map[string]bool)
		for _, bt := range resp.ByTenant {
			tenantIDs[bt.TenantID] = true
		}
		assert.True(t, tenantIDs["tenant-a"], "tenant-a should be in by_tenant")
		assert.True(t, tenantIDs["tenant-a/child"], "tenant-a/child should be in by_tenant")
		assert.False(t, tenantIDs["tenant-b"], "tenant-b must not appear")
	})
}
