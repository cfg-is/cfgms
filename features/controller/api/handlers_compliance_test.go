// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

	t.Run("registered steward online returns compliant", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		now := time.Now().UTC()
		server.mu.Lock()
		server.registeredStewards["steward-1"] = &RegisteredSteward{
			StewardID:     "steward-1",
			TenantID:      "tenant-1",
			RegisteredAt:  now.Add(-1 * time.Hour),
			LastHeartbeat: now.Add(-10 * time.Second),
			Status:        "online",
		}
		server.mu.Unlock()

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

	t.Run("registered steward offline returns critical", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		now := time.Now().UTC()
		server.mu.Lock()
		server.registeredStewards["steward-1"] = &RegisteredSteward{
			StewardID:     "steward-1",
			TenantID:      "tenant-1",
			RegisteredAt:  now.Add(-1 * time.Hour),
			LastHeartbeat: now.Add(-10 * time.Minute),
			Status:        "offline",
		}
		server.mu.Unlock()

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

	t.Run("zero LastHeartbeat falls back to RegisteredAt", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		registeredAt := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
		server.mu.Lock()
		server.registeredStewards["steward-1"] = &RegisteredSteward{
			StewardID:    "steward-1",
			TenantID:     "tenant-1",
			RegisteredAt: registeredAt,
			// LastHeartbeat is zero value
			Status: "online",
		}
		server.mu.Unlock()

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-1/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceStatusResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, registeredAt.Format(time.RFC3339), resp.LastChecked)
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

	t.Run("registered steward with heartbeat returns report", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		now := time.Now().UTC()
		heartbeat := now.Add(-5 * time.Minute)
		server.mu.Lock()
		server.registeredStewards["steward-1"] = &RegisteredSteward{
			StewardID:     "steward-1",
			TenantID:      "tenant-1",
			RegisteredAt:  now.Add(-1 * time.Hour),
			LastHeartbeat: heartbeat,
			Status:        "online",
		}
		server.mu.Unlock()

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
		assert.Equal(t, heartbeat.Format(time.RFC3339), resp.LastPatchDate)
		assert.NotEmpty(t, resp.ReportGeneratedAt)
	})

	t.Run("zero LastHeartbeat falls back to RegisteredAt", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		registeredAt := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
		server.mu.Lock()
		server.registeredStewards["steward-1"] = &RegisteredSteward{
			StewardID:    "steward-1",
			TenantID:     "tenant-1",
			RegisteredAt: registeredAt,
			// LastHeartbeat is zero value
			Status: "online",
		}
		server.mu.Unlock()

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-1/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceReportResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, registeredAt.Format(time.RFC3339), resp.LastPatchDate)
	})

	t.Run("offline steward returns critical status", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		now := time.Now().UTC()
		server.mu.Lock()
		server.registeredStewards["steward-1"] = &RegisteredSteward{
			StewardID:     "steward-1",
			TenantID:      "tenant-1",
			RegisteredAt:  now.Add(-1 * time.Hour),
			LastHeartbeat: now.Add(-10 * time.Minute),
			Status:        "offline",
		}
		server.mu.Unlock()

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

		now := time.Now().UTC()
		server.mu.Lock()
		server.registeredStewards["s1"] = &RegisteredSteward{
			StewardID: "s1", TenantID: "tenant-1", Status: "online",
			RegisteredAt: now, LastHeartbeat: now,
		}
		server.registeredStewards["s2"] = &RegisteredSteward{
			StewardID: "s2", TenantID: "tenant-1", Status: "offline",
			RegisteredAt: now, LastHeartbeat: now,
		}
		server.registeredStewards["s3"] = &RegisteredSteward{
			StewardID: "s3", TenantID: "tenant-2", Status: "online",
			RegisteredAt: now, LastHeartbeat: now,
		}
		server.registeredStewards["s4"] = &RegisteredSteward{
			StewardID: "s4", TenantID: "tenant-2", Status: "unknown",
			RegisteredAt: now, LastHeartbeat: now,
		}
		server.mu.Unlock()

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

		now := time.Now().UTC()
		server.mu.Lock()
		server.registeredStewards["s1"] = &RegisteredSteward{
			StewardID: "s1", TenantID: "tenant-1", Status: "online",
			RegisteredAt: now, LastHeartbeat: now,
		}
		server.registeredStewards["s2"] = &RegisteredSteward{
			StewardID: "s2", TenantID: "tenant-2", Status: "online",
			RegisteredAt: now, LastHeartbeat: now,
		}
		server.mu.Unlock()

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

		now := time.Now().UTC()
		server.mu.Lock()
		server.registeredStewards["s1"] = &RegisteredSteward{
			StewardID: "s1", TenantID: "tenant-1", Status: "online",
			RegisteredAt: now, LastHeartbeat: now,
		}
		server.mu.Unlock()

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
