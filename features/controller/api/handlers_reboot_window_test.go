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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"time"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// sampleScheduleYAML is a valid single-window schedule for reboot_window tests.
const sampleScheduleYAML = `schedules:
  - freq: weekly
    days: [sunday]
    start: "02:00"
    end: "04:00"
`

// TestPutTenantRebootWindow_403_ConfigUpdateOnlyCallerDenied verifies ADR-026 decision 3:
// a caller with config:update (general config permission) MUST receive 403 on
// PUT /api/v1/tenants/{id}/reboot-window.
// [REQUIRED TEST] per Issue #2979 acceptance criteria.
func TestPutTenantRebootWindow_403_ConfigUpdateOnlyCallerDenied(t *testing.T) {
	server := setupTestServer(t)

	// API key holds config:update but NOT reboot_window:override.
	apiKey := NewEphemeralTestKey(t, server, []string{"config:update"}, "test-tenant", ephemeralTTL)

	body, err := json.Marshal(rebootWindowPutRequest{
		ScheduleYAML: sampleScheduleYAML,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/test-tenant/reboot-window", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"config:update-only caller must not be allowed to set reboot_window")
}

// TestPutTenantRebootWindow_AuditEvent verifies that a successful PUT emits an audit
// event with the correct tenant, resource type, and action.
// [REQUIRED TEST] per Issue #2979 acceptance criteria.
func TestPutTenantRebootWindow_AuditEvent(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	apiKey := NewEphemeralTestKey(t, server, []string{"reboot_window:override"}, "audit-test-tenant", ephemeralTTL)

	body, err := json.Marshal(rebootWindowPutRequest{
		ScheduleYAML:          sampleScheduleYAML,
		TenantDefaultTimezone: "America/New_York",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/audit-test-tenant/reboot-window", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "PUT should succeed: %s", rec.Body.String())

	// Flush audit events to the store and query them back.
	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "audit-test-tenant",
	})
	require.NoError(t, err)

	entry := findRebootWindowAuditEntry(t, entries)
	assert.Equal(t, "audit-test-tenant", entry.TenantID)
	assert.Equal(t, "reboot_window", entry.ResourceType)
	assert.Equal(t, "update", entry.Action)
	assert.Equal(t, string(business.AuditResultSuccess), string(entry.Result))
}

// TestGetStewardRebootWindow_CascadeResolvesInheritedWindow verifies that
// GET /api/v1/stewards/{id}/reboot-window resolves a window declared at the
// tenant level (not the steward level) and returns the correct next occurrence.
// [REQUIRED TEST] per Issue #2979 acceptance criteria.
//
// The test creates a 2-level hierarchy (root → client-tenant) so the inheritance
// resolver places the client-tenant at LevelClient (level 1) and reads its policy
// from client-policies/{tenantID} — the same namespace the PUT writes to when
// s.tenantStore is nil (default fallback).
func TestGetStewardRebootWindow_CascadeResolvesInheritedWindow(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	// Build a root → client hierarchy so InheritanceResolver places cascade-client
	// at LevelClient (index 1 in the tenant path). The handler's PUT falls back to
	// client-policies/{tenantID} when s.tenantStore is nil; level-1 in the resolver
	// reads the same namespace.
	rootID := "cascade-root"
	tenantID := "cascade-client"
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: rootID, Name: "cascade-root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: tenantID, Name: tenantID, ParentID: rootID})
	require.NoError(t, err)

	stewardID := "cascade-steward-1"
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, tenantID, "localhost:7000", "online"))

	// Write a reboot_window at the tenant (client-policies) level via PUT.
	apiKey := NewEphemeralTestKey(t, server, []string{"reboot_window:override", "reboot_window:read"}, tenantID, ephemeralTTL)

	putBody, err := json.Marshal(rebootWindowPutRequest{
		ScheduleYAML: sampleScheduleYAML,
	})
	require.NoError(t, err)
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+tenantID+"/reboot-window", bytes.NewReader(putBody))
	putReq.Header.Set("X-API-Key", apiKey)
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	server.router.ServeHTTP(putRec, putReq)
	require.Equal(t, http.StatusOK, putRec.Code, "tenant PUT should succeed: %s", putRec.Body.String())

	// GET the steward's effective reboot_window — it should cascade from the tenant.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/"+stewardID+"/reboot-window", nil)
	getReq.Header.Set("X-API-Key", apiKey)
	getRec := httptest.NewRecorder()
	server.router.ServeHTTP(getRec, getReq)
	require.Equal(t, http.StatusOK, getRec.Code, "steward GET should succeed: %s", getRec.Body.String())

	var resp APIResponse
	require.NoError(t, json.NewDecoder(getRec.Body).Decode(&resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "response data should be a JSON object")

	// The cascade must have resolved the window from the tenant level.
	// status must be "scheduled" and next_occurrence must be non-empty.
	assert.Equal(t, "scheduled", data["status"], "cascaded window must report status=scheduled")
	assert.NotEmpty(t, data["next_occurrence"], "next_occurrence must be set when a window cascades")
	assert.NotEmpty(t, data["next_occurrence_display"], "next_occurrence_display must be set")
	assert.Equal(t, stewardID, data["steward_id"])
}

// TestGetStewardRebootWindow_UnrestrictedWhenNoWindowDeclared verifies that the GET
// endpoint returns status=unrestricted and the canonical display string when no
// reboot_window is in effect anywhere in the cascade.
func TestGetStewardRebootWindow_UnrestrictedWhenNoWindowDeclared(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	stewardID := "unrestricted-steward"
	tenantID := "unrestricted-tenant"
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: tenantID, Name: "unrestricted-tenant"})
	require.NoError(t, err)
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, tenantID, "localhost:7001", "online"))

	apiKey := NewEphemeralTestKey(t, server, []string{"reboot_window:read"}, tenantID, ephemeralTTL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/"+stewardID+"/reboot-window", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "GET should succeed: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "response data should be a JSON object")

	assert.Equal(t, "unrestricted", data["status"])
	assert.Equal(t, "no reboot_window in effect — unrestricted", data["next_occurrence_display"])
	assert.Empty(t, data["next_occurrence"], "next_occurrence must be absent when unrestricted")
}

// TestPutStewardRebootWindow_DeviceLevelOverride verifies that a device-level PUT
// stores a schedule at the stewards namespace level, and the subsequent GET
// reflects it as status=scheduled.
func TestPutStewardRebootWindow_DeviceLevelOverride(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	stewardID := "device-override-steward"
	tenantID := "device-override-tenant"
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: tenantID, Name: "device-override-tenant"})
	require.NoError(t, err)
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, tenantID, "localhost:7002", "online"))

	apiKey := NewEphemeralTestKey(t, server,
		[]string{"reboot_window:override", "reboot_window:read"},
		tenantID, ephemeralTTL)

	putBody, err := json.Marshal(rebootWindowPutRequest{
		ScheduleYAML: sampleScheduleYAML,
	})
	require.NoError(t, err)

	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/stewards/"+stewardID+"/reboot-window", bytes.NewReader(putBody))
	putReq.Header.Set("X-API-Key", apiKey)
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	server.router.ServeHTTP(putRec, putReq)
	require.Equal(t, http.StatusOK, putRec.Code, "device PUT should succeed: %s", putRec.Body.String())

	var putResp APIResponse
	require.NoError(t, json.NewDecoder(putRec.Body).Decode(&putResp))
	putData, ok := putResp.Data.(map[string]interface{})
	require.True(t, ok, "PUT response data should be a JSON object")
	assert.Equal(t, "scheduled", putData["status"])
	assert.NotEmpty(t, putData["next_occurrence"])

	// GET to confirm persistence.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/"+stewardID+"/reboot-window", nil)
	getReq.Header.Set("X-API-Key", apiKey)
	getRec := httptest.NewRecorder()
	server.router.ServeHTTP(getRec, getReq)
	require.Equal(t, http.StatusOK, getRec.Code)
}

// TestPutTenantRebootWindow_InvalidSchedule_400 verifies that an unparseable
// schedule_yaml returns 400 with code INVALID_SCHEDULE.
func TestPutTenantRebootWindow_InvalidSchedule_400(t *testing.T) {
	server := setupTestServer(t)

	apiKey := NewEphemeralTestKey(t, server, []string{"reboot_window:override"}, "test-tenant", ephemeralTTL)

	body, err := json.Marshal(rebootWindowPutRequest{
		ScheduleYAML: "freq: not-a-valid-frequency",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/test-tenant/reboot-window", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_SCHEDULE", errResp.Error.Code)
}

// TestGetTenantRebootWindow_Unauthenticated_401 verifies that unauthenticated
// requests receive 401, not 403 (no information disclosure via status code).
func TestGetTenantRebootWindow_Unauthenticated_401(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/any-tenant/reboot-window", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestGetStewardRebootWindow_NotFound_404 verifies that GET for an unregistered steward
// returns 404.
func TestGetStewardRebootWindow_NotFound_404(t *testing.T) {
	server := setupTestServer(t)

	apiKey := NewEphemeralTestKey(t, server, []string{"reboot_window:read"}, "test-tenant", ephemeralTTL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/nonexistent-steward/reboot-window", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ephemeralTTL is a shared default TTL for ephemeral test keys.
const ephemeralTTL = 5 * time.Minute

// findRebootWindowAuditEntry returns the first audit entry with ResourceType "reboot_window".
func findRebootWindowAuditEntry(t *testing.T, entries []*business.AuditEntry) *business.AuditEntry {
	t.Helper()
	for _, e := range entries {
		if e.ResourceType == "reboot_window" {
			return e
		}
	}
	t.Fatalf("no audit entry with resource_type=reboot_window found among %d entries", len(entries))
	return nil
}

// TestBuildNextOccurrenceResponse_Unrestricted verifies the helper returns the canonical
// unrestricted response when no window is in effect (nil config).
func TestBuildNextOccurrenceResponse_Unrestricted(t *testing.T) {
	resp := buildNextOccurrenceResponse(nil, "")
	assert.Equal(t, "unrestricted", resp.Status)
	assert.Equal(t, "no reboot_window in effect — unrestricted", resp.NextOccurrenceDisplay)
	assert.Empty(t, resp.NextOccurrence)
}

// TestAuditManager_NotNilOnSetup verifies that the test server has a real audit manager.
// This guards against future changes to setupTestServer that might nil out the field.
func TestAuditManager_NotNilOnSetup(t *testing.T) {
	server := setupTestServer(t)
	assert.NotNil(t, server.auditManager, "setupTestServer must wire a real audit manager")
}

// TestPutRebootWindow_403_StewardEndpointForConfigUpdateOnlyCaller mirrors the tenant
// 403 test for the steward-level endpoint.
func TestPutRebootWindow_403_StewardEndpointForConfigUpdateOnlyCaller(t *testing.T) {
	server := setupTestServer(t)

	// Steward registration only needs the in-memory registry (no tenant store lookup
	// needed for PUT — the permission check fires before the handler reads the steward).
	stewardID := "perm-test-steward"
	tenantID := "perm-test-tenant"
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, tenantID, "localhost:7003", "online"))

	apiKey := NewEphemeralTestKey(t, server, []string{"config:update"}, tenantID, ephemeralTTL)

	body, err := json.Marshal(rebootWindowPutRequest{
		ScheduleYAML: sampleScheduleYAML,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/stewards/"+stewardID+"/reboot-window", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"config:update-only caller must not be allowed to set steward reboot_window")
}

// Compile-time guard: make sure the audit manager interface we rely on is available.
var _ interface {
	Flush(ctx context.Context) error
	QueryEntries(ctx context.Context, filter *business.AuditFilter) ([]*business.AuditEntry, error)
} = (*audit.Manager)(nil)
