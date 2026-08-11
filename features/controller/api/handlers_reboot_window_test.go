// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"time"

	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
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

// TestRebootWindowPermissions_GrantableThroughCreateAPIKey verifies that a
// least-privilege credential can actually be minted holding the reboot_window
// permissions, and that such a credential reaches the endpoints.
//
// The other tests in this file mint keys via NewEphemeralTestKey, which bypasses
// isKnownPermission; that path cannot detect a permission that is enforced on a route
// and registered in the RBAC catalog but missing from the knownPermissions allow-list.
// With such a gap, handleCreateAPIKey rejects the permission with 400 INVALID_PERMISSION
// and the only principal able to reach the routes is an unscoped one (Permissions == nil,
// which hasPermission blanket-allows) — the privilege inflation ADR-026 decision 3 exists
// to avoid. This test goes through handleCreateAPIKey so that gap fails the suite.
func TestRebootWindowPermissions_GrantableThroughCreateAPIKey(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	tenantID := "least-priv-tenant"
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: tenantID, Name: tenantID})
	require.NoError(t, err)

	createBody := []byte(`{"name":"reboot-window-key","tenant_id":"` + tenantID +
		`","permissions":["reboot_window:read","reboot_window:override"]}`)
	createRec := callHandleCreateAPIKey(server, createBody, tenantID)
	require.Equal(t, http.StatusCreated, createRec.Code,
		"reboot_window permissions must be grantable to a scoped API key: %s", createRec.Body.String())

	var created struct {
		Data struct {
			Key         string   `json:"key"`
			Permissions []string `json:"permissions"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &created))
	require.NotEmpty(t, created.Data.Key, "plaintext key must be returned on creation")
	assert.ElementsMatch(t,
		[]string{"reboot_window:read", "reboot_window:override"}, created.Data.Permissions,
		"created key must carry exactly the requested reboot_window permissions")

	// The scoped key (Permissions != nil) must be accepted by both routes.
	putBody, err := json.Marshal(rebootWindowPutRequest{ScheduleYAML: sampleScheduleYAML})
	require.NoError(t, err)
	putReq := httptest.NewRequest(http.MethodPut,
		"/api/v1/tenants/"+tenantID+"/reboot-window", bytes.NewReader(putBody))
	putReq.Header.Set("X-API-Key", created.Data.Key)
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	server.router.ServeHTTP(putRec, putReq)
	require.Equal(t, http.StatusOK, putRec.Code,
		"scoped reboot_window:override key must be authorised for PUT: %s", putRec.Body.String())

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID+"/reboot-window", nil)
	getReq.Header.Set("X-API-Key", created.Data.Key)
	getRec := httptest.NewRecorder()
	server.router.ServeHTTP(getRec, getReq)
	require.Equal(t, http.StatusOK, getRec.Code,
		"scoped reboot_window:read key must be authorised for GET: %s", getRec.Body.String())

	// The key really is scoped: it must not inherit unrelated authority.
	server.mu.RLock()
	stored := server.apiKeys[created.Data.Key]
	server.mu.RUnlock()
	require.NotNil(t, stored, "created key must be registered for authentication")
	assert.NotNil(t, stored.Permissions,
		"created key must carry an explicit permission set, not the blanket-allow nil set")
}

// TestRebootWindowPermissions_InRBACCatalogAndAllowList verifies that every
// reboot_window permission enforced on a route is simultaneously present in the RBAC
// catalog and in the knownPermissions allow-list. A permission in only one of the two
// is unusable: enforced but ungrantable.
func TestRebootWindowPermissions_InRBACCatalogAndAllowList(t *testing.T) {
	for _, permID := range []string{"reboot_window:read", "reboot_window:override"} {
		assert.True(t, isKnownPermission(permID),
			"%s is enforced by requirePermission but absent from knownPermissions, so no "+
				"scoped API key or web account can ever hold it", permID)
	}

	// Catalog IDs use dots where the API permission IDs use a colon separator.
	catalog := make(map[string]bool)
	for _, p := range rbac.DefaultPermissions {
		catalog[p.Id] = true
	}
	assert.True(t, catalog["reboot_window.read"], "reboot_window.read must be in the RBAC catalog")
	assert.True(t, catalog["reboot_window.override"], "reboot_window.override must be in the RBAC catalog")
}

// TestGetStewardRebootWindow_CrossTenantCaller_404 verifies tenant isolation on
// GET /api/v1/stewards/{id}/reboot-window: a caller scoped to tenant A holding
// reboot_window:read must not be able to read the window of a steward in tenant B.
//
// The permission middleware cannot catch this — these routes name a steward under
// {id} with resourceType "reboot_window", so extractTargetTenantFromRequest resolves
// to "" and the isolation-engine check is skipped. The refusal must come from the
// handler, and must be 404 (not 403) so the status code is not an existence oracle
// for steward IDs in other tenants.
func TestGetStewardRebootWindow_CrossTenantCaller_404(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	victimTenant := "iso-victim-tenant"
	attackerTenant := "iso-attacker-tenant"
	stewardID := "iso-victim-steward"

	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: victimTenant, Name: victimTenant})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: attackerTenant, Name: attackerTenant})
	require.NoError(t, err)
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, victimTenant, "localhost:7010", "online"))

	attackerKey := NewEphemeralTestKey(t, server, []string{"reboot_window:read"}, attackerTenant, ephemeralTTL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/"+stewardID+"/reboot-window", nil)
	req.Header.Set("X-API-Key", attackerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant steward reboot_window read must be refused: %s", rec.Body.String())
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code,
		"refusal must be indistinguishable from an unknown steward")
}

// TestPutStewardRebootWindow_CrossTenantCaller_404_NoWrite verifies the write side of
// the same boundary: a caller scoped to tenant A holding reboot_window:override must
// not be able to overwrite the reboot window of a steward in tenant B, and no config
// document may be written for the victim steward.
func TestPutStewardRebootWindow_CrossTenantCaller_404_NoWrite(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	victimTenant := "write-victim-tenant"
	attackerTenant := "write-attacker-tenant"
	stewardID := "write-victim-steward"

	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: victimTenant, Name: victimTenant})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: attackerTenant, Name: attackerTenant})
	require.NoError(t, err)
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, victimTenant, "localhost:7011", "online"))

	attackerKey := NewEphemeralTestKey(t, server, []string{"reboot_window:override"}, attackerTenant, ephemeralTTL)

	body, err := json.Marshal(rebootWindowPutRequest{ScheduleYAML: sampleScheduleYAML})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/stewards/"+stewardID+"/reboot-window", bytes.NewReader(body))
	req.Header.Set("X-API-Key", attackerKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant steward reboot_window write must be refused: %s", rec.Body.String())
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)

	// Nothing may have been persisted against the victim steward's tenant.
	configStore := server.rebootWindowConfigStore()
	require.NotNil(t, configStore, "test server must expose a config store")
	stored, getErr := configStore.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  victimTenant,
		Namespace: "stewards",
		Name:      stewardID,
	})
	require.Error(t, getErr, "refused cross-tenant PUT must not have written a config doc")
	assert.True(t, errors.Is(getErr, cfgconfig.ErrConfigNotFound),
		"expected ErrConfigNotFound, got %v", getErr)
	assert.Nil(t, stored)
}

// TestGetStewardRebootWindow_RootScopedCallerWithoutCrossing_Challenged verifies the
// ADR-025 Decision 1 root<->MSP boundary on the steward reboot_window endpoints. The
// middleware's boundary check also resolves to "" for these routes (the steward's
// tenant is only knowable after a registry lookup), so a root-scoped operator would
// otherwise reach an MSP tenant's steward with no active crossing and no break-glass
// record.
func TestGetStewardRebootWindow_RootScopedCallerWithoutCrossing_Challenged(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()

	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-rw", ParentID: "root"})
	require.NoError(t, err)

	stewardID := "msp-rw-steward"
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, "msp-rw", "localhost:7012", "online"))

	caller := rootScopedPrincipal("root-operator-rw")
	req := requestAsPrincipal(t, http.MethodGet,
		"/api/v1/stewards/"+stewardID+"/reboot-window", stewardID, caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetStewardRebootWindow(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code,
		"root-scoped caller without a crossing must get a tenant-crossing challenge")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)

	var challenge map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&challenge))
	assert.Equal(t, "tenant_crossing_required", challenge["error"])
	assert.Equal(t, "/api/v1/tenants/msp-rw/break-glass", challenge["break_glass_endpoint"])
}

// TestPutStewardRebootWindow_RootScopedCallerWithActiveCrossing_Allowed is the
// counterpart: the same root-scoped caller with an active grant on the MSP tenant must
// be let through and the write must land under the steward's own tenant.
func TestPutStewardRebootWindow_RootScopedCallerWithActiveCrossing_Allowed(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()

	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-rw2", ParentID: "root"})
	require.NoError(t, err)

	stewardID := "msp-rw2-steward"
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, "msp-rw2", "localhost:7013", "online"))

	caller := rootScopedPrincipal("root-operator-rw2")
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID:          "grant-reboot-window-1",
		TenantID:    "msp-rw2",
		PrincipalID: caller.ID,
		Kind:        business.TenantCrossingKindGrant,
		GrantedBy:   "msp-rw2-admin",
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Hour),
	}))

	body, err := json.Marshal(rebootWindowPutRequest{ScheduleYAML: sampleScheduleYAML})
	require.NoError(t, err)
	req := requestAsPrincipal(t, http.MethodPut,
		"/api/v1/stewards/"+stewardID+"/reboot-window", stewardID, caller, body)
	rec := httptest.NewRecorder()
	server.handlePutStewardRebootWindow(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"an active crossing must let the root-scoped caller through: %s", rec.Body.String())

	stored, getErr := server.rebootWindowConfigStore().GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  "msp-rw2",
		Namespace: "stewards",
		Name:      stewardID,
	})
	require.NoError(t, getErr, "write must land under the steward's own tenant")
	require.NotNil(t, stored)
}

// Compile-time guard: make sure the audit manager interface we rely on is available.
var _ interface {
	Flush(ctx context.Context) error
	QueryEntries(ctx context.Context, filter *business.AuditFilter) ([]*business.AuditEntry, error)
} = (*audit.Manager)(nil)
