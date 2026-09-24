// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
)

// TestHandleListModules_ReturnsAllStatuses verifies that GET /api/v1/modules
// returns every cache entry regardless of approval status (Issue #4270, AC1) —
// unlike GET /api/v1/modules/approvals, which filters to pending only.
func TestHandleListModules_ReturnsAllStatuses(t *testing.T) {
	server, mc, _ := setupModuleApprovalServer(t)

	pendingAddr := makePendingBundle(t, mc, "cfgms", "hyperv", "0.2.1")
	approvedAddr := makePendingBundle(t, mc, "cfgms", "firewall", "1.0.0")
	require.NoError(t, mc.SetApprovalStatus(approvedAddr, cache.ApprovalStatusApproved))

	listKey := NewTestKey(t, server, []string{"module:list-approvals"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modules", nil)
	req.Header.Set("X-API-Key", listKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)

	modules, ok := data["modules"].([]interface{})
	require.True(t, ok)
	require.Len(t, modules, 2)
	assert.EqualValues(t, 2, data["total"])

	byName := map[string]map[string]interface{}{}
	for _, m := range modules {
		entry, ok := m.(map[string]interface{})
		require.True(t, ok)
		byName[entry["name"].(string)] = entry
	}

	pending := byName["hyperv"]
	require.NotNil(t, pending)
	assert.Equal(t, pendingAddr.Publisher, pending["publisher"])
	assert.Equal(t, pendingAddr.Version, pending["version"])
	assert.Equal(t, string(cache.ApprovalStatusPending), pending["status"])

	approved := byName["firewall"]
	require.NotNil(t, approved)
	assert.Equal(t, string(cache.ApprovalStatusApproved), approved["status"])
}

// TestHandleListModules_StatusFilter verifies the ?status= query filter maps
// 1:1 onto cache.ApprovalStatus (Issue #4270, AC1).
func TestHandleListModules_StatusFilter(t *testing.T) {
	server, mc, _ := setupModuleApprovalServer(t)

	makePendingBundle(t, mc, "cfgms", "hyperv", "0.2.1")
	approvedAddr := makePendingBundle(t, mc, "cfgms", "firewall", "1.0.0")
	require.NoError(t, mc.SetApprovalStatus(approvedAddr, cache.ApprovalStatusApproved))

	listKey := NewTestKey(t, server, []string{"module:list-approvals"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modules?status=pending", nil)
	req.Header.Set("X-API-Key", listKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data := resp.Data.(map[string]interface{})
	modules := data["modules"].([]interface{})
	require.Len(t, modules, 1)
	entry := modules[0].(map[string]interface{})
	assert.Equal(t, "hyperv", entry["name"])
	assert.EqualValues(t, 1, data["total"])
}

// TestHandleListModules_InvalidStatusFilter verifies an unknown ?status= value
// is rejected client-side (400), not silently ignored.
func TestHandleListModules_InvalidStatusFilter(t *testing.T) {
	server, _, _ := setupModuleApprovalServer(t)

	listKey := NewTestKey(t, server, []string{"module:list-approvals"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modules?status=bogus", nil)
	req.Header.Set("X-API-Key", listKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "INVALID_STATUS", errResp.Error.Code)
}

// TestHandleListModules_EmptyCache returns an empty modules list and total 0.
func TestHandleListModules_EmptyCache(t *testing.T) {
	server, _, _ := setupModuleApprovalServer(t)

	listKey := NewTestKey(t, server, []string{"module:list-approvals"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modules", nil)
	req.Header.Set("X-API-Key", listKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data := resp.Data.(map[string]interface{})
	assert.Empty(t, data["modules"])
	assert.EqualValues(t, 0, data["total"])
}

// TestHandleListModules_NilCacheReturns503 verifies that the endpoint returns
// 503 when moduleCacheLister is not configured.
func TestHandleListModules_NilCacheReturns503(t *testing.T) {
	server := setupTestServer(t)
	// moduleCacheLister is nil (no SetModuleResolution call).

	listKey := NewTestKey(t, server, []string{"module:list-approvals"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modules", nil)
	req.Header.Set("X-API-Key", listKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "SERVICE_UNAVAILABLE", errResp.Error.Code)
}

// TestHandleListModules_PermissionRequired verifies a caller lacking
// module:list-approvals is rejected — the new route reuses that permission
// rather than introducing a new ID (Issue #4270 design decision).
func TestHandleListModules_PermissionRequired(t *testing.T) {
	server, _, _ := setupModuleApprovalServer(t)

	// A key with an unrelated permission must not be able to list modules.
	otherKey := NewTestKey(t, server, []string{"account:list"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modules", nil)
	req.Header.Set("X-API-Key", otherKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
