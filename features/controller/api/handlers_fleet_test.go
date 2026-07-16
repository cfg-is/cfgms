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
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fleetTestStewardProvider backs MemoryQuery with a fixed steward list for resolve tests.
type fleetTestStewardProvider struct {
	stewards []fleet.StewardData
}

func (p *fleetTestStewardProvider) GetAllStewards() []fleet.StewardData {
	return p.stewards
}

func makeSeedSteward(id, hostname, os, arch string, tags string) fleet.StewardData {
	return fleet.StewardData{
		ID:            id,
		TenantID:      "tenant-a",
		Status:        "online",
		LastHeartbeat: time.Now(),
		DNAAttributes: map[string]string{
			"hostname": hostname,
			"os":       os,
			"arch":     arch,
			"tags":     tags,
		},
	}
}

// seededFleetQuery returns a MemoryQuery backed by the given stewards.
func seededFleetQuery(stewards ...fleet.StewardData) fleet.FleetQuery {
	return fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: stewards})
}

func postResolveSelector(server *Server, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/resolve",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleResolveSelector(rec, req)
	return rec
}

func postResolveSelectorWithTenant(server *Server, body, tenantID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/resolve",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if tenantID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, tenantID))
	}
	rec := httptest.NewRecorder()
	server.handleResolveSelector(rec, req)
	return rec
}

// ── handleResolveSelector: input validation ───────────────────────────────────

func TestHandleResolveSelector_MissingSelector_Returns400(t *testing.T) {
	server := setupTestServer(t)
	rec := postResolveSelector(server, `{"selector":""}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "MISSING_SELECTOR", resp.Error.Code)
}

func TestHandleResolveSelector_InvalidJSON_Returns400(t *testing.T) {
	server := setupTestServer(t)
	rec := postResolveSelector(server, `not json`)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "INVALID_JSON", resp.Error.Code)
}

func TestHandleResolveSelector_UnknownKey_Returns400(t *testing.T) {
	server := setupTestServer(t)
	rec := postResolveSelector(server, `{"selector":"typo:value"}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "INVALID_SELECTOR", resp.Error.Code)
}

// ── handleResolveSelector: resolution against seeded DNA data ─────────────────

func TestHandleResolveSelector_All_ReturnsAllStewards(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("s1", "web-01", "linux", "amd64", "prod"),
		makeSeedSteward("s2", "db-01", "linux", "arm64", "prod"),
		makeSeedSteward("s3", "win-01", "windows", "amd64", "prod"),
	)

	rec := postResolveSelector(server, `{"selector":"all"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, list, 3)
}

func TestHandleResolveSelector_NameGlob_ExactMatch(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("s1", "es-hv01", "linux", "amd64", "prod"),
		makeSeedSteward("s2", "es-hv02", "linux", "arm64", "prod"),
		makeSeedSteward("s3", "db-server-01", "linux", "amd64", "prod"),
	)

	rec := postResolveSelector(server, `{"selector":"name:es-hv0*"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	// Exactly the two es-hv0* stewards, not db-server.
	assert.Len(t, list, 2)
}

func TestHandleResolveSelector_OS_Filter(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("s1", "linux-host", "linux", "amd64", "prod"),
		makeSeedSteward("s2", "win-host", "windows", "amd64", "prod"),
	)

	rec := postResolveSelector(server, `{"selector":"os:linux"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	require.Len(t, list, 1)

	item := list[0].(map[string]interface{})
	dna := item["dna"].(map[string]interface{})
	assert.Equal(t, "linux", dna["os"])
}

func TestHandleResolveSelector_Combined_NarrowsToOne(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("s1", "es-hv01", "linux", "arm64", "prod,web"),
		makeSeedSteward("s2", "es-hv02", "linux", "amd64", "prod,db"),
		makeSeedSteward("s3", "win-01", "windows", "amd64", "prod"),
	)

	// name glob + os + arch must select exactly s1.
	rec := postResolveSelector(server, `{"selector":"name:es-hv0* os:linux arch:arm64"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	require.Len(t, list, 1)

	item := list[0].(map[string]interface{})
	dna := item["dna"].(map[string]interface{})
	assert.Equal(t, "es-hv01", dna["hostname"])
}

func TestHandleResolveSelector_FleetQueryError_Returns500(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = &failingFleetQuery{}

	rec := postResolveSelector(server, `{"selector":"all"}`)
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "INTERNAL_ERROR", resp.Error.Code)
}

// ── handleResolveSelector: id: selector ──────────────────────────────────────

// TestHandleResolveSelector_IDSelector_SingleMatch verifies that id:<steward-id>
// returns the one matching steward and nothing else (exact match semantics).
func TestHandleResolveSelector_IDSelector_SingleMatch(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("steward-1780659937223058807", "host-a", "linux", "amd64", "prod"),
		makeSeedSteward("steward-other", "host-b", "linux", "arm64", "dev"),
	)

	rec := postResolveSelector(server, `{"selector":"id:steward-1780659937223058807"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	require.Len(t, list, 1, "only the targeted steward should be returned")

	item := list[0].(map[string]interface{})
	assert.Equal(t, "steward-1780659937223058807", item["id"])
}

// TestHandleResolveSelector_IDSelector_NoMatch verifies that id: with an unknown
// steward ID returns an empty result set without error (not 404).
func TestHandleResolveSelector_IDSelector_NoMatch(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("steward-known", "host-a", "linux", "amd64", "prod"),
	)

	rec := postResolveSelector(server, `{"selector":"id:steward-nonexistent"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Empty(t, list, "unknown steward ID must return empty result set, not an error")
}

// TestHandleResolveSelector_IDSelector_MultiValue verifies that id:a,b uses OR
// semantics — a steward matching either ID is included.
func TestHandleResolveSelector_IDSelector_MultiValue(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("steward-abc", "host-a", "linux", "amd64", "prod"),
		makeSeedSteward("steward-def", "host-b", "windows", "amd64", "prod"),
		makeSeedSteward("steward-other", "host-c", "linux", "arm64", "dev"),
	)

	rec := postResolveSelector(server, `{"selector":"id:steward-abc,steward-def"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	require.Len(t, list, 2, "both comma-separated IDs should be returned")

	ids := make([]string, len(list))
	for i, item := range list {
		ids[i] = item.(map[string]interface{})["id"].(string)
	}
	assert.ElementsMatch(t, []string{"steward-abc", "steward-def"}, ids)
}

// TestHandleResolveSelector_IDSelector_AND_WithOS verifies AND semantics when
// id: is combined with another key — the steward must satisfy both.
func TestHandleResolveSelector_IDSelector_AND_WithOS(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("steward-linux", "host-a", "linux", "amd64", "prod"),
		makeSeedSteward("steward-win", "host-b", "windows", "amd64", "prod"),
	)

	// steward-linux + os:windows → no match (AND semantics across keys).
	rec := postResolveSelector(server, `{"selector":"id:steward-linux os:windows"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Empty(t, list, "id: and os: must be AND-combined — no match expected")
}

// TestHandleResolveSelector_IDSelector_UnknownKeyStillRejected verifies that other
// unknown keys remain rejected now that id: is in the accepted set.
func TestHandleResolveSelector_IDSelector_UnknownKeyStillRejected(t *testing.T) {
	server := setupTestServer(t)

	rec := postResolveSelector(server, `{"selector":"unknownkey:value"}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "INVALID_SELECTOR", resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "id", "error message must list id in the valid key set")
}

// ── handleResolveSelector: subtree boundary enforcement ──────────────────────

// postResolveSelectorWithPrincipal sends a resolve request with both a principal
// and a tenant ID in context, simulating an authenticated operator session.
func postResolveSelectorWithPrincipal(server *Server, body, tenantID string, isAdmin bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/resolve",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := req.Context()
	if tenantID != "" {
		ctx = context.WithValue(ctx, ctxkeys.TenantID, tenantID)
	}
	if isAdmin {
		ctx = context.WithValue(ctx, principalContextKey, &Principal{IsAdmin: true, TenantID: ""})
	} else {
		ctx = context.WithValue(ctx, principalContextKey, &Principal{IsAdmin: false, TenantID: tenantID})
	}
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleResolveSelector(rec, req)
	return rec
}

// multiTenantFleet returns a fleet with stewards in several tenant positions for
// subtree boundary tests.
func multiTenantFleet() []fleet.StewardData {
	return []fleet.StewardData{
		{ID: "s-msp-a-client-1", TenantID: "msp-a/client-1", Status: "online",
			LastHeartbeat: time.Now(), DNAAttributes: map[string]string{"hostname": "host-1"}},
		{ID: "s-msp-a-client-1-web", TenantID: "msp-a/client-1/servers/web", Status: "online",
			LastHeartbeat: time.Now(), DNAAttributes: map[string]string{"hostname": "web-1"}},
		{ID: "s-msp-a-client-2", TenantID: "msp-a/client-2", Status: "online",
			LastHeartbeat: time.Now(), DNAAttributes: map[string]string{"hostname": "host-2"}},
		{ID: "s-msp-b-client-1", TenantID: "msp-b/client-1", Status: "online",
			LastHeartbeat: time.Now(), DNAAttributes: map[string]string{"hostname": "host-3"}},
	}
}

// resolveIDs unmarshals the response steward list and returns their IDs.
func resolveIDs(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	ids := make([]string, len(list))
	for i, item := range list {
		ids[i] = item.(map[string]interface{})["id"].(string)
	}
	return ids
}

// TestHandleResolveSelector_SubtreeBoundary_DefaultSubtree verifies that an
// operator with no explicit tenant prefix in the selector sees their entire
// subtree (exact tenant + descendants), not just the exact tenant.
func TestHandleResolveSelector_SubtreeBoundary_DefaultSubtree(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: multiTenantFleet()})

	// Operator at msp-a/client-1 with "all" selector — should see client-1 AND client-1/servers/web.
	rec := postResolveSelectorWithTenant(server, `{"selector":"all"}`, "msp-a/client-1")
	require.Equal(t, http.StatusOK, rec.Code)

	ids := resolveIDs(t, rec)
	assert.Contains(t, ids, "s-msp-a-client-1", "exact tenant must be included")
	assert.Contains(t, ids, "s-msp-a-client-1-web", "descendant tenant must be included")
	assert.NotContains(t, ids, "s-msp-a-client-2", "sibling tenant must be excluded")
	assert.NotContains(t, ids, "s-msp-b-client-1", "different MSP must be excluded")
}

// TestHandleResolveSelector_SubtreeBoundary_ExplicitDescendantAllowed verifies
// that an operator may explicitly target a descendant tenant in their selector.
func TestHandleResolveSelector_SubtreeBoundary_ExplicitDescendantAllowed(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: multiTenantFleet()})

	// Operator at msp-a targets descendant msp-a/client-1/servers/web explicitly.
	rec := postResolveSelectorWithTenant(server, `{"selector":"msp-a/client-1/servers/web/all"}`, "msp-a")
	require.Equal(t, http.StatusOK, rec.Code)

	ids := resolveIDs(t, rec)
	assert.Contains(t, ids, "s-msp-a-client-1-web")
	assert.NotContains(t, ids, "s-msp-a-client-1")
	assert.NotContains(t, ids, "s-msp-a-client-2")
}

// TestHandleResolveSelector_SubtreeBoundary_SiblingRejected verifies that an
// operator cannot target a sibling tenant — the request returns 403.
func TestHandleResolveSelector_SubtreeBoundary_SiblingRejected(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: multiTenantFleet()})

	// Operator at msp-a/client-1 attempts to target msp-a/client-2 — must be 403.
	rec := postResolveSelectorWithTenant(server, `{"selector":"msp-a/client-2/all"}`, "msp-a/client-1")
	require.Equal(t, http.StatusForbidden, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "CROSS_TENANT", resp.Error.Code)
}

// TestHandleResolveSelector_SubtreeBoundary_UnrelatedTenantRejected verifies
// that targeting a completely unrelated tenant returns 403.
func TestHandleResolveSelector_SubtreeBoundary_UnrelatedTenantRejected(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: multiTenantFleet()})

	// Operator at msp-a/client-1 attempts to target msp-b/client-1 — must be 403.
	rec := postResolveSelectorWithTenant(server, `{"selector":"msp-b/client-1/all"}`, "msp-a/client-1")
	require.Equal(t, http.StatusForbidden, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "CROSS_TENANT", resp.Error.Code)
}

// TestHandleResolveSelector_SubtreeBoundary_ParentTargetsDescendant verifies
// that a parent operator can explicitly target a child or grandchild tenant.
func TestHandleResolveSelector_SubtreeBoundary_ParentTargetsDescendant(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: multiTenantFleet()})

	// Operator at msp-a (parent) targets msp-a/client-1 (child).
	rec := postResolveSelectorWithTenant(server, `{"selector":"msp-a/client-1/all"}`, "msp-a")
	require.Equal(t, http.StatusOK, rec.Code)

	ids := resolveIDs(t, rec)
	assert.Contains(t, ids, "s-msp-a-client-1")
	assert.Contains(t, ids, "s-msp-a-client-1-web")
	assert.NotContains(t, ids, "s-msp-a-client-2")
}

// TestHandleResolveSelector_SubtreeBoundary_AdminUnrestricted verifies that an
// admin caller (empty tenant, IsAdmin=true) is not limited by subtree boundaries.
func TestHandleResolveSelector_SubtreeBoundary_AdminUnrestricted(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: multiTenantFleet()})

	// Admin with "all" — must see everything.
	rec := postResolveSelectorWithPrincipal(server, `{"selector":"all"}`, "", true)
	require.Equal(t, http.StatusOK, rec.Code)

	ids := resolveIDs(t, rec)
	assert.Len(t, ids, len(multiTenantFleet()), "admin must see all stewards")
}

// TestHandleResolveSelector_SubtreeBoundary_ExplicitOwnTenantAllowed verifies
// that a caller may explicitly name their own tenant as the selector prefix.
func TestHandleResolveSelector_SubtreeBoundary_ExplicitOwnTenantAllowed(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: multiTenantFleet()})

	// Operator at msp-a/client-1 explicitly targets msp-a/client-1 (themselves).
	rec := postResolveSelectorWithTenant(server, `{"selector":"msp-a/client-1/all"}`, "msp-a/client-1")
	require.Equal(t, http.StatusOK, rec.Code)

	ids := resolveIDs(t, rec)
	assert.Contains(t, ids, "s-msp-a-client-1")
	assert.Contains(t, ids, "s-msp-a-client-1-web")
}

// TestHandleResolveSelector_TenantIsolation verifies that a caller authenticated
// as tenant-a cannot see tenant-b stewards even when the selector would otherwise
// match them (e.g. "all"). The authenticated tenant is always AND-ed onto the filter.
func TestHandleResolveSelector_TenantIsolation(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{
		stewards: []fleet.StewardData{
			{
				ID:            "tenant-a-steward",
				TenantID:      "tenant-a",
				Status:        "online",
				LastHeartbeat: time.Now(),
				DNAAttributes: map[string]string{"hostname": "host-a", "os": "linux", "arch": "amd64"},
			},
			{
				ID:            "tenant-b-steward",
				TenantID:      "tenant-b",
				Status:        "online",
				LastHeartbeat: time.Now(),
				DNAAttributes: map[string]string{"hostname": "host-b", "os": "linux", "arch": "amd64"},
			},
		},
	})

	// Authenticated as tenant-a with an "all" selector — must only see tenant-a's steward.
	rec := postResolveSelectorWithTenant(server, `{"selector":"all"}`, "tenant-a")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	require.Len(t, list, 1, "tenant-a must only see its own steward")

	item := list[0].(map[string]interface{})
	assert.Equal(t, "tenant-a-steward", item["id"])
}

// TestHandleResolveSelector_TenantIDPresentInResponse verifies that the
// tenant_id field is populated on each resolved StewardInfo entry, completing
// the contract the CLI-side StewardInfo type already declares.
func TestHandleResolveSelector_TenantIDPresentInResponse(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("steward-123", "hv01", "linux", "amd64", "prod"),
	)
	// makeSeedSteward hard-codes TenantID = "tenant-a" in the fleet data;
	// the handler must now forward it in the JSON response.

	rec := postResolveSelector(server, `{"selector":"all"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	list, ok := resp.Data.([]interface{})
	require.True(t, ok)
	require.Len(t, list, 1)

	item := list[0].(map[string]interface{})
	assert.Equal(t, "tenant-a", item["tenant_id"],
		"tenant_id must be present in the resolve response so the CLI can derive it without a second round-trip")
}
