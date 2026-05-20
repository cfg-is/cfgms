// SPDX-License-Identifier: Apache-2.0
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
