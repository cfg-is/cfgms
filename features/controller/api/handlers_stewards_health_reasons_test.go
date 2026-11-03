// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func getStewardJSON(t *testing.T, server *Server, key, id string) (int, StewardInfo) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/"+id, nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	if rec.Code == http.StatusOK {
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	}
	return rec.Code, resp.Data
}

// wireSharedStewardStore gives the server and its controller service one real store.
func wireSharedStewardStore(t *testing.T, server *Server) business.StewardStore {
	t.Helper()
	st := newTestSQLiteStewardStore(t)
	server.SetStewardStore(st)
	server.controllerService.SetStewardStore(st)
	return st
}

// TestHandleGetSteward_HealthReasons verifies Issue #5651: GET returns the
// persisted reasons, and a caller scoped to another tenant gets a 404 with no
// reasons.
func TestHandleGetSteward_HealthReasons(t *testing.T) {
	server := setupTestServer(t)
	seedTenantTree(t, server)
	st := wireSharedStewardStore(t, server)

	id := registerTestStewardWithDNA(t, server, map[string]string{"hostname": "h-reasons", "os": "linux"}, "msp-a")
	seedSteward(t, st, &business.StewardRecord{ID: id, TenantID: "msp-a", Status: business.StewardStatusActive})
	server.controllerService.RecordHealthReasons(id, []controlplaneTypes.HealthReason{
		{Component: "disk", Code: "disk.low", Message: "free space below 5%"},
		{Component: "module", Code: "module.failed"},
	})

	own := NewEphemeralTestKey(t, server, []string{"steward:read", "steward:list"}, "msp-a", 5*time.Minute)
	code, got := getStewardJSON(t, server, own, id)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, []HealthReasonInfo{
		{Component: "disk", Code: "disk.low", Message: "free space below 5%"},
		{Component: "module", Code: "module.failed"},
	}, got.HealthReasons)

	other := NewEphemeralTestKey(t, server, []string{"steward:read", "steward:list"}, "msp-b", 5*time.Minute)
	code, got = getStewardJSON(t, server, other, id)
	assert.Equal(t, http.StatusNotFound, code)
	assert.Empty(t, got.HealthReasons, "a caller outside the tenant scope must not see reasons")

	// Cleared when the steward reports none.
	server.controllerService.RecordHealthReasons(id, nil)
	_, got = getStewardJSON(t, server, own, id)
	assert.Empty(t, got.HealthReasons)
}

// TestHandleGetSteward_HealthReasons_PeerNode verifies two controller nodes
// sharing a store return the same reasons for a steward attached to only one.
func TestHandleGetSteward_HealthReasons_PeerNode(t *testing.T) {
	nodeA := setupTestServer(t)
	seedTenantTree(t, nodeA)
	st := wireSharedStewardStore(t, nodeA)

	nodeB := setupTestServer(t)
	seedTenantTree(t, nodeB)
	nodeB.SetStewardStore(st)
	nodeB.controllerService.SetStewardStore(st)

	id := registerTestStewardWithDNA(t, nodeA, map[string]string{"hostname": "h-peer", "os": "linux"}, "msp-a")
	seedSteward(t, st, &business.StewardRecord{ID: id, TenantID: "msp-a", Status: business.StewardStatusActive})
	_, attached := nodeB.controllerService.GetStewardInfo(id)
	require.False(t, attached, "precondition: steward is attached only to node A")

	nodeA.controllerService.RecordHealthReasons(id, []controlplaneTypes.HealthReason{{Component: "net", Code: "net.down", Message: "m"}})

	want := []HealthReasonInfo{{Component: "net", Code: "net.down", Message: "m"}}
	keyA := NewEphemeralTestKey(t, nodeA, []string{"steward:read", "steward:list"}, "msp-a", 5*time.Minute)
	keyB := NewEphemeralTestKey(t, nodeB, []string{"steward:read", "steward:list"}, "msp-a", 5*time.Minute)
	codeA, gotA := getStewardJSON(t, nodeA, keyA, id)
	codeB, gotB := getStewardJSON(t, nodeB, keyB, id)
	require.Equal(t, http.StatusOK, codeA)
	require.Equal(t, http.StatusOK, codeB)
	assert.Equal(t, want, gotA.HealthReasons)
	assert.Equal(t, want, gotB.HealthReasons)
}

// TestHandleListStewards_HealthReasons covers all list branches: unfiltered
// (node-local + durable overlay) and filtered, with tenant scoping.
func TestHandleListStewards_HealthReasons(t *testing.T) {
	server := setupTestServer(t)
	seedTenantTree(t, server)
	st := wireSharedStewardStore(t, server)

	idA := registerTestStewardWithDNA(t, server, map[string]string{"hostname": "list-a", "os": "linux"}, "msp-a")
	idB := registerTestStewardWithDNA(t, server, map[string]string{"hostname": "list-b", "os": "linux"}, "msp-b")
	seedSteward(t, st, &business.StewardRecord{ID: idA, TenantID: "msp-a", Status: business.StewardStatusActive})
	seedSteward(t, st, &business.StewardRecord{ID: idB, TenantID: "msp-b", Status: business.StewardStatusActive})
	// A peer-attached steward: durable record only.
	seedSteward(t, st, &business.StewardRecord{ID: "peer-1", TenantID: "msp-a", Status: business.StewardStatusActive})

	reason := []controlplaneTypes.HealthReason{{Component: "disk", Code: "disk.low"}}
	server.controllerService.RecordHealthReasons(idA, reason)
	server.controllerService.RecordHealthReasons(idB, reason)
	server.controllerService.RecordHealthReasons("peer-1", reason)

	list := func(key, query string) map[string][]HealthReasonInfo {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards"+query, nil)
		req.Header.Set("X-API-Key", key)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp struct {
			Data []StewardInfo `json:"data"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		out := map[string][]HealthReasonInfo{}
		for _, s := range resp.Data {
			out[s.ID] = s.HealthReasons
		}
		return out
	}

	keyA := NewEphemeralTestKey(t, server, []string{"steward:read", "steward:list"}, "msp-a", 5*time.Minute)
	want := []HealthReasonInfo{{Component: "disk", Code: "disk.low"}}

	got := list(keyA, "")
	assert.Equal(t, want, got[idA], "node-local row")
	assert.Equal(t, want, got["peer-1"], "durable overlay row")
	_, seesB := got[idB]
	assert.False(t, seesB, "other tenant's steward must not be listed")

	got = list(keyA, "?os=linux")
	assert.Equal(t, want, got[idA], "filtered row")
	_, seesB = got[idB]
	assert.False(t, seesB)

	got = list(keyA, "?q=list-a")
	if assert.Contains(t, got, idA) {
		assert.Equal(t, want, got[idA], "selector row")
	}
}

// TestHandleFleetHealth_ReasonCounts verifies reason_counts is scoped to the
// caller's tenants and counts each steward once per code.
func TestHandleFleetHealth_ReasonCounts(t *testing.T) {
	now := time.Now()
	server := setupTestServer(t)
	st := wireSharedStewardStore(t, server)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{
		stewards: []fleet.StewardData{
			{ID: "a1", TenantID: "tenant-a", Status: "active", LastHeartbeat: now},
			{ID: "a2", TenantID: "tenant-a", Status: "active", LastHeartbeat: now},
			{ID: "b1", TenantID: "tenant-b", Status: "active", LastHeartbeat: now},
		},
	})
	for _, rec := range []*business.StewardRecord{
		{ID: "a1", TenantID: "tenant-a", Status: business.StewardStatusActive},
		{ID: "a2", TenantID: "tenant-a", Status: business.StewardStatusActive},
		{ID: "b1", TenantID: "tenant-b", Status: business.StewardStatusActive},
	} {
		seedSteward(t, st, rec)
	}
	ctx := context.Background()
	require.NoError(t, st.SetHealthReasons(ctx, "a1", []business.HealthReasonRecord{{Component: "disk", Code: "disk.low"}, {Component: "disk", Code: "disk.low"}, {Component: "net", Code: "net.down"}}))
	require.NoError(t, st.SetHealthReasons(ctx, "a2", []business.HealthReasonRecord{{Component: "disk", Code: "disk.low"}}))
	require.NoError(t, st.SetHealthReasons(ctx, "b1", []business.HealthReasonRecord{{Component: "disk", Code: "disk.low"}, {Component: "x", Code: "only.b"}}))

	decode := func(rec *httptest.ResponseRecorder) map[string]int {
		require.Equal(t, http.StatusOK, rec.Code)
		var resp struct {
			Data struct {
				ReasonCounts map[string]int `json:"reason_counts"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.Data.ReasonCounts
	}

	assert.Equal(t, map[string]int{"disk.low": 3, "net.down": 1, "only.b": 1}, decode(getFleetHealth(server)))
	assert.Equal(t, map[string]int{"disk.low": 2, "net.down": 1}, decode(getFleetHealthWithTenant(server, "tenant-a")),
		"a tenant-scoped caller counts only its own stewards' reasons")
}

// TestHealthReasonsFromRecord_Truncates verifies over-long fields are cut
// before they are returned, even if a record carries them.
func TestHealthReasonsFromRecord_Truncates(t *testing.T) {
	long := strings.Repeat("z", 3000)
	out := healthReasonsFromRecord(&business.StewardRecord{HealthReasons: []business.HealthReasonRecord{{Component: long, Code: long, Message: long}}})
	require.Len(t, out, 1)
	assert.Len(t, out[0].Component, controlplaneTypes.MaxHealthReasonComponent)
	assert.Len(t, out[0].Code, controlplaneTypes.MaxHealthReasonCode)
	assert.Len(t, out[0].Message, controlplaneTypes.MaxHealthReasonMessageLen)
	assert.Nil(t, healthReasonsFromRecord(&business.StewardRecord{}))
}
