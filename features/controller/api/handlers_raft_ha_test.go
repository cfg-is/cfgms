// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// TestRaftStatus_AuthorizedRequest_Returns200 verifies that an authenticated request
// with the ha:read-status permission returns 200 when a real ClusterMode HA manager
// is available. A real raftTransport is wired by newClusterModeHAManager so that
// handleRaftStatus can delegate to transport.HandleStatus.
func TestRaftStatus_AuthorizedRequest_Returns200(t *testing.T) {
	certMgr := newTLSTestCertManager(t)
	haManager := newClusterModeHAManager(t, "", certMgr)

	// Set up a fully-wired test server and inject the commercial HA manager.
	// The router and authentication middleware were registered during New(), so
	// changing haManager here only affects what the handler reads at request time.
	server := setupTestServer(t)
	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()

	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/raft/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code,
		"authorized request with ha:read-status permission and a running HA manager must return 200")
}

// TestHandleRaftMessage_NilHAManager_Returns503 exercises the first nil guard in
// handleRaftMessage: with no HA manager wired (the default for setupRouteTestServer),
// POST /raft/message on the internal router must return 503 with the plain-text
// "HA manager not available" body written by http.Error — not a panic and not a
// delegation to a nil transport.
func TestHandleRaftMessage_NilHAManager_Returns503(t *testing.T) {
	s := setupRouteTestServer(t)
	require.Nil(t, s.getHAManager(), "test server must start with no HA manager wired")

	req := httptest.NewRequest(http.MethodPost, "/raft/message", nil)
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	s.internalRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"POST /raft/message must return 503 when no HA manager is wired")
	assert.Equal(t, "HA manager not available", strings.TrimSpace(rec.Body.String()),
		"503 body must name the missing dependency without exposing internals")
}

// TestHandleRaftMessage_NilRaftTransport_Returns503 exercises the second nil guard in
// handleRaftMessage: a real HA manager is wired, but it runs in SingleServerMode, so
// RaftConsensus is never initialized and Manager.GetRaftTransport() returns nil. The
// handler must return 503 rather than calling HandleMessage on a nil transport.
func TestHandleRaftMessage_NilRaftTransport_Returns503(t *testing.T) {
	s := setupRouteTestServer(t)

	// SingleServerMode manager: no Raft consensus, hence no Raft transport.
	haManager := newHAManagerWithCAPEM(t, nil)
	require.Nil(t, haManager.GetRaftTransport(),
		"SingleServerMode manager must expose no Raft transport")

	s.mu.Lock()
	s.haManager = haManager
	s.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/raft/message", nil)
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	s.internalRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"POST /raft/message must return 503 when the HA manager has no Raft transport")
	assert.Equal(t, "Raft transport not available", strings.TrimSpace(rec.Body.String()),
		"503 body must distinguish a missing transport from a missing HA manager")
}

// TestHandleRaftStatus_NilHAManager_Returns503 exercises the first nil guard in
// handleRaftStatus: an authorized request with ha:read-status must return 503 (not 500,
// not a panic) when no HA manager is wired, with the JSON error envelope produced by
// respondError.
func TestHandleRaftStatus_NilHAManager_Returns503(t *testing.T) {
	server := setupTestServer(t)
	require.Nil(t, server.getHAManager(), "test server must start with no HA manager wired")

	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/raft/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code,
		"/api/v1/raft/status must return 503 when no HA manager is wired")

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp),
		"503 response must be the JSON error envelope")
	assert.Equal(t, "HA manager not available", resp["error"])
}

// TestHandleRaftStatus_NilRaftTransport_Returns503 exercises the second nil guard in
// handleRaftStatus: a real SingleServerMode HA manager is wired but has no Raft
// transport, so the handler must return 503 instead of delegating to HandleStatus.
func TestHandleRaftStatus_NilRaftTransport_Returns503(t *testing.T) {
	server := setupTestServer(t)

	haManager := newHAManagerWithCAPEM(t, nil)
	require.Nil(t, haManager.GetRaftTransport(),
		"SingleServerMode manager must expose no Raft transport")

	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()

	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/raft/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code,
		"/api/v1/raft/status must return 503 when the HA manager has no Raft transport")

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp),
		"503 response must be the JSON error envelope")
	assert.Equal(t, "Raft transport not available", resp["error"],
		"503 body must distinguish a missing transport from a missing HA manager")
}

// TestBothStatusSurfaces_NonLeader_IsLeaderAndRaftIsLeaderAgree is the REQUIRED
// inter-surface agreement test for Issue #3435. It verifies that both status
// surfaces — GET /api/v1/raft/status (raftStatusResponse) and GET /api/v1/ha/status
// (HAStatusResponse) — report the same is_leader value for the same underlying
// manager state, and that both surfaces expose the raft_is_leader field introduced
// by this story.
//
// The non-leader case is used here because it is deterministic: newClusterModeHAManager
// uses RestartNode with no bootstrapped voter configuration, so the node stays a
// follower (IsRaftLeader=false, HasLeadership=false) throughout the test. Both
// surfaces must therefore report is_leader=false and raft_is_leader=false.
//
// The lease-expired-but-Raft-leader case requires internal access to RaftConsensus
// and is covered in pkg/ha/raft_transport_test.go:TestHandleStatus_BothSurfacesAgreeOnIsLeader.
func TestBothStatusSurfaces_NonLeader_IsLeaderAndRaftIsLeaderAgree(t *testing.T) {
	certMgr := newTLSTestCertManager(t)
	haManager := newClusterModeHAManager(t, "", certMgr)

	server := setupTestServer(t)
	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()

	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	// Query /api/v1/raft/status (raftStatusResponse surface).
	raftReq := httptest.NewRequest("GET", "/api/v1/raft/status", nil)
	raftReq.Header.Set("X-API-Key", apiKey)
	raftW := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(raftW, raftReq)
	require.Equal(t, 200, raftW.Code, "/api/v1/raft/status must return 200 with ClusterMode HA manager")

	var raftStatus struct {
		IsLeader     bool `json:"is_leader"`
		RaftIsLeader bool `json:"raft_is_leader"`
	}
	require.NoError(t, json.NewDecoder(raftW.Body).Decode(&raftStatus),
		"/api/v1/raft/status response must be valid JSON")

	// Query /api/v1/ha/status (HAStatusResponse surface).
	haReq := httptest.NewRequest("GET", "/api/v1/ha/status", nil)
	haReq.Header.Set("X-API-Key", apiKey)
	haW := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(haW, haReq)
	require.Equal(t, 200, haW.Code, "/api/v1/ha/status must return 200")

	var haStatus struct {
		IsLeader     bool `json:"is_leader"`
		RaftIsLeader bool `json:"raft_is_leader"`
	}
	require.NoError(t, json.NewDecoder(haW.Body).Decode(&haStatus),
		"/api/v1/ha/status response must be valid JSON")

	// Both surfaces must agree on is_leader for the same underlying manager state.
	assert.Equal(t, haStatus.IsLeader, raftStatus.IsLeader,
		"both status surfaces must agree on is_leader for the same underlying manager state")

	// Both surfaces must report false: the follower node has no lease-backed authority.
	assert.False(t, raftStatus.IsLeader,
		"/api/v1/raft/status is_leader must be false for a non-leader node")
	assert.False(t, haStatus.IsLeader,
		"/api/v1/ha/status is_leader must be false for a non-leader node")

	// Both surfaces must expose raft_is_leader (new field from this story).
	assert.False(t, raftStatus.RaftIsLeader,
		"/api/v1/raft/status raft_is_leader must be false for a non-leader node")
	assert.False(t, haStatus.RaftIsLeader,
		"/api/v1/ha/status raft_is_leader must be false for a non-leader node")
}

// TestHAStatus_NonLeader_IsLeaderFalse_RaftIsLeaderFalse verifies the shape of
// HAStatusResponse for a non-leader node: is_leader=false (from HasLeadership),
// raft_is_leader=false (from IsRaftLeader).
func TestHAStatus_NonLeader_IsLeaderFalse_RaftIsLeaderFalse(t *testing.T) {
	certMgr := newTLSTestCertManager(t)
	haManager := newClusterModeHAManager(t, "", certMgr)

	server := setupTestServer(t)
	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()

	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/ha/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(w, req)

	require.Equal(t, 200, w.Code, "/api/v1/ha/status must return 200")

	var resp HAStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.False(t, resp.IsLeader,
		"is_leader must be false: non-leader node has no lease-backed authority (HasLeadership() = false)")
	assert.False(t, resp.RaftIsLeader,
		"raft_is_leader must be false: non-leader node is not Raft leader (IsRaftLeader() = false)")
}

// TestHAStatus_AbsentCapabilities_ReportedToAuthorizedCaller verifies that a
// deployment missing an optional capability reports it in GET /api/v1/ha/status
// with the capability name, subsystem, consequence, and provider — satisfying the
// REQUIRED TEST from Issue #3409: "A deployment missing an optional capability
// reports it; a deployment with all capabilities reports none."
func TestHAStatus_AbsentCapabilities_ReportedToAuthorizedCaller(t *testing.T) {
	server := setupTestServer(t)

	// Wire a SingleServerMode HA manager so handleHAStatus proceeds past the nil guard.
	haManager := newHAManagerWithCAPEM(t, nil)
	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()

	// Wire one absent optional capability — the push subsystem's PushStore, the
	// motivating case from Issue #3409 (cluster controller with no push-state store).
	absent := []interfaces.AbsentCapability{
		{
			Capability:  "PushStore",
			Subsystem:   "push",
			Consequence: "Push-state is not persisted — in-flight config pushes may not resume after a controller restart (provider: flatfile)",
			Provider:    "flatfile",
		},
	}
	server.SetAbsentCapabilities(absent)

	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ha/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp HAStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	require.Len(t, resp.AbsentCapabilities, 1,
		"one absent optional capability must be reported")
	got := resp.AbsentCapabilities[0]
	assert.Equal(t, "PushStore", got.Capability)
	assert.Equal(t, "push", got.Subsystem)
	assert.Equal(t, "flatfile", got.Provider)
	assert.NotEmpty(t, got.Consequence,
		"consequence must be non-empty so the operator knows what the absence means")
}

// TestHAStatus_AllCapabilitiesPresent_ReportsNone verifies the complement: when no
// optional capabilities are absent, the absent_capabilities field is either absent
// or empty — the operator can read "no degradation" from the status output.
func TestHAStatus_AllCapabilitiesPresent_ReportsNone(t *testing.T) {
	server := setupTestServer(t)

	// Wire a SingleServerMode HA manager so handleHAStatus proceeds past the nil guard.
	haManager := newHAManagerWithCAPEM(t, nil)
	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()
	// Do not call SetAbsentCapabilities — the default is nil/empty.

	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ha/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp HAStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.Empty(t, resp.AbsentCapabilities,
		"a deployment with all capabilities present must report an empty absent_capabilities list")
}

// TestHAStatus_AbsentCapabilities_NotExposedToUnauthenticatedCaller verifies that
// absent-capability detail is NOT exposed to callers who do not hold the
// ha:read-status permission — satisfying the REQUIRED TEST from Issue #3409:
// "The information is not exposed to callers who should not see administrative
// detail, with a negative case for the scoping."
func TestHAStatus_AbsentCapabilities_NotExposedToUnauthenticatedCaller(t *testing.T) {
	server := setupTestServer(t)

	// Wire a SingleServerMode HA manager and absent capabilities — the handler
	// would return capability detail if the caller were authenticated.
	haManager := newHAManagerWithCAPEM(t, nil)
	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()

	absent := []interfaces.AbsentCapability{
		{
			Capability:  "PushStore",
			Subsystem:   "push",
			Consequence: "Push-state is not persisted — in-flight config pushes may not resume after a controller restart (provider: flatfile)",
			Provider:    "flatfile",
		},
	}
	server.SetAbsentCapabilities(absent)

	// Unauthenticated request — no API key.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ha/status", nil)
	w := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(w, req)

	// Must be rejected at the auth layer, not leak any capability detail.
	assert.NotEqual(t, http.StatusOK, w.Code,
		"unauthenticated request must not receive 200 — the auth middleware must reject it")
	body := w.Body.String()
	assert.NotContains(t, body, "PushStore",
		"absent capability names must not appear in unauthenticated responses")
	assert.NotContains(t, body, "absent_capabilities",
		"the absent_capabilities field must not appear in unauthenticated responses")
}
