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
