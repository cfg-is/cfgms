// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/cluster"
)

// setupClusterTestServer returns a test server with an InMemoryMembershipStore.
func setupClusterTestServer(t *testing.T) (*Server, *cluster.InMemoryMembershipStore) {
	t.Helper()
	srv := setupTestServer(t)
	store := cluster.NewInMemoryMembershipStore()
	srv.SetMembershipStore(store)
	return srv, store
}

// drainRequest builds a POST request for the drain endpoint with mux vars set.
func drainRequest(nodeID string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/"+nodeID+"/drain", nil)
	return mux.SetURLVars(req, map[string]string{"id": nodeID})
}

// TestHandleClusterNodeDrain_NonAdminRejects403 is the required AC test:
// non-admin principal (or nil) must receive HTTP 403 with no membership state change.
func TestHandleClusterNodeDrain_NonAdminRejects403(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateActive,
		RegisteredAt: time.Now(),
	}))

	t.Run("nil principal", func(t *testing.T) {
		rec := httptest.NewRecorder()
		srv.handleClusterNodeDrain(rec, drainRequest("node-1"))
		assert.Equal(t, http.StatusForbidden, rec.Code)

		got, err := store.GetNode("node-1")
		require.NoError(t, err)
		assert.Equal(t, cluster.StateActive, got.State, "state must not change on 403")
		assert.False(t, srv.clusterDraining.Load(), "health gate must not be set on 403")
	})

	t.Run("non-admin principal", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := injectNonAdminPrincipal(drainRequest("node-1"))
		srv.handleClusterNodeDrain(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)

		got, err := store.GetNode("node-1")
		require.NoError(t, err)
		assert.Equal(t, cluster.StateActive, got.State, "state must not change on 403")
	})
}

// TestHandleClusterNodeDrain_AdminValidNode_Returns202 is the required AC test:
// admin principal + valid node ID -> HTTP 202 and node state becomes StateDraining.
func TestHandleClusterNodeDrain_AdminValidNode_Returns202(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateActive,
		RegisteredAt: time.Now(),
	}))

	req := injectAdminPrincipal(drainRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, "body: %s", rec.Body.String())

	var resp clusterNodeDrainResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "node-1", resp.NodeID)
	assert.Equal(t, "draining", resp.State)

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDraining, got.State)
	assert.True(t, srv.clusterDraining.Load(), "health gate must be set after drain")
}

// TestHandleClusterNodeDrain_NodeNotFound_Returns404 verifies HTTP 404 for an
// unknown node ID with no membership state side-effects.
func TestHandleClusterNodeDrain_NodeNotFound_Returns404(t *testing.T) {
	srv, _ := setupClusterTestServer(t)

	req := injectAdminPrincipal(drainRequest("ghost"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.False(t, srv.clusterDraining.Load())
}

// TestHandleClusterNodeDrain_AlreadyDraining_Returns409 verifies HTTP 409 when the
// target node is already draining.
func TestHandleClusterNodeDrain_AlreadyDraining_Returns409(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:    "node-1",
		State: cluster.StateDraining,
	}))

	req := injectAdminPrincipal(drainRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// TestHandleClusterNodeDrain_NilMembershipStore_Returns503 verifies that calling
// drain when the store is unconfigured returns 503 with no panic.
func TestHandleClusterNodeDrain_NilMembershipStore_Returns503(t *testing.T) {
	srv := setupTestServer(t) // no membership store set

	req := injectAdminPrincipal(drainRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleHealth_ReturnsDegradedWhenDraining verifies that the health endpoint
// returns HTTP 503 and includes the "drain" service key after SetDraining(true).
// The health endpoint wraps its response in an APIResponse envelope
// ({"data": {...}, "timestamp": ...}) because it uses s.writeResponse.
func TestHandleHealth_ReturnsDegradedWhenDraining(t *testing.T) {
	srv := setupTestServer(t)
	srv.SetDraining(true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	srv.handleHealth(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	// Unwrap the APIResponse envelope: {"data": {HealthStatus}, "timestamp": ...}
	var envelope map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&envelope))
	data, ok := envelope["data"].(map[string]interface{})
	require.True(t, ok, "response must have a data field")
	services, ok := data["services"].(map[string]interface{})
	require.True(t, ok, "data must have a services field")
	assert.Equal(t, "draining", services["drain"])
	assert.Equal(t, "degraded", data["status"])
}
