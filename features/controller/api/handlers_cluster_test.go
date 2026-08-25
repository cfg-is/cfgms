// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/cluster"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/transport/registry"
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

// TestHandleClusterNodeDrain_NilPrincipalRejects403 verifies that a nil principal
// (unauthenticated) is rejected 403 by the handler's nil check (always present).
func TestHandleClusterNodeDrain_NilPrincipalRejects403(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateActive,
		RegisteredAt: time.Now(),
	}))

	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, drainRequest("node-1"))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateActive, got.State, "state must not change on 403")
	assert.False(t, srv.clusterDraining.Load(), "health gate must not be set on 403")
}

// TestAssuranceGate_ClusterDrain_BasicAssuranceGetsStepUp verifies that a Basic-assurance
// principal receives 401 step-up for cluster:drain-node via requirePermission directly
// (assurance gate lives in requirePermission, not auth middleware; Issue #2780).
func TestAssuranceGate_ClusterDrain_BasicAssuranceGetsStepUp(t *testing.T) {
	srv, _ := setupClusterTestServer(t)

	basicPrincipal := &Principal{
		ID:            "web-user",
		Name:          "web-session:web-user",
		Assurance:     session.AssuranceBasic,
		ImplicitAdmin: true,
	}
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := srv.requirePermission("cluster", "drain-node")(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/node-1/drain", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, basicPrincipal))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "Basic-assurance caller must get 401 step-up")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
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

// TestHandleClusterNodeDrain_TenantScopedPrincipal_Returns403 verifies the Issue #3303
// scope guard: cluster:drain-node is grantable, but the route carries no tenant path
// variable, so requirePermission's tenant-isolation block admits a tenant-scoped holder.
// The handler must deny it — controller cluster nodes serve every tenant — and leave
// membership state and the health gate untouched.
func TestHandleClusterNodeDrain_TenantScopedPrincipal_Returns403(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateActive,
		RegisteredAt: time.Now(),
	}))

	req := injectAdminPrincipalWithTenant(drainRequest("node-1"), "alice", "client-1")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateActive, got.State, "state must not change on 403")
	assert.False(t, srv.clusterDraining.Load(), "health gate must not be set on 403")
}

// TestHandleClusterNodeDrain_RootScopedPrincipal_Returns202 verifies the in-scope side
// of the Issue #3303 guard: a root-scoped SaaS operator carries TenantID == "" and owns
// the controller's own infrastructure, so drain succeeds.
func TestHandleClusterNodeDrain_RootScopedPrincipal_Returns202(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateActive,
		RegisteredAt: time.Now(),
	}))

	req := injectAdminPrincipal(drainRequest("node-1"), "alice")
	principal, ok := req.Context().Value(principalContextKey).(*Principal)
	require.True(t, ok)
	principal.RootScoped = true

	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, "body: %s", rec.Body.String())

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDraining, got.State)
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

// decommissionRequest builds a POST request for the decommission endpoint with
// mux vars set.
func decommissionRequest(nodeID string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/"+nodeID+"/decommission", nil)
	return mux.SetURLVars(req, map[string]string{"id": nodeID})
}

// setupClusterTestServerWithRegistry returns a test server with an
// InMemoryMembershipStore and a real InMemoryRegistry so that the decommission
// handler can call cluster.Decommission without a nil counter.
func setupClusterTestServerWithRegistry(t *testing.T) (*Server, *cluster.InMemoryMembershipStore) {
	t.Helper()
	srv, store := setupClusterTestServer(t)
	srv.SetRegistry(registry.NewRegistry())
	return srv, store
}

// TestHandleClusterNodeDecommission_NilPrincipalRejects403 verifies that a nil
// principal is rejected 403 by the handler's nil check.
func TestHandleClusterNodeDecommission_NilPrincipalRejects403(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateDraining,
		RegisteredAt: time.Now(),
	}))

	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, decommissionRequest("node-1"))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDraining, got.State, "state must not change on 403")
}

// TestAssuranceGate_ClusterDecommission_BasicAssuranceGetsStepUp verifies that a
// Basic-assurance principal receives 401 step-up for cluster:decommission-node via
// requirePermission directly (Issue #2780).
func TestAssuranceGate_ClusterDecommission_BasicAssuranceGetsStepUp(t *testing.T) {
	srv, _ := setupClusterTestServer(t)

	basicPrincipal := &Principal{
		ID:            "web-user",
		Name:          "web-session:web-user",
		Assurance:     session.AssuranceBasic,
		ImplicitAdmin: true,
	}
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := srv.requirePermission("cluster", "decommission-node")(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/node-1/decommission", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, basicPrincipal))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "Basic-assurance caller must get 401 step-up")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
}

// TestHandleClusterNodeDecommission_TenantScopedPrincipal_Returns403 verifies the
// Issue #3303 scope guard on the decommission handler: a tenant-scoped holder of
// cluster:decommission-node is denied and the node stays draining.
func TestHandleClusterNodeDecommission_TenantScopedPrincipal_Returns403(t *testing.T) {
	srv, store := setupClusterTestServerWithRegistry(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateDraining,
		RegisteredAt: time.Now(),
	}))

	req := injectAdminPrincipalWithTenant(decommissionRequest("node-1"), "alice", "client-1")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDraining, got.State, "state must not change on 403")
}

// TestHandleClusterNodeDecommission_RootScopedPrincipal_Returns200 verifies the in-scope
// side of the Issue #3303 guard on the decommission handler.
func TestHandleClusterNodeDecommission_RootScopedPrincipal_Returns200(t *testing.T) {
	srv, store := setupClusterTestServerWithRegistry(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateDraining,
		RegisteredAt: time.Now(),
	}))

	req := injectAdminPrincipal(decommissionRequest("node-1"), "alice")
	principal, ok := req.Context().Value(principalContextKey).(*Principal)
	require.True(t, ok)
	principal.RootScoped = true

	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDecommissioned, got.State)
}

// TestHandleClusterNodeDecommission_NilMembershipStore_Returns503 verifies that
// calling decommission when the store is unconfigured returns 503 with no panic.
func TestHandleClusterNodeDecommission_NilMembershipStore_Returns503(t *testing.T) {
	srv := setupTestServer(t) // no membership store set

	req := injectAdminPrincipal(decommissionRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleClusterNodeDecommission_NilRegistry_Returns503 verifies that calling
// decommission when the session registry is not configured returns 503 with no panic.
func TestHandleClusterNodeDecommission_NilRegistry_Returns503(t *testing.T) {
	srv, store := setupClusterTestServer(t) // membership store set, registry NOT set
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:    "node-1",
		State: cluster.StateDraining,
	}))

	req := injectAdminPrincipal(decommissionRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleClusterNodeDecommission_NodeNotDraining_Returns409 verifies HTTP 409
// when the target node is not in StateDraining.
func TestHandleClusterNodeDecommission_NodeNotDraining_Returns409(t *testing.T) {
	srv, store := setupClusterTestServerWithRegistry(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:    "node-1",
		State: cluster.StateActive,
	}))

	req := injectAdminPrincipal(decommissionRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// TestHandleClusterNodeDecommission_NodeNotFound_Returns404 verifies HTTP 404
// for an unknown node ID.
func TestHandleClusterNodeDecommission_NodeNotFound_Returns404(t *testing.T) {
	srv, _ := setupClusterTestServerWithRegistry(t)

	req := injectAdminPrincipal(decommissionRequest("ghost"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleClusterNodeDrain_NonLeader_Returns503 verifies the Issue #3538 leadership
// gate: when registrationLeaderStatus is set and HasLeadership() returns false (the
// partition scenario — minority node still holds the raw Raft leader flag but has lost
// quorum), the handler returns 503 immediately without invoking cluster.Drain or
// touching s.membershipStore.
func TestHandleClusterNodeDrain_NonLeader_Returns503(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateActive,
		RegisteredAt: time.Now(),
	}))
	srv.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}

	req := injectAdminPrincipal(drainRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "non-leader must return 503")

	// Verify cluster.Drain was not invoked: node state must remain unchanged.
	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateActive, got.State, "drain must not have run on non-leader")
	assert.False(t, srv.clusterDraining.Load(), "health gate must not be set on non-leader")
}

// TestHandleClusterNodeDecommission_NonLeader_Returns503 verifies the Issue #3538
// leadership gate on the decommission handler: a minority node returns 503 without
// invoking cluster.Decommission or touching s.membershipStore or s.registry.
func TestHandleClusterNodeDecommission_NonLeader_Returns503(t *testing.T) {
	srv, store := setupClusterTestServerWithRegistry(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateDraining,
		RegisteredAt: time.Now(),
	}))
	srv.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}

	req := injectAdminPrincipal(decommissionRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "non-leader must return 503")

	// Verify cluster.Decommission was not invoked: node state must remain unchanged.
	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDraining, got.State, "decommission must not have run on non-leader")
}

// TestHandleClusterNodeDrain_NilLeaderChecker_ReachesExistingLogic verifies that
// a nil registrationLeaderStatus (SingleServerMode / no HA) still reaches the
// existing drain logic unchanged — the gate is a no-op when the checker is nil.
func TestHandleClusterNodeDrain_NilLeaderChecker_ReachesExistingLogic(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateActive,
		RegisteredAt: time.Now(),
	}))
	srv.registrationLeaderStatus = nil // explicit nil: no HA configured

	req := injectAdminPrincipal(drainRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, "nil checker must not block drain")
	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDraining, got.State, "drain must have run with nil checker")
}

// TestHandleClusterNodeDecommission_NilLeaderChecker_ReachesExistingLogic verifies
// that a nil registrationLeaderStatus still reaches the existing decommission logic.
func TestHandleClusterNodeDecommission_NilLeaderChecker_ReachesExistingLogic(t *testing.T) {
	srv, store := setupClusterTestServerWithRegistry(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateDraining,
		RegisteredAt: time.Now(),
	}))
	srv.registrationLeaderStatus = nil // explicit nil: no HA configured

	req := injectAdminPrincipal(decommissionRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "nil checker must not block decommission")
	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDecommissioned, got.State, "decommission must have run with nil checker")
}

// TestHandleClusterNodeDecommission_AdminDrainingNode_Returns200 verifies the
// success path: admin principal + node in StateDraining with no active sessions
// returns HTTP 200 with the decommissioned state.
func TestHandleClusterNodeDecommission_AdminDrainingNode_Returns200(t *testing.T) {
	srv, store := setupClusterTestServerWithRegistry(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateDraining,
		RegisteredAt: time.Now(),
	}))

	req := injectAdminPrincipal(decommissionRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp clusterNodeDecommissionResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "node-1", resp.NodeID)
	assert.Equal(t, "decommissioned", resp.State)

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDecommissioned, got.State)
}
