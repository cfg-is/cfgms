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

// TestHandleClusterNodeDrain_SucceedsOnNonAuthoritativeNode is the [REQUIRED TEST]
// for handlers_cluster.go (Issue #3761, ADR-031 Decision 1): handleClusterNodeDrain
// used to return 503 and leave the membership store untouched when the serving node
// held no lease-backed leadership. Under any-node service every cluster node accepts
// the write — the shared membership store is the serialization point, not leadership —
// so draining against a real, deliberately non-authoritative *ha.Manager (ClusterMode,
// no lease ever acquired) must return 202 and move the node to StateDraining.
func TestHandleClusterNodeDrain_SucceedsOnNonAuthoritativeNode(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateActive,
		RegisteredAt: time.Now(),
	}))
	srv.haManager = newNonAuthoritativeHAManager(t)

	req := injectAdminPrincipal(drainRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, "drain must succeed regardless of leadership: %s", rec.Body.String())

	// Verify cluster.Drain actually ran: node state must have advanced.
	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDraining, got.State, "drain must have run on a non-authoritative node")
	assert.True(t, srv.clusterDraining.Load(), "health gate must be set once drain runs")
}

// TestHandleClusterNodeDecommission_SucceedsOnNonAuthoritativeNode is the same
// any-node assertion for handleClusterNodeDecommission (Issue #3761, ADR-031
// Decision 1): a node holding no lease-backed leadership must still perform the
// decommission against the shared membership store instead of returning 503.
func TestHandleClusterNodeDecommission_SucceedsOnNonAuthoritativeNode(t *testing.T) {
	srv, store := setupClusterTestServerWithRegistry(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateDraining,
		RegisteredAt: time.Now(),
	}))
	srv.haManager = newNonAuthoritativeHAManager(t)

	req := injectAdminPrincipal(decommissionRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDecommission(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "decommission must succeed regardless of leadership: %s", rec.Body.String())

	// Verify cluster.Decommission actually ran: node state must have advanced.
	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDecommissioned, got.State, "decommission must have run on a non-authoritative node")
}

// TestHandleClusterNodeDrain_SucceedsOnAuthoritativeNode is the mirror case: removing
// the gate must not have broken the authoritative path either, so a real *ha.Manager
// in SingleServerMode (HasLeadership() == true) still reaches the existing drain logic.
func TestHandleClusterNodeDrain_SucceedsOnAuthoritativeNode(t *testing.T) {
	srv, store := setupClusterTestServer(t)
	require.NoError(t, store.Register(cluster.NodeRecord{
		ID:           "node-1",
		State:        cluster.StateActive,
		RegisteredAt: time.Now(),
	}))
	srv.haManager = newAuthoritativeHAManager(t)

	req := injectAdminPrincipal(drainRequest("node-1"), "alice")
	rec := httptest.NewRecorder()
	srv.handleClusterNodeDrain(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, "drain must succeed on an authoritative node: %s", rec.Body.String())
	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDraining, got.State, "drain must have run on an authoritative node")
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

// TestClusterNodeDecommission_UsesTargetNodeSessionCount is the [REQUIRED TEST]
// for Issue #3895: handleClusterNodeDecommission's drain-wait must resolve the
// *target* node's session count, not whichever node happens to receive the
// decommission request. Two *Server instances share one durable membership
// store and one durable routing store (modeling two cluster nodes behind the
// same database). node-a carries a nonzero LOCAL registry count (unrelated
// live sessions on node-a itself) that must be ignored; node-b — the
// decommission target — has zero routing-store-recorded sessions. A
// decommission request for node-b sent to node-a must resolve node-b's (zero)
// count and return promptly, rather than blocking on node-a's local count.
func TestClusterNodeDecommission_UsesTargetNodeSessionCount(t *testing.T) {
	membershipStore := cluster.NewInMemoryMembershipStore()
	require.NoError(t, membershipStore.Register(cluster.NodeRecord{
		ID:           "node-a",
		State:        cluster.StateActive,
		RegisteredAt: time.Now(),
	}))
	require.NoError(t, membershipStore.Register(cluster.NodeRecord{
		ID:           "node-b",
		State:        cluster.StateDraining,
		RegisteredAt: time.Now(),
	}))

	routingStore := newTestFlatFileRoutingStore(t)

	// node-b has no routing-store-recorded sessions: a correct fix resolves
	// Count() == 0 immediately and Decommission returns without polling.
	// (No RecordConnection calls for node-b — absence is the zero count.)

	nodeA := setupTestServer(t)
	nodeA.SetMembershipStore(membershipStore)
	nodeA.SetRoutingStore(routingStore)
	registryA := registry.NewRegistry()
	nodeA.SetRegistry(registryA)
	// node-a's own local registry reports a nonzero count — live sessions on
	// node-a itself, unrelated to node-b. If the handler used this count
	// instead of node-b's, the drain-wait would poll every 5s and never
	// return within the short deadline this test enforces below.
	registerTestConnection(t, registryA, "steward-on-node-a")
	require.Equal(t, 1, registryA.Count(), "sanity: node-a's local registry must be nonzero")

	// Bound the worst case (buggy behavior) well below the production 5-minute
	// default so a regression fails fast instead of hanging the test suite.
	nodeA.decommissionTimeout = 2 * time.Second

	req := injectAdminPrincipal(decommissionRequest("node-b"), "alice")

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		nodeA.handleClusterNodeDecommission(rec, req)
		done <- rec
	}()

	select {
	case rec := <-done:
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	case <-time.After(500 * time.Millisecond):
		t.Fatal("decommission did not resolve promptly: drain-wait appears to be blocked on " +
			"node-a's local session count instead of node-b's (target) count")
	}

	got, err := membershipStore.GetNode("node-b")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDecommissioned, got.State, "node-b must be decommissioned")

	gotA, err := membershipStore.GetNode("node-a")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateActive, gotA.State, "node-a's own state must be untouched")
}

// TestNodeScopedSessionCounter_CountFailsSafeOnStoreError covers the fail-safe
// branch of nodeScopedSessionCounter.Count (Issue #3895): when the routing store
// cannot answer, Count must report a non-zero count.
//
// cluster.waitForSessionDrain reads 0 as "drained, stop waiting immediately", so
// returning 0 on a read failure would let a store outage force-complete a
// decommission the instant it was requested — dropping live steward sessions
// that were never counted. Returning 1 keeps the caller in its poll loop, which
// still force-completes at the deadline, exactly as an honestly non-zero count
// would.
//
// The failure is induced against a real flat-file routing store whose durable
// state is unparsable, not a substituted implementation.
func TestNodeScopedSessionCounter_CountFailsSafeOnStoreError(t *testing.T) {
	srv := setupTestServer(t)
	routingStore := newUnreadableTestFlatFileRoutingStore(t)

	_, err := routingStore.CountByNode(context.Background(), "node-b")
	require.Error(t, err, "pre-condition: the routing store must genuinely fail its read")

	counter := &nodeScopedSessionCounter{
		ctx:          context.Background(),
		routingStore: routingStore,
		nodeID:       "node-b",
		logger:       srv.logger,
	}

	assert.Equal(t, 1, counter.Count(),
		"a routing-store read failure must yield a non-zero count, never 0 (which the "+
			"drain-wait reads as 'already drained')")
}

// TestNodeScopedSessionCounter_CountReportsTargetNodeCount pins the success path
// the fail-safe branch is measured against: with a readable store, Count must
// return the target node's actual recorded session count — not a constant.
func TestNodeScopedSessionCounter_CountReportsTargetNodeCount(t *testing.T) {
	srv := setupTestServer(t)
	routingStore := newTestFlatFileRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, routingStore.RecordConnection(ctx, "steward-1", "node-b"))
	require.NoError(t, routingStore.RecordConnection(ctx, "steward-2", "node-b"))
	require.NoError(t, routingStore.RecordConnection(ctx, "steward-3", "node-a"))

	counter := &nodeScopedSessionCounter{
		ctx:          ctx,
		routingStore: routingStore,
		nodeID:       "node-b",
		logger:       srv.logger,
	}

	assert.Equal(t, 2, counter.Count(), "Count must report only the target node's sessions")
}

// TestClusterNodeDecommission_RoutingStoreErrorWaitsForTimeout is the handler-level
// half of the Issue #3895 fail-safe: with the routing store unable to answer,
// handleClusterNodeDecommission must fall back to poll-until-timeout rather than
// completing immediately.
//
// The local registry is deliberately empty (Count() == 0): if the handler read
// the store failure as 0 — or silently fell back to the local registry — the
// request would return well inside the deadline. Asserting the elapsed time
// reaches the configured timeout is what distinguishes the fail-safe from a
// fail-open. The forced completion afterwards is by design (cluster.Decommission
// marks the node decommissioned on timeout), so a store outage delays a
// decommission, it never silently skips the drain.
func TestClusterNodeDecommission_RoutingStoreErrorWaitsForTimeout(t *testing.T) {
	membershipStore := cluster.NewInMemoryMembershipStore()
	require.NoError(t, membershipStore.Register(cluster.NodeRecord{
		ID:           "node-b",
		State:        cluster.StateDraining,
		RegisteredAt: time.Now(),
	}))

	srv := setupTestServer(t)
	srv.SetMembershipStore(membershipStore)
	srv.SetRoutingStore(newUnreadableTestFlatFileRoutingStore(t))
	srv.SetRegistry(registry.NewRegistry())

	const timeout = 400 * time.Millisecond
	srv.decommissionTimeout = timeout

	req := injectAdminPrincipal(decommissionRequest("node-b"), "alice")
	rec := httptest.NewRecorder()

	start := time.Now()
	srv.handleClusterNodeDecommission(rec, req)
	elapsed := time.Since(start)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.GreaterOrEqual(t, elapsed, timeout,
		"an unreadable routing store must not be mistaken for a drained node: the "+
			"drain-wait must poll until the deadline instead of returning at once")

	got, err := membershipStore.GetNode("node-b")
	require.NoError(t, err)
	assert.Equal(t, cluster.StateDecommissioned, got.State,
		"forced decommission after the timeout is by design")
}
