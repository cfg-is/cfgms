// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/storage"
)

// newLeaseLeaderHAManager returns a real, started ClusterMode *ha.Manager wired to
// a real (flatfile) business.LeaseStore, waited until it actually acquires the S3
// database lease (ADR-031 Decision 5) — the counterpart to newClusterModeHAManager
// (server_tls_ha_test.go), which never calls SetLeaseStore or Start() and so never
// holds the lease. Used to exercise the "leader" side of the two-status-surface
// agreement required by Issue #3760.
func newLeaseLeaderHAManager(t *testing.T) *ha.Manager {
	t.Helper()

	certMgr := newTLSTestCertManager(t)
	sm, err := storage.CreateTestStorageManager()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, sm.Close()) })

	cfg := ha.DefaultConfig()
	cfg.Mode = ha.ClusterMode
	cfg.Node.ID = fmt.Sprintf("lease-leader-node-%d", time.Now().UnixNano())
	cfg.Cluster = ha.FastElectionConfig()
	cfg.Cluster.Discovery.Config["nodes"] = []interface{}{
		map[string]interface{}{"id": cfg.Node.ID, "address": "127.0.0.1:0"},
	}

	manager, err := ha.NewManager(cfg, logging.GetLogger(), sm, certMgr, "")
	require.NoError(t, err)

	store := newTestFlatFileLeaseStore(t)
	require.NoError(t, manager.SetLeaseStore(store))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Start(ctx))
	t.Cleanup(func() { assert.NoError(t, manager.Stop(context.Background())) })

	require.Eventually(t, manager.HasLeadership, 5*time.Second, 5*time.Millisecond,
		"test manager must acquire the database lease before the test body runs")

	return manager
}

// TestBothStatusSurfaces_Leader_IsLeaderAndRaftIsLeaderAgree is the REQUIRED test
// (Issue #3760 AC) proving GET /api/v1/ha/status and GET /api/v1/raft/status report
// identical is_leader values once the S3 database lease backs HasLeadership(). The
// non-leader agreement case is already covered by
// TestBothStatusSurfaces_NonLeader_IsLeaderAndRaftIsLeaderAgree
// (handlers_raft_ha_test.go); this is the true-leadership counterpart — the state
// that only exists once a node actually holds the database lease.
func TestBothStatusSurfaces_Leader_IsLeaderAndRaftIsLeaderAgree(t *testing.T) {
	// Do the expensive, variable-latency setup (RBAC init and its SQLite writes
	// inside setupTestServer, then ephemeral key generation) BEFORE acquiring the
	// lease, not after. newLeaseLeaderHAManager's require.Eventually only proves
	// the lease was held at the moment it observed HasLeadership() == true: the
	// local-authority cache backing that check is valid for just
	// FastElectionConfig's derived SafetyMargin (160ms — 0.8 × 200ms
	// ElectionTimeout, see ClusterConfig.LeaseDuration / lease.SafetyMargin), a
	// window sized for the background renewal loop's own ~20ms cadence, not for a
	// one-time setup step sandwiched in front of the assertions. On a loaded CI
	// runner setupTestServer alone can take longer than that margin, so a manager
	// started first can have its cached authority lapse before the HTTP requests
	// below ever run (Issue #3840). Acquiring the lease last confines the window
	// between "lease confirmed held" and the assertions to two cheap in-process
	// ServeHTTP calls — the same shape every passing pkg/ha
	// Eventually-then-immediate-assertion test already uses.
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	haManager := newLeaseLeaderHAManager(t)
	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()

	raftReq := httptest.NewRequest("GET", "/api/v1/raft/status", nil)
	raftReq.Header.Set("X-API-Key", apiKey)
	raftW := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(raftW, raftReq)
	require.Equal(t, 200, raftW.Code, "/api/v1/raft/status must return 200 with a leader HA manager")

	var raftStatus struct {
		IsLeader     bool `json:"is_leader"`
		RaftIsLeader bool `json:"raft_is_leader"`
	}
	require.NoError(t, json.NewDecoder(raftW.Body).Decode(&raftStatus),
		"/api/v1/raft/status response must be valid JSON")

	haReq := httptest.NewRequest("GET", "/api/v1/ha/status", nil)
	haReq.Header.Set("X-API-Key", apiKey)
	haW := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(haW, haReq)
	require.Equal(t, 200, haW.Code, "/api/v1/ha/status must return 200")

	var haStatus HAStatusResponse
	require.NoError(t, json.NewDecoder(haW.Body).Decode(&haStatus),
		"/api/v1/ha/status response must be valid JSON")

	assert.True(t, haStatus.IsLeader,
		"/api/v1/ha/status is_leader must be true once the database lease is held")
	assert.True(t, raftStatus.IsLeader,
		"/api/v1/raft/status is_leader must be true once the database lease is held (lease-backed, ADR-031 Decision 5)")
	assert.Equal(t, haStatus.IsLeader, raftStatus.IsLeader,
		"both status surfaces must agree on is_leader once the lease is held")
}
