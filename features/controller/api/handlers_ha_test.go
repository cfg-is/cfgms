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
// holds the lease. Used to exercise the "leader" side of GET /api/v1/ha/status.
func newLeaseLeaderHAManager(t *testing.T) *ha.Manager {
	t.Helper()

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

	manager, err := ha.NewManager(cfg, logging.GetLogger(), sm)
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

// TestHAStatus_Leader_IsLeaderTrue proves GET /api/v1/ha/status reports
// is_leader=true once the S3 database lease backs HasLeadership() (ADR-031
// Decision 5). The non-leader case is covered by
// TestHAStatus_NonLeader_IsLeaderFalse.
func TestHAStatus_Leader_IsLeaderTrue(t *testing.T) {
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
	// started first can have its cached authority lapse before the HTTP request
	// below ever runs (Issue #3840). Acquiring the lease last confines the window
	// between "lease confirmed held" and the assertion to one cheap in-process
	// ServeHTTP call — the same shape every passing pkg/ha
	// Eventually-then-immediate-assertion test already uses.
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	haManager := newLeaseLeaderHAManager(t)
	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()

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
}

// TestHAStatus_NonLeader_IsLeaderFalse verifies that GET /api/v1/ha/status
// reports is_leader=false for a ClusterMode node that has never acquired the
// cluster leadership lease (ADR-031 Decision 5). newClusterModeHAManager
// (server_tls_ha_test.go) never calls SetLeaseStore or Start(), so
// HasLeadership() stays false.
func TestHAStatus_NonLeader_IsLeaderFalse(t *testing.T) {
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
}
