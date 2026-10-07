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

	// WaitForLeadership blocks on the manager's own acquisition signal instead
	// of polling HasLeadership() on a wall-clock budget (Issue #4160): a
	// require.Eventually poll depends on its own goroutine also waking up
	// promptly on a fixed interval, so under host scheduling pressure both
	// goroutines competing for the same runnable slots could push the observed
	// latency past the budget even though the underlying acquisition itself
	// was fast.
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	require.True(t, manager.WaitForLeadership(waitCtx),
		"test manager must acquire the database lease before the test body runs")

	return manager
}

// TestHAStatus_Leader_IsLeaderTrue proves GET /api/v1/ha/status reports
// is_leader=true once the S3 database lease backs HasLeadership() (ADR-031
// Decision 5). The non-leader case is covered by
// TestHAStatus_NonLeader_IsLeaderFalse.
//
// Issue #4253 (recurrence of #4160, evicted PR #4245 on a stalling
// windows-latest merge-queue runner): #4160 confined the window between "lease
// confirmed held" and the assertion to a single in-process ServeHTTP call, but
// that call is still a *second* read of leadership, taken at a *later* instant
// than newLeaseLeaderHAManager's WaitForLeadership observation — WaitForLeadership
// unblocks the instant runLeaseAcquisition's first successful TryAcquire closes
// the "acquired" channel, which is the same instant HasLeadership()'s
// local-authority cache (leaseManager.HasLocalAuthority, pkg/lease.go) starts its
// monotonic-clock deadline. handleHAStatus's isLeader := haManager.HasLeadership()
// re-reads that same cache later, after server.mu.Lock()/Unlock() and
// httptest.NewRequest/NewRecorder construction. Those steps are normally
// microseconds, but on run 35932617052 (job 107422448309, 2026-09-23 23:24Z) the
// whole features/controller/api package took 324.9s against a normal ~205s and a
// sibling test measured a single PowerShell cold-start of 1m51s — evidence the
// runner was stalling the whole process for seconds at a time, which stalls
// runLeaseAcquisition's renewal goroutine right along with the test goroutine.
// FastElectionConfig's derived numbers (setLeaseStoreLocked, ElectionTimeout =
// 200ms): leaseTTL = 200ms, renewalInterval = maxAllowedRenewalLatency = 20ms, so
// lease.SafetyMargin = 200ms − 20ms − 20ms = 160ms. Any stall longer than that
// 160ms window between the WaitForLeadership instant and the handler's
// HasLeadership() read lapses the cached authority — truthfully: the lease *was*
// held a moment ago, but the cache backing that answer has an explicit, narrow
// expiry, and #4160 removed the wrong side of the race (the polling goroutine's
// own wake-up latency) rather than this one (elapsed wall-clock time between two
// distinct reads).
//
// The fix here is option (a) from the issue: assert with require.Eventually
// against the live endpoint instead of a single read. newLeaseLeaderHAManager's
// manager is already running its background renewal loop (runLeaseAcquisition,
// started by manager.Start()) for the lifetime of the test, re-issuing
// TryAcquire every renewalInterval (20ms) — nothing else contends for this
// lease, so every renewal succeeds and refreshes the cache's 160ms window. A
// stall that lapses one cached read is invisible to Eventually: the very next
// poll, taken after the renewal loop has had a chance to run again, observes
// is_leader=true. Only a handler that never reports leadership (the actual bug
// this test guards against) can still exhaust the Eventually budget.
func TestHAStatus_Leader_IsLeaderTrue(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	haManager := newLeaseLeaderHAManager(t)
	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()

	// 10s budget, polled every 25ms: the poll cadence sits close to the 20ms
	// renewal interval so a poll lands shortly after most renewals without
	// busy-looping, and the budget is comfortably longer than any single stall —
	// only a handler that never reports leadership (the actual bug this test
	// guards against, AC3) can exhaust it.
	var haStatus HAStatusResponse
	require.Eventually(t, func() bool {
		haReq := httptest.NewRequest("GET", "/api/v1/ha/status", nil)
		haReq.Header.Set("X-API-Key", apiKey)
		haW := httptest.NewRecorder()
		server.GetRouter().ServeHTTP(haW, haReq)
		if haW.Code != 200 {
			return false
		}

		var status HAStatusResponse
		if err := json.NewDecoder(haW.Body).Decode(&status); err != nil {
			return false
		}
		haStatus = status
		return haStatus.IsLeader
	}, 10*time.Second, 25*time.Millisecond,
		"/api/v1/ha/status is_leader must become true while the database lease is held")

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
