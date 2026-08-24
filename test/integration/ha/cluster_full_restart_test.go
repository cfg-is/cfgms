// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClusterFullRestart_ElectsLeaderFromPersistedState verifies the fix for
// Issue #3479: a cluster whose nodes are ALL stopped and restarted together,
// with their persisted Raft logs intact, must elect a leader without operator
// intervention — no WAL deletion, no manual raft.db surgery.
//
// This is deliberately not TestNodeRestart_RebuildsMembershipAndLeader
// (Issue #3394): that test restarts one node into a still-live quorum, where
// the surviving two nodes never lose their Raft voter state. This test stops
// every controller at once, so every node's Raft voter set comes only from
// what NewRaftConsensus can recover from disk on the next boot — exactly the
// path seedConfStateSnapshot (pkg/ha/raft_consensus.go) exists to repair.
//
// Before the fix, every node restarted with "peers: []" (an empty voter set,
// since nothing had ever persisted a ConfState) and GET /api/v1/raft/status
// reported "leader":0 forever; recovery required deleting every node's
// raft.db by hand. That is also why haRestoreQuorum's WAL-wipe workaround
// (removed by this same story) existed in the e2e suite: it papered over this
// exact defect so the e2e suites could leave the lab cluster healthy.
func TestClusterFullRestart_ElectsLeaderFromPersistedState(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	helper := NewDockerComposeHelper()

	t.Log("Starting HA cluster for full-restart test...")
	require.NoError(t, helper.StartCluster(ctx))
	defer func() {
		if err := helper.StopCluster(context.Background()); err != nil {
			t.Logf("Warning: Failed to stop cluster: %v", err)
		}
	}()

	services := []string{"controller-east", "controller-central", "controller-west"}
	require.NoError(t, helper.WaitForServices(ctx, 3*time.Minute, services...))

	controllerURLs := []string{controllerEastURL, controllerCentralURL, controllerWestURL}

	// Wait for full 3-node membership and a first leader election. This is
	// what puts real ConfChange entries — the AddNode for each of the three
	// controllers — into every node's persisted Raft log before the restart,
	// reproducing the state the lab cluster was actually in.
	t.Log("Waiting for full cluster formation (3-node membership, leader elected)...")
	require.Eventually(t, func() bool {
		for _, url := range controllerURLs {
			nodes, err := getHANodes(url)
			if err != nil || len(nodes) != 3 {
				return false
			}
		}
		return true
	}, 3*time.Minute, 5*time.Second, "all nodes must report 3-node membership before the full-cluster restart")

	preRestartLeader, err := getHALeaderID(controllerCentralURL)
	require.NoError(t, err, "must be able to read leader before restart")
	require.NotEmpty(t, preRestartLeader, "a leader must be elected before the full-cluster restart")
	t.Logf("Leader before full-cluster restart: %s", preRestartLeader)

	// Stop every node in the cluster, then start every node back up. Persisted
	// per-node data (including raft.db) lives on named Compose volumes
	// (controller_{east,central,west}_data), which `docker compose rm` does
	// not remove — only anonymous volumes are dropped — so this reproduces a
	// real stop-all/start-all cycle with the Raft logs intact, not a fresh
	// bootstrap.
	t.Log("Stopping every controller in the cluster...")
	require.NoError(t, helper.StopCluster(ctx))

	t.Log("Restarting every controller in the cluster...")
	require.NoError(t, helper.StartCluster(ctx))
	require.NoError(t, helper.WaitForServices(ctx, 3*time.Minute, services...))

	// The core assertion: every restarted node must elect a leader from its
	// persisted Raft state, with no operator intervention. Before the fix this
	// never converges — every node comes back with an empty voter set and
	// GET /api/v1/raft/status reports leader:0 indefinitely.
	t.Log("Waiting for the restarted cluster to elect a leader...")
	require.Eventually(t, func() bool {
		for _, url := range controllerURLs {
			id, err := getHALeaderID(url)
			if err != nil || id == "" {
				return false
			}
		}
		return true
	}, 3*time.Minute, 5*time.Second,
		"every node must report a non-empty leader after a full-cluster restart with persisted state")

	t.Run("AllNodesAgreeOnLeader", func(t *testing.T) {
		leaderIDs := make(map[string]string, len(controllerURLs))
		for _, url := range controllerURLs {
			id, err := getHALeaderID(url)
			require.NoError(t, err)
			leaderIDs[url] = id
		}
		first := leaderIDs[controllerURLs[0]]
		for url, id := range leaderIDs {
			assert.Equal(t, first, id, "node %s must agree with the rest of the cluster on the leader", url)
		}
	})

	t.Run("MembershipSurvivesRestart", func(t *testing.T) {
		for _, url := range controllerURLs {
			nodes, err := getHANodes(url)
			require.NoError(t, err)
			assert.Len(t, nodes, 3, "node %s must report all 3 cluster members after restart", url)
		}
	})
}
