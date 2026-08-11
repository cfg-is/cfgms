// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/raft/v3"

	"github.com/cfgis/cfgms/pkg/logging"
)

// TestRaftConsensus_NodeUpdatePopulatesClusterState pins the replication path
// that backs GET /api/v1/ha/cluster.
//
// The HA integration suite asserts that every controller reports three cluster
// members, and instead saw `{"leader":"","nodes":null}` on all three while
// leadership itself was working — GET /api/v1/ha/status correctly identified one
// leader and two followers. Both endpoints read ClusterState.Nodes, which is
// populated exclusively by an applied node_update command, so an empty map makes
// the cluster look memberless and leaderless no matter how healthy Raft is.
//
// A single-node cluster is enough to cover the propose -> commit -> apply chain
// without any transport, which is what this test isolates.
func TestRaftConsensus_NodeUpdatePopulatesClusterState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clusterCfg := &ClusterConfig{
		HeartbeatInterval: 50 * time.Millisecond,
		ElectionTimeout:   250 * time.Millisecond,
	}

	const nodeID uint64 = 1
	nodeInfo := &NodeInfo{
		ID:      "controller-solo",
		Address: "controller-solo:9443",
		State:   NodeStateHealthy,
		Role:    NodeRoleFollower,
		Region:  "us-east",
	}

	rc, err := NewRaftConsensus(ctx, nodeID, nodeInfo, []raft.Peer{{ID: nodeID}}, clusterCfg, logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	require.NoError(t, rc.Start())

	// A proposal made before a leader exists is dropped, so wait for election
	// exactly as Manager.startClusterMode does.
	select {
	case <-rc.leaderElectedC:
	case <-time.After(10 * time.Second):
		t.Fatal("no leader elected within 10s")
	}

	require.NoError(t, rc.ProposeNodeUpdate(nodeInfo))

	require.Eventually(t, func() bool {
		return len(rc.GetClusterNodes()) == 1
	}, 10*time.Second, 50*time.Millisecond,
		"node_update was proposed after leader election but never reached ClusterState.Nodes")

	nodes := rc.GetClusterNodes()
	require.Len(t, nodes, 1)
	assert.Equal(t, "controller-solo", nodes[0].ID)

	// GetLeaderInfo resolves the leader through the same map, so an empty
	// ClusterState.Nodes is what made /api/v1/ha/cluster report no leader.
	leader, err := rc.GetLeaderInfo()
	require.NoError(t, err, "leader info must resolve once the node's own update is applied")
	assert.Equal(t, "controller-solo", leader.ID)
}

// TestRaftCommand_PreservesLargeNodeIDs guards the encoding of the replicated
// command envelope.
//
// Node IDs are hashStringToUint64 values that routinely exceed 2^53, where
// float64 can no longer represent consecutive integers. RaftCommand.Data used to
// be interface{}: decoding put the ID in a float64 and applyCommand re-marshalled
// it to reach the typed command, so 10972337506993669137 was applied as
// 10972337506993670000. ClusterState.Nodes was then keyed by an ID that matched
// nothing, which is why a healthy three-node cluster reported no leader.
func TestRaftCommand_PreservesLargeNodeIDs(t *testing.T) {
	// Real value observed for "controller-east"; above 2^53 and not
	// representable as a float64.
	const nodeID uint64 = 10972337506993669137
	require.Greater(t, nodeID, uint64(1)<<53, "test value must exceed float64 integer precision")

	encoded, err := marshalRaftCommand("node_update", NodeUpdateCommand{
		NodeID:   nodeID,
		NodeInfo: &NodeInfo{ID: "controller-east"},
	})
	require.NoError(t, err)

	var cmd RaftCommand
	require.NoError(t, json.Unmarshal(encoded, &cmd))
	require.Equal(t, "node_update", cmd.Type)

	var update NodeUpdateCommand
	require.NoError(t, json.Unmarshal(cmd.Data, &update))

	assert.Equal(t, nodeID, update.NodeID,
		"node ID must survive the Raft command round trip exactly")
	assert.Equal(t, "controller-east", update.NodeInfo.ID)
}
