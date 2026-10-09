// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/testing/storage"
)

// TestFailoverManager_electNewLeader_DefersToLease verifies that electNewLeader
// no longer calls promoteToLeader/demoteFromLeader but instead defers to the
// cluster leadership lease (ADR-031 Decision 5). After the legacy election
// removal (Issue #1291), electNewLeader always returns nil.
func TestFailoverManager_electNewLeader_DefersToLease(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "test-failover-raft-node"

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)

	fm, err := NewFailoverManager(cfg.Failover, logger, manager)
	require.NoError(t, err)

	ctx := context.Background()
	// electNewLeader must return nil — the cluster leadership lease is the
	// election authority.
	err = fm.electNewLeader(ctx)
	assert.NoError(t, err, "electNewLeader must defer to the lease and return nil")
}

// TestFailoverManager_executeFailover_NonClusterMode verifies that in non-cluster
// mode, executeFailover no longer calls promoteToLeader (which has been removed).
func TestFailoverManager_executeFailover_NonClusterMode(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)

	fm, err := NewFailoverManager(cfg.Failover, logger, manager)
	require.NoError(t, err)

	ctx := context.Background()

	// Should not panic (no promoteToLeader call) and should complete without error.
	err = fm.executeFailover(ctx, "test_non_cluster_failover", false)
	assert.NoError(t, err)
}

// startRegistryBackedPair starts two ClusterMode managers over one shared lease
// store and one shared node registry, and waits until both are registered and one
// holds the leadership lease.
func startRegistryBackedPair(t *testing.T, registryStore business.NodeRegistryStore, minQuorum int) (*Manager, *Manager) {
	t.Helper()
	leaseStore := newTestLeaseStore(t)
	a := newLeaseBackedClusterManager(t, "failover-reg-a", leaseStore)
	b := newLeaseBackedClusterManager(t, "failover-reg-b", leaseStore)
	for _, m := range []*Manager{a, b} {
		// FastElectionConfig's 200ms lease TTL can lapse between renewals on a
		// loaded runner, which makes GetLeader report "no leader elected" and
		// fires a genuine no_leader_elected failover. These tests exercise the
		// failover monitor's view of a stable cluster, not election speed, so
		// rebuild the lease manager on the production ElectionTimeout.
		m.cfg.Cluster.ElectionTimeout = DefaultConfig().Cluster.ElectionTimeout
		require.NoError(t, m.SetLeaseStore(leaseStore))
		m.nodeRegistryStore = registryStore
		m.cfg.Cluster.MinQuorum = minQuorum
		m.nodeInfo.Version = "v-test"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	require.NoError(t, a.Start(ctx))
	require.NoError(t, b.Start(ctx))
	t.Cleanup(func() {
		assert.NoError(t, a.Stop(context.Background()))
		assert.NoError(t, b.Stop(context.Background()))
	})

	require.Eventually(t, func() bool {
		nodes, err := registryStore.ListNodes(context.Background())
		return err == nil && len(nodes) == 2
	}, 5*time.Second, 25*time.Millisecond, "both managers must self-register")
	require.Eventually(t, func() bool {
		return a.HasLeadership() || b.HasLeadership()
	}, 5*time.Second, 5*time.Millisecond, "one manager must hold the lease")
	return a, b
}

// TestFailoverManager_HealthyRegistryCluster_TriggersNoFailover is the REQUIRED
// regression test for Issue #4514: with two live nodes in a shared registry, the
// failover monitor must see a healthy leader and trigger nothing.
func TestFailoverManager_HealthyRegistryCluster_TriggersNoFailover(t *testing.T) {
	registryStore := newTestNodeRegistryStore(t)
	a, b := startRegistryBackedPair(t, registryStore, 2)

	for _, m := range []*Manager{a, b} {
		fm, err := NewFailoverManager(m.cfg.Failover, logging.GetLogger(), m)
		require.NoError(t, err)
		impl := fm
		for i := 0; i < 5; i++ {
			impl.checkForFailoverConditions()
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		history, err := impl.GetFailoverHistory()
		require.NoError(t, err)
		assert.Empty(t, history, "a healthy cluster must trigger no automatic failover")
	}

	nodes, err := a.GetClusterNodes()
	require.NoError(t, err)
	require.Len(t, nodes, 2)
	for _, n := range nodes {
		assert.Equal(t, NodeStateHealthy, n.State)
		assert.Equal(t, "v-test", n.Version)
		assert.False(t, n.LastSeen.IsZero())
		assert.False(t, n.StartedAt.IsZero())
	}
	leader, err := b.GetLeader()
	require.NoError(t, err)
	assert.Equal(t, NodeStateHealthy, leader.State)
	assert.Equal(t, "v-test", leader.Version)
	assert.False(t, leader.LastSeen.IsZero())
	assert.False(t, leader.StartedAt.IsZero())
}

// TestFailoverManager_StaleRegistryNode_AbsentAndQuorumLost is the REQUIRED test
// that a node whose registry record is not refreshed past NodeRegistryStaleAfter
// drops out of GetClusterNodes, and that a MinQuorum above the live count still
// triggers quorum_lost.
func TestFailoverManager_StaleRegistryNode_AbsentAndQuorumLost(t *testing.T) {
	root := t.TempDir()
	registryStore := newTestNodeRegistryStoreAt(t, root)

	a, _ := startRegistryBackedPair(t, registryStore, 3)

	// Plant a record last refreshed well past the stale window.
	stale := time.Now().Add(-2 * business.NodeRegistryStaleAfter)
	path := filepath.Join(root, "node_registry", "node_registry.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	entries := map[string]map[string]interface{}{}
	require.NoError(t, json.Unmarshal(raw, &entries))
	entries["stale-peer"] = map[string]interface{}{"address": "stale:9080", "version": "v-old", "updated_at": stale}
	raw, err = json.Marshal(entries)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0600))

	nodes, err := a.GetClusterNodes()
	require.NoError(t, err)
	for _, n := range nodes {
		assert.NotEqual(t, "stale-peer", n.ID, "a stale record must be absent from GetClusterNodes")
	}
	assert.Len(t, nodes, 2)

	fm, err := NewFailoverManager(a.cfg.Failover, logging.GetLogger(), a)
	require.NoError(t, err)
	impl := fm
	impl.checkForFailoverConditions()

	require.Eventually(t, func() bool {
		history, histErr := impl.GetFailoverHistory()
		if histErr != nil {
			return false
		}
		for _, e := range history {
			if e.Reason == "quorum_lost" {
				return true
			}
		}
		return false
	}, 5*time.Second, 25*time.Millisecond, "MinQuorum above the live count must trigger quorum_lost")
}
