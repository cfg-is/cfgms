// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package clusterregistry_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/clusterregistry"
	"github.com/cfgis/cfgms/features/controller/fleet"
)

// liveOwner is an isOwnerLive function that treats all owners as live.
func liveOwner(_ string) bool { return true }

// deadOwner is an isOwnerLive function that treats all owners as dead.
func deadOwner(_ string) bool { return false }

// liveSet returns an isOwnerLive function that treats exactly the given set of
// owner IDs as live (all others are dead).
func liveSet(live ...string) func(string) bool {
	set := make(map[string]bool, len(live))
	for _, id := range live {
		set[id] = true
	}
	return func(ownerID string) bool { return set[ownerID] }
}

// makeClusterSteward builds a StewardData with the given DNA attributes.
// LastHeartbeat is set to time.Now() (live).
func makeClusterSteward(id string, dna map[string]string) fleet.StewardData {
	return fleet.StewardData{
		ID:            id,
		TenantID:      "default",
		Status:        "active",
		LastHeartbeat: time.Now(),
		DNAAttributes: dna,
	}
}

// TestReconcile_HappyPath_PresentWithLiveOwner is the required AC test for the
// healthy case: a declared role exists in the registry with a single live owner.
func TestReconcile_HappyPath_PresentWithLiveOwner(t *testing.T) {
	stewards := []fleet.StewardData{
		makeClusterSteward("node-a", map[string]string{
			"cluster:cfg-lab.resource_owner.vm1": "node-a",
		}),
	}
	reg := clusterregistry.BuildRegistry(stewards)
	declared := []clusterregistry.DeclaredResource{
		{ClusterName: "cfg-lab", RoleName: "vm1"},
	}

	results := clusterregistry.Reconcile(declared, reg, stewards, liveOwner)

	require.Len(t, results, 1)
	assert.Equal(t, clusterregistry.StatusPresentLiveOwner, results[0].Status)
	assert.Equal(t, "cfg-lab", results[0].ClusterName)
	assert.Equal(t, "vm1", results[0].RoleName)
	assert.Equal(t, "node-a", results[0].OwnerID)
	assert.Empty(t, results[0].AllOwnerClaims)
}

// TestReconcile_CreateCoverageGap_DeclaredButMissing is the required AC test for
// the create-coverage gap: a role is declared in config but no steward has
// published a resource_owner entry for it.
func TestReconcile_CreateCoverageGap_DeclaredButMissing(t *testing.T) {
	// Cluster members exist but neither has published resource_owner for "vm2".
	stewards := []fleet.StewardData{
		makeClusterSteward("node-a", map[string]string{
			"cluster:cfg-lab.member_nodes": "node-a,node-b",
		}),
		makeClusterSteward("node-b", map[string]string{
			"cluster:cfg-lab.member_nodes": "node-a,node-b",
		}),
	}
	reg := clusterregistry.BuildRegistry(stewards)
	declared := []clusterregistry.DeclaredResource{
		{ClusterName: "cfg-lab", RoleName: "vm2"},
	}

	results := clusterregistry.Reconcile(declared, reg, stewards, liveOwner)

	require.Len(t, results, 1)
	assert.Equal(t, clusterregistry.StatusDeclaredMissing, results[0].Status)
	assert.Equal(t, "cfg-lab", results[0].ClusterName)
	assert.Equal(t, "vm2", results[0].RoleName)
	assert.Empty(t, results[0].OwnerID, "declared-but-missing must not report an owner")
	assert.Empty(t, results[0].AllOwnerClaims)
}

// TestReconcile_DeadOwner_OrphanDeadOwner is the required AC test for the dead-owner
// case: a role has a registry entry but the owner's heartbeat is stale.
func TestReconcile_DeadOwner_OrphanDeadOwner(t *testing.T) {
	stewards := []fleet.StewardData{
		makeClusterSteward("node-a", map[string]string{
			"cluster:cfg-lab.resource_owner.csv": "node-a",
		}),
	}
	reg := clusterregistry.BuildRegistry(stewards)
	declared := []clusterregistry.DeclaredResource{
		{ClusterName: "cfg-lab", RoleName: "csv"},
	}

	// deadOwner treats all owners as stale/offline.
	results := clusterregistry.Reconcile(declared, reg, stewards, deadOwner)

	require.Len(t, results, 1)
	assert.Equal(t, clusterregistry.StatusOrphanDeadOwner, results[0].Status)
	assert.Equal(t, "node-a", results[0].OwnerID)
	assert.Empty(t, results[0].AllOwnerClaims)
}

// TestReconcile_SplitBrain is the required AC test for split-brain:
// two cluster members report different owner values for the same role.
func TestReconcile_SplitBrain(t *testing.T) {
	// node-a reports that it owns "csv"; node-b simultaneously reports it owns "csv".
	stewards := []fleet.StewardData{
		makeClusterSteward("node-a", map[string]string{
			"cluster:cfg-lab.resource_owner.csv": "node-a",
		}),
		makeClusterSteward("node-b", map[string]string{
			"cluster:cfg-lab.resource_owner.csv": "node-b",
		}),
	}
	reg := clusterregistry.BuildRegistry(stewards)
	declared := []clusterregistry.DeclaredResource{
		{ClusterName: "cfg-lab", RoleName: "csv"},
	}

	results := clusterregistry.Reconcile(declared, reg, stewards, liveOwner)

	require.Len(t, results, 1)
	assert.Equal(t, clusterregistry.StatusSplitBrain, results[0].Status)
	assert.ElementsMatch(t, []string{"node-a", "node-b"}, results[0].AllOwnerClaims,
		"split-brain must list all distinct owner claims")
}

// TestReconcile_SameOwnerAgreed verifies that two stewards reporting the SAME
// owner value is NOT split-brain — they both agree on who owns the role.
func TestReconcile_SameOwnerAgreed(t *testing.T) {
	stewards := []fleet.StewardData{
		makeClusterSteward("node-a", map[string]string{
			"cluster:cfg-lab.resource_owner.csv": "node-a",
		}),
		makeClusterSteward("node-b", map[string]string{
			"cluster:cfg-lab.resource_owner.csv": "node-a", // agrees: node-a owns csv
		}),
	}
	reg := clusterregistry.BuildRegistry(stewards)
	declared := []clusterregistry.DeclaredResource{
		{ClusterName: "cfg-lab", RoleName: "csv"},
	}

	results := clusterregistry.Reconcile(declared, reg, stewards, liveOwner)

	require.Len(t, results, 1)
	assert.Equal(t, clusterregistry.StatusPresentLiveOwner, results[0].Status,
		"two stewards agreeing on the same owner is not split-brain")
	assert.Equal(t, "node-a", results[0].OwnerID)
	assert.Empty(t, results[0].AllOwnerClaims)
}

// TestReconcile_MultipleRoles verifies mixed results when a cluster has several
// roles in different states.
func TestReconcile_MultipleRoles(t *testing.T) {
	stewards := []fleet.StewardData{
		makeClusterSteward("node-a", map[string]string{
			"cluster:cfg-lab.resource_owner.vm1": "node-a",
			"cluster:cfg-lab.resource_owner.vm2": "node-a",
			// vm3 is declared but not yet created (no resource_owner.vm3).
		}),
		makeClusterSteward("node-b", map[string]string{
			// node-b claims vm2 (split-brain with node-a).
			"cluster:cfg-lab.resource_owner.vm2": "node-b",
		}),
	}
	reg := clusterregistry.BuildRegistry(stewards)
	declared := []clusterregistry.DeclaredResource{
		{ClusterName: "cfg-lab", RoleName: "vm1"},
		{ClusterName: "cfg-lab", RoleName: "vm2"},
		{ClusterName: "cfg-lab", RoleName: "vm3"},
	}

	// vm1's owner (node-a) is live; vm2 is split-brain; vm3 is missing.
	results := clusterregistry.Reconcile(declared, reg, stewards, liveSet("node-a"))

	require.Len(t, results, 3)

	vm1 := results[0]
	assert.Equal(t, "vm1", vm1.RoleName)
	assert.Equal(t, clusterregistry.StatusPresentLiveOwner, vm1.Status)
	assert.Equal(t, "node-a", vm1.OwnerID)

	vm2 := results[1]
	assert.Equal(t, "vm2", vm2.RoleName)
	assert.Equal(t, clusterregistry.StatusSplitBrain, vm2.Status)
	assert.ElementsMatch(t, []string{"node-a", "node-b"}, vm2.AllOwnerClaims)

	vm3 := results[2]
	assert.Equal(t, "vm3", vm3.RoleName)
	assert.Equal(t, clusterregistry.StatusDeclaredMissing, vm3.Status)
}

// TestReconcile_EmptyDeclared verifies that an empty declared list returns an
// empty (non-nil) result slice — no declared resources, nothing to reconcile.
func TestReconcile_EmptyDeclared(t *testing.T) {
	stewards := []fleet.StewardData{
		makeClusterSteward("node-a", map[string]string{
			"cluster:cfg-lab.resource_owner.csv": "node-a",
		}),
	}
	reg := clusterregistry.BuildRegistry(stewards)

	results := clusterregistry.Reconcile(nil, reg, stewards, liveOwner)
	assert.NotNil(t, results, "Reconcile must return a non-nil slice even for empty declared")
	assert.Empty(t, results)
}

// TestReconcile_UnknownOwnerTreatedAsDead verifies that when the owner ID in the
// registry does not correspond to any known steward, isOwnerLive returns false
// and the result is orphan-dead-owner.
func TestReconcile_UnknownOwnerTreatedAsDead(t *testing.T) {
	stewards := []fleet.StewardData{
		makeClusterSteward("node-a", map[string]string{
			"cluster:cfg-lab.resource_owner.csv": "unknown-node",
		}),
	}
	reg := clusterregistry.BuildRegistry(stewards)
	declared := []clusterregistry.DeclaredResource{
		{ClusterName: "cfg-lab", RoleName: "csv"},
	}

	// Only node-a is live; unknown-node is not in the live set.
	results := clusterregistry.Reconcile(declared, reg, stewards, liveSet("node-a"))

	require.Len(t, results, 1)
	assert.Equal(t, clusterregistry.StatusOrphanDeadOwner, results[0].Status,
		"unknown owner (not in isOwnerLive set) must be treated as dead")
	assert.Equal(t, "unknown-node", results[0].OwnerID)
}

// TestReconcile_CrossClusterIsolation verifies that declared resources for one
// cluster are not affected by entries in a different cluster.
func TestReconcile_CrossClusterIsolation(t *testing.T) {
	stewards := []fleet.StewardData{
		makeClusterSteward("node-a", map[string]string{
			// Only cfg-prod has resource_owner.vm1; cfg-lab does not.
			"cluster:cfg-prod.resource_owner.vm1": "node-a",
		}),
	}
	reg := clusterregistry.BuildRegistry(stewards)
	declared := []clusterregistry.DeclaredResource{
		{ClusterName: "cfg-lab", RoleName: "vm1"},
	}

	results := clusterregistry.Reconcile(declared, reg, stewards, liveOwner)

	require.Len(t, results, 1)
	assert.Equal(t, clusterregistry.StatusDeclaredMissing, results[0].Status,
		"cfg-prod.vm1 must not satisfy cfg-lab.vm1 declaration")
}

// TestDeadOwnerStaleThreshold verifies the exported constant matches the
// heartbeat.StewardOfflineTimeout default (60 s, epic #1664).
func TestDeadOwnerStaleThreshold(t *testing.T) {
	assert.Equal(t, 60*time.Second, clusterregistry.DeadOwnerStaleThreshold,
		"DeadOwnerStaleThreshold must match heartbeat.Config.StewardOfflineTimeout default")
}
