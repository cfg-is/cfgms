// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package clusterregistry_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/clusterregistry"
	"github.com/cfgis/cfgms/features/controller/fleet"
)

// TestClusterRegistry_ParsesDNAAttributes_MultiSteward is the required AC test.
// It asserts both the forward view (cluster → members → role owners) and the
// reverse MemberClusters(stewardID) lookup against the same fixture data.
func TestClusterRegistry_ParsesDNAAttributes_MultiSteward(t *testing.T) {
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAAttributes: map[string]string{
				"cluster:cfg-lab.member_nodes":       "CFG-70-02,CFG-AB-02",
				"cluster:cfg-lab.resource_owner.csv": "CFG-70-02",
				"cluster:cfg-lab.resource_owner.cno": "CFG-AB-02",
				"hostname": "CFG-70-02",
			},
		},
		{
			ID:       "steward-b",
			TenantID: "default",
			DNAAttributes: map[string]string{
				"cluster:cfg-lab.member_nodes":       "CFG-70-02,CFG-AB-02",
				"cluster:cfg-lab.resource_owner.csv": "CFG-70-02",
				"cluster:cfg-lab.resource_owner.cno": "CFG-AB-02",
				"hostname": "CFG-AB-02",
			},
		},
	}

	reg := clusterregistry.BuildRegistry(stewards)
	require.NotNil(t, reg)

	// Forward view: cluster → members → role owners.
	clusters := reg.Clusters()
	assert.Len(t, clusters, 1)

	entry, ok := clusters["cfg-lab"]
	require.True(t, ok, "expected cluster 'cfg-lab' in registry")
	assert.Equal(t, "cfg-lab", entry.Name)

	members := make([]string, len(entry.Members))
	copy(members, entry.Members)
	sort.Strings(members)
	assert.Equal(t, []string{"steward-a", "steward-b"}, members)

	assert.Equal(t, map[string]string{
		"csv": "CFG-70-02",
		"cno": "CFG-AB-02",
	}, entry.RoleOwners)

	// Reverse lookup: stewardID → cluster names.
	clustersA := reg.MemberClusters("steward-a")
	assert.Equal(t, []string{"cfg-lab"}, clustersA)

	clustersB := reg.MemberClusters("steward-b")
	assert.Equal(t, []string{"cfg-lab"}, clustersB)

	// Unknown steward returns empty/nil.
	clustersC := reg.MemberClusters("unknown-steward")
	assert.Empty(t, clustersC)
}

func TestClusterRegistry_EmptyInput(t *testing.T) {
	reg := clusterregistry.BuildRegistry(nil)
	require.NotNil(t, reg)
	assert.Empty(t, reg.Clusters())
	assert.Empty(t, reg.MemberClusters("any"))
}

func TestClusterRegistry_NoClusterKeys(t *testing.T) {
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAAttributes: map[string]string{
				"hostname": "myhost",
				"os":       "linux",
			},
		},
	}
	reg := clusterregistry.BuildRegistry(stewards)
	assert.Empty(t, reg.Clusters())
	assert.Empty(t, reg.MemberClusters("steward-a"))
}

func TestClusterRegistry_MalformedKeySkipped(t *testing.T) {
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAAttributes: map[string]string{
				// Malformed: no dot separator → should be silently skipped.
				"cluster:badkey":                     "val",
				// Malformed: empty cluster name → should be silently skipped.
				"cluster:.member_nodes":              "x",
				// Valid key alongside the bad ones.
				"cluster:cfg-lab.member_nodes":       "CFG-70-02",
				"cluster:cfg-lab.resource_owner.csv": "CFG-70-02",
			},
		},
	}
	reg := clusterregistry.BuildRegistry(stewards)
	clusters := reg.Clusters()
	// Only the valid cluster should appear; malformed keys are silently dropped.
	assert.Len(t, clusters, 1)
	_, ok := clusters["cfg-lab"]
	assert.True(t, ok)
	// Bad keys must not have leaked into the registry.
	_, badPresent := clusters["badkey"]
	assert.False(t, badPresent)
}

func TestClusterRegistry_MultipleClusters(t *testing.T) {
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAAttributes: map[string]string{
				"cluster:cfg-lab.member_nodes":         "CFG-70-02",
				"cluster:cfg-lab.resource_owner.csv":   "CFG-70-02",
				"cluster:cfg-prod.member_nodes":        "CFG-70-02",
				"cluster:cfg-prod.resource_owner.cno":  "CFG-70-02",
			},
		},
	}
	reg := clusterregistry.BuildRegistry(stewards)

	assert.Len(t, reg.Clusters(), 2)

	labEntry := reg.Cluster("cfg-lab")
	require.NotNil(t, labEntry)
	assert.Equal(t, []string{"steward-a"}, labEntry.Members)

	prodEntry := reg.Cluster("cfg-prod")
	require.NotNil(t, prodEntry)
	assert.Equal(t, []string{"steward-a"}, prodEntry.Members)

	// Reverse lookup: steward-a belongs to both clusters.
	memberClusters := reg.MemberClusters("steward-a")
	sort.Strings(memberClusters)
	assert.Equal(t, []string{"cfg-lab", "cfg-prod"}, memberClusters)
}

func TestClusterRegistry_StewardDeduplication(t *testing.T) {
	// A steward with multiple cluster:name.* keys for the same cluster should
	// appear exactly once as a member, even though multiple keys trigger it.
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAAttributes: map[string]string{
				"cluster:cfg-lab.member_nodes":       "CFG-70-02",
				"cluster:cfg-lab.resource_owner.csv": "CFG-70-02",
				"cluster:cfg-lab.resource_owner.cno": "CFG-70-02",
				"cluster:cfg-lab.found":              "true",
			},
		},
	}
	reg := clusterregistry.BuildRegistry(stewards)
	entry := reg.Cluster("cfg-lab")
	require.NotNil(t, entry)
	assert.Len(t, entry.Members, 1, "steward should appear exactly once as a member")
	assert.Equal(t, []string{"steward-a"}, entry.Members)
}

func TestClusterRegistry_Cluster_NotFound(t *testing.T) {
	reg := clusterregistry.BuildRegistry(nil)
	assert.Nil(t, reg.Cluster("does-not-exist"))
}

func TestClusterRegistry_RoleOwnerNotOverwrittenByNonOwnerField(t *testing.T) {
	// Non resource_owner fields (e.g., member_nodes, found) must not pollute RoleOwners.
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAAttributes: map[string]string{
				"cluster:cfg-lab.member_nodes":       "CFG-70-02",
				"cluster:cfg-lab.found":              "true",
				"cluster:cfg-lab.resource_owner.csv": "CFG-70-02",
			},
		},
	}
	reg := clusterregistry.BuildRegistry(stewards)
	entry := reg.Cluster("cfg-lab")
	require.NotNil(t, entry)
	// Only csv role should be present; member_nodes and found must not appear.
	assert.Equal(t, map[string]string{"csv": "CFG-70-02"}, entry.RoleOwners)
}
