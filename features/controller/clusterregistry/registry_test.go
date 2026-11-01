// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package clusterregistry_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/clusterregistry"
	"github.com/cfgis/cfgms/features/controller/fleet"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
)

// ─── fragment helpers ─────────────────────────────────────────────────────────

// clusterFragment builds a cluster:<name> fragment with the given resource_owner
// map and any extra state fields. Construction goes through sdna.NewFragment —
// the same production path the steward's monitor bridge uses — so the canonical
// bytes and hash are never hand-rolled.
func clusterFragment(t *testing.T, clusterName string, owners map[string]string, extra ...map[string]interface{}) *commonpb.Fragment {
	t.Helper()
	state := sdna.MapState{
		"name":           clusterName,
		"resource_owner": owners,
	}
	for _, m := range extra {
		for k, v := range m {
			state[k] = v
		}
	}
	frag, err := sdna.NewFragment("cluster:"+clusterName, "hyperv", state)
	require.NoError(t, err)
	return frag
}

// memberOnlyFragment builds a cluster:<name> fragment with no resource_owner entries.
// Used for stewards that are cluster members but do not own any roles.
func memberOnlyFragment(t *testing.T, clusterName string, extra ...map[string]interface{}) *commonpb.Fragment {
	t.Helper()
	return clusterFragment(t, clusterName, map[string]string{}, extra...)
}

// ─── ClustersFromFragments tests ─────────────────────────────────────────────

// TestClustersFromFragments_NoCandidates covers the 0-candidate case:
// nil input returns an empty slice.
func TestClustersFromFragments_NoCandidates(t *testing.T) {
	names := clusterregistry.ClustersFromFragments(nil)
	assert.Empty(t, names)
}

// TestClustersFromFragments_OnlyNonClusterFragments covers the 0-candidate case
// where fragments exist but none carry a cluster: prefix.
func TestClustersFromFragments_OnlyNonClusterFragments(t *testing.T) {
	frags := []*commonpb.Fragment{
		{FragmentId: "host:cpu"},
		{FragmentId: "service:sshd"},
		nil,
	}
	names := clusterregistry.ClustersFromFragments(frags)
	assert.Empty(t, names)
}

// TestClustersFromFragments_OneCandidate covers the 1-candidate case.
func TestClustersFromFragments_OneCandidate(t *testing.T) {
	frags := []*commonpb.Fragment{
		memberOnlyFragment(t, "cfg-lab"),
	}
	names := clusterregistry.ClustersFromFragments(frags)
	assert.Equal(t, []string{"cfg-lab"}, names)
}

// TestClustersFromFragments_TwoCandidates covers the 2+-candidate case.
func TestClustersFromFragments_TwoCandidates(t *testing.T) {
	frags := []*commonpb.Fragment{
		memberOnlyFragment(t, "cfg-lab"),
		memberOnlyFragment(t, "cfg-prod"),
	}
	names := clusterregistry.ClustersFromFragments(frags)
	assert.Equal(t, []string{"cfg-lab", "cfg-prod"}, names)
}

// TestClustersFromFragments_Deduplicated verifies multiple fragments for the
// same cluster name are returned as a single entry.
func TestClustersFromFragments_Deduplicated(t *testing.T) {
	frags := []*commonpb.Fragment{
		memberOnlyFragment(t, "cfg-lab"),
		memberOnlyFragment(t, "cfg-lab"), // duplicate cluster name
	}
	names := clusterregistry.ClustersFromFragments(frags)
	assert.Equal(t, []string{"cfg-lab"}, names)
}

// TestClustersFromFragments_EmptyClusterNameIgnored verifies that a fragment
// with ID "cluster:" (empty name after prefix) is silently skipped.
func TestClustersFromFragments_EmptyClusterNameIgnored(t *testing.T) {
	frags := []*commonpb.Fragment{
		{FragmentId: "cluster:"}, // empty name — skipped
		{FragmentId: "cluster:good"},
	}
	names := clusterregistry.ClustersFromFragments(frags)
	assert.Equal(t, []string{"good"}, names)
}

// TestClustersFromFragments_MalformedBytesDoNotGateMembership verifies that
// ClustersFromFragments only inspects fragment IDs, never canonical bytes.
// A fragment with an undecodable CanonicalBytes still contributes its cluster name.
func TestClustersFromFragments_MalformedBytesDoNotGateMembership(t *testing.T) {
	frags := []*commonpb.Fragment{
		{FragmentId: "cluster:with-bad-bytes", CanonicalBytes: []byte{0xFF, 0xFF}},
	}
	names := clusterregistry.ClustersFromFragments(frags)
	assert.Equal(t, []string{"with-bad-bytes"}, names,
		"ClustersFromFragments must not decode bytes; the fragment ID alone determines membership")
}

// TestClustersFromFragments_SortedOutput verifies the returned slice is sorted.
func TestClustersFromFragments_SortedOutput(t *testing.T) {
	frags := []*commonpb.Fragment{
		{FragmentId: "cluster:z-cluster"},
		{FragmentId: "cluster:a-cluster"},
		{FragmentId: "cluster:m-cluster"},
	}
	names := clusterregistry.ClustersFromFragments(frags)
	assert.Equal(t, []string{"a-cluster", "m-cluster", "z-cluster"}, names)
}

// ─── BuildRegistry tests ──────────────────────────────────────────────────────

// TestClusterRegistry_ParsesDNAFragments_MultiSteward is the required AC test.
// It asserts both the forward view (cluster → members → role owners) and the
// reverse MemberClusters(stewardID) lookup against the same fixture data.
func TestClusterRegistry_ParsesDNAFragments_MultiSteward(t *testing.T) {
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAAttributes: map[string]string{
				"hostname": "CFG-70-02",
			},
			DNAFragments: []*commonpb.Fragment{
				clusterFragment(t, "cfg-lab", map[string]string{
					"csv": "CFG-70-02",
					"cno": "CFG-AB-02",
				}, map[string]interface{}{"member_nodes": []string{"CFG-70-02", "CFG-AB-02"}}),
			},
		},
		{
			ID:       "steward-b",
			TenantID: "default",
			DNAAttributes: map[string]string{
				"hostname": "CFG-AB-02",
			},
			DNAFragments: []*commonpb.Fragment{
				clusterFragment(t, "cfg-lab", map[string]string{
					"csv": "CFG-70-02",
					"cno": "CFG-AB-02",
				}, map[string]interface{}{"member_nodes": []string{"CFG-70-02", "CFG-AB-02"}}),
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

func TestClusterRegistry_NoClusterFragments(t *testing.T) {
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAAttributes: map[string]string{
				"hostname": "myhost",
				"os":       "linux",
			},
			// No DNAFragments — steward is not a cluster member.
		},
	}
	reg := clusterregistry.BuildRegistry(stewards)
	assert.Empty(t, reg.Clusters())
	assert.Empty(t, reg.MemberClusters("steward-a"))
}

func TestClusterRegistry_MalformedFragmentSkipped(t *testing.T) {
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAFragments: []*commonpb.Fragment{
				// Malformed: empty cluster name (cluster: with no name after prefix).
				{FragmentId: "cluster:", CanonicalBytes: []byte{0x00}},
				// Malformed: non-cluster fragment — should be silently skipped.
				{FragmentId: "host:cpu", CanonicalBytes: []byte{0x00}},
				// Malformed: canonical bytes that cannot be decoded.
				{FragmentId: "cluster:bad-bytes", CanonicalBytes: []byte{0xFF, 0xFF}},
				// Valid cluster fragment alongside the bad ones.
				clusterFragment(t, "cfg-lab", map[string]string{"csv": "CFG-70-02"}),
			},
		},
	}
	reg := clusterregistry.BuildRegistry(stewards)
	clusters := reg.Clusters()
	// Only the valid cluster should appear; malformed fragments are silently dropped.
	assert.Len(t, clusters, 1)
	_, ok := clusters["cfg-lab"]
	assert.True(t, ok)
}

func TestClusterRegistry_MultipleClusters(t *testing.T) {
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAFragments: []*commonpb.Fragment{
				clusterFragment(t, "cfg-lab", map[string]string{"csv": "CFG-70-02"}),
				clusterFragment(t, "cfg-prod", map[string]string{"cno": "CFG-70-02"}),
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
	// A steward with a single cluster fragment — the registry must record it exactly once.
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAFragments: []*commonpb.Fragment{
				clusterFragment(t, "cfg-lab", map[string]string{
					"csv": "CFG-70-02",
					"cno": "CFG-70-02",
				}),
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

// TestBuildRegistry_NonCNOSteward_HasClusterMembership is the AC5 acceptance
// test for issue #2891. It verifies that clusterregistry.BuildRegistry correctly
// includes non-CNO cluster members (stewards that carry a cluster:* fragment
// produced by the whole-domain observe path without owning any roles).
//
// Fixture: steward-1 is NODE1 (CNO owner), steward-2 is NODE2 (non-CNO member).
// Both stewards publish cluster:cfg-lab fragments — steward-2 via observeLocalCluster
// (no declared resource). The registry must list both as members.
func TestBuildRegistry_NonCNOSteward_HasClusterMembership(t *testing.T) {
	stewards := []fleet.StewardData{
		{
			ID:       "steward-1",
			TenantID: "default",
			DNAFragments: []*commonpb.Fragment{
				clusterFragment(t, "cfg-lab", map[string]string{"web-01": "NODE1"},
					map[string]interface{}{
						"member_nodes":   []string{"NODE1", "NODE2"},
						"cno_owner_node": "NODE1",
						"found":          true,
					}),
			},
		},
		{
			ID:       "steward-2",
			TenantID: "default",
			DNAFragments: []*commonpb.Fragment{
				// Non-CNO member: has a cluster fragment but no resource_owner entries.
				memberOnlyFragment(t, "cfg-lab", map[string]interface{}{
					"member_nodes":   []string{"NODE1", "NODE2"},
					"cno_owner_node": "NODE1",
					"found":          true,
				}),
			},
		},
	}

	reg := clusterregistry.BuildRegistry(stewards)
	require.NotNil(t, reg)

	entry := reg.Cluster("cfg-lab")
	require.NotNil(t, entry, "cfg-lab must be in the registry")

	members := make([]string, len(entry.Members))
	copy(members, entry.Members)
	sort.Strings(members)
	assert.Equal(t, []string{"steward-1", "steward-2"}, members,
		"non-CNO member (steward-2/NODE2) must appear in cluster membership")

	// Reverse lookup: steward-2 belongs to cfg-lab even without CNO ownership.
	clustersFor2 := reg.MemberClusters("steward-2")
	assert.Equal(t, []string{"cfg-lab"}, clustersFor2,
		"MemberClusters for non-CNO steward must include cfg-lab")

	// Reverse lookup: steward-1 still has its membership too.
	clustersFor1 := reg.MemberClusters("steward-1")
	assert.Equal(t, []string{"cfg-lab"}, clustersFor1)
}

func TestClusterRegistry_RoleOwnerNotOverwrittenByNonOwnerField(t *testing.T) {
	// Fragment has non-resource_owner fields (member_nodes, found) alongside csv.
	// Only csv should appear in RoleOwners; the other fields are fragment payload, not roles.
	stewards := []fleet.StewardData{
		{
			ID:       "steward-a",
			TenantID: "default",
			DNAFragments: []*commonpb.Fragment{
				clusterFragment(t, "cfg-lab", map[string]string{"csv": "CFG-70-02"},
					map[string]interface{}{
						"member_nodes": []string{"CFG-70-02"},
						"found":        true,
					}),
			},
		},
	}
	reg := clusterregistry.BuildRegistry(stewards)
	entry := reg.Cluster("cfg-lab")
	require.NotNil(t, entry)
	// Only csv role should be present; member_nodes and found must not appear.
	assert.Equal(t, map[string]string{"csv": "CFG-70-02"}, entry.RoleOwners)
}
