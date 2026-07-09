// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/batchjob"
)

// makeMeta is a helper to build StewardMeta with an optional cluster_role.
func makeMeta(id, clusterRole string) batchjob.StewardMeta {
	attrs := map[string]string{}
	if clusterRole != "" {
		attrs["cluster_role"] = clusterRole
	}
	return batchjob.StewardMeta{ID: id, DNAAttributes: attrs}
}

// roleOf returns the cluster_role value from the steward's index in a provided
// lookup map — used to assert quorum in test helpers.
func noSharedRole(t *testing.T, batches [][]string, roleByID map[string]string) {
	t.Helper()
	for i, batch := range batches {
		seen := map[string]string{} // role → first steward ID that claimed it
		for _, id := range batch {
			role := roleByID[id]
			if role == "" {
				continue // plain stewards never conflict
			}
			if prev, conflict := seen[role]; conflict {
				t.Errorf("batch %d contains two stewards with cluster_role=%q: %s and %s",
					i, role, prev, id)
			}
			seen[role] = id
		}
	}
}

// TestDnaRoleQuorumChecker_MixedRolesAndPlain is the REQUIRED acceptance-criteria test:
// 6 stewards — 2 with cluster_role=hyperv-cluster, 1 with cluster_role=sql-ag,
// 3 with no role; batchSize=3 — assert no batch contains two stewards sharing
// a cluster_role value.
func TestDnaRoleQuorumChecker_MixedRolesAndPlain(t *testing.T) {
	checker := batchjob.NewDnaRoleQuorumChecker()

	stewards := []batchjob.StewardMeta{
		makeMeta("hv-1", "hyperv-cluster"),
		makeMeta("hv-2", "hyperv-cluster"),
		makeMeta("sql-1", "sql-ag"),
		makeMeta("plain-1", ""),
		makeMeta("plain-2", ""),
		makeMeta("plain-3", ""),
	}

	roleByID := map[string]string{
		"hv-1":    "hyperv-cluster",
		"hv-2":    "hyperv-cluster",
		"sql-1":   "sql-ag",
		"plain-1": "",
		"plain-2": "",
		"plain-3": "",
	}

	batches := checker.Partition(stewards, 3)
	require.NotEmpty(t, batches)

	// Primary assertion: no batch may have two stewards with the same cluster_role.
	noSharedRole(t, batches, roleByID)

	// Sanity: all 6 stewards appear exactly once across all batches.
	all := make(map[string]int)
	for _, batch := range batches {
		for _, id := range batch {
			all[id]++
		}
	}
	for _, s := range stewards {
		assert.Equal(t, 1, all[s.ID], "steward %s must appear exactly once", s.ID)
	}
}

// TestDnaRoleQuorumChecker_SingleGroupExceedsBatchSize is the REQUIRED
// acceptance-criteria test: single role group of 4 members, batchSize=2 —
// assert each batch contains exactly 1 member of that role group.
func TestDnaRoleQuorumChecker_SingleGroupExceedsBatchSize(t *testing.T) {
	checker := batchjob.NewDnaRoleQuorumChecker()

	stewards := []batchjob.StewardMeta{
		makeMeta("dc-1", "dc-site-a"),
		makeMeta("dc-2", "dc-site-a"),
		makeMeta("dc-3", "dc-site-a"),
		makeMeta("dc-4", "dc-site-a"),
	}

	roleByID := map[string]string{
		"dc-1": "dc-site-a",
		"dc-2": "dc-site-a",
		"dc-3": "dc-site-a",
		"dc-4": "dc-site-a",
	}

	batches := checker.Partition(stewards, 2)
	require.NotEmpty(t, batches)

	// Primary assertion: no batch may contain two stewards sharing a
	// cluster_role. Since all four stewards share dc-site-a, this forces each
	// batch to hold exactly one of them.
	noSharedRole(t, batches, roleByID)

	// Each batch must therefore contain exactly 1 member of the dc-site-a group.
	for i, batch := range batches {
		assert.Equal(t, 1, len(batch),
			"batch %d must contain exactly 1 steward when group size exceeds batchSize", i)
	}

	// Total batches must equal 4 (one per steward).
	assert.Equal(t, 4, len(batches))

	// All 4 stewards must appear exactly once.
	all := make(map[string]int)
	for _, batch := range batches {
		for _, id := range batch {
			all[id]++
		}
	}
	for _, s := range stewards {
		assert.Equal(t, 1, all[s.ID], "steward %s must appear exactly once", s.ID)
	}
}

// TestDnaRoleQuorumChecker_EmptyInput returns nil for an empty steward list.
func TestDnaRoleQuorumChecker_EmptyInput(t *testing.T) {
	checker := batchjob.NewDnaRoleQuorumChecker()
	batches := checker.Partition(nil, 3)
	assert.Nil(t, batches)
}

// TestDnaRoleQuorumChecker_AllPlain delegates to naive partitioning when no
// steward carries a cluster_role.
func TestDnaRoleQuorumChecker_AllPlain(t *testing.T) {
	checker := batchjob.NewDnaRoleQuorumChecker()

	stewards := []batchjob.StewardMeta{
		makeMeta("p-1", ""),
		makeMeta("p-2", ""),
		makeMeta("p-3", ""),
		makeMeta("p-4", ""),
	}

	batches := checker.Partition(stewards, 2)
	require.Len(t, batches, 2, "4 plain stewards / batchSize 2 = 2 batches")
	assert.Len(t, batches[0], 2)
	assert.Len(t, batches[1], 2)
}

// TestDnaRoleQuorumChecker_NoSharedRoleAcrossAllBatches is a broader fuzz-style
// test: multiple groups of varying sizes with plain stewards interleaved.
func TestDnaRoleQuorumChecker_NoSharedRoleAcrossAllBatches(t *testing.T) {
	checker := batchjob.NewDnaRoleQuorumChecker()

	stewards := []batchjob.StewardMeta{
		makeMeta("a1", "group-a"),
		makeMeta("a2", "group-a"),
		makeMeta("a3", "group-a"),
		makeMeta("b1", "group-b"),
		makeMeta("b2", "group-b"),
		makeMeta("c1", "group-c"),
		makeMeta("plain-1", ""),
		makeMeta("plain-2", ""),
	}

	roleByID := map[string]string{
		"a1": "group-a", "a2": "group-a", "a3": "group-a",
		"b1": "group-b", "b2": "group-b",
		"c1": "group-c",
	}

	batches := checker.Partition(stewards, 3)
	require.NotEmpty(t, batches)
	noSharedRole(t, batches, roleByID)

	// All stewards appear exactly once.
	all := make(map[string]int)
	for _, batch := range batches {
		for _, id := range batch {
			all[id]++
		}
	}
	for _, s := range stewards {
		assert.Equal(t, 1, all[s.ID], "steward %s must appear exactly once", s.ID)
	}
}
