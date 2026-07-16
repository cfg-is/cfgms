// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package clusterregistry

import (
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
)

// DeadOwnerStaleThreshold is the age of a steward's last heartbeat after which
// its cluster-role ownership is considered stale. Matches
// heartbeat.Config.StewardOfflineTimeout (epic #1664: 3 missed heartbeats at 20 s
// interval = 60 s). Both values must stay in sync; this const documents the
// relationship rather than importing the heartbeat package (which would create a
// circular dependency and is not needed here).
const DeadOwnerStaleThreshold = 60 * time.Second

// ResourceStatus classifies a declared clustered resource's reconciliation outcome.
type ResourceStatus string

const (
	// StatusPresentLiveOwner means the declared resource exists in the cluster
	// registry with a live, non-stale owner — the expected healthy state.
	StatusPresentLiveOwner ResourceStatus = "present-with-live-owner"

	// StatusDeclaredMissing means the resource is declared in the cascaded config
	// but has no owner entry in the cluster registry (create-coverage gap). A non-
	// owner steward's compliant-by-delegation abstain is NOT safe for this resource.
	StatusDeclaredMissing ResourceStatus = "declared-but-missing"

	// StatusOrphanDeadOwner means the resource exists in the registry but its owner
	// node's last heartbeat exceeds DeadOwnerStaleThreshold — the owner steward is
	// considered offline and the resource is orphaned.
	StatusOrphanDeadOwner ResourceStatus = "orphan-dead-owner"

	// StatusSplitBrain means two or more cluster members report different owner
	// values for the same role (>1 claimed owner). All distinct claims are listed
	// in AllOwnerClaims.
	StatusSplitBrain ResourceStatus = "split-brain"
)

// DeclaredResource is a clustered resource declared in the cascaded config
// (typically from a cluster-policies/<clusterName> StewardConfig document).
type DeclaredResource struct {
	// ClusterName is the failover cluster name this resource belongs to.
	ClusterName string
	// RoleName is the resource/role name within the cluster. It must match the
	// suffix of the cluster:<ClusterName>.resource_owner.<RoleName> DNA key.
	RoleName string
}

// ReconciliationResult holds the reconciliation classification for one declared
// clustered resource.
type ReconciliationResult struct {
	// ClusterName and RoleName identify the declared resource.
	ClusterName string `json:"cluster_name"`
	RoleName    string `json:"role_name"`
	// Status is the reconciliation classification.
	Status ResourceStatus `json:"status"`
	// OwnerID is the reported owner for present-with-live-owner and
	// orphan-dead-owner results; empty for declared-but-missing.
	// For split-brain, this is the last-wins owner from BuildRegistry.
	OwnerID string `json:"owner_id,omitempty"`
	// AllOwnerClaims lists all distinct owner values reported by cluster members
	// for this role. Populated only for split-brain; nil otherwise.
	AllOwnerClaims []string `json:"all_owner_claims,omitempty"`
}

// Reconcile classifies each declared resource against the actual cluster registry.
//
// It detects four conditions:
//   - present-with-live-owner: the resource exists in the registry and its owner
//     has a recent heartbeat.
//   - declared-but-missing: the resource is declared in config but has no owner
//     in any member steward's DNA (create-coverage gap).
//   - orphan-dead-owner: the resource has a registry entry but its owner steward
//     has not sent a heartbeat within DeadOwnerStaleThreshold.
//   - split-brain: two or more cluster members report different owner values for
//     the same role (>1 claimed owner); all claims are surfaced.
//
// Parameters:
//   - declared: the resources that should exist (from the cascaded config).
//   - reg: the actual cluster state (from BuildRegistry over the same stewards).
//   - stewards: the raw steward slice (same slice used to build reg). Used to
//     detect split-brain by comparing each member's resource_owner.* DNA keys.
//   - isOwnerLive: caller-supplied liveness check; receives the owner value from
//     the DNA attribute (typically a cluster node name or steward ID) and returns
//     true when that owner has a sufficiently recent heartbeat.
//
// Results preserve the order of declared. If declared is empty, Reconcile returns
// an empty (non-nil) slice.
func Reconcile(
	declared []DeclaredResource,
	reg *Registry,
	stewards []fleet.StewardData,
	isOwnerLive func(ownerID string) bool,
) []ReconciliationResult {
	claimSets := buildRoleClaimSets(stewards)
	results := make([]ReconciliationResult, 0, len(declared))

	for _, d := range declared {
		result := reconcileOne(d, reg, claimSets, isOwnerLive)
		results = append(results, result)
	}
	return results
}

// reconcileOne classifies a single declared resource.
func reconcileOne(
	d DeclaredResource,
	reg *Registry,
	claimSets map[string]map[string][]string,
	isOwnerLive func(ownerID string) bool,
) ReconciliationResult {
	clusterClaims := claimSets[d.ClusterName]
	roleClaims := clusterClaims[d.RoleName] // nil / empty if no steward reported this role

	switch {
	case len(roleClaims) == 0:
		// No steward has published a resource_owner entry for this role: gap.
		return ReconciliationResult{
			ClusterName: d.ClusterName,
			RoleName:    d.RoleName,
			Status:      StatusDeclaredMissing,
		}

	case len(roleClaims) > 1:
		// Multiple distinct owner values: split-brain.
		claims := make([]string, len(roleClaims))
		copy(claims, roleClaims)
		sort.Strings(claims)

		// Use the last-wins registry value as the canonical OwnerID.
		var ownerID string
		if entry := reg.Cluster(d.ClusterName); entry != nil {
			ownerID = entry.RoleOwners[d.RoleName]
		}
		return ReconciliationResult{
			ClusterName:    d.ClusterName,
			RoleName:       d.RoleName,
			Status:         StatusSplitBrain,
			OwnerID:        ownerID,
			AllOwnerClaims: claims,
		}

	default:
		// Exactly one distinct owner value reported.
		ownerID := roleClaims[0]
		if isOwnerLive(ownerID) {
			return ReconciliationResult{
				ClusterName: d.ClusterName,
				RoleName:    d.RoleName,
				Status:      StatusPresentLiveOwner,
				OwnerID:     ownerID,
			}
		}
		return ReconciliationResult{
			ClusterName: d.ClusterName,
			RoleName:    d.RoleName,
			Status:      StatusOrphanDeadOwner,
			OwnerID:     ownerID,
		}
	}
}

// buildRoleClaimSets scans each steward's DNA attributes for
// cluster:<name>.resource_owner.<role> keys and collects all distinct owner
// values reported by different stewards for each (cluster, role) pair.
//
// Returns map[clusterName]map[roleName][]distinctOwnerValues.
// len(distinctOwnerValues) > 1 for a given role signals split-brain.
func buildRoleClaimSets(stewards []fleet.StewardData) map[string]map[string][]string {
	claimSets := make(map[string]map[string][]string)

	for _, steward := range stewards {
		for key, value := range steward.DNAAttributes {
			if !strings.HasPrefix(key, clusterKeyPrefix) {
				continue
			}
			rest := key[len(clusterKeyPrefix):]
			dotIdx := strings.Index(rest, ".")
			if dotIdx <= 0 {
				continue
			}
			clusterName := rest[:dotIdx]
			field := rest[dotIdx+1:]
			if !strings.HasPrefix(field, resourceOwnerPrefix) {
				continue
			}
			roleName := field[len(resourceOwnerPrefix):]
			if roleName == "" || value == "" {
				continue
			}

			if claimSets[clusterName] == nil {
				claimSets[clusterName] = make(map[string][]string)
			}
			// Append only if this distinct owner value isn't already recorded.
			alreadySeen := false
			for _, existing := range claimSets[clusterName][roleName] {
				if existing == value {
					alreadySeen = true
					break
				}
			}
			if !alreadySeen {
				claimSets[clusterName][roleName] = append(claimSets[clusterName][roleName], value)
			}
		}
	}
	return claimSets
}
