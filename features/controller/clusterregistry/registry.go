// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package clusterregistry builds a read-model cluster registry from steward DNA
// fragments (ADR-017). It has no internal state of its own — BuildRegistry is a
// pure parse function over already-durable data; callers provide the steward slice
// (usually from fleet.StewardProvider.GetAllStewards) and receive an immutable
// Registry snapshot. The registry is eventually consistent: it reflects whatever
// DNA fragments were last published by the steward's DNARefreshLoop ticker
// (default 30 min); topology changes can take up to one interval to appear.
package clusterregistry

import (
	"sort"
	"strings"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/fleet"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
)

const clusterFragmentPrefix = "cluster:"

// ClusterEntry holds the parsed view for one cluster.
type ClusterEntry struct {
	// Name is the cluster name extracted from the cluster:<Name> fragment ID.
	Name string
	// Members is the sorted list of steward IDs whose DNA carries a cluster:<Name> fragment.
	Members []string
	// RoleOwners maps role name → owner value parsed from the fragment's resource_owner field.
	RoleOwners map[string]string
}

// Registry is the cluster view derived from steward DNA fragments.
// It is immutable after construction by BuildRegistry.
type Registry struct {
	clusters    map[string]*ClusterEntry
	memberIndex map[string][]string // stewardID → sorted slice of cluster names
}

// Clusters returns all cluster entries keyed by cluster name.
// The returned map must not be mutated by the caller.
func (r *Registry) Clusters() map[string]*ClusterEntry {
	return r.clusters
}

// Cluster returns the entry for one cluster by name, or nil if not found.
func (r *Registry) Cluster(name string) *ClusterEntry {
	return r.clusters[name]
}

// MemberClusters returns the sorted cluster names that stewardID belongs to.
// Returns nil (not an empty slice) when stewardID has no cluster membership.
func (r *Registry) MemberClusters(stewardID string) []string {
	return r.memberIndex[stewardID]
}

// ClustersFromFragments returns the sorted, deduplicated cluster names present in
// frags. It is the canonical parser for cluster:<name> fragment IDs: only the
// fragment ID is inspected; canonical bytes are not decoded. Both BuildRegistry
// (server-side registry construction) and the CLI's promote-hv-role command
// (client-side cluster derivation) use this function so the extraction logic
// lives in exactly one place.
//
// Tenant scoping must be applied by the caller before passing the fragment slice.
func ClustersFromFragments(frags []*commonpb.Fragment) []string {
	seen := make(map[string]struct{})
	for _, frag := range frags {
		if frag == nil || !strings.HasPrefix(frag.FragmentId, clusterFragmentPrefix) {
			continue
		}
		name := frag.FragmentId[len(clusterFragmentPrefix):]
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// BuildRegistry parses cluster:<name> DNA fragments from the given stewards
// into an immutable Registry.
//
// Each cluster:<name> fragment's CanonicalBytes are decoded to extract the
// resource_owner map (a map of role name → owner node, from ClusterStatus.AsMap).
//
// Tenant scoping must be applied by the caller before passing the steward slice
// (pass only stewards whose TenantID is in the caller's scope).
//
// Defensive parsing: fragments with undecodable CanonicalBytes are silently
// skipped and never affect other stewards' valid fragments.
func BuildRegistry(stewards []fleet.StewardData) *Registry {
	reg := &Registry{
		clusters:    make(map[string]*ClusterEntry),
		memberIndex: make(map[string][]string),
	}

	// seen tracks which stewards have already been recorded as members of each
	// cluster so that multiple cluster:<name> fragments for the same steward
	// do not produce duplicate member entries.
	seen := make(map[string]map[string]bool) // clusterName → set of steward IDs

	for _, steward := range stewards {
		for _, frag := range steward.DNAFragments {
			// ClustersFromFragments is the canonical cluster-name extractor; use it
			// on each fragment so the parsing logic is not duplicated here.
			names := ClustersFromFragments([]*commonpb.Fragment{frag})
			if len(names) == 0 {
				continue
			}
			clusterName := names[0]

			// Decode canonical bytes to extract cluster state.
			data, err := sdna.DecodeCanonicalFragment(frag.CanonicalBytes)
			if err != nil {
				// Malformed fragment — skip silently, never affect other entries.
				continue
			}

			// Get or create the cluster entry.
			entry, exists := reg.clusters[clusterName]
			if !exists {
				entry = &ClusterEntry{
					Name:       clusterName,
					RoleOwners: make(map[string]string),
				}
				reg.clusters[clusterName] = entry
				seen[clusterName] = make(map[string]bool)
			}

			// Record this steward as a member exactly once per cluster.
			if !seen[clusterName][steward.ID] {
				seen[clusterName][steward.ID] = true
				entry.Members = append(entry.Members, steward.ID)
				reg.memberIndex[steward.ID] = append(reg.memberIndex[steward.ID], clusterName)
			}

			// Extract resource_owner map from decoded fragment data.
			if owners, ok := data["resource_owner"].(map[string]interface{}); ok {
				for role, ownerV := range owners {
					if owner, ok := ownerV.(string); ok && role != "" && owner != "" {
						entry.RoleOwners[role] = owner
					}
				}
			}
		}
	}

	// Sort for deterministic output.
	for _, entry := range reg.clusters {
		sort.Strings(entry.Members)
	}
	for id := range reg.memberIndex {
		sort.Strings(reg.memberIndex[id])
	}

	return reg
}
