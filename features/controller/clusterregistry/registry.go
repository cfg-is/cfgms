// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package clusterregistry builds a read-model cluster registry from steward DNA
// attributes. It has no internal state of its own — BuildRegistry is a pure
// parse function over already-durable data; callers provide the steward slice
// (usually from fleet.StewardProvider.GetAllStewards) and receive an immutable
// Registry snapshot. The registry is eventually consistent: it reflects whatever
// DNA attributes were last published by the steward's DNARefreshLoop ticker
// (default 30 min); topology changes can take up to one interval to appear.
package clusterregistry

import (
	"sort"
	"strings"

	"github.com/cfgis/cfgms/features/controller/fleet"
)

const (
	clusterKeyPrefix    = "cluster:"
	resourceOwnerPrefix = "resource_owner."
)

// ClusterEntry holds the parsed view for one cluster.
type ClusterEntry struct {
	// Name is the cluster name extracted from the cluster:<Name>.* DNA key prefix.
	Name string
	// Members is the sorted list of steward IDs whose DNA carries cluster:<Name>.* keys.
	Members []string
	// RoleOwners maps role name → owner value parsed from cluster:<Name>.resource_owner.<role> keys.
	RoleOwners map[string]string
}

// Registry is the cluster view derived from steward DNA attributes.
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

// BuildRegistry parses cluster:<name>.* DNA attributes from the given stewards
// into an immutable Registry.
//
// Tenant scoping must be applied by the caller before passing the steward slice
// (pass only stewards whose TenantID is in the caller's scope).
//
// Defensive parsing: unrecognised or malformed cluster:* keys are silently
// skipped and never affect other stewards' valid keys.
func BuildRegistry(stewards []fleet.StewardData) *Registry {
	reg := &Registry{
		clusters:    make(map[string]*ClusterEntry),
		memberIndex: make(map[string][]string),
	}

	// seen tracks which stewards have already been recorded as members of each
	// cluster so that multiple cluster:<name>.* keys for the same steward do
	// not produce duplicate member entries.
	seen := make(map[string]map[string]bool) // clusterName → set of steward IDs

	for _, steward := range stewards {
		for key, value := range steward.DNAAttributes {
			if !strings.HasPrefix(key, clusterKeyPrefix) {
				continue
			}
			rest := key[len(clusterKeyPrefix):]
			dotIdx := strings.Index(rest, ".")
			if dotIdx <= 0 {
				// Malformed: no dot separator or empty cluster name — skip silently.
				continue
			}
			clusterName := rest[:dotIdx]
			field := rest[dotIdx+1:]
			if field == "" {
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

			// Parse role ownership from resource_owner.<role> fields.
			if strings.HasPrefix(field, resourceOwnerPrefix) {
				role := field[len(resourceOwnerPrefix):]
				if role != "" {
					entry.RoleOwners[role] = value
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
