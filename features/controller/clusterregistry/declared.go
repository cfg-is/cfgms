// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package clusterregistry

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ClusterMembersNamespace is the ConfigStore namespace holding admin-declared
// cluster membership (ADR-035). One document per cluster, keyed by cluster name,
// under the tenant that owns the cluster.
const ClusterMembersNamespace = "cluster-members"

// ClusterMembersDocument is the JSON body of a cluster-members declaration.
type ClusterMembersDocument struct {
	// Members lists the steward IDs an administrator declared as members.
	Members []string `json:"members"`
}

// StewardTenantLookup resolves a steward ID to its fleet tenant. ok is false when
// the steward is unknown; an unknown steward is never a member.
type StewardTenantLookup func(stewardID string) (tenantID string, ok bool)

// DeclaredMembership answers cluster membership from administrator declarations
// (ADR-035). Steward DNA cluster:<name> fragments are never consulted: only a
// declaration stored in the steward's own tenant grants membership. It holds no
// cache, so every answer reflects the store.
type DeclaredMembership struct {
	store  cfgconfig.ConfigStore
	tenant StewardTenantLookup
}

// NewDeclaredMembership builds a reader over store. tenantOf supplies each
// steward's fleet tenant.
func NewDeclaredMembership(store cfgconfig.ConfigStore, tenantOf StewardTenantLookup) *DeclaredMembership {
	return &DeclaredMembership{store: store, tenant: tenantOf}
}

// MemberClusters returns the sorted names of clusters that declare stewardID as a
// member within the steward's own tenant. Any store fault yields an empty result.
func (d *DeclaredMembership) MemberClusters(stewardID string) []string {
	tenantID, ok := d.stewardTenant(stewardID)
	if !ok {
		return nil
	}
	entries, err := d.store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{
		TenantID:  tenantID,
		Namespace: ClusterMembersNamespace,
	})
	if err != nil {
		logging.NewLogger("info").Warn("Failed to list declared cluster membership",
			"error", logging.SanitizeLogValue(err.Error()))
		return nil
	}
	var names []string
	for _, entry := range entries {
		// Defence in depth: never trust the store's filtering for the tenant boundary.
		if entry == nil || entry.Key == nil || entry.Key.TenantID != tenantID ||
			entry.Key.Namespace != ClusterMembersNamespace {
			continue
		}
		if declares(entry, stewardID) {
			names = append(names, entry.Key.Name)
		}
	}
	sort.Strings(names)
	return names
}

// IsClusterMember reports whether an administrator declared stewardID a member of
// clusterName in the steward's own tenant. It satisfies dnasync.ClusterMembership.
// Any store fault yields false.
func (d *DeclaredMembership) IsClusterMember(stewardID, clusterName string) bool {
	tenantID, ok := d.stewardTenant(stewardID)
	if !ok || clusterName == "" {
		return false
	}
	entry, err := d.store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: ClusterMembersNamespace,
		Name:      clusterName,
	})
	if err != nil {
		if !errors.Is(err, cfgconfig.ErrConfigNotFound) {
			logging.NewLogger("info").Warn("Failed to read declared cluster membership",
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return false
	}
	return declares(entry, stewardID)
}

func (d *DeclaredMembership) stewardTenant(stewardID string) (string, bool) {
	if d.store == nil || d.tenant == nil || stewardID == "" {
		return "", false
	}
	tenantID, ok := d.tenant(stewardID)
	if !ok || tenantID == "" {
		return "", false
	}
	return tenantID, true
}

// declares reports whether entry's document lists stewardID. A malformed document
// declares nobody.
func declares(entry *cfgconfig.ConfigEntry, stewardID string) bool {
	if entry == nil {
		return false
	}
	var doc ClusterMembersDocument
	if err := json.Unmarshal(entry.Data, &doc); err != nil {
		logging.NewLogger("info").Warn("Malformed cluster-members declaration ignored",
			"error", logging.SanitizeLogValue(err.Error()))
		return false
	}
	for _, m := range doc.Members {
		if m == stewardID {
			return true
		}
	}
	return false
}
