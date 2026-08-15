// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync

import (
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// ResolveSubjectEID resolves the EID, Observation.Source, and optional ClaimScope
// for a single fragment observation. It is the sole authority for eid construction
// in the dnasync writer, and is exported so S2 (edge-endpoint resolution) and S6
// (apply-outcome eid resolution) can share the same logic without editing writer.go.
//
// Authority-boundary invariant: peerHostAuthority is the mTLS-verified peer identity
// and is the sole input to the authority segment of any returned EID. No field from
// payload or fragID can reach the authority segment.
//
// Three branches:
//
//   - vm kind whose decoded payload carries a non-empty ha_role.cluster_name:
//     EID = cluster:<clusterName>/vm:<vmName>, source = peerHostAuthority/moduleAuthority,
//     claimScope = nil.
//     Multiple stewards observing the same clustered VM converge on the same EID,
//     which is stable across live migration. When a standalone VM (host:<peer>/vm:<name>)
//     later joins a cluster, subsequent reports land on the cluster-scoped EID; the old
//     host-scoped EID is orphaned rather than migrated (retroactive migration is out of
//     scope — clusterregistry dead-owner detection handles eventual cleanup).
//
//   - Cluster-kind fragments (taxonomy AuthorityClasses does NOT contain "host"):
//     EID = cluster:<clusterName> (bare authority, no local_id), source = peerHostAuthority/moduleAuthority,
//     claimScope = nil. Multiple stewards observing the same cluster converge on one EID.
//
//   - All other host-scoped kinds (AuthorityClasses contains "host", or unknown kind):
//     EID = host:<peerHostAuthority>/<fragID>, source = peerHostAuthority,
//     claimScope is non-nil (ClaimScope.AsOf is the zero value; callers must set it before use).
//
// The payload argument is the decoded fragment payload (as produced by buildPayload),
// which carries module_authority (= frag.GetAuthority()) and the decoded canonical fields
// including ha_role when present.
func ResolveSubjectEID(
	kind, peerHostAuthority, fragID string,
	payload map[string]interface{},
	taxonomy *types.Taxonomy,
) (types.EID, string, *types.ClaimScope, error) {
	desc, ok := taxonomy.LookupEntityType(kind)
	isHostScoped := !ok || containsString(desc.AuthorityClasses, "host")

	// Cluster-scoped VM: vm kind whose decoded payload carries ha_role.cluster_name.
	// Produces cluster:<clusterName>/vm:<vmName>; no ClaimScope (same reason as bare
	// cluster-kind: a single node's view is not the complete picture for a multi-observer entity).
	if kind == "vm" && isHostScoped {
		if clusterName := extractVMClusterName(payload); clusterName != "" {
			vmName := fragID
			if idx := strings.Index(fragID, ":"); idx >= 0 {
				vmName = fragID[idx+1:]
			}
			eid, err := types.NewEID("cluster", clusterName, "vm:"+vmName)
			if err != nil {
				return types.EID{}, "", nil, fmt.Errorf("dnasync/resolve: cluster vm eid for %q: %w", fragID, err)
			}
			return eid, clusterSource(peerHostAuthority, payload), nil, nil
		}
	}

	if isHostScoped {
		// Host-scoped: EID = host:<peerHostAuthority>/<fragID>.
		// Source MUST be peerHostAuthority (not module authority) so that
		// ClaimScope.Source and Observation.Source are equal, enabling retraction.
		eid, err := types.NewEID("host", peerHostAuthority, fragID)
		if err != nil {
			return types.EID{}, "", nil, fmt.Errorf("dnasync/resolve: host eid for %q: %w", fragID, err)
		}
		cs := &types.ClaimScope{
			Source: peerHostAuthority,
			Pattern: types.ClaimScopePattern{
				Entity: &types.EntityScopePattern{
					AuthorityPrefix: "host:" + peerHostAuthority,
				},
			},
			// AsOf is zero; callers must set it before adding to a batch.
		}
		return eid, peerHostAuthority, cs, nil
	}

	// Cluster-kind: EID = cluster:<clusterName> (bare authority, no local_id).
	// No ClaimScope: a single steward's view is not the complete picture for a
	// shared multi-observer entity.
	clusterName := fragID
	if idx := strings.Index(fragID, ":"); idx >= 0 {
		clusterName = fragID[idx+1:]
	}
	eid, err := types.NewEID("cluster", clusterName, "")
	if err != nil {
		return types.EID{}, "", nil, fmt.Errorf("dnasync/resolve: cluster eid for %q: %w", fragID, err)
	}
	return eid, clusterSource(peerHostAuthority, payload), nil, nil
}

// extractVMClusterName reads ha_role.cluster_name from the decoded fragment payload.
// Returns empty string when absent, nil, or not a non-empty string.
func extractVMClusterName(payload map[string]interface{}) string {
	haRole, ok := payload["ha_role"].(map[string]interface{})
	if !ok {
		return ""
	}
	name, _ := haRole["cluster_name"].(string)
	return name
}

// clusterSource builds Observation.Source for cluster-scoped observations
// (both cluster-kind fragments and cluster-scoped VMs).
// The format is peerHostAuthority/moduleAuthority, or just peerHostAuthority
// when the payload carries no module_authority, so per-steward attribution is
// preserved for split-brain/dead-owner detection.
func clusterSource(peerHostAuthority string, payload map[string]interface{}) string {
	if modAuth, _ := payload["module_authority"].(string); modAuth != "" {
		return peerHostAuthority + "/" + modAuth
	}
	return peerHostAuthority
}

// containsString reports whether ss contains s.
func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
