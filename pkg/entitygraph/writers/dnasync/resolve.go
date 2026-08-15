// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// maxClusterAuthorityNameLen bounds a cluster name before it is used as a lookup
// key or an EID authority segment. A Windows failover cluster name is a NetBIOS/DNS
// label, so 253 bytes (the DNS name limit) is generous; the bound exists because the
// name arrives inside steward-supplied fragment data and is otherwise unbounded.
const maxClusterAuthorityNameLen = 253

// ClusterMembership answers, from controller-side state, whether the mTLS-verified
// peer identity peerHostAuthority belongs to clusterName.
//
// It is the trust boundary for the single place where a steward-supplied value is
// permitted to reach an EID authority segment: the cluster-scoped VM branch of
// ResolveSubjectEID reads ha_role.cluster_name out of the decoded fragment payload.
// Stewards run on hosts that may be compromised (CLAUDE.md threat model), so an
// ungated payload value would let any authenticated steward write observations into
// another cluster's entity namespace — and those observations deliberately carry no
// ClaimScope, so they could never be retracted.
//
// Implementations MUST answer from state the controller holds independently of the
// delta currently being ingested, and MUST NOT grant membership on the strength of
// the asserting peer's own claim alone. Returning false is always safe: the fragment
// then resolves to its host-scoped EID, which is exactly the pre-cluster behaviour.
type ClusterMembership interface {
	IsClusterMember(peerHostAuthority, clusterName string) bool
}

// StaticClusterMembership is an immutable ClusterMembership snapshot: an explicit
// table of cluster name → the peer authorities the controller has verified as
// members of that cluster. Callers rebuild it when their membership view changes;
// it holds no locks and is safe for concurrent reads.
type StaticClusterMembership struct {
	members map[string]map[string]struct{}
}

// Compile-time proof that the shipped snapshot type satisfies the verifier contract,
// so wiring cannot drift onto a type that silently fails to gate cluster authority.
var _ ClusterMembership = (*StaticClusterMembership)(nil)

// NewStaticClusterMembership builds a membership snapshot from a cluster name →
// member peer authority mapping. The input is copied, so later mutation of the
// caller's map cannot change the snapshot's answers.
func NewStaticClusterMembership(byCluster map[string][]string) *StaticClusterMembership {
	m := &StaticClusterMembership{members: make(map[string]map[string]struct{}, len(byCluster))}
	for cluster, peers := range byCluster {
		set := make(map[string]struct{}, len(peers))
		for _, p := range peers {
			if p != "" {
				set[p] = struct{}{}
			}
		}
		m.members[cluster] = set
	}
	return m
}

// IsClusterMember implements ClusterMembership.
func (m *StaticClusterMembership) IsClusterMember(peerHostAuthority, clusterName string) bool {
	if m == nil || peerHostAuthority == "" || clusterName == "" {
		return false
	}
	set, ok := m.members[clusterName]
	if !ok {
		return false
	}
	_, member := set[peerHostAuthority]
	return member
}

// ResolveSubjectEID resolves the EID, Observation.Source, and optional ClaimScope
// for a single fragment observation. It is the sole authority for eid construction
// in the dnasync writer, and is exported so S2 (edge-endpoint resolution) and S6
// (apply-outcome eid resolution) can share the same logic without editing writer.go.
//
// Authority-boundary rule (SE threat #1 — authority confusion). The authority segment
// of a returned EID has exactly two possible origins, and no other input can reach it:
//
//   - peerHostAuthority, the mTLS-verified peer identity, for every host-scoped EID.
//     Nothing the steward supplies (fragment_id, fragment authority, payload) can
//     influence it — that case is structurally unrepresentable, not detected-and-rejected.
//
//   - A cluster name, for the two cluster-scoped branches. A cluster is a shared
//     multi-observer entity, so its authority segment cannot be the reporting peer;
//     the name is steward-supplied and each branch states its own trust basis:
//
//     -- Cluster-scoped VM: the name is read from the decoded payload
//     (ha_role.cluster_name) and reaches the authority segment ONLY when the
//     caller-supplied ClusterMembership confirms peerHostAuthority is a member of
//     that cluster. A nil verifier, a negative answer, or a malformed name all fall
//     through to the host-scoped branch — this path fails closed.
//
//     -- Bare cluster-kind fragment: the name is the fragment_id's local part, and is
//     NOT membership-gated. It cannot be: a steward's cluster:<name> fragment is the
//     evidence the controller's cluster membership view is itself built from
//     (features/controller/clusterregistry), so gating it on membership would be
//     circular. Consumers must therefore treat a cluster:<name> entity as
//     source-attributed evidence from each reporting peer (Observation.Source carries
//     peerHostAuthority), never as an authoritative statement about that cluster.
//
// Three branches:
//
//   - vm kind whose decoded payload carries a non-empty, membership-verified
//     ha_role.cluster_name:
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
//   - All other host-scoped kinds (AuthorityClasses contains "host", or unknown kind),
//     including a vm whose cluster claim was not verified:
//     EID = host:<peerHostAuthority>/<fragID>, source = peerHostAuthority,
//     claimScope is non-nil (ClaimScope.AsOf is the zero value; callers must set it before use).
//
// The payload argument is the decoded fragment payload (as produced by buildPayload),
// which carries module_authority (= frag.GetAuthority()) and the decoded canonical fields
// including ha_role when present. membership may be nil, which denies every cluster-scoped
// VM claim.
func ResolveSubjectEID(
	kind, peerHostAuthority, fragID string,
	payload map[string]interface{},
	taxonomy *types.Taxonomy,
	membership ClusterMembership,
) (types.EID, string, *types.ClaimScope, error) {
	desc, ok := taxonomy.LookupEntityType(kind)
	isHostScoped := !ok || containsString(desc.AuthorityClasses, "host")

	// Cluster-scoped VM: vm kind whose decoded payload carries ha_role.cluster_name
	// AND whose peer is a verified member of that cluster. Produces
	// cluster:<clusterName>/vm:<vmName>; no ClaimScope (same reason as bare
	// cluster-kind: a single node's view is not the complete picture for a
	// multi-observer entity).
	//
	// An unverified claim is NOT an error: it falls through to the host-scoped
	// branch below, so an honest steward whose membership has not yet reached the
	// controller still gets its VM recorded — under its own authority, with a
	// ClaimScope, and therefore retractable.
	if kind == "vm" && isHostScoped {
		clusterName := extractVMClusterName(payload)
		if clusterAuthorityAccepted(peerHostAuthority, clusterName, membership) {
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
	// shared multi-observer entity. See the authority-boundary rule above for why
	// this branch is not membership-gated.
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

// clusterAuthorityAccepted reports whether a steward-asserted cluster name may be
// used as an EID authority segment for peerHostAuthority. It is deliberately the
// only gate on that transition: shape is checked first so a malformed name never
// becomes a lookup key, then membership is confirmed against controller-side state.
// A nil verifier denies, so an unwired caller cannot silently get the permissive
// behaviour.
func clusterAuthorityAccepted(peerHostAuthority, clusterName string, membership ClusterMembership) bool {
	if !validClusterAuthorityName(clusterName) {
		return false
	}
	if membership == nil {
		return false
	}
	return membership.IsClusterMember(peerHostAuthority, clusterName)
}

// validClusterAuthorityName reports whether a steward-supplied cluster name is
// storable as an EID authority segment: non-empty, bounded, valid UTF-8, free of
// '/' (which would split the authority segment and forge a local_id) and free of
// control characters (which would otherwise reach storage keys and log records).
func validClusterAuthorityName(name string) bool {
	if name == "" || len(name) > maxClusterAuthorityNameLen {
		return false
	}
	if !utf8.ValidString(name) {
		return false
	}
	if strings.ContainsRune(name, '/') {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// extractVMClusterName reads ha_role.cluster_name from the decoded fragment payload.
// Returns empty string when absent, nil, or not a non-empty string.
//
// The returned value is steward-supplied and unverified; it must pass through
// clusterAuthorityAccepted before it can reach an EID authority segment.
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
