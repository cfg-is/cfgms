// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
)

// --- ResolveSubjectEID unit tests ---
//
// These tests exercise the EID resolution logic directly against crafted payload maps,
// without encoding/decoding canonical bytes, to keep the unit tests focused on the
// branch logic rather than the wire format.

// TestResolve_ClusteredVM verifies that a vm fragment whose payload carries
// ha_role.cluster_name resolves to cluster:<clusterName>/vm:<vmName>.
func TestResolve_ClusteredVM(t *testing.T) {
	payload := map[string]interface{}{
		"ha_role":          map[string]interface{}{"cluster_name": "prod-cluster"},
		"module_authority": "observer:hyperv",
		"state":            "running",
	}
	eid, src, cs, err := dnasync.ResolveSubjectEID("vm", "node-1", "vm:prod-vm1", payload, types.DefaultTaxonomy())
	require.NoError(t, err)
	require.Equal(t, "cluster:prod-cluster/vm:prod-vm1", eid.String())
	require.Equal(t, "node-1/observer:hyperv", src)
	require.Nil(t, cs, "cluster-scoped VM must carry no ClaimScope")
}

// TestResolve_ClusteredVM_NoModuleAuthority verifies that a clustered VM with no
// module_authority in the payload uses peerHostAuthority alone as source.
func TestResolve_ClusteredVM_NoModuleAuthority(t *testing.T) {
	payload := map[string]interface{}{
		"ha_role": map[string]interface{}{"cluster_name": "failover-cluster"},
	}
	eid, src, cs, err := dnasync.ResolveSubjectEID("vm", "node-42", "vm:vm01", payload, types.DefaultTaxonomy())
	require.NoError(t, err)
	require.Equal(t, "cluster:failover-cluster/vm:vm01", eid.String())
	require.Equal(t, "node-42", src)
	require.Nil(t, cs)
}

// TestResolve_StandaloneVM verifies that a vm fragment with no ha_role resolves to
// host:<peerHostAuthority>/vm:<name>, preserving today's behavior.
func TestResolve_StandaloneVM(t *testing.T) {
	payload := map[string]interface{}{
		"module_authority": "observer:hyperv",
		"state":            "running",
	}
	eid, src, cs, err := dnasync.ResolveSubjectEID("vm", "node-1", "vm:standalone", payload, types.DefaultTaxonomy())
	require.NoError(t, err)
	require.Equal(t, "host:node-1/vm:standalone", eid.String())
	require.Equal(t, "node-1", src)
	require.NotNil(t, cs, "standalone VM must carry a ClaimScope")
	require.Equal(t, "node-1", cs.Source)
	require.Equal(t, "host:node-1", cs.Pattern.Entity.AuthorityPrefix)
}

// TestResolve_VMEmptyClusterName verifies that ha_role present but cluster_name empty
// falls back to the host-scoped path (not a cluster-scoped VM).
func TestResolve_VMEmptyClusterName(t *testing.T) {
	payload := map[string]interface{}{
		"ha_role": map[string]interface{}{"cluster_name": ""},
	}
	eid, src, cs, err := dnasync.ResolveSubjectEID("vm", "node-x", "vm:noname", payload, types.DefaultTaxonomy())
	require.NoError(t, err)
	require.Equal(t, "host:node-x/vm:noname", eid.String())
	require.Equal(t, "node-x", src)
	require.NotNil(t, cs)
}

// TestResolve_VMHARoleNotAMap verifies that ha_role present but not a map[string]interface{}
// falls back to the host-scoped path.
func TestResolve_VMHARoleNotAMap(t *testing.T) {
	payload := map[string]interface{}{
		"ha_role": "not-a-map",
	}
	eid, _, cs, err := dnasync.ResolveSubjectEID("vm", "node-x", "vm:noname", payload, types.DefaultTaxonomy())
	require.NoError(t, err)
	require.Equal(t, "host:node-x/vm:noname", eid.String())
	require.NotNil(t, cs)
}

// TestResolve_ClusterKind verifies that cluster-kind fragments produce the bare
// cluster EID (no local_id) and no ClaimScope, matching today's behavior.
func TestResolve_ClusterKind(t *testing.T) {
	payload := map[string]interface{}{
		"module_authority": "observer:hyperv",
	}
	eid, src, cs, err := dnasync.ResolveSubjectEID("cluster", "steward-A", "cluster:mycluster", payload, types.DefaultTaxonomy())
	require.NoError(t, err)
	require.Equal(t, "cluster:mycluster", eid.String())
	require.Equal(t, "steward-A/observer:hyperv", src)
	require.Nil(t, cs, "cluster-kind must carry no ClaimScope")
}

// TestResolve_FileKind verifies that host-only kinds (e.g. file) remain host-scoped
// regardless of payload content.
func TestResolve_FileKind(t *testing.T) {
	payload := map[string]interface{}{
		"module_authority": "enforcing-module:file",
		"ha_role":          map[string]interface{}{"cluster_name": "should-be-ignored"},
	}
	eid, src, cs, err := dnasync.ResolveSubjectEID("file", "steward-B", "file:/etc/hosts", payload, types.DefaultTaxonomy())
	require.NoError(t, err)
	require.Equal(t, "host:steward-B/file:/etc/hosts", eid.String())
	require.Equal(t, "steward-B", src)
	require.NotNil(t, cs)
}

// TestResolve_UnknownKindDefaultsToHostScoped verifies that an unregistered kind
// defaults to host-scoped (the safe fallback).
func TestResolve_UnknownKindDefaultsToHostScoped(t *testing.T) {
	eid, src, cs, err := dnasync.ResolveSubjectEID("unknown-kind", "steward-C", "unknown-kind:foo", nil, types.DefaultTaxonomy())
	require.NoError(t, err)
	require.Equal(t, "host:steward-C/unknown-kind:foo", eid.String())
	require.Equal(t, "steward-C", src)
	require.NotNil(t, cs)
}

// TestResolve_ClaimScopeAsOfIsZero verifies that the returned ClaimScope's AsOf
// is the zero value — callers must populate it before adding to a batch.
func TestResolve_ClaimScopeAsOfIsZero(t *testing.T) {
	_, _, cs, err := dnasync.ResolveSubjectEID("file", "steward-D", "file:/tmp/x", nil, types.DefaultTaxonomy())
	require.NoError(t, err)
	require.NotNil(t, cs)
	require.True(t, cs.AsOf.IsZero(), "ClaimScope.AsOf must be zero; caller sets it")
}

// TestResolve_ClusteredVMSource_TwoStewards verifies that two stewards produce
// distinct sources for the same clustered VM, enabling per-steward attribution.
func TestResolve_ClusteredVMSource_TwoStewards(t *testing.T) {
	payload := func(peer string) map[string]interface{} {
		return map[string]interface{}{
			"ha_role":          map[string]interface{}{"cluster_name": "shared-cluster"},
			"module_authority": "observer:hyperv",
		}
	}

	eid1, src1, _, err := dnasync.ResolveSubjectEID("vm", "node-a", "vm:shared-vm", payload("node-a"), types.DefaultTaxonomy())
	require.NoError(t, err)
	eid2, src2, _, err := dnasync.ResolveSubjectEID("vm", "node-b", "vm:shared-vm", payload("node-b"), types.DefaultTaxonomy())
	require.NoError(t, err)

	require.Equal(t, eid1.String(), eid2.String(), "both nodes must produce the same cluster-scoped EID")
	require.NotEqual(t, src1, src2, "sources must differ so per-steward attribution is preserved")
	require.Equal(t, "node-a/observer:hyperv", src1)
	require.Equal(t, "node-b/observer:hyperv", src2)
}
