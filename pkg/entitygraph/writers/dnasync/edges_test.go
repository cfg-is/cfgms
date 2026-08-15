// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// --- canonical encoding helpers for edge test fixtures ---
//
// These support strings, map[string]interface{}, and []interface{} — which
// covers the __entitygraph_edges list. Distinct function names avoid conflicts
// with writer_test.go helpers in the same package.

func edgesEncodeValue(v interface{}) []byte {
	switch val := v.(type) {
	case string:
		vlen := make([]byte, 4)
		binary.BigEndian.PutUint32(vlen, uint32(len(val)))
		b := []byte{'S'}
		b = append(b, vlen...)
		return append(b, val...)
	case map[string]interface{}:
		b := []byte{'M'}
		return append(b, edgesEncodeMap(val)...)
	case []interface{}:
		hdr := make([]byte, 5)
		hdr[0] = 'L'
		binary.BigEndian.PutUint32(hdr[1:], uint32(len(val)))
		buf := append([]byte(nil), hdr...)
		for _, item := range val {
			buf = append(buf, edgesEncodeValue(item)...)
		}
		return buf
	default:
		panic(fmt.Sprintf("edgesEncodeValue: unsupported type %T", v))
	}
}

func edgesEncodeMap(m map[string]interface{}) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(keys)))
	buf := append([]byte(nil), hdr...)
	for _, k := range keys {
		klen := make([]byte, 4)
		binary.BigEndian.PutUint32(klen, uint32(len(k)))
		buf = append(buf, klen...)
		buf = append(buf, k...)
		buf = append(buf, edgesEncodeValue(m[k])...)
	}
	return buf
}

// makeEdgesCanonBytes builds valid canonical bytes from a map whose values may
// be strings, map[string]interface{}, or []interface{}.
func makeEdgesCanonBytes(fields map[string]interface{}) []byte {
	return edgesEncodeMap(fields)
}

// makeFragWithEdges returns a Fragment whose canonical bytes include both entity
// fields and a __entitygraph_edges list.
func makeFragWithEdges(fragID, authority string, entityFields map[string]string, edges []interface{}) *commonpb.Fragment {
	payload := make(map[string]interface{}, len(entityFields)+1)
	for k, v := range entityFields {
		payload[k] = v
	}
	payload["__entitygraph_edges"] = edges
	return &commonpb.Fragment{
		FragmentId:     fragID,
		Authority:      authority,
		CanonicalBytes: makeEdgesCanonBytes(payload),
	}
}

// makeFragWithoutEdges returns a Fragment whose canonical bytes carry only
// entity fields — no __entitygraph_edges key (regression / no-edges case).
func makeFragWithoutEdges(fragID, authority string, entityFields map[string]string) *commonpb.Fragment {
	payload := make(map[string]interface{}, len(entityFields))
	for k, v := range entityFields {
		payload[k] = v
	}
	return &commonpb.Fragment{
		FragmentId:     fragID,
		Authority:      authority,
		CanonicalBytes: makeEdgesCanonBytes(payload),
	}
}

// outboundEdges returns all edges from the store whose from_subject equals fromEIDStr.
func outboundEdges(t *testing.T, p interfaces.EntityGraphProvider, fromEIDStr string) []*interfaces.EdgeView {
	t.Helper()
	fromEID, err := types.ParseEID(fromEIDStr)
	require.NoError(t, err)
	ref := fromEID
	edges, err := p.GetEdges(context.Background(), interfaces.EdgeFilter{FromEID: &ref})
	require.NoError(t, err)
	return edges
}

// --- AC1: fragment with __entitygraph_edges produces edge Observations ---

// TestE1_EdgeObservationFromClusterFragment verifies that a cluster-kind fragment
// carrying __entitygraph_edges produces edge Observations via ReportObservations,
// with Subject in the canonical "edgeType|from|to" format.
//
// Cluster-kind is not host-scoped in the taxonomy, so fromEID = cluster:src
// (bare authority) and "cluster:dst" resolves to cluster:dst (bare authority).
func TestE1_EdgeObservationFromClusterFragment(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithEdges(
		"cluster:eg-src",
		"observer:hyperv",
		map[string]string{"state": "healthy"},
		[]interface{}{
			map[string]interface{}{"type": "contains", "to": "cluster:eg-dst"},
		},
	)

	err := w.WriteFragmentDelta(ctx, "node-e1",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	edges := outboundEdges(t, p, "cluster:eg-src")
	require.Len(t, edges, 1, "one edge Observation must be stored for the declared edge")
	assert.Equal(t, "contains", edges[0].Edge.Type)
	assert.Equal(t, "cluster:eg-src", edges[0].Edge.From.String())
	assert.Equal(t, "cluster:eg-dst", edges[0].Edge.To.String())
}

// TestE1_HostScopedFragmentWithEdge verifies that a host-scoped VM fragment with
// __entitygraph_edges produces edges whose from EID is host:<peer>/<fragID>, and
// whose to EID is resolved via the same taxonomy authority-classes branch.
//
// vswitch kind has AuthorityClasses ["cluster", "host"] — it is host-scoped, so
// "vswitch:External" resolves to host:<peer>/vswitch:External.
func TestE1_HostScopedFragmentWithEdge(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithEdges(
		"vm:e1-vm",
		"observer:hyperv",
		map[string]string{"state": "running"},
		[]interface{}{
			map[string]interface{}{"type": "connects-to", "to": "vswitch:External"},
		},
	)

	err := w.WriteFragmentDelta(ctx, "e1-node",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	fromEIDStr := "host:e1-node/vm:e1-vm"
	edges := outboundEdges(t, p, fromEIDStr)
	require.Len(t, edges, 1, "edge from host-scoped fragment must be stored")
	assert.Equal(t, "connects-to", edges[0].Edge.Type)
	assert.Equal(t, fromEIDStr, edges[0].Edge.From.String())
	// vswitch is host-scoped → resolves to host:e1-node/vswitch:External.
	assert.Equal(t, "host:e1-node/vswitch:External", edges[0].Edge.To.String())
}

// TestE1_MultipleEdgesFromOneFragment verifies that multiple edge declarations
// in a single fragment produce multiple edge Observations.
func TestE1_MultipleEdgesFromOneFragment(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithEdges(
		"cluster:multi-eg",
		"observer:hyperv",
		map[string]string{"state": "healthy"},
		[]interface{}{
			map[string]interface{}{"type": "contains", "to": "cluster:dst-a"},
			map[string]interface{}{"type": "contains", "to": "cluster:dst-b"},
		},
	)

	err := w.WriteFragmentDelta(ctx, "node-multi-e1",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	edges := outboundEdges(t, p, "cluster:multi-eg")
	require.Len(t, edges, 2, "two declared edges must produce two Observations")
	toSet := map[string]struct{}{}
	for _, e := range edges {
		toSet[e.Edge.To.String()] = struct{}{}
	}
	assert.Contains(t, toSet, "cluster:dst-a")
	assert.Contains(t, toSet, "cluster:dst-b")
}

// --- AC2: __entitygraph_edges key stripped from entity attribute payload ---

// TestE2_EdgeKeyStrippedFromEntityAttributes verifies that the __entitygraph_edges
// key does NOT appear in the entity's merged attribute set. A fragment payload
// carrying the key must have it stripped before entity storage.
func TestE2_EdgeKeyStrippedFromEntityAttributes(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithEdges(
		"service:e2-svc",
		"enforcing-module:service",
		map[string]string{"state": "active", "owning_tenant": "root/e2-tenant"},
		[]interface{}{
			map[string]interface{}{"type": "contains", "to": "cluster:some-cluster"},
		},
	)

	err := w.WriteFragmentDelta(ctx, "e2-peer",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	eid := mustParseEID(t, "host:e2-peer/service:e2-svc")
	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/e2-tenant"})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.NotNil(t, view.Entity)

	_, hasEdgesKey := view.Entity.Attributes["__entitygraph_edges"]
	assert.False(t, hasEdgesKey,
		"__entitygraph_edges must not appear as an entity attribute after stripping")
	assert.Equal(t, "active", view.Entity.Attributes["state"],
		"entity state field must survive the edge-key strip")
}

// --- AC3: unknown edge type emitted as related:<type>, not dropped or errored ---

// TestE3_UnknownEdgeTypeRelatedEscape verifies that an edge type not registered
// in DefaultTaxonomy is emitted as related:<type>, not dropped or causing an error.
func TestE3_UnknownEdgeTypeRelatedEscape(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithEdges(
		"cluster:e3-src",
		"observer:hyperv",
		map[string]string{"state": "ok"},
		[]interface{}{
			map[string]interface{}{"type": "custom-topology-link", "to": "cluster:e3-dst"},
		},
	)

	err := w.WriteFragmentDelta(ctx, "node-e3",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	edges := outboundEdges(t, p, "cluster:e3-src")
	require.Len(t, edges, 1, "unknown edge type must be emitted as related: escape, not dropped")
	assert.Equal(t, "related:custom-topology-link", edges[0].Edge.Type,
		"unknown edge type must be wrapped with related: prefix")
}

// TestE3_AlreadyRelatedEscapeNotDoubleWrapped verifies that an edge type already
// in related: form is emitted as-is (not double-wrapped).
func TestE3_AlreadyRelatedEscapeNotDoubleWrapped(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithEdges(
		"cluster:e3b-src",
		"observer:hyperv",
		map[string]string{"state": "ok"},
		[]interface{}{
			map[string]interface{}{"type": "related:already-escaped", "to": "cluster:e3b-dst"},
		},
	)

	err := w.WriteFragmentDelta(ctx, "node-e3b",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	edges := outboundEdges(t, p, "cluster:e3b-src")
	require.Len(t, edges, 1)
	assert.Equal(t, "related:already-escaped", edges[0].Edge.Type,
		"already-escaped edge type must not be double-wrapped")
}

// --- AC4 (REQUIRED TEST): claim-scoped retraction on re-enumeration ---
//
// Pattern mirrors testEGClaimScopeEdgeReplace from interfaces/contract_test.go:
// delta 1 asserts edges to peer1 and peer2; delta 2 asserts only peer1;
// the ClaimScope fires and retracts peer2's edge.

// TestE4_ClaimScopedRetraction is the REQUIRED retraction correctness test.
// A source's second WriteFragmentDelta that omits a previously-declared edge
// causes that edge to be retracted (verified via the store's edge read after
// both calls, mirroring the egReportEdge/GetEdges pattern in contract_test.go).
func TestE4_ClaimScopedRetraction(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()
	const peer = "ret-node"

	// Delta 1: vm fragment declares two "connects-to" edges.
	frag1 := makeFragWithEdges(
		"vm:ret-vm",
		"observer:hyperv",
		map[string]string{"state": "running"},
		[]interface{}{
			map[string]interface{}{"type": "connects-to", "to": "vswitch:sw1"},
			map[string]interface{}{"type": "connects-to", "to": "vswitch:sw2"},
		},
	)
	require.NoError(t, w.WriteFragmentDelta(ctx, peer,
		[]*commonpb.Fragment{frag1}, nil, types.DefaultTaxonomy()))

	fromEIDStr := "host:" + peer + "/vm:ret-vm"
	edges := outboundEdges(t, p, fromEIDStr)
	require.Len(t, edges, 2, "both edges must be present after first WriteFragmentDelta")

	toSet := map[string]struct{}{}
	for _, e := range edges {
		toSet[e.Edge.To.String()] = struct{}{}
	}
	assert.Contains(t, toSet, "host:"+peer+"/vswitch:sw1", "sw1 must be present after delta 1")
	assert.Contains(t, toSet, "host:"+peer+"/vswitch:sw2", "sw2 must be present after delta 1")

	// Delta 2: same fragment but only sw1 in __entitygraph_edges (sw2 omitted).
	// The per-(source,edgeType) ClaimScope for "connects-to" fires with a current
	// set that contains only sw1, so sw2 is retracted.
	frag2 := makeFragWithEdges(
		"vm:ret-vm",
		"observer:hyperv",
		map[string]string{"state": "running"},
		[]interface{}{
			map[string]interface{}{"type": "connects-to", "to": "vswitch:sw1"},
		},
	)
	require.NoError(t, w.WriteFragmentDelta(ctx, peer,
		[]*commonpb.Fragment{frag2}, nil, types.DefaultTaxonomy()))

	edgesAfter := outboundEdges(t, p, fromEIDStr)
	require.Len(t, edgesAfter, 1, "sw2 edge must be retracted after re-enumeration omits it")
	assert.Equal(t, "host:"+peer+"/vswitch:sw1", edgesAfter[0].Edge.To.String(),
		"sw1 edge must remain after re-enumeration")
}

// TestE4_RetractionDoesNotAffectOtherSource verifies that the ClaimScope for
// source A does not retract edges asserted by source B.
func TestE4_RetractionDoesNotAffectOtherSource(t *testing.T) {
	p := newTestProvider(t)
	// Two distinct peers report the same cluster fragment (shared multi-observer entity).
	w1 := newTestWriter(t, p)
	w2 := newTestWriter(t, p)
	ctx := context.Background()

	makeClusterFrag := func(edge string) *commonpb.Fragment {
		return makeFragWithEdges(
			"cluster:shared-cluster",
			"observer:hyperv",
			map[string]string{"state": "ok"},
			[]interface{}{
				map[string]interface{}{"type": "contains", "to": edge},
			},
		)
	}

	// Peer A and peer B both assert contains edges from cluster:shared-cluster.
	require.NoError(t, w1.WriteFragmentDelta(ctx, "peer-A",
		[]*commonpb.Fragment{makeClusterFrag("cluster:dst-a")}, nil, types.DefaultTaxonomy()))
	require.NoError(t, w2.WriteFragmentDelta(ctx, "peer-B",
		[]*commonpb.Fragment{makeClusterFrag("cluster:dst-b")}, nil, types.DefaultTaxonomy()))

	// Both edges visible.
	edges := outboundEdges(t, p, "cluster:shared-cluster")
	require.Len(t, edges, 2, "edges from two peers must coexist")

	// Peer A re-enumerates with a different edge. Peer B's edge must survive.
	require.NoError(t, w1.WriteFragmentDelta(ctx, "peer-A",
		[]*commonpb.Fragment{makeClusterFrag("cluster:dst-a2")}, nil, types.DefaultTaxonomy()))

	// dst-a (peer-A's prior edge) is retracted; dst-b (peer-B's edge) survives.
	edgesAfter := outboundEdges(t, p, "cluster:shared-cluster")
	require.Len(t, edgesAfter, 2, "peer-B's edge must survive peer-A's re-enumeration")
	toSet := map[string]struct{}{}
	for _, e := range edgesAfter {
		toSet[e.Edge.To.String()] = struct{}{}
	}
	assert.Contains(t, toSet, "cluster:dst-b",
		"peer-B's edge must not be retracted by peer-A's ClaimScope")
	assert.Contains(t, toSet, "cluster:dst-a2",
		"peer-A's new edge must be present after re-enumeration")
	assert.NotContains(t, toSet, "cluster:dst-a",
		"peer-A's old edge must be retracted")
}

// --- AC5 (REQUIRED TEST): fragment without __entitygraph_edges behaves identically to today ---

// TestE5_NoEdgesKeyBehavesIdenticallyToday verifies that a fragment with no
// __entitygraph_edges key produces the same entity observation it always has —
// no regression in existing entity-only ingest.
func TestE5_NoEdgesKeyBehavesIdenticallyToday(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithoutEdges("service:e5-svc", "enforcing-module:service",
		map[string]string{"state": "active", "owning_tenant": "root/e5-tenant"})

	err := w.WriteFragmentDelta(ctx, "e5-peer",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	// Entity observation must be present, as before.
	eid := mustParseEID(t, "host:e5-peer/service:e5-svc")
	records := stateHistory(t, p, eid)
	require.Len(t, records, 1, "entity-only fragment must produce exactly one entity observation")
	assert.Equal(t, "active", records[0].Observation.Payload["state"],
		"entity payload must carry the declared fields unchanged")

	// No edge observations (no __entitygraph_edges declared).
	edges := outboundEdges(t, p, eid.String())
	assert.Empty(t, edges, "fragment without __entitygraph_edges must produce no edge Observations")
}

// TestE5_ExistingEntityRetractionUnaffected verifies that the host-scoped entity
// retraction test (TestRetraction_HostScopedFragmentDropped) still passes when
// edge declarations are present — no regression to the existing ingest path.
func TestE5_ExistingEntityRetractionUnaffected(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()
	const peer = "e5b-peer"

	// Delta 1: two fragments — one with edges, one plain.
	fragWithEdge := makeFragWithEdges(
		"vm:e5-vm",
		"observer:hyperv",
		map[string]string{"state": "running"},
		[]interface{}{
			map[string]interface{}{"type": "connects-to", "to": "vswitch:Ext"},
		},
	)
	fragPlain := makeFragWithoutEdges("service:e5-sshd", "enforcing-module:service",
		map[string]string{"state": "active"})

	require.NoError(t, w.WriteFragmentDelta(ctx, peer,
		[]*commonpb.Fragment{fragWithEdge, fragPlain}, nil, types.DefaultTaxonomy()))

	vmEID := mustParseEID(t, "host:"+peer+"/vm:e5-vm")
	sshEID := mustParseEID(t, "host:"+peer+"/service:e5-sshd")
	require.Len(t, stateHistory(t, p, vmEID), 1, "vm entity must have one observation after delta 1")
	require.Len(t, stateHistory(t, p, sshEID), 1, "sshd entity must have one observation after delta 1")

	// Delta 2: only the plain service fragment; vm fragment is dropped.
	// The host entity ClaimScope retracts the vm entity.
	require.NoError(t, w.WriteFragmentDelta(ctx, peer,
		[]*commonpb.Fragment{fragPlain}, nil, types.DefaultTaxonomy()))

	// sshd entity must remain.
	require.Len(t, stateHistory(t, p, sshEID), 1, "sshd entity must survive delta 2")

	// vm entity must be retracted by the host entity ClaimScope.
	vmView, vmErr := p.GetEntity(ctx, vmEID, interfaces.GetEntityOpts{})
	retracted := vmView == nil || vmErr != nil
	assert.True(t, retracted,
		"vm entity must be retracted when its fragment is dropped from the delta; view=%v err=%v", vmView, vmErr)
}

// --- "self" sentinel ---

// TestE6_SelfSentinelResolvesToHostEID verifies that the "self" sentinel in
// a "to" field resolves to host:<peerHostAuthority> — the bare host-authority
// EID for the reporting steward, not the fragment's own EID. This is used by
// standalone VMs to express "runs on my own host".
func TestE6_SelfSentinelResolvesToHostEID(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()
	const peer = "e6-node"

	frag := makeFragWithEdges(
		"vm:e6-vm",
		"observer:hyperv",
		map[string]string{"state": "running"},
		[]interface{}{
			map[string]interface{}{"type": "runs-on", "to": "self"},
		},
	)

	err := w.WriteFragmentDelta(ctx, peer,
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	fromEIDStr := "host:" + peer + "/vm:e6-vm"
	edges := outboundEdges(t, p, fromEIDStr)
	require.Len(t, edges, 1, "runs-on edge via 'self' sentinel must be stored")
	assert.Equal(t, "runs-on", edges[0].Edge.Type)
	assert.Equal(t, fromEIDStr, edges[0].Edge.From.String())
	// "self" must resolve to the bare host-authority EID, not the VM's own EID.
	assert.Equal(t, "host:"+peer, edges[0].Edge.To.String(),
		"'self' must resolve to the bare host-authority EID of the reporting steward")
}

// --- edge source matches peerHostAuthority ---

// TestE7_EdgeSourceIsPeerHostAuthority verifies that the edge Observation.Source
// is always peerHostAuthority — not the module authority or the cluster source.
// This is required so that ClaimScope.Source and Observation.Source are equal,
// enabling the retraction machinery to fire (collectScopeSubjects requires string
// equality between obs.Source and cs.Source).
func TestE7_EdgeSourceIsPeerHostAuthority(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()
	const peer = "e7-node"
	const moduleAuth = "observer:hyperv"

	// Use a cluster fragment to verify the edge source is peerHostAuthority
	// rather than the clusterSource (peerHostAuthority/moduleAuthority) that the
	// cluster entity observation itself uses.
	frag := makeFragWithEdges(
		"cluster:e7-cluster",
		moduleAuth,
		map[string]string{"state": "healthy"},
		[]interface{}{
			map[string]interface{}{"type": "contains", "to": "cluster:e7-dst"},
		},
	)

	err := w.WriteFragmentDelta(ctx, peer,
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	fromEID, parseErr := types.ParseEID("cluster:e7-cluster")
	require.NoError(t, parseErr)
	ref := fromEID

	// Edge must be retrievable by source = peerHostAuthority.
	byPeer, err := p.GetEdges(ctx, interfaces.EdgeFilter{FromEID: &ref, Source: peer})
	require.NoError(t, err)
	require.Len(t, byPeer, 1,
		"edge must be retrievable by source = peerHostAuthority")

	// Edge must NOT be retrievable by module authority.
	byModule, err := p.GetEdges(ctx, interfaces.EdgeFilter{FromEID: &ref, Source: moduleAuth})
	require.NoError(t, err)
	assert.Empty(t, byModule,
		"edge must NOT be retrievable by module authority — source must be peerHostAuthority")

	// Combined source (peerHostAuthority/moduleAuthority, used for cluster entity
	// observations) must also return nothing — proving edge source ≠ cluster source.
	byClusterSrc, err := p.GetEdges(ctx, interfaces.EdgeFilter{
		FromEID: &ref, Source: peer + "/" + moduleAuth,
	})
	require.NoError(t, err)
	assert.Empty(t, byClusterSrc,
		"edge source must be plain peerHostAuthority, not the cluster compound source")
}

// --- malformed and empty declarations ---

// TestE8_EmptyEdgeListProducesNoEdges verifies that __entitygraph_edges as an
// empty list produces no edge Observations and does not error.
func TestE8_EmptyEdgeListProducesNoEdges(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithEdges(
		"service:e8-empty",
		"enforcing-module:service",
		map[string]string{"state": "active"},
		[]interface{}{}, // empty
	)

	err := w.WriteFragmentDelta(ctx, "e8-peer",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	eid := mustParseEID(t, "host:e8-peer/service:e8-empty")
	records := stateHistory(t, p, eid)
	require.Len(t, records, 1, "entity observation must still be stored for empty edge list")

	_, hasEdgesKey := records[0].Observation.Payload["__entitygraph_edges"]
	assert.False(t, hasEdgesKey,
		"__entitygraph_edges must be stripped even when it is an empty list")

	edges := outboundEdges(t, p, eid.String())
	assert.Empty(t, edges, "empty __entitygraph_edges must produce no edge Observations")
}

// TestE8_EdgeEntryMissingTypeIsSkipped verifies that a malformed edge entry (no
// "type" field) is silently skipped without failing the ingest.
func TestE8_EdgeEntryMissingTypeIsSkipped(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithEdges(
		"service:e8-notype",
		"enforcing-module:service",
		map[string]string{"state": "active"},
		[]interface{}{
			map[string]interface{}{"to": "cluster:some-cluster"}, // missing "type"
		},
	)

	err := w.WriteFragmentDelta(ctx, "e8b-peer",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	eid := mustParseEID(t, "host:e8b-peer/service:e8-notype")
	records := stateHistory(t, p, eid)
	require.Len(t, records, 1, "entity observation must still be stored despite malformed edge")

	edges := outboundEdges(t, p, eid.String())
	assert.Empty(t, edges, "entry missing 'type' must be silently skipped")
}

// TestE8_EdgeEntryMissingToIsSkipped verifies that a malformed edge entry (no
// "to" field) is silently skipped without failing the ingest.
func TestE8_EdgeEntryMissingToIsSkipped(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithEdges(
		"service:e8-noto",
		"enforcing-module:service",
		map[string]string{"state": "active"},
		[]interface{}{
			map[string]interface{}{"type": "contains"}, // missing "to"
		},
	)

	err := w.WriteFragmentDelta(ctx, "e8c-peer",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	edges := outboundEdges(t, p, "host:e8c-peer/service:e8-noto")
	assert.Empty(t, edges, "entry missing 'to' must be silently skipped")
}

// --- hostile input: edge-subject delimiter and control characters ---
//
// The edge subject is "edge_type|from_eid|to_eid" and providers parse it back
// with strings.SplitN(subject, "|", 3). Every component below is
// steward-controlled, so an accepted '|' would let a compromised steward choose
// the parsed `from` anchor — an entity in another authority's namespace — and
// the resulting edge would be unretractable (the ClaimScope stores the unsplit
// edge type while the provider matches the parsed prefix).

// TestE9_EdgeTypeWithPipeIsRejected is the primary authority-boundary test: an
// edge type containing the subject delimiter must be skipped, and must not
// create an edge anchored on the injected EID.
func TestE9_EdgeTypeWithPipeIsRejected(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()
	const peer = "e9-node"

	// "contains|cluster:victim-cluster" would otherwise assemble the subject
	// "related:contains|cluster:victim-cluster|host:e9-node/vm:e9-vm|host:e9-node/vswitch:x",
	// which parses to from="cluster:victim-cluster".
	frag := makeFragWithEdges(
		"vm:e9-vm",
		"observer:hyperv",
		map[string]string{"state": "running"},
		[]interface{}{
			map[string]interface{}{"type": "contains|cluster:victim-cluster", "to": "vswitch:x"},
		},
	)

	require.NoError(t, w.WriteFragmentDelta(ctx, peer,
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))

	// The entity itself is still ingested — only the edge entry is skipped.
	vmEID := mustParseEID(t, "host:"+peer+"/vm:e9-vm")
	require.Len(t, stateHistory(t, p, vmEID), 1,
		"entity observation must still be stored when an edge entry is rejected")

	assert.Empty(t, outboundEdges(t, p, vmEID.String()),
		"edge type containing the '|' subject delimiter must be skipped")

	// The forged anchor must not have been materialized as a placeholder node.
	victim, err := types.ParseEID("cluster:victim-cluster")
	require.NoError(t, err)
	assert.Empty(t, outboundEdges(t, p, victim.String()),
		"no edge may be anchored on the attacker-chosen 'from' EID")
	view, err := p.GetEntity(ctx, victim, interfaces.GetEntityOpts{})
	if err == nil {
		assert.Nil(t, view,
			"rejected edge must not materialize a placeholder node in another authority's namespace")
	}
}

// TestE9_RelatedEscapedTypeWithPipeIsRejected covers the untransformed path: a
// type already carrying the related: prefix bypasses FormatRelatedEscape and
// reaches the subject verbatim, so it needs the same rejection.
func TestE9_RelatedEscapedTypeWithPipeIsRejected(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()
	const peer = "e9b-node"

	frag := makeFragWithEdges(
		"vm:e9b-vm",
		"observer:hyperv",
		map[string]string{"state": "running"},
		[]interface{}{
			map[string]interface{}{"type": "related:x|cluster:victim-b", "to": "vswitch:x"},
		},
	)

	require.NoError(t, w.WriteFragmentDelta(ctx, peer,
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))

	assert.Empty(t, outboundEdges(t, p, "host:"+peer+"/vm:e9b-vm"),
		"related:-escaped edge type containing '|' must be skipped")

	victim, err := types.ParseEID("cluster:victim-b")
	require.NoError(t, err)
	assert.Empty(t, outboundEdges(t, p, victim.String()),
		"no edge may be anchored on the attacker-chosen 'from' EID")
}

// TestE9_ToWithPipeIsRejected covers the endpoint component: a "to" value
// containing '|' would split the trailing field and rebind the edge target.
func TestE9_ToWithPipeIsRejected(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()
	const peer = "e9c-node"

	frag := makeFragWithEdges(
		"vm:e9c-vm",
		"observer:hyperv",
		map[string]string{"state": "running"},
		[]interface{}{
			map[string]interface{}{"type": "connects-to", "to": "vswitch:sw|cluster:victim-c"},
		},
	)

	require.NoError(t, w.WriteFragmentDelta(ctx, peer,
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))

	assert.Empty(t, outboundEdges(t, p, "host:"+peer+"/vm:e9c-vm"),
		"'to' value containing '|' must be skipped")
}

// TestE9_FromEIDWithPipeRejectsWholeDeclarationList covers the anchor component.
// A bare cluster-kind fragment's authority is the steward-supplied fragment_id
// local part, which types.ParseEID accepts with a '|' in it. Since the anchor is
// shared by every declared edge and by the ClaimScope, the whole list is skipped.
func TestE9_FromEIDWithPipeRejectsWholeDeclarationList(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeFragWithEdges(
		"cluster:e9d-src|host:pad",
		"observer:hyperv",
		map[string]string{"state": "healthy"},
		[]interface{}{
			map[string]interface{}{"type": "contains", "to": "cluster:e9d-dst"},
			map[string]interface{}{"type": "contains", "to": "cluster:e9d-dst2"},
		},
	)

	require.NoError(t, w.WriteFragmentDelta(ctx, "e9d-node",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))

	assert.Empty(t, outboundEdges(t, p, "cluster:e9d-src|host:pad"),
		"edges anchored on a from-EID containing '|' must all be skipped")

	// Without the guard the subject "contains|cluster:e9d-src|host:pad|cluster:e9d-dst"
	// re-parses with from="cluster:e9d-src" — the truncated anchor. Nothing may be
	// anchored there, and no placeholder node may be materialized for it.
	truncated := "cluster:e9d-src"
	assert.Empty(t, outboundEdges(t, p, truncated),
		"no edge may be anchored on the truncated 'from' EID produced by the injection")
	truncatedEID := mustParseEID(t, truncated)
	view, err := p.GetEntity(ctx, truncatedEID, interfaces.GetEntityOpts{})
	if err == nil {
		assert.Nil(t, view,
			"rejected anchor must not materialize a placeholder node for the truncated EID")
	}

	for _, dst := range []string{"cluster:e9d-dst", "cluster:e9d-dst2"} {
		eid := mustParseEID(t, dst)
		edges, getErr := p.GetEdges(ctx, interfaces.EdgeFilter{ToEID: &eid})
		require.NoError(t, getErr)
		assert.Empty(t, edges, "no edge may reference %s when the anchor is rejected", dst)
	}
}

// TestE9_ControlCharacterFieldsAreRejected verifies that 0x1F (the provider's
// edge_key / claim_scope_key component separator) and other control characters
// are rejected in both the type and the to field.
func TestE9_ControlCharacterFieldsAreRejected(t *testing.T) {
	cases := []struct {
		name      string
		edgeType  string
		to        string
		fragLocal string
		peer      string
	}{
		{
			name:      "unit separator in type",
			edgeType:  "connects-to\x1fforged",
			to:        "vswitch:sw1",
			fragLocal: "e9e-vm",
			peer:      "e9e-node",
		},
		{
			name:      "unit separator in to",
			edgeType:  "connects-to",
			to:        "vswitch:sw1\x1fforged",
			fragLocal: "e9f-vm",
			peer:      "e9f-node",
		},
		{
			name:      "newline in type",
			edgeType:  "connects-to\nforged",
			to:        "vswitch:sw1",
			fragLocal: "e9g-vm",
			peer:      "e9g-node",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(t)
			w := newTestWriter(t, p)
			ctx := context.Background()

			frag := makeFragWithEdges(
				"vm:"+tc.fragLocal,
				"observer:hyperv",
				map[string]string{"state": "running"},
				[]interface{}{
					map[string]interface{}{"type": tc.edgeType, "to": tc.to},
				},
			)

			require.NoError(t, w.WriteFragmentDelta(ctx, tc.peer,
				[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))

			assert.Empty(t, outboundEdges(t, p, "host:"+tc.peer+"/vm:"+tc.fragLocal),
				"edge field containing a control character must be skipped")
		})
	}
}

// TestE9_OversizeFieldsAreRejected verifies the length bound on the two
// steward-supplied fields. The canonical decoder accepts strings up to the 8 MiB
// fragment limit, so without a bound an unbounded value reaches storage keys.
func TestE9_OversizeFieldsAreRejected(t *testing.T) {
	oversize := strings.Repeat("a", 254) // maxEdgeFieldLen is 253

	t.Run("oversize type", func(t *testing.T) {
		p := newTestProvider(t)
		w := newTestWriter(t, p)
		frag := makeFragWithEdges(
			"vm:e9h-vm",
			"observer:hyperv",
			map[string]string{"state": "running"},
			[]interface{}{
				map[string]interface{}{"type": oversize, "to": "vswitch:sw1"},
			},
		)
		require.NoError(t, w.WriteFragmentDelta(context.Background(), "e9h-node",
			[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))
		assert.Empty(t, outboundEdges(t, p, "host:e9h-node/vm:e9h-vm"),
			"edge type longer than the field bound must be skipped")
	})

	t.Run("oversize to", func(t *testing.T) {
		p := newTestProvider(t)
		w := newTestWriter(t, p)
		frag := makeFragWithEdges(
			"vm:e9i-vm",
			"observer:hyperv",
			map[string]string{"state": "running"},
			[]interface{}{
				map[string]interface{}{"type": "connects-to", "to": "vswitch:" + oversize},
			},
		)
		require.NoError(t, w.WriteFragmentDelta(context.Background(), "e9i-node",
			[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))
		assert.Empty(t, outboundEdges(t, p, "host:e9i-node/vm:e9i-vm"),
			"'to' value longer than the field bound must be skipped")
	})

	t.Run("at bound is accepted", func(t *testing.T) {
		p := newTestProvider(t)
		w := newTestWriter(t, p)
		atBound := "vswitch:" + strings.Repeat("b", 253-len("vswitch:"))
		frag := makeFragWithEdges(
			"vm:e9j-vm",
			"observer:hyperv",
			map[string]string{"state": "running"},
			[]interface{}{
				map[string]interface{}{"type": "connects-to", "to": atBound},
			},
		)
		require.NoError(t, w.WriteFragmentDelta(context.Background(), "e9j-node",
			[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))
		edges := outboundEdges(t, p, "host:e9j-node/vm:e9j-vm")
		require.Len(t, edges, 1, "a 'to' value at the field bound must be accepted")
		assert.Equal(t, "host:e9j-node/"+atBound, edges[0].Edge.To.String())
	})
}

// TestE9_RejectedEntryDoesNotSuppressValidSiblings verifies that rejection is
// per-entry: a hostile entry alongside a well-formed one drops only the hostile
// one, so a compromised steward cannot use one bad edge to hide a whole list.
func TestE9_RejectedEntryDoesNotSuppressValidSiblings(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()
	const peer = "e9k-node"

	frag := makeFragWithEdges(
		"vm:e9k-vm",
		"observer:hyperv",
		map[string]string{"state": "running"},
		[]interface{}{
			map[string]interface{}{"type": "connects-to|cluster:victim-k", "to": "vswitch:bad"},
			map[string]interface{}{"type": "connects-to", "to": "vswitch:good"},
		},
	)

	require.NoError(t, w.WriteFragmentDelta(ctx, peer,
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))

	edges := outboundEdges(t, p, "host:"+peer+"/vm:e9k-vm")
	require.Len(t, edges, 1, "only the well-formed sibling edge must be stored")
	assert.Equal(t, "connects-to", edges[0].Edge.Type)
	assert.Equal(t, "host:"+peer+"/vswitch:good", edges[0].Edge.To.String())

	// The hostile sibling must not have landed under its injected anchor either.
	assert.Empty(t, outboundEdges(t, p, "cluster:victim-k"),
		"the rejected sibling must not create an edge on the attacker-chosen anchor")
}
