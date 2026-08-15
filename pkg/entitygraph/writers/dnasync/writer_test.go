// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dnasync_test

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	sqliteprovider "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
)

// --- test helpers ---

func newTestProvider(t *testing.T) *sqliteprovider.SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := sqliteprovider.NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// newTestWriter builds a Writer with no cluster-membership verifier — the
// fail-closed default, under which every steward-asserted ha_role.cluster_name is
// denied and the fragment stays host-scoped.
func newTestWriter(t *testing.T, p *sqliteprovider.SQLiteEntityGraphProvider) *dnasync.Writer {
	t.Helper()
	w, err := dnasync.New(p)
	require.NoError(t, err)
	return w
}

// newTestWriterWithMembership builds a Writer whose cluster-membership verifier is
// the real dnasync.StaticClusterMembership snapshot, populated from cluster name →
// verified member peer authorities.
func newTestWriterWithMembership(
	t *testing.T,
	p *sqliteprovider.SQLiteEntityGraphProvider,
	byCluster map[string][]string,
) *dnasync.Writer {
	t.Helper()
	w, err := dnasync.New(p, dnasync.WithClusterMembership(dnasync.NewStaticClusterMembership(byCluster)))
	require.NoError(t, err)
	return w
}

func mustParseEID(t *testing.T, s string) types.EID {
	t.Helper()
	eid, err := types.ParseEID(s)
	require.NoError(t, err)
	return eid
}

func wideRange() interfaces.TimeRange {
	return interfaces.TimeRange{
		From: time.Unix(0, 0).UTC(),
		To:   time.Now().UTC().Add(time.Hour),
	}
}

// makeTestCanonBytes builds a valid canonical byte encoding for a string-keyed
// map with string values. It mirrors the format of CanonicalizeFragment without
// importing features/ (pkg/ import direction rule). The format is:
//
//	[uint32 BE: count][sorted entries: [uint32 key-len][key]['S'][uint32 val-len][val]]
func makeTestCanonBytes(fields map[string]string) []byte {
	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(fields))
	for k, v := range fields {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })

	var buf []byte
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(pairs)))
	buf = append(buf, hdr...)
	for _, p := range pairs {
		klen := make([]byte, 4)
		binary.BigEndian.PutUint32(klen, uint32(len(p.k)))
		buf = append(buf, klen...)
		buf = append(buf, p.k...)
		vlen := make([]byte, 4)
		binary.BigEndian.PutUint32(vlen, uint32(len(p.v)))
		buf = append(buf, 'S')
		buf = append(buf, vlen...)
		buf = append(buf, p.v...)
	}
	return buf
}

// makeTestCanonBytesNested builds a valid canonical byte encoding for a
// map[string]interface{} where values may be strings or nested map[string]interface{}.
// This is needed to encode payload fields such as ha_role.cluster_name that
// decodeCanonicalFragment will recover as a nested map.
func makeTestCanonBytesNested(fields map[string]interface{}) []byte {
	return encodeTestCanonMap(fields)
}

func encodeTestCanonMap(m map[string]interface{}) []byte {
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
		buf = append(buf, encodeTestCanonValue(m[k])...)
	}
	return buf
}

func encodeTestCanonValue(v interface{}) []byte {
	switch val := v.(type) {
	case string:
		vlen := make([]byte, 4)
		binary.BigEndian.PutUint32(vlen, uint32(len(val)))
		b := []byte{'S'}
		b = append(b, vlen...)
		b = append(b, val...)
		return b
	case map[string]interface{}:
		b := []byte{'M'}
		b = append(b, encodeTestCanonMap(val)...)
		return b
	default:
		panic("encodeTestCanonValue: unsupported type")
	}
}

// makeHostFrag creates a Fragment with a host-scoped fragment_id, an authority,
// and valid canonical bytes encoding one string field.
func makeHostFrag(fragID, authority string) *commonpb.Fragment {
	return &commonpb.Fragment{
		FragmentId:     fragID,
		Authority:      authority,
		CanonicalBytes: makeTestCanonBytes(map[string]string{"path": fragID}),
	}
}

// stateHistory returns the state-kind observation records for eid.
func stateHistory(t *testing.T, p *sqliteprovider.SQLiteEntityGraphProvider, eid types.EID) []*interfaces.ObservationRecord {
	t.Helper()
	records, err := p.GetHistory(context.Background(), eid, wideRange())
	require.NoError(t, err)
	var out []*interfaces.ObservationRecord
	for _, r := range records {
		if r.Observation.Kind == types.ObservationKindState {
			out = append(out, r)
		}
	}
	return out
}

// --- constructor tests ---

// TestNewWriterNilProvider verifies that New rejects a nil provider.
func TestNewWriterNilProvider(t *testing.T) {
	_, err := dnasync.New(nil)
	require.Error(t, err)
}

// TestWriteEmptyFragmentsIsNoop verifies that an empty fragment list returns nil
// and produces no observations.
func TestWriteEmptyFragmentsIsNoop(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	err := w.WriteFragmentDelta(context.Background(), "steward-A", nil, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	err = w.WriteFragmentDelta(context.Background(), "steward-A", []*commonpb.Fragment{}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)
}

// --- AC Group A: observation construction ---

// TestA1_HostScopedSubjectEID verifies that host-scoped fragments produce
// Subject = "host:<peerHostAuthority>/<fragment_id>", Source = peerHostAuthority
// (not the module authority), and preserve module identity in Payload["module_authority"].
//
// Using peerHostAuthority as Source keeps ClaimScope.Source and Observation.Source
// equal, which is required for the retraction machinery to fire (see the
// claimscope.go collectScopeSubjects / retractEntityProjection source-equality check).
func TestA1_HostScopedSubjectEID(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeHostFrag("file:/etc/hosts", "enforcing-module:file")
	err := w.WriteFragmentDelta(ctx, "steward-A", []*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	eid := mustParseEID(t, "host:steward-A/file:/etc/hosts")
	records := stateHistory(t, p, eid)
	require.Len(t, records, 1, "exactly one state observation expected")

	obs := records[0].Observation
	require.Equal(t, "host:steward-A/file:/etc/hosts", obs.Subject)
	require.Equal(t, types.ObservationKindState, obs.Kind)
	// Source MUST be peerHostAuthority for ClaimScope retraction to work.
	require.Equal(t, "steward-A", obs.Source,
		"host-scoped Observation.Source must be peerHostAuthority, not module identity")
	// Module identity is preserved in the payload instead.
	require.Equal(t, "enforcing-module:file", obs.Payload["module_authority"],
		"module identity must be preserved in Payload[module_authority]")
}

// TestA1_EmptyFragmentAuthorityPreservesModuleAttributionInPayload verifies that
// when a fragment carries no authority, Payload["module_authority"] is absent (not
// set to an empty string), and Source is still peerHostAuthority.
func TestA1_EmptyFragmentAuthorityPreservesModuleAttributionInPayload(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := &commonpb.Fragment{
		FragmentId:     "service:sshd",
		Authority:      "", // no module identity
		CanonicalBytes: makeTestCanonBytes(map[string]string{"state": "active"}),
	}
	err := w.WriteFragmentDelta(ctx, "steward-B", []*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	eid := mustParseEID(t, "host:steward-B/service:sshd")
	records := stateHistory(t, p, eid)
	require.Len(t, records, 1)
	// Source is always peerHostAuthority for host-scoped fragments.
	require.Equal(t, "steward-B", records[0].Observation.Source)
	// No module_authority in payload when fragment has no authority.
	_, hasModAuth := records[0].Observation.Payload["module_authority"]
	require.False(t, hasModAuth, "module_authority must not be set in payload when fragment authority is empty")
}

// TestA2_ConfidencePersistedInPayload verifies that confidence from the envelope
// (or the default when no envelope is present) is stored in Payload["confidence"].
func TestA2_ConfidencePersistedInPayload(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeHostFrag("patch:kb5042099", "enforcing-module:patch")
	envelopes := map[string]*commonpb.FragmentEnvelope{
		"patch:kb5042099": {Confidence: "medium"},
	}
	err := w.WriteFragmentDelta(ctx, "steward-C", []*commonpb.Fragment{frag}, envelopes, types.DefaultTaxonomy())
	require.NoError(t, err)

	eid := mustParseEID(t, "host:steward-C/patch:kb5042099")
	records := stateHistory(t, p, eid)
	require.Len(t, records, 1)

	got, ok := records[0].Observation.Payload["confidence"]
	require.True(t, ok, "confidence must be present in observation payload")
	require.Equal(t, "medium", got)
}

// TestA2_DefaultConfidenceIsHigh verifies that the confidence defaults to "high"
// when no envelope is provided (PO ruling: all fragments are high confidence
// unless the producer declares otherwise).
func TestA2_DefaultConfidenceIsHigh(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeHostFrag("hostname:thehost", "enforcing-module:hostname")
	err := w.WriteFragmentDelta(ctx, "steward-D", []*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	eid := mustParseEID(t, "host:steward-D/hostname:thehost")
	records := stateHistory(t, p, eid)
	require.Len(t, records, 1)

	got := records[0].Observation.Payload["confidence"]
	require.Equal(t, "high", got)
}

// TestA3_ClusterKindEID verifies that cluster-kind fragments produce a bare
// cluster EID ("cluster:<clusterName>") rather than a host-scoped one (Finding 1 fix).
func TestA3_ClusterKindEID(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	clusterFrag := &commonpb.Fragment{
		FragmentId:     "cluster:prod-cluster",
		Authority:      "observer:hyperv",
		CanonicalBytes: makeTestCanonBytes(map[string]string{"resource_owner": "tenant-x"}),
	}
	err := w.WriteFragmentDelta(ctx, "steward-E", []*commonpb.Fragment{clusterFrag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	clusterEID := mustParseEID(t, "cluster:prod-cluster")
	records := stateHistory(t, p, clusterEID)
	require.Len(t, records, 1, "one state observation expected on the cluster EID")

	obs := records[0].Observation
	require.Equal(t, "cluster:prod-cluster", obs.Subject)
	require.Equal(t, types.ObservationKindState, obs.Kind)

	// Source must carry peerHostAuthority attribution (split-brain detection).
	require.Contains(t, obs.Source, "steward-E")
}

// TestA3_ClusterNotWrittenUnderHostAuthority verifies that after a cluster-kind
// delta, no observation lands under host:<peerHostAuthority>/cluster:* — cluster
// entities are never wrapped in the host namespace (Finding 1 fix).
func TestA3_ClusterNotWrittenUnderHostAuthority(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	clusterFrag := &commonpb.Fragment{
		FragmentId:     "cluster:mycluster",
		Authority:      "observer:hyperv",
		CanonicalBytes: makeTestCanonBytes(map[string]string{"node_count": "3"}),
	}
	err := w.WriteFragmentDelta(ctx, "steward-F", []*commonpb.Fragment{clusterFrag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	// There must be NO observation under the host-namespaced EID.
	hostWrappedEID := mustParseEID(t, "host:steward-F/cluster:mycluster")
	hostRecords := stateHistory(t, p, hostWrappedEID)
	require.Empty(t, hostRecords, "cluster fragment must never land under host:<peerHostAuthority>")

	// Confirm it IS under the bare cluster EID.
	clusterEID := mustParseEID(t, "cluster:mycluster")
	clusterRecords := stateHistory(t, p, clusterEID)
	require.Len(t, clusterRecords, 1)
}

// TestA4_SameClusterEIDFromTwoStewards verifies that two stewards reporting the
// same cluster fragment_id converge on the same cluster EID. Each contributes one
// state observation attributing the reporting steward in Source.
func TestA4_SameClusterEIDFromTwoStewards(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	makeClusterFrag := func(authority string) *commonpb.Fragment {
		return &commonpb.Fragment{
			FragmentId:     "cluster:shared",
			Authority:      authority,
			CanonicalBytes: makeTestCanonBytes(map[string]string{"resource_owner": "tenant-a"}),
		}
	}

	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-G1",
		[]*commonpb.Fragment{makeClusterFrag("observer:hyperv")}, nil, types.DefaultTaxonomy()))

	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-G2",
		[]*commonpb.Fragment{makeClusterFrag("observer:hyperv")}, nil, types.DefaultTaxonomy()))

	clusterEID := mustParseEID(t, "cluster:shared")
	records := stateHistory(t, p, clusterEID)

	// Two distinct source observations must exist on the single cluster EID.
	require.Len(t, records, 2, "one observation per reporting steward on the shared cluster EID")

	sources := map[string]struct{}{}
	for _, r := range records {
		sources[r.Observation.Source] = struct{}{}
	}
	_, hasG1 := sources["steward-G1/observer:hyperv"]
	_, hasG2 := sources["steward-G2/observer:hyperv"]
	require.True(t, hasG1, "steward-G1 attribution must appear in source")
	require.True(t, hasG2, "steward-G2 attribution must appear in source")
}

// TestA5_BitIdenticalFragmentDedup verifies that two calls with bit-identical
// fragments produce exactly one observation in GetHistory (content-hash dedup,
// ADR-022 §4).
func TestA5_BitIdenticalFragmentDedup(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	canon := makeTestCanonBytes(map[string]string{"state": "active"})
	frag := &commonpb.Fragment{
		FragmentId:     "service:sshd",
		Authority:      "enforcing-module:service",
		CanonicalBytes: canon,
	}

	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-H", []*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))
	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-H", []*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))

	eid := mustParseEID(t, "host:steward-H/service:sshd")
	records := stateHistory(t, p, eid)
	require.Len(t, records, 1, "bit-identical observations must be deduped by the entity graph provider")
}

// TestA5_DifferentCanonBytesProducesNewObservation verifies that a second call
// with changed canonical bytes produces a second observation (state change landed).
func TestA5_DifferentCanonBytesProducesNewObservation(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag1 := &commonpb.Fragment{
		FragmentId:     "service:sshd",
		Authority:      "enforcing-module:service",
		CanonicalBytes: makeTestCanonBytes(map[string]string{"state": "active"}),
	}
	frag2 := &commonpb.Fragment{
		FragmentId:     "service:sshd",
		Authority:      "enforcing-module:service",
		CanonicalBytes: makeTestCanonBytes(map[string]string{"state": "inactive"}),
	}

	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-I", []*commonpb.Fragment{frag1}, nil, types.DefaultTaxonomy()))
	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-I", []*commonpb.Fragment{frag2}, nil, types.DefaultTaxonomy()))

	eid := mustParseEID(t, "host:steward-I/service:sshd")
	records := stateHistory(t, p, eid)
	require.Len(t, records, 2, "changed canonical bytes must produce a second observation")
}

// --- AC Group B: authority-boundary enforcement ---

// TestB1_AdversarialFragmentID_NoAuthoritySegmentInfluence is the key
// SE-threat-#1 regression test. A fragment whose fragment_id contains a
// steward identity ("host:steward-B/evil:path") must NEVER produce an
// observation under host:steward-B when the mTLS-verified peerHostAuthority
// is steward-A. The authority segment is built entirely from peerHostAuthority
// — authority confusion is structurally unrepresentable, not detected-and-rejected.
func TestB1_AdversarialFragmentID_NoAuthoritySegmentInfluence(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	// A fragment_id shaped to look like a different steward's EID.
	adversarialFrag := &commonpb.Fragment{
		FragmentId:     "host:steward-B/evil:path",
		Authority:      "enforcing-module:file",
		CanonicalBytes: makeTestCanonBytes(map[string]string{"x": "y"}),
	}

	err := w.WriteFragmentDelta(ctx, "steward-A",
		[]*commonpb.Fragment{adversarialFrag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	// The observation MUST land under steward-A's authority, not steward-B's.
	// EID = "host:steward-A/host:steward-B/evil:path"
	expectedEID := mustParseEID(t, "host:steward-A/host:steward-B/evil:path")
	records := stateHistory(t, p, expectedEID)
	require.Len(t, records, 1, "observation must land under host:steward-A authority")
	require.Equal(t, "host:steward-A/host:steward-B/evil:path", records[0].Observation.Subject)

	// Crucially, NOTHING must land under steward-B's EID.
	// Construct any EID that would be in steward-B's authority segment.
	// GetHistory with an EID not in the graph must return empty, not an error.
	stewardBEID, parseErr := types.ParseEID("host:steward-B/evil:path")
	require.NoError(t, parseErr)
	stealthRecords := stateHistory(t, p, stewardBEID)
	require.Empty(t, stealthRecords, "no observation must ever land under host:steward-B authority")
}

// TestB2_AdversarialPayload_EIDUnaffected verifies that adversarial canonical
// bytes whose decoded fields include a "fragment_id" key pointing to a different
// steward's namespace cannot influence the observation's Subject or the entity
// attribute values: the writer always overwrites fragment_id in the payload from
// the verified frag.GetFragmentId() field, and the EID is built before the payload.
func TestB2_AdversarialPayload_EIDUnaffected(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	// Canonical bytes that encode {"fragment_id": "host:steward-B/evil"} — an attempt
	// to poison the fragment_id attribute stored in the entity graph.
	poisonedCanon := makeTestCanonBytes(map[string]string{
		"fragment_id": "host:steward-B/evil",
		"state":       "active",
	})

	frag := &commonpb.Fragment{
		FragmentId:     "file:/etc/hosts",
		Authority:      "enforcing-module:file",
		CanonicalBytes: poisonedCanon,
	}

	err := w.WriteFragmentDelta(ctx, "steward-A",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	// The observation must land on the correct EID.
	eid := mustParseEID(t, "host:steward-A/file:/etc/hosts")
	records := stateHistory(t, p, eid)
	require.Len(t, records, 1)

	obs := records[0].Observation
	require.Equal(t, "host:steward-A/file:/etc/hosts", obs.Subject,
		"Subject must reflect the verified fragment_id, not the adversarial payload value")

	// The fragment_id in the payload must be the real value, not the adversarial one.
	gotFragID, ok := obs.Payload["fragment_id"]
	require.True(t, ok, "fragment_id must be present in the observation payload")
	require.Equal(t, "file:/etc/hosts", gotFragID,
		"payload fragment_id must be the verified value, never the adversarial canonical-bytes value")

	// No observation may exist under steward-B.
	stewardBEID, parseErr := types.ParseEID("host:steward-B/evil")
	require.NoError(t, parseErr)
	require.Empty(t, stateHistory(t, p, stewardBEID),
		"adversarial payload fragment_id must not create an entity under host:steward-B")
}

// TestGetEntityAfterWrite verifies the E2E path: WriteFragmentDelta followed by
// GetEntity returns a non-nil view with the expected entity attributes.
func TestGetEntityAfterWrite(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := makeHostFrag("firewall:default", "enforcing-module:firewall")
	err := w.WriteFragmentDelta(ctx, "steward-J",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy())
	require.NoError(t, err)

	eid := mustParseEID(t, "host:steward-J/firewall:default")
	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, view, "GetEntity must return a non-nil view after WriteFragmentDelta")
	require.NotNil(t, view.Entity)

	// The fragment_id attribute must be present in the merged entity state.
	fragIDAttr, ok := view.Entity.Attributes["fragment_id"]
	require.True(t, ok, "fragment_id attribute must be present in entity view")
	require.Equal(t, "firewall:default", fragIDAttr)
}

// TestClaimScopeOnHostFragments verifies that the batch carries a ClaimScope
// covering the host authority, enabling retraction semantics (#2874).
// We exercise this indirectly: two calls with DIFFERENT host-scoped fragment sets
// from the same steward. The second call's ClaimScope should cause the entity
// graph to retract the observation from the first set. This test only verifies
// the positive case (new fragments appear) since retraction rollout depends on
// the provider's implementation of ClaimScope semantics.
func TestClaimScopeOnHostFragments(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	// First delta: one host-scoped fragment.
	frag1 := makeHostFrag("service:sshd", "enforcing-module:service")
	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-K",
		[]*commonpb.Fragment{frag1}, nil, types.DefaultTaxonomy()))

	eid1 := mustParseEID(t, "host:steward-K/service:sshd")
	records1 := stateHistory(t, p, eid1)
	require.Len(t, records1, 1, "first fragment must have one state observation")

	// Second delta: different host-scoped fragment.
	frag2 := makeHostFrag("service:httpd", "enforcing-module:service")
	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-K",
		[]*commonpb.Fragment{frag2}, nil, types.DefaultTaxonomy()))

	eid2 := mustParseEID(t, "host:steward-K/service:httpd")
	records2 := stateHistory(t, p, eid2)
	require.Len(t, records2, 1, "second fragment must have one state observation")
}

// TestRetraction_HostScopedFragmentDropped is the key retraction correctness test.
// It verifies that when a steward stops reporting a fragment, the entity graph
// retracts the prior observation so stale state does not persist indefinitely.
//
// This test would FAIL with Observation.Source = frag.GetAuthority() because
// collectScopeSubjects requires obs.Source == ClaimScope.Source (string equality),
// and retractEntityProjection deletes rows by (subject, source). If Source were
// the module identity, neither step would match the claim scope source.
func TestRetraction_HostScopedFragmentDropped(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	// Delta 1: steward reports both file:/etc/hosts AND service:sshd.
	fragFile := makeHostFrag("file:/etc/hosts", "enforcing-module:file")
	fragSSHD := makeHostFrag("service:sshd", "enforcing-module:service")
	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-ret",
		[]*commonpb.Fragment{fragFile, fragSSHD}, nil, types.DefaultTaxonomy()))

	eidFile := mustParseEID(t, "host:steward-ret/file:/etc/hosts")
	eidSSHD := mustParseEID(t, "host:steward-ret/service:sshd")

	require.Len(t, stateHistory(t, p, eidFile), 1, "file fragment must have one state observation after delta 1")
	require.Len(t, stateHistory(t, p, eidSSHD), 1, "sshd fragment must have one state observation after delta 1")

	// Delta 2: steward reports ONLY service:sshd — file:/etc/hosts is dropped.
	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-ret",
		[]*commonpb.Fragment{fragSSHD}, nil, types.DefaultTaxonomy()))

	// service:sshd must still be active.
	require.Len(t, stateHistory(t, p, eidSSHD), 1, "sshd observation must survive delta 2")

	// file:/etc/hosts must have been retracted: the provider writes an absence
	// observation and removes the entity projection. GetEntity must return nil or
	// ErrNotFound (both signal retraction; the provider returns ErrNotFound when
	// the entity projection row is gone).
	fileView, fileErr := p.GetEntity(ctx, eidFile, interfaces.GetEntityOpts{})
	retracted := fileView == nil || errors.Is(fileErr, sqliteprovider.ErrNotFound)
	require.True(t, retracted,
		"file:/etc/hosts entity must be retracted (nil view or ErrNotFound) after it is dropped from the delta set; got view=%v err=%v",
		fileView, fileErr)
}

// --- AC Group C: cluster-scoped VM (Issue #3367) ---

// TestC1_ClusteredVMEIDFromTwoStewards is the identity-stability test for Issue #3367.
// Two WriteFragmentDelta calls from two different peerHostAuthority values, each
// reporting the same clustered VM fragment, must converge on the identical
// cluster:<name>/vm:<vmname> EID — not mint two separate host-scoped EIDs.
//
// This is the core property this story exists to deliver: VM EID stability across
// live migration between cluster nodes.
func TestC1_ClusteredVMEIDFromTwoStewards(t *testing.T) {
	p := newTestProvider(t)
	// Both nodes are verified members of prod-cluster, so their asserted
	// ha_role.cluster_name is allowed to become the eid authority segment.
	w := newTestWriterWithMembership(t, p, map[string][]string{
		"prod-cluster": {"node-1", "node-2"},
	})
	ctx := context.Background()

	makeClusteredVMFrag := func() *commonpb.Fragment {
		return &commonpb.Fragment{
			FragmentId: "vm:prod-vm1",
			Authority:  "observer:hyperv",
			CanonicalBytes: makeTestCanonBytesNested(map[string]interface{}{
				"state":   "running",
				"ha_role": map[string]interface{}{"cluster_name": "prod-cluster"},
			}),
		}
	}

	// Two distinct cluster nodes each report the same clustered VM.
	require.NoError(t, w.WriteFragmentDelta(ctx, "node-1",
		[]*commonpb.Fragment{makeClusteredVMFrag()}, nil, types.DefaultTaxonomy()))
	require.NoError(t, w.WriteFragmentDelta(ctx, "node-2",
		[]*commonpb.Fragment{makeClusteredVMFrag()}, nil, types.DefaultTaxonomy()))

	// Both calls must converge on the same cluster-scoped EID.
	clusterVMEID := mustParseEID(t, "cluster:prod-cluster/vm:prod-vm1")
	records := stateHistory(t, p, clusterVMEID)
	require.Len(t, records, 2, "both cluster nodes must contribute one observation to the shared cluster-scoped VM EID")

	sources := map[string]struct{}{}
	for _, r := range records {
		sources[r.Observation.Source] = struct{}{}
	}
	_, hasNode1 := sources["node-1/observer:hyperv"]
	_, hasNode2 := sources["node-2/observer:hyperv"]
	require.True(t, hasNode1, "node-1 attribution must appear in source")
	require.True(t, hasNode2, "node-2 attribution must appear in source")

	// Verify neither node minted a host-scoped VM EID.
	for _, peer := range []string{"node-1", "node-2"} {
		hostEID := mustParseEID(t, "host:"+peer+"/vm:prod-vm1")
		require.Empty(t, stateHistory(t, p, hostEID),
			"clustered VM must never land under host:%s authority", peer)
	}
}

// TestC2_StandaloneVMRemainsHostScoped verifies that a VM fragment with no ha_role
// still ingests under host:<peer>/vm:<name>, exactly as today — no regression.
func TestC2_StandaloneVMRemainsHostScoped(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	standaloneFrag := &commonpb.Fragment{
		FragmentId: "vm:standalone-vm",
		Authority:  "observer:hyperv",
		CanonicalBytes: makeTestCanonBytesNested(map[string]interface{}{
			"state": "running",
		}),
	}
	require.NoError(t, w.WriteFragmentDelta(ctx, "node-solo",
		[]*commonpb.Fragment{standaloneFrag}, nil, types.DefaultTaxonomy()))

	hostEID := mustParseEID(t, "host:node-solo/vm:standalone-vm")
	records := stateHistory(t, p, hostEID)
	require.Len(t, records, 1, "standalone VM must land on host-scoped EID")
	require.Equal(t, "host:node-solo/vm:standalone-vm", records[0].Observation.Subject)

	// Confirm no cluster-scoped EID was minted.
	// (There is no cluster name to even try to look up, but we can confirm the
	// host EID received the observation and is the sole result.)
	require.Equal(t, "node-solo", records[0].Observation.Source,
		"standalone VM source must be peerHostAuthority for ClaimScope retraction")
}

// TestC3_LiveMigrationOrphan is the live-migration regression test for Issue #3367.
//
// Scenario: a VM is first reported standalone (host:<peer>/vm:<name>), then — after
// joining a failover cluster — subsequent reports carry ha_role.cluster_name and land
// on cluster:<name>/vm:<name>.
//
// This test verifies that post-join the cluster-scoped EID is queryable (the primary
// correctness property). The old host-scoped EID is orphaned rather than migrated:
// retroactive EID migration is out of scope for this story. The existing ClaimScope
// retraction will eventually clean up the orphan when the steward's next host-scoped
// delta omits the now-clustered VM, but that cleanup is not asserted here.
func TestC3_LiveMigrationOrphan(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriterWithMembership(t, p, map[string][]string{
		"failover-cluster": {"node-alpha"},
	})
	ctx := context.Background()

	// Phase 1: VM reported as standalone (no ha_role).
	standaloneFrag := &commonpb.Fragment{
		FragmentId: "vm:migrate-me",
		Authority:  "observer:hyperv",
		CanonicalBytes: makeTestCanonBytesNested(map[string]interface{}{
			"state": "running",
		}),
	}
	require.NoError(t, w.WriteFragmentDelta(ctx, "node-alpha",
		[]*commonpb.Fragment{standaloneFrag}, nil, types.DefaultTaxonomy()))

	hostEID := mustParseEID(t, "host:node-alpha/vm:migrate-me")
	require.Len(t, stateHistory(t, p, hostEID), 1,
		"standalone VM must land on host-scoped EID before cluster join")

	// Phase 2: VM now carries ha_role.cluster_name (post cluster-join).
	clusteredFrag := &commonpb.Fragment{
		FragmentId: "vm:migrate-me",
		Authority:  "observer:hyperv",
		CanonicalBytes: makeTestCanonBytesNested(map[string]interface{}{
			"state":   "running",
			"ha_role": map[string]interface{}{"cluster_name": "failover-cluster"},
		}),
	}
	require.NoError(t, w.WriteFragmentDelta(ctx, "node-alpha",
		[]*commonpb.Fragment{clusteredFrag}, nil, types.DefaultTaxonomy()))

	// Post-join: cluster-scoped EID must be readable.
	clusterEID := mustParseEID(t, "cluster:failover-cluster/vm:migrate-me")
	clusterRecords := stateHistory(t, p, clusterEID)
	require.Len(t, clusterRecords, 1,
		"clustered VM must land on cluster-scoped EID after joining the cluster")
	require.Equal(t, "cluster:failover-cluster/vm:migrate-me", clusterRecords[0].Observation.Subject)
}

// TestC4_ClusteredVMHasNoClaimScope verifies that cluster-scoped VMs do NOT produce
// a host-authority ClaimScope — two nodes' observations of the same VM coexist.
func TestC4_ClusteredVMHasNoClaimScope(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriterWithMembership(t, p, map[string][]string{
		"shared-cluster": {"node-P1", "node-P2"},
	})
	ctx := context.Background()

	makeClusteredVMFrag := func() *commonpb.Fragment {
		return &commonpb.Fragment{
			FragmentId: "vm:shared-vm",
			Authority:  "observer:hyperv",
			CanonicalBytes: makeTestCanonBytesNested(map[string]interface{}{
				"state":   "running",
				"ha_role": map[string]interface{}{"cluster_name": "shared-cluster"},
			}),
		}
	}

	// Node-P1 writes first.
	require.NoError(t, w.WriteFragmentDelta(ctx, "node-P1",
		[]*commonpb.Fragment{makeClusteredVMFrag()}, nil, types.DefaultTaxonomy()))

	// Node-P2 writes second — must NOT retract node-P1's observation.
	require.NoError(t, w.WriteFragmentDelta(ctx, "node-P2",
		[]*commonpb.Fragment{makeClusteredVMFrag()}, nil, types.DefaultTaxonomy()))

	clusterEID := mustParseEID(t, "cluster:shared-cluster/vm:shared-vm")
	records := stateHistory(t, p, clusterEID)
	require.Len(t, records, 2,
		"both nodes' cluster-scoped VM observations must survive — no implicit retraction")
}

// --- AC Group D: cluster-authority trust boundary (SE threat #1) ---

// TestD1_CrossClusterClaimRejected is the authority-confusion regression test for
// the cluster-scoped VM branch. A compromised steward that is a verified member of
// its own cluster asserts ha_role.cluster_name = a DIFFERENT cluster it does not
// belong to. That claim must not reach the eid authority segment: the observation
// lands under the attacker's own host authority instead, and nothing appears under
// the victim cluster.
func TestD1_CrossClusterClaimRejected(t *testing.T) {
	p := newTestProvider(t)
	// evil-node is a member of its own cluster only.
	w := newTestWriterWithMembership(t, p, map[string][]string{
		"attacker-cluster": {"evil-node"},
		"victim-cluster":   {"honest-node-1", "honest-node-2"},
	})
	ctx := context.Background()

	forgedFrag := &commonpb.Fragment{
		FragmentId: "vm:critical-db",
		Authority:  "observer:hyperv",
		CanonicalBytes: makeTestCanonBytesNested(map[string]interface{}{
			"state":   "running",
			"ha_role": map[string]interface{}{"cluster_name": "victim-cluster"},
		}),
	}
	require.NoError(t, w.WriteFragmentDelta(ctx, "evil-node",
		[]*commonpb.Fragment{forgedFrag}, nil, types.DefaultTaxonomy()))

	// Nothing may exist under the victim cluster's authority.
	victimEID := mustParseEID(t, "cluster:victim-cluster/vm:critical-db")
	require.Empty(t, stateHistory(t, p, victimEID),
		"an unverified cluster claim must never write under cluster:victim-cluster")

	// The observation is recorded under the asserting peer's own authority.
	hostEID := mustParseEID(t, "host:evil-node/vm:critical-db")
	records := stateHistory(t, p, hostEID)
	require.Len(t, records, 1, "denied cluster claim must fall back to the host-scoped eid")
	require.Equal(t, "evil-node", records[0].Observation.Source)
}

// TestD2_DeniedClusterClaimRemainsRetractable verifies the security property that
// makes the host-scoped fallback the safe outcome: unlike a cluster-scoped
// observation (which carries no ClaimScope and can therefore never be retracted),
// the fallback observation is covered by the peer's host ClaimScope, so it
// disappears once the steward stops reporting it.
func TestD2_DeniedClusterClaimRemainsRetractable(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriterWithMembership(t, p, map[string][]string{
		"real-cluster": {"honest-node"},
	})
	ctx := context.Background()

	forgedVM := &commonpb.Fragment{
		FragmentId: "vm:forged",
		Authority:  "observer:hyperv",
		CanonicalBytes: makeTestCanonBytesNested(map[string]interface{}{
			"state":   "running",
			"ha_role": map[string]interface{}{"cluster_name": "not-my-cluster"},
		}),
	}
	keeper := makeHostFrag("service:sshd", "enforcing-module:service")

	require.NoError(t, w.WriteFragmentDelta(ctx, "rogue-node",
		[]*commonpb.Fragment{forgedVM, keeper}, nil, types.DefaultTaxonomy()))

	forgedEID := mustParseEID(t, "host:rogue-node/vm:forged")
	require.Len(t, stateHistory(t, p, forgedEID), 1,
		"denied cluster claim must land host-scoped before retraction")

	// Next delta omits the forged VM: the host ClaimScope retracts it.
	require.NoError(t, w.WriteFragmentDelta(ctx, "rogue-node",
		[]*commonpb.Fragment{keeper}, nil, types.DefaultTaxonomy()))

	view, err := p.GetEntity(ctx, forgedEID, interfaces.GetEntityOpts{})
	retracted := view == nil || errors.Is(err, sqliteprovider.ErrNotFound)
	require.True(t, retracted,
		"host-scoped fallback must remain retractable; got view=%v err=%v", view, err)
}

// TestD3_NoVerifierDeniesClusterClaim verifies the fail-closed default: a Writer
// constructed without WithClusterMembership treats every ha_role.cluster_name as
// unverified, so clustered VMs stay host-scoped rather than minting cluster-scoped
// entities on a steward's unchecked say-so.
func TestD3_NoVerifierDeniesClusterClaim(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p) // no membership verifier wired
	ctx := context.Background()

	frag := &commonpb.Fragment{
		FragmentId: "vm:unverified",
		Authority:  "observer:hyperv",
		CanonicalBytes: makeTestCanonBytesNested(map[string]interface{}{
			"ha_role": map[string]interface{}{"cluster_name": "some-cluster"},
		}),
	}
	require.NoError(t, w.WriteFragmentDelta(ctx, "node-nv",
		[]*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))

	require.Empty(t, stateHistory(t, p, mustParseEID(t, "cluster:some-cluster/vm:unverified")),
		"a Writer with no membership verifier must not create cluster-scoped entities")
	require.Len(t, stateHistory(t, p, mustParseEID(t, "host:node-nv/vm:unverified")), 1,
		"the fragment must still be recorded under the peer's own authority")
}

// TestClusterFragmentHasNoClaimScope verifies that cluster-kind fragments do NOT
// produce a host-authority ClaimScope. The batch for a cluster-only delta should
// report zero ClaimScopes so that concurrent stewards' observations are preserved.
// We verify this indirectly: two stewards report the same cluster, then we
// confirm both observations survive after the second write (no implicit retraction).
func TestClusterFragmentHasNoClaimScope(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	clusterFrag := func(authority string) *commonpb.Fragment {
		return &commonpb.Fragment{
			FragmentId:     "cluster:shared-cluster",
			Authority:      authority,
			CanonicalBytes: makeTestCanonBytes(map[string]string{"state": "healthy"}),
		}
	}

	// Steward-L1 writes first.
	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-L1",
		[]*commonpb.Fragment{clusterFrag("observer:hyperv")}, nil, types.DefaultTaxonomy()))

	// Steward-L2 writes second — must NOT retract steward-L1's observation.
	require.NoError(t, w.WriteFragmentDelta(ctx, "steward-L2",
		[]*commonpb.Fragment{clusterFrag("observer:hyperv")}, nil, types.DefaultTaxonomy()))

	clusterEID := mustParseEID(t, "cluster:shared-cluster")
	records := stateHistory(t, p, clusterEID)
	require.Len(t, records, 2,
		"both stewards' cluster observations must survive — no implicit retraction on cluster-kind")
}
