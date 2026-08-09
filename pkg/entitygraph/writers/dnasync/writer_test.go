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

func newTestWriter(t *testing.T, p *sqliteprovider.SQLiteEntityGraphProvider) *dnasync.Writer {
	t.Helper()
	w, err := dnasync.New(p)
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
