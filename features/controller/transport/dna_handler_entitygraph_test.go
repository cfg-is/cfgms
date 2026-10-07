// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package transport — entity-graph integration tests for the DNA delta handler.
//
// This file exercises the authority-boundary invariant (SE threat #1) through the
// full delta receive path: a real mTLS-authenticated context + in-process gRPC
// stream → handleDeltaGRPC → WithEntityGraph → entity-graph writer.
//
// The security property being tested: no steward-supplied string (fragment_id,
// canonical_bytes) can produce an entity-graph observation whose EID authority
// segment names any steward other than the mTLS-verified peer.
package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	common "github.com/cfgis/cfgms/api/proto/common"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	dptypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	sqliteprovider "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestEGProvider opens a fresh SQLite entity graph provider backed by a temp file.
func newTestEGProvider(t *testing.T) *sqliteprovider.SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := sqliteprovider.NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// egStateHistory returns only ObservationKindState records for the given EID.
func egStateHistory(t *testing.T, p *sqliteprovider.SQLiteEntityGraphProvider, eid egtypes.EID) []*interfaces.ObservationRecord {
	t.Helper()
	wide := interfaces.TimeRange{
		From: time.Unix(0, 0).UTC(),
		To:   time.Now().UTC().Add(time.Hour),
	}
	records, err := p.GetHistory(context.Background(), eid, wide)
	require.NoError(t, err)
	var out []*interfaces.ObservationRecord
	for _, r := range records {
		if r.Observation.Kind == egtypes.ObservationKindState {
			out = append(out, r)
		}
	}
	return out
}

// adversarialFrag builds a fragment whose fragment_id is shaped to look like
// another steward's EID ("host:<otherSteward>/..."). The canonical bytes and
// FragmentHash are valid so the fragment passes verifyFragmentLeaves.
func adversarialFrag(fragmentID, authority string) *common.Fragment {
	canon := []byte(`{"adversarial":"payload","host_target":"steward-B"}`)
	return &common.Fragment{
		FragmentId:     fragmentID,
		Authority:      authority,
		CanonicalBytes: canon,
		FragmentHash:   sdna.FragmentHash(canon),
	}
}

// TestDNAHandler_DeltaGRPC_EntityGraph_B1_AdversarialFragmentID is the SE threat
// #1 regression test through the full delta transport path.
//
// A steward authenticated as "steward-A" sends a fragment whose fragment_id is
// "host:steward-B/evil:path" — shaped to look like a different steward's EID.
// The handler must route the entity-graph observation to host:steward-A (the
// mTLS-verified authority), never to host:steward-B. Authority confusion is
// structurally unrepresentable: the EID authority segment is built from the
// mTLS-verified peerID, never from the fragment_id field.
func TestDNAHandler_DeltaGRPC_EntityGraph_B1_AdversarialFragmentID(t *testing.T) {
	ca := newTestCA(t)
	p := newTestEGProvider(t)
	egWriter, err := dnasync.New(p)
	require.NoError(t, err)
	taxonomy := egtypes.DefaultTaxonomy()

	// Adversarial fragment whose fragment_id contains a foreign steward identity.
	evil := adversarialFrag("host:steward-B/evil:path", "test-authority")

	manifest := fragmentsToManifest([]*common.Fragment{evil})
	claimedRoot, err := sdna.AggregateRoot(manifest)
	require.NoError(t, err)

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-A", manifest)

	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil).
		WithPartialSync(store, nil).
		WithEntityGraph(egWriter, taxonomy)
	h.recordDeltaRequest("steward-A", claimedRoot, manifestIDs(manifest))

	ctx := peerContextWithCA(t, ca, "steward-A")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-A", []*common.Fragment{evil})...)
	require.NoError(t, h.HandleGRPC(stream))
	require.NotNil(t, stream.resp)
	require.True(t, stream.resp.GetAccepted())

	// The observation MUST land under steward-A's authority — the fragment_id
	// "host:steward-B/evil:path" goes into the localID, not the authority segment.
	// EID = "host:steward-A/host:steward-B/evil:path"
	eidStewardA, parseErr := egtypes.ParseEID("host:steward-A/host:steward-B/evil:path")
	require.NoError(t, parseErr)
	recordsA := egStateHistory(t, p, eidStewardA)
	require.Len(t, recordsA, 1,
		"exactly one state observation must land under host:steward-A authority")
	require.Equal(t, "host:steward-A/host:steward-B/evil:path", recordsA[0].Observation.Subject,
		"Subject must be rooted under the mTLS-verified steward-A, not steward-B")

	// No observation may exist under steward-B's namespace.
	eidStewardB, parseErr := egtypes.ParseEID("host:steward-B/evil:path")
	require.NoError(t, parseErr)
	recordsB := egStateHistory(t, p, eidStewardB)
	require.Empty(t, recordsB,
		"adversarial fragment_id must never produce an observation under host:steward-B")
}

// TestDNAHandler_DeltaGRPC_EntityGraph_NormalFragmentsLandCorrectly verifies that
// after a valid delta the entity-graph observations for normal host-scoped fragments
// land under the authenticated steward's host authority and have the correct Kind.
func TestDNAHandler_DeltaGRPC_EntityGraph_NormalFragmentsLandCorrectly(t *testing.T) {
	ca := newTestCA(t)
	p := newTestEGProvider(t)
	egWriter, err := dnasync.New(p)
	require.NoError(t, err)
	taxonomy := egtypes.DefaultTaxonomy()

	// Three standard host-scoped fragments.
	frags := []*common.Fragment{
		adversarialFrag("file:/etc/hosts", "enforcing-module:file"),
		adversarialFrag("service:sshd", "enforcing-module:service"),
		adversarialFrag("patch:kb5042099", "enforcing-module:patch"),
	}

	manifest := fragmentsToManifest(frags)
	claimedRoot, err := sdna.AggregateRoot(manifest)
	require.NoError(t, err)

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-Z", manifest)

	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil).
		WithPartialSync(store, nil).
		WithEntityGraph(egWriter, taxonomy)
	h.recordDeltaRequest("steward-Z", claimedRoot, manifestIDs(manifest))

	ctx := peerContextWithCA(t, ca, "steward-Z")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-Z", frags)...)
	require.NoError(t, h.HandleGRPC(stream))
	require.True(t, stream.resp.GetAccepted())

	// All three fragments must produce state observations under steward-Z.
	for _, frag := range frags {
		eid, parseErr := egtypes.ParseEID("host:steward-Z/" + frag.GetFragmentId())
		require.NoError(t, parseErr)
		records := egStateHistory(t, p, eid)
		require.Len(t, records, 1,
			"fragment %q must have exactly one state observation under host:steward-Z",
			frag.GetFragmentId())
		require.Equal(t, egtypes.ObservationKindState, records[0].Observation.Kind)
	}
}

// TestDNAHandler_DeltaGRPC_EntityGraph_WriterFailureNonFatal verifies that an
// entity-graph write failure does NOT fail the delta RPC. The steward's stream
// must still receive Accepted=true and the manifest must be committed.
func TestDNAHandler_DeltaGRPC_EntityGraph_WriterFailureNonFatal(t *testing.T) {
	ca := newTestCA(t)

	// Use a nil provider to trigger the egWriter constructor to fail — instead,
	// we wire a writer backed by a closed provider so the write itself fails.
	p := newTestEGProvider(t)
	// Close the provider immediately so writes fail.
	_ = p.Close()

	egWriter, err := dnasync.New(p)
	require.NoError(t, err, "New must succeed — the close error only surfaces on write")
	taxonomy := egtypes.DefaultTaxonomy()

	frags := makeTestFragments(2)
	manifest := fragmentsToManifest(frags)
	claimedRoot, rootErr := sdna.AggregateRoot(manifest)
	require.NoError(t, rootErr)

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-nonfatal", manifest)

	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil).
		WithPartialSync(store, nil).
		WithEntityGraph(egWriter, taxonomy)
	h.recordDeltaRequest("steward-nonfatal", claimedRoot, manifestIDs(manifest))

	ctx := peerContextWithCA(t, ca, "steward-nonfatal")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-nonfatal", frags)...)

	// The handler must succeed even though the entity-graph write fails.
	require.NoError(t, h.HandleGRPC(stream),
		"a failed entity-graph write must not fail the delta RPC")
	require.NotNil(t, stream.resp)
	require.True(t, stream.resp.GetAccepted(),
		"the steward must still receive Accepted=true when the eg write fails")

	// The manifest must have been committed (pendingDeltas cleared).
	_, stillPending := h.pendingDeltas.Load("steward-nonfatal")
	require.False(t, stillPending,
		"pendingDeltas must be cleared even when the entity-graph write fails")
}

// TestDNAHandler_DeltaGRPC_EntityGraph_NoWriterSkipsGracefully verifies that a
// DNAHandler WITHOUT WithEntityGraph wired still accepts the delta normally.
func TestDNAHandler_DeltaGRPC_EntityGraph_NoWriterSkipsGracefully(t *testing.T) {
	ca := newTestCA(t)

	frags := makeTestFragments(2)
	manifest := fragmentsToManifest(frags)
	claimedRoot, err := sdna.AggregateRoot(manifest)
	require.NoError(t, err)

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-nowire", manifest)

	// Handler with WithPartialSync but no WithEntityGraph.
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil).
		WithPartialSync(store, nil)
	h.recordDeltaRequest("steward-nowire", claimedRoot, manifestIDs(manifest))

	ctx := peerContextWithCA(t, ca, "steward-nowire")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-nowire", frags)...)
	require.NoError(t, h.HandleGRPC(stream),
		"a handler without entity-graph wired must still accept the delta")
	require.True(t, stream.resp.GetAccepted())
}

// TestDNAHandler_DeltaGRPC_DriftDiff_RoundTrip asserts the required story round-trip
// (Issue #3373 AC): steward-side StateDiff → DNATransfer.DriftDiffBytes → controller
// handleDeltaGRPC → WriteDriftDiffs → GetDriftState returns matching content.
//
// This is an integration-style unit test: it uses a real SQLite entity-graph provider
// and a real mTLS-authenticated context (no mocks). The drift-diff bytes are
// constructed exactly as the steward's encodeDriftDiffs does: JSON-marshalled
// commonpb.DriftDiffRecord values packed into a [][]byte slice.
func TestDNAHandler_DeltaGRPC_DriftDiff_RoundTrip(t *testing.T) {
	ca := newTestCA(t)
	p := newTestEGProvider(t)
	egWriter, err := dnasync.New(p)
	require.NoError(t, err)
	taxonomy := egtypes.DefaultTaxonomy()

	const peerID = "steward-drift-rt"
	const configRev = "cfg-v1.7.0"

	// Two managed resources: one with drift, one matching.
	driftRec1 := &common.DriftDiffRecord{
		FragmentID:     "service:sshd",
		ConfigRevision: configRev,
		DetectedAt:     time.Now().UTC(),
		Fields: []*common.DriftDiffField{
			{Attribute: "enabled", Desired: true, Actual: false, Matching: false},
			{Attribute: "port", Desired: float64(22), Actual: float64(22), Matching: true},
		},
	}
	driftRec2 := &common.DriftDiffRecord{
		FragmentID:     "file:sudoers",
		ConfigRevision: configRev,
		DetectedAt:     time.Now().UTC(),
		Fields: []*common.DriftDiffField{
			{Attribute: "content", Desired: "secure", Actual: "secure", Matching: true},
		},
	}
	b1, err := json.Marshal(driftRec1)
	require.NoError(t, err)
	b2, err := json.Marshal(driftRec2)
	require.NoError(t, err)

	// Build the delta transfer with drift-diff bytes alongside fragments.
	frags := makeTestFragments(1)
	manifest := fragmentsToManifest(frags)
	claimedRoot, err := sdna.AggregateRoot(manifest)
	require.NoError(t, err)

	transfer := &dptypes.DNATransfer{
		StewardID:      peerID,
		TenantID:       "t1",
		Delta:          true,
		Fragments:      frags,
		DriftDiffBytes: [][]byte{b1, b2},
	}
	payload, err := json.Marshal(transfer)
	require.NoError(t, err)
	chunks := []*transportpb.DNAChunk{{
		StewardId:   peerID,
		TenantId:    "t1",
		Data:        payload,
		ChunkIndex:  0,
		TotalChunks: 1,
		IsDelta:     true,
	}}

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest(peerID, manifest)

	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil).
		WithPartialSync(store, nil).
		WithEntityGraph(egWriter, taxonomy)
	h.recordDeltaRequest(peerID, claimedRoot, manifestIDs(manifest))

	ctx := peerContextWithCA(t, ca, peerID)
	stream := newTestDNAStream(ctx, chunks...)
	require.NoError(t, h.HandleGRPC(stream))
	require.True(t, stream.resp.GetAccepted(), "delta with drift-diff bytes must be accepted")

	// GetDriftState must return the content shipped in DriftDiffBytes.
	eid1, err := egtypes.ParseEID("host:" + peerID + "/service:sshd")
	require.NoError(t, err)
	state1, err := p.GetDriftState(context.Background(), eid1)
	require.NoError(t, err, "drift state for service:sshd must be written")
	require.NotNil(t, state1)
	assert.Equal(t, configRev, state1.ConfigRevision, "config revision must match")
	assert.Equal(t, "detected", state1.LifecycleStatus)
	assert.Len(t, state1.Fields, 2)

	// The non-matching field must be present.
	var foundEnabled bool
	for _, f := range state1.Fields {
		if f.Attribute == "enabled" {
			foundEnabled = true
			assert.False(t, f.Matching, "enabled field must be non-matching")
		}
	}
	assert.True(t, foundEnabled, "enabled field must be recorded in state1")

	// Second resource (file:sudoers) — matching-only, still persisted.
	eid2, err := egtypes.ParseEID("host:" + peerID + "/file:sudoers")
	require.NoError(t, err)
	state2, err := p.GetDriftState(context.Background(), eid2)
	require.NoError(t, err, "drift state for file:sudoers must be written")
	require.NotNil(t, state2)
	assert.Equal(t, configRev, state2.ConfigRevision)
	require.Len(t, state2.Fields, 1)
	assert.True(t, state2.Fields[0].Matching, "content field must be matching")
}

// TestDNAHandler_DeltaGRPC_DriftDiff_NonFatalOnWriteFailure verifies that a
// drift-diff write failure does NOT fail the delta RPC. The steward's stream
// must still receive Accepted=true and the manifest must be committed.
func TestDNAHandler_DeltaGRPC_DriftDiff_NonFatalOnWriteFailure(t *testing.T) {
	ca := newTestCA(t)
	p := newTestEGProvider(t)
	_ = p.Close() // force write failures

	egWriter, err := dnasync.New(p)
	require.NoError(t, err)
	taxonomy := egtypes.DefaultTaxonomy()

	const peerID = "steward-drift-nonfatal"

	driftRec := &common.DriftDiffRecord{
		FragmentID:     "service:crond",
		ConfigRevision: "v1",
		DetectedAt:     time.Now().UTC(),
		Fields: []*common.DriftDiffField{
			{Attribute: "running", Desired: true, Actual: false, Matching: false},
		},
	}
	b, err := json.Marshal(driftRec)
	require.NoError(t, err)

	frags := makeTestFragments(1)
	manifest := fragmentsToManifest(frags)
	claimedRoot, err := sdna.AggregateRoot(manifest)
	require.NoError(t, err)

	transfer := &dptypes.DNATransfer{
		StewardID:      peerID,
		TenantID:       "t1",
		Delta:          true,
		Fragments:      frags,
		DriftDiffBytes: [][]byte{b},
	}
	payload, err := json.Marshal(transfer)
	require.NoError(t, err)
	chunks := []*transportpb.DNAChunk{{
		StewardId:   peerID,
		TenantId:    "t1",
		Data:        payload,
		ChunkIndex:  0,
		TotalChunks: 1,
		IsDelta:     true,
	}}

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest(peerID, manifest)

	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil).
		WithPartialSync(store, nil).
		WithEntityGraph(egWriter, taxonomy)
	h.recordDeltaRequest(peerID, claimedRoot, manifestIDs(manifest))

	ctx := peerContextWithCA(t, ca, peerID)
	stream := newTestDNAStream(ctx, chunks...)
	// Must succeed even when the entity-graph write fails.
	require.NoError(t, h.HandleGRPC(stream), "drift-diff write failure must not fail the RPC")
	require.True(t, stream.resp.GetAccepted())
}

// driftDiffChunks marshals a full-snapshot DNATransfer carrying identity fragments
// plus the given drift-diff records, exactly as the steward's send path does
// (features/steward/client encodeDriftDiffs → DNATransfer.DriftDiffBytes).
func driftDiffChunks(t *testing.T, peerID string, recs []*common.DriftDiffRecord) []*transportpb.DNAChunk {
	t.Helper()
	raw := make([][]byte, 0, len(recs))
	for _, r := range recs {
		b, err := json.Marshal(r)
		require.NoError(t, err)
		raw = append(raw, b)
	}
	return dnaChunksForTransfer(t, &dptypes.DNATransfer{
		StewardID:      peerID,
		TenantID:       "t1",
		FragmentBytes:  identityFragmentBytes(t, map[string]string{"hostname": "drift-host", "os": "linux"}),
		DriftDiffBytes: raw,
	}, 1)
}

// TestDNAHandler_FullSyncGRPC_DriftDiff_RoundTrip covers the FULL-SYNC drift-diff
// write path (HandleGRPC → reassembleDNA → WriteDriftDiffs), the sibling of the delta
// path exercised above. A full sync is what a steward sends on first connect and
// whenever partial sync is unavailable, so it is the path most drift records travel.
func TestDNAHandler_FullSyncGRPC_DriftDiff_RoundTrip(t *testing.T) {
	ca := newTestCA(t)
	p := newTestEGProvider(t)
	egWriter, err := dnasync.New(p)
	require.NoError(t, err)
	taxonomy := egtypes.DefaultTaxonomy()

	const peerID = "steward-full-drift"
	const configRev = "cfg-full-9"

	chunks := driftDiffChunks(t, peerID, []*common.DriftDiffRecord{
		{
			FragmentID:     "service:sshd",
			ConfigRevision: configRev,
			DetectedAt:     time.Now().UTC(),
			Fields: []*common.DriftDiffField{
				{Attribute: "enabled", Desired: true, Actual: false, Matching: false},
				{Attribute: "port", Desired: float64(22), Actual: float64(22), Matching: true},
			},
		},
		{
			FragmentID:     "file:sudoers",
			ConfigRevision: configRev,
			DetectedAt:     time.Now().UTC(),
			Fields: []*common.DriftDiffField{
				{Attribute: "content", Desired: "secure", Actual: "secure", Matching: true},
			},
		},
	})

	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), registeredService(t, peerID)).
		WithEntityGraph(egWriter, taxonomy)

	stream := newTestDNAStream(peerContextWithCA(t, ca, peerID), chunks...)
	require.NoError(t, h.HandleGRPC(stream))
	require.True(t, stream.resp.GetAccepted())

	eid := mustParseEGEID(t, "host:"+peerID+"/service:sshd")
	state, err := p.GetDriftState(context.Background(), eid)
	require.NoError(t, err, "the full-sync path must write drift state")
	require.NotNil(t, state)
	assert.Equal(t, configRev, state.ConfigRevision)
	assert.Equal(t, "detected", state.LifecycleStatus)
	require.Len(t, state.Fields, 2, "the full compared field set must survive the full-sync path")

	matching := 0
	for _, f := range state.Fields {
		if f.Matching {
			matching++
		}
	}
	assert.Equal(t, 1, matching, "the matching field must be recorded, not only the drifted one")

	// The second record must land on its own EID.
	eid2 := mustParseEGEID(t, "host:"+peerID+"/file:sudoers")
	state2, err := p.GetDriftState(context.Background(), eid2)
	require.NoError(t, err)
	require.NotNil(t, state2)
	assert.Equal(t, configRev, state2.ConfigRevision)
}

// TestDNAHandler_FullSyncGRPC_DriftDiff_NonFatalOnWriteFailure asserts that a
// drift-diff write failure on the full-sync path does not fail the steward's stream.
// The DNA snapshot is already committed at that point; failing the RPC would make the
// steward retry a sync that has, from the controller's side, already succeeded.
func TestDNAHandler_FullSyncGRPC_DriftDiff_NonFatalOnWriteFailure(t *testing.T) {
	ca := newTestCA(t)
	p := newTestEGProvider(t)
	require.NoError(t, p.Close()) // force every entity-graph write to fail

	egWriter, err := dnasync.New(p)
	require.NoError(t, err)

	const peerID = "steward-full-drift-nonfatal"
	svc := registeredService(t, peerID)
	chunks := driftDiffChunks(t, peerID, []*common.DriftDiffRecord{{
		FragmentID:     "service:crond",
		ConfigRevision: "v1",
		DetectedAt:     time.Now().UTC(),
		Fields:         []*common.DriftDiffField{{Attribute: "running", Desired: true, Actual: false}},
	}})

	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), svc).
		WithEntityGraph(egWriter, egtypes.DefaultTaxonomy())

	stream := newTestDNAStream(peerContextWithCA(t, ca, peerID), chunks...)
	require.NoError(t, h.HandleGRPC(stream),
		"a drift-graph write failure must not fail the DNA sync RPC")
	require.True(t, stream.resp.GetAccepted())

	// The primary payload still committed.
	info, ok := svc.GetStewardInfo(peerID)
	require.True(t, ok)
	require.NotNil(t, info.DNA, "the DNA snapshot must be persisted regardless of the drift write")
}

// TestDNAHandler_FullSyncGRPC_DriftDiff_HostileFragmentIDRejected asserts that a
// steward-supplied drift-diff fragment_id gets the same validation every other
// fragment_id on this handler gets. types.NewEID does not validate local_id, so an
// unchecked value would become a storage key and a log record verbatim.
//
// A valid record in the same batch must still be written: the bounds filter records,
// they do not black-hole the sync.
func TestDNAHandler_FullSyncGRPC_DriftDiff_HostileFragmentIDRejected(t *testing.T) {
	ca := newTestCA(t)
	p := newTestEGProvider(t)
	egWriter, err := dnasync.New(p)
	require.NoError(t, err)

	const peerID = "steward-hostile-fragid"
	oversized := strings.Repeat("A", maxFragmentIDLen+1)

	chunks := driftDiffChunks(t, peerID, []*common.DriftDiffRecord{
		{FragmentID: "service:evil\x00\x1b[2J", ConfigRevision: "v1",
			Fields: []*common.DriftDiffField{{Attribute: "a", Desired: "x", Actual: "y"}}},
		{FragmentID: "service:" + oversized, ConfigRevision: "v1",
			Fields: []*common.DriftDiffField{{Attribute: "a", Desired: "x", Actual: "y"}}},
		{FragmentID: "", ConfigRevision: "v1",
			Fields: []*common.DriftDiffField{{Attribute: "a", Desired: "x", Actual: "y"}}},
		{FragmentID: "service:legit", ConfigRevision: "v1",
			Fields: []*common.DriftDiffField{{Attribute: "enabled", Desired: true, Actual: false}}},
	})

	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), registeredService(t, peerID)).
		WithEntityGraph(egWriter, egtypes.DefaultTaxonomy())

	stream := newTestDNAStream(peerContextWithCA(t, ca, peerID), chunks...)
	require.NoError(t, h.HandleGRPC(stream))
	require.True(t, stream.resp.GetAccepted())

	// The legitimate record landed.
	good, err := p.GetDriftState(context.Background(),
		mustParseEGEID(t, "host:"+peerID+"/service:legit"))
	require.NoError(t, err)
	require.NotNil(t, good)

	// Exactly one drift record exists in the whole graph: the three unstorable
	// fragment IDs produced nothing at all.
	drifted, err := p.ListDrifted(context.Background(), interfaces.DriftFilter{})
	require.NoError(t, err)
	require.Len(t, drifted, 1,
		"only the storable fragment_id may produce a drift record")
	assert.Equal(t, "host:"+peerID+"/service:legit", drifted[0].EID.String())
}

// ─── acceptDriftDiffs: input bounds at the transport trust boundary ───────────

// encodeDriftRecords marshals records into the wire form DriftDiffBytes carries.
func encodeDriftRecords(t *testing.T, recs ...*common.DriftDiffRecord) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(recs))
	for _, r := range recs {
		b, err := json.Marshal(r)
		require.NoError(t, err)
		out = append(out, b)
	}
	return out
}

func driftRecord(id string, fields int) *common.DriftDiffRecord {
	rec := &common.DriftDiffRecord{FragmentID: id, ConfigRevision: "v1"}
	for i := 0; i < fields; i++ {
		rec.Fields = append(rec.Fields, &common.DriftDiffField{
			Attribute: fmt.Sprintf("attr%d", i), Desired: "a", Actual: "b",
		})
	}
	return rec
}

// TestAcceptDriftDiffs_BoundsRecordCount asserts the per-sync record cap holds. Each
// accepted record produces a permanent observation row plus a drift-projection upsert,
// so an uncapped batch is unbounded permanent growth in a tenant-shared store.
func TestAcceptDriftDiffs_BoundsRecordCount(t *testing.T) {
	recs := make([]*common.DriftDiffRecord, 0, maxDriftDiffRecords+50)
	for i := 0; i < maxDriftDiffRecords+50; i++ {
		recs = append(recs, driftRecord(fmt.Sprintf("service:s%d", i), 1))
	}

	kept, rejected := acceptDriftDiffs(encodeDriftRecords(t, recs...))
	assert.Len(t, kept, maxDriftDiffRecords)
	assert.Equal(t, 50, rejected, "every record beyond the cap must be counted, not silently dropped")
}

// TestAcceptDriftDiffs_BoundsRecordSize asserts an oversized record is rejected before
// it is decoded, which is what bounds both the decode cost and the persisted payload.
func TestAcceptDriftDiffs_BoundsRecordSize(t *testing.T) {
	huge := &common.DriftDiffRecord{
		FragmentID:     "service:huge",
		ConfigRevision: strings.Repeat("x", maxDriftDiffRecordBytes+1),
	}
	kept, rejected := acceptDriftDiffs(encodeDriftRecords(t,
		huge, driftRecord("service:small", 1)))

	require.Len(t, kept, 1)
	assert.Equal(t, "service:small", kept[0].FragmentID)
	assert.Equal(t, 1, rejected)
}

// TestAcceptDriftDiffs_BoundsFieldCount asserts the per-record field cap holds.
func TestAcceptDriftDiffs_BoundsFieldCount(t *testing.T) {
	kept, rejected := acceptDriftDiffs(encodeDriftRecords(t,
		driftRecord("service:wide", maxDriftDiffFields+1),
		driftRecord("service:narrow", 2)))

	require.Len(t, kept, 1)
	assert.Equal(t, "service:narrow", kept[0].FragmentID)
	assert.Equal(t, 1, rejected)
}

// TestAcceptDriftDiffs_RejectsUnstorableIdentifiers asserts fragment IDs and attribute
// names get the same storable-string rule (non-empty, bounded, valid UTF-8, no control
// characters) that validateFragmentID applies everywhere else on this handler. Both
// reach storage keys — the fragment_id as an EID local_id, the attribute as a payload
// map key.
func TestAcceptDriftDiffs_RejectsUnstorableIdentifiers(t *testing.T) {
	oversized := strings.Repeat("A", maxFragmentIDLen+1)

	cases := []struct {
		name string
		rec  *common.DriftDiffRecord
	}{
		{"empty fragment id", &common.DriftDiffRecord{FragmentID: ""}},
		{"control character in fragment id", &common.DriftDiffRecord{FragmentID: "service:a\nb"}},
		{"oversized fragment id", &common.DriftDiffRecord{FragmentID: oversized}},
		{"empty attribute", &common.DriftDiffRecord{
			FragmentID: "service:ok",
			Fields:     []*common.DriftDiffField{{Attribute: ""}},
		}},
		{"control character in attribute", &common.DriftDiffRecord{
			FragmentID: "service:ok",
			Fields:     []*common.DriftDiffField{{Attribute: "bad\x07name"}},
		}},
		{"oversized attribute", &common.DriftDiffRecord{
			FragmentID: "service:ok",
			Fields:     []*common.DriftDiffField{{Attribute: oversized}},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, rejected := acceptDriftDiffs(encodeDriftRecords(t, tc.rec))
			assert.Empty(t, kept)
			assert.Equal(t, 1, rejected)
		})
	}
}

// TestAcceptDriftDiffs_RejectsDuplicateFragmentIDs asserts a repeated fragment_id in
// one batch is rejected: it only rewrites the same projection row, so it is pure
// amplification of the write cost.
func TestAcceptDriftDiffs_RejectsDuplicateFragmentIDs(t *testing.T) {
	kept, rejected := acceptDriftDiffs(encodeDriftRecords(t,
		driftRecord("service:dup", 1),
		driftRecord("service:dup", 1),
		driftRecord("service:other", 1)))

	require.Len(t, kept, 2)
	assert.Equal(t, 1, rejected)
}

// TestAcceptDriftDiffs_SkipsMalformedAndCountsThem asserts malformed JSON is filtered
// rather than fatal, so one bad record cannot black-hole a steward's DNA reporting.
func TestAcceptDriftDiffs_SkipsMalformedAndCountsThem(t *testing.T) {
	raw := encodeDriftRecords(t, driftRecord("service:good", 1))
	raw = append([][]byte{[]byte("not json"), {}}, raw...)

	kept, rejected := acceptDriftDiffs(raw)
	require.Len(t, kept, 1)
	assert.Equal(t, "service:good", kept[0].FragmentID)
	assert.Equal(t, 2, rejected)
}

// TestAcceptDriftDiffs_EmptyInput asserts the no-drift case costs nothing.
func TestAcceptDriftDiffs_EmptyInput(t *testing.T) {
	kept, rejected := acceptDriftDiffs(nil)
	assert.Nil(t, kept)
	assert.Zero(t, rejected)
}

// mustParseEGEID parses an EID or fails the test.
func mustParseEGEID(t *testing.T, s string) egtypes.EID {
	t.Helper()
	eid, err := egtypes.ParseEID(s)
	require.NoError(t, err)
	return eid
}
