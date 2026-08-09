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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	common "github.com/cfgis/cfgms/api/proto/common"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
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
