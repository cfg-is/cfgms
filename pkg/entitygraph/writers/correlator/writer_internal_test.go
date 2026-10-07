// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Internal tests for the correlator's fan-out bounds. These live in package
// correlator (rather than correlator_test) so the assertions can be expressed in
// terms of maxJoinGroupSize and maxObservationBatch instead of hardcoding the
// values the production code uses.
package correlator

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	sqliteprovider "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// --- helpers ---

func newInternalTestProvider(t *testing.T) *sqliteprovider.SQLiteEntityGraphProvider {
	t.Helper()
	p, err := sqliteprovider.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// addHost registers a host entity carrying mac as its only adapter.
func addHost(t *testing.T, p interfaces.EntityGraphProvider, subject, mac string) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, p.ReportObservations(context.Background(), interfaces.ObservationBatch{
		Source: "test",
		Observations: []types.Observation{{
			Source:     "test",
			ObservedAt: now,
			RecordedAt: now,
			Subject:    subject,
			Kind:       types.ObservationKindState,
			Confidence: types.ConfidenceHigh,
			Payload: map[string]interface{}{
				"entity_kind":   "host",
				"owning_tenant": "root",
				"primary_mac":   mac,
				"mac_addresses": mac,
			},
		}},
	}))
}

func sameAsEdgeCount(t *testing.T, p interfaces.EntityGraphProvider) int {
	t.Helper()
	edges, err := p.GetEdges(context.Background(), interfaces.EdgeFilter{Types: []string{"same-as"}})
	require.NoError(t, err)
	return len(edges)
}

// --- normalizeMAC join-key hygiene ---

// TestNormalizeMACRejectsNonIdentifyingAddresses verifies that syntactically
// valid but non-identifying MAC addresses never become join keys. Each of these
// is emitted by real collectors — the steward DNA network collector reports
// iface.HardwareAddr for every non-loopback adapter, and Windows pseudo-adapters
// report all-zero or fleet-wide-fixed addresses. Accepting them would collapse
// every host that has such an adapter into one identity.
func TestNormalizeMACRejectsNonIdentifyingAddresses(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"all zero colon", "00:00:00:00:00:00"},
		{"all zero bare", "000000000000"},
		{"all zero hyphen", "00-00-00-00-00-00"},
		{"broadcast", "ff:ff:ff:ff:ff:ff"},
		{"broadcast bare", "FFFFFFFFFFFF"},
		{"ipv4 multicast", "01:00:5E:00:00:01"},
		{"ipv6 multicast", "33:33:00:00:00:01"},
		{"stp multicast", "01:80:C2:00:00:00"},
		{"microsoft loopback adapter", "02:00:4C:4F:4F:50"},
		{"microsoft loopback adapter lowercase", "02:00:4c:4f:4f:50"},
		{"microsoft loopback adapter bare", "02004C4F4F50"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, "", normalizeMAC(tc.in),
				"non-identifying MAC must not produce a join key")
		})
	}
}

// TestNormalizeMACAcceptsStationAddresses verifies the hygiene filter does not
// reject real adapter addresses, including locally-administered ones — those are
// what hypervisors assign to VM adapters and are exactly what the correlator
// exists to join on.
func TestNormalizeMACAcceptsStationAddresses(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"00:15:5d:ea:a3:35", "00:15:5D:EA:A3:35"}, // Hyper-V universally administered
		{"00-15-5D-EA-A3-35", "00:15:5D:EA:A3:35"},
		{"00155DEAA335", "00:15:5D:EA:A3:35"},
		{"02:00:4c:4f:4f:51", "02:00:4C:4F:4F:51"}, // locally administered, not the loopback MAC
		{"0a:00:27:00:00:0f", "0A:00:27:00:00:0F"}, // locally administered
		{"00:00:00:00:00:01", "00:00:00:00:00:01"}, // near-zero but not all-zero
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.want, normalizeMAC(tc.in))
		})
	}
}

// --- group-size cap ---

// TestCorrelateSkipsOversizedMACGroup verifies that a MAC shared by more than
// maxJoinGroupSize entities asserts no same-as edges at all.
//
// Without the cap this is the amplification primitive: the pairwise loop emits
// one ConfidenceHigh edge per cross-authority pair, so k hosts sharing one
// duplicated MAC produce k(k-1)/2 edges — at fleet scale, tens of millions of
// observations and a fleet-wide false identity collapse spanning tenants. A
// compromised steward reaches the same state by minting synthetic entities that
// all carry one MAC.
func TestCorrelateSkipsOversizedMACGroup(t *testing.T) {
	p := newInternalTestProvider(t)
	w, err := New(p)
	require.NoError(t, err)

	const dupMAC = "00:15:5D:AA:BB:CC"
	for i := 0; i <= maxJoinGroupSize; i++ { // maxJoinGroupSize+1 members
		addHost(t, p, fmt.Sprintf("host:dup-%03d", i), dupMAC)
	}

	require.NoError(t, w.Correlate(context.Background()))
	require.Equal(t, 0, sameAsEdgeCount(t, p),
		"a MAC shared by more than maxJoinGroupSize entities must assert no edges")
}

// TestCorrelateCorrelatesGroupAtCap verifies the cap is an upper bound and not
// an off-by-one that suppresses legitimate correlation: a group of exactly
// maxJoinGroupSize distinct authorities still produces the full pairwise edge set.
func TestCorrelateCorrelatesGroupAtCap(t *testing.T) {
	p := newInternalTestProvider(t)
	w, err := New(p)
	require.NoError(t, err)

	const sharedMAC = "00:15:5D:AA:BB:CD"
	for i := 0; i < maxJoinGroupSize; i++ {
		addHost(t, p, fmt.Sprintf("host:cap-%03d", i), sharedMAC)
	}

	require.NoError(t, w.Correlate(context.Background()))

	want := maxJoinGroupSize * (maxJoinGroupSize - 1) / 2
	require.Equal(t, want, sameAsEdgeCount(t, p),
		"a group at exactly the cap must still correlate fully")
}

// --- bounded observation batches ---

// batchRecorder is a pass-through instrumentation wrapper: every call, including
// ReportObservations, is executed by the embedded real provider. It records the
// size of each correlator batch so the test can assert the write path is
// chunked. It fakes no behavior and is not a mock.
type batchRecorder struct {
	interfaces.EntityGraphProvider
	sizes []int
}

func (r *batchRecorder) ReportObservations(ctx context.Context, batch interfaces.ObservationBatch) error {
	if batch.Source == observationSource {
		r.sizes = append(r.sizes, len(batch.Observations))
	}
	return r.EntityGraphProvider.ReportObservations(ctx, batch)
}

// TestCorrelateFlushesBoundedBatches verifies that a sweep producing more than
// maxObservationBatch observations is written as several bounded batches rather
// than one unbounded slice in a single provider transaction, and that no edge is
// lost across a chunk boundary.
func TestCorrelateFlushesBoundedBatches(t *testing.T) {
	real := newInternalTestProvider(t)
	rec := &batchRecorder{EntityGraphProvider: real}
	w, err := New(rec)
	require.NoError(t, err)

	// Each group of maxJoinGroupSize members yields C(n,2) edges. Use enough
	// groups to exceed maxObservationBatch.
	perGroup := maxJoinGroupSize * (maxJoinGroupSize - 1) / 2
	groups := maxObservationBatch/perGroup + 1
	for g := 0; g < groups; g++ {
		mac := fmt.Sprintf("00:15:5D:00:%02X:01", g)
		for i := 0; i < maxJoinGroupSize; i++ {
			addHost(t, rec, fmt.Sprintf("host:batch-%03d-%03d", g, i), mac)
		}
	}
	wantEdges := groups * perGroup
	require.Greater(t, wantEdges, maxObservationBatch, "test must exceed one batch")

	require.NoError(t, w.Correlate(context.Background()))

	require.Greater(t, len(rec.sizes), 1, "observations must be flushed in multiple batches")
	for i, size := range rec.sizes {
		require.LessOrEqual(t, size, maxObservationBatch, "batch %d exceeds the cap", i)
	}

	total := 0
	for _, size := range rec.sizes {
		total += size
	}
	require.Equal(t, wantEdges, total, "every pair must be reported exactly once")
	require.Equal(t, wantEdges, sameAsEdgeCount(t, real),
		"every edge must be persisted across chunk boundaries")
}
