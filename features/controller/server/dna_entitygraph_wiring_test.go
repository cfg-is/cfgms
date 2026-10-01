// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for the server.go DNA-sync -> entity-graph wiring (Issue #4444).
//
// features/controller/server/server.go previously constructed the DNA handler
// (controllerTransport.NewDNAHandler) without ever chaining .WithEntityGraph onto
// it, so egWriter and egTaxonomy stayed nil on every controller: a steward's
// committed DNA delta reached ApplyDelta but never the entity graph, silently,
// exactly as WithEntityGraph's own doc comment predicts for an unwired handler.
// pkg/entitygraph/writers/dnasync's own logic was already correct and already
// covered by features/controller/transport/dna_handler_entitygraph_test.go — the
// defect was purely in this package's wiring, which is what these tests exercise:
// buildDNAEntityGraphWriter and wireDNAEntityGraph, the two pieces server.go's
// New()/Start() call, built the same way New() builds them.
//
// The fake mTLS peer context, gRPC stream and FragmentDeltaStore below are
// necessarily reimplemented here rather than imported from the transport
// package's own test helpers: Go test files are not importable across packages,
// and this package cannot import transport's _test.go files. Each is a direct,
// small implementation of a real interface (cfgcert for the CA, the real
// FragmentDeltaStore contract) — not a mock of a CFGMS component.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	stewarddna "github.com/cfgis/cfgms/features/steward/dna"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dptypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ─── test doubles: mTLS peer context ───────────────────────────────────────

// newWiringTestCA creates a fresh CA backed by in-memory key material, using the
// real pkg/cert provider (no mocking of certificate logic).
func newWiringTestCA(t *testing.T) *cfgcert.CA {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS DNA Wiring Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	return ca
}

// wiringPeerContext generates a real client certificate from ca with cn as its
// Common Name and returns a context carrying it as the gRPC mTLS peer, exactly
// as quictransport.PeerStewardID expects to read it.
func wiringPeerContext(t *testing.T, ca *cfgcert.CA, cn string) context.Context {
	t.Helper()
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   cn,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	block, _ := pem.Decode(cert.CertificatePEM)
	require.NotNil(t, block, "PEM decode of client cert must succeed")
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates:  []*x509.Certificate{x509Cert},
				VerifiedChains:    [][]*x509.Certificate{{x509Cert}},
				HandshakeComplete: true,
			},
		},
	}
	return peer.NewContext(context.Background(), p)
}

// ─── test doubles: gRPC client-streaming server ────────────────────────────

// wiringDNAStream is a minimal test double for
// grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse].
type wiringDNAStream struct {
	chunks []*transportpb.DNAChunk
	pos    int
	resp   *transportpb.DNASyncResponse
	ctx    context.Context
}

func newWiringDNAStream(ctx context.Context, chunks ...*transportpb.DNAChunk) *wiringDNAStream {
	return &wiringDNAStream{chunks: chunks, ctx: ctx}
}

func (s *wiringDNAStream) Recv() (*transportpb.DNAChunk, error) {
	if s.pos >= len(s.chunks) {
		return nil, io.EOF
	}
	c := s.chunks[s.pos]
	s.pos++
	return c, nil
}

func (s *wiringDNAStream) SendAndClose(resp *transportpb.DNASyncResponse) error {
	s.resp = resp
	return nil
}

func (s *wiringDNAStream) SetHeader(metadata.MD) error  { return nil }
func (s *wiringDNAStream) SendHeader(metadata.MD) error { return nil }
func (s *wiringDNAStream) SetTrailer(metadata.MD)       {}
func (s *wiringDNAStream) Context() context.Context     { return s.ctx }
func (s *wiringDNAStream) SendMsg(interface{}) error    { return nil }
func (s *wiringDNAStream) RecvMsg(interface{}) error    { return nil }

var _ grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse] = (*wiringDNAStream)(nil)

// ─── test doubles: FragmentDeltaStore and CommandPublisher ─────────────────

// wiringFragmentStore is a minimal, thread-safe FragmentDeltaStore implementation.
// It is not a mock: CurrentManifest and ApplyDelta are the real per-steward
// manifest state the interface contract describes, just held in memory.
type wiringFragmentStore struct {
	mu        sync.Mutex
	manifests map[string][]*commonpb.ManifestEntry
}

func newWiringFragmentStore() *wiringFragmentStore {
	return &wiringFragmentStore{manifests: make(map[string][]*commonpb.ManifestEntry)}
}

func (s *wiringFragmentStore) SetManifest(stewardID string, manifest []*commonpb.ManifestEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manifests[stewardID] = manifest
}

func (s *wiringFragmentStore) CurrentManifest(stewardID string) ([]*commonpb.ManifestEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.manifests[stewardID], nil
}

func (s *wiringFragmentStore) ApplyDelta(stewardID string, fragments []*commonpb.Fragment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manifests[stewardID] = mergeManifestEntriesForTest(s.manifests[stewardID], fragments)
	return nil
}

var _ controllerTransport.FragmentDeltaStore = (*wiringFragmentStore)(nil)

// mergeManifestEntriesForTest replaces or adds one manifest entry per fragment,
// deriving fragment_hash from canonical bytes (never copying the steward-asserted
// hash) exactly as the production FragmentDeltaStore contract requires. It is
// used both by wiringFragmentStore.ApplyDelta and, before that, by the test itself
// to precompute the aggregate root the steward would legitimately claim.
func mergeManifestEntriesForTest(stored []*commonpb.ManifestEntry, fragments []*commonpb.Fragment) []*commonpb.ManifestEntry {
	existing := make(map[string]*commonpb.ManifestEntry, len(stored))
	for _, e := range stored {
		existing[e.GetFragmentId()] = e
	}
	for _, f := range fragments {
		existing[f.GetFragmentId()] = &commonpb.ManifestEntry{
			FragmentId:   f.GetFragmentId(),
			FragmentHash: stewarddna.FragmentHash(f.GetCanonicalBytes()),
		}
	}
	merged := make([]*commonpb.ManifestEntry, 0, len(existing))
	for _, e := range existing {
		merged = append(merged, e)
	}
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].GetFragmentId() < merged[j].GetFragmentId()
	})
	return merged
}

// wiringNoopPublisher is a minimal CommandPublisher: HandleHeartbeatRoot requires
// one to be wired before it will dispatch SYNC_DNA, but these tests drive the
// delta directly and don't need to observe the dispatched command.
type wiringNoopPublisher struct{}

func (wiringNoopPublisher) PublishCommand(_ context.Context, _ string, _ controlplaneTypes.CommandType, _ map[string]interface{}) (string, error) {
	return "cmd-wiring-test", nil
}

var _ controllerTransport.CommandPublisher = wiringNoopPublisher{}

// ─── shared fixtures ────────────────────────────────────────────────────────

// wiringEGProvider opens a fresh SQLite entity-graph provider backed by a temp file.
func wiringEGProvider(t *testing.T) *egsqlite.SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := egsqlite.NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// plainFragmentForTest builds a simple host-scoped fragment via the real
// steward-side canonicalization path (features/steward/dna.NewFragment).
func plainFragmentForTest(t *testing.T, fragmentID string, content map[string]interface{}) *commonpb.Fragment {
	t.Helper()
	frag, err := stewarddna.NewFragment(fragmentID, "test-authority", stewarddna.MapState(content))
	require.NoError(t, err)
	return frag
}

// deltaChunksForTest wraps fragments into a single is_delta=true DNAChunk, mirroring
// the wire encoding a real steward produces for a partial-sync delta.
func deltaChunksForTest(t *testing.T, peerID string, fragments []*commonpb.Fragment) []*transportpb.DNAChunk {
	t.Helper()
	transfer := &dptypes.DNATransfer{
		StewardID: peerID,
		TenantID:  "t1",
		Delta:     true,
		Fragments: fragments,
	}
	payload, err := json.Marshal(transfer)
	require.NoError(t, err)
	return []*transportpb.DNAChunk{{
		StewardId:   peerID,
		TenantId:    "t1",
		Data:        payload,
		ChunkIndex:  0,
		TotalChunks: 1,
		IsDelta:     true,
	}}
}

// wideTimeRange spans well before and after "now" so a GetHistory call in these
// tests cannot miss a record on a timestamp technicality.
func wideTimeRange() eginterfaces.TimeRange {
	return eginterfaces.TimeRange{
		From: time.Now().Add(-time.Hour),
		To:   time.Now().Add(time.Hour),
	}
}

// ─── TestWireDNAEntityGraph_DeltaCommitReachesEntityGraph (REQUIRED TEST) ──
//
// A steward delta that commits through ApplyDelta must produce the corresponding
// entity-graph state. Confirmed to fail against the pre-fix code (server.go never
// called WithEntityGraph, so DNAHandler.egWriter stayed nil and the write was
// skipped silently) and to pass once buildDNAEntityGraphWriter/wireDNAEntityGraph
// are wired into New()/Start().
func TestWireDNAEntityGraph_DeltaCommitReachesEntityGraph(t *testing.T) {
	ca := newWiringTestCA(t)
	p := wiringEGProvider(t)
	const peerID = "steward-wiring-delta"

	svc := &Server{egProvider: p, logger: logging.NewNoopLogger()}
	writer, err := svc.buildDNAEntityGraphWriter()
	require.NoError(t, err)
	svc.egDNAWriter = writer

	// The steward previously reported this fragment with different content; the
	// delta now reports an update to the SAME fragment_id.
	oldFrag := plainFragmentForTest(t, "file:/etc/hosts", map[string]interface{}{"content": "old"})
	storedManifest := []*commonpb.ManifestEntry{{
		FragmentId:   oldFrag.GetFragmentId(),
		FragmentHash: stewarddna.FragmentHash(oldFrag.GetCanonicalBytes()),
	}}
	store := newWiringFragmentStore()
	store.SetManifest(peerID, storedManifest)

	newFrag := plainFragmentForTest(t, "file:/etc/hosts", map[string]interface{}{"content": "new"})
	prospective := mergeManifestEntriesForTest(storedManifest, []*commonpb.Fragment{newFrag})
	claimedRoot, err := stewarddna.AggregateRoot(prospective)
	require.NoError(t, err)

	dnaHandler := controllerTransport.NewDNAHandler(logging.NewNoopLogger(), controllerTransport.NewTenantQueue(), nil).
		WithPartialSync(store, wiringNoopPublisher{})
	svc.wireDNAEntityGraph(dnaHandler)

	// Simulate the ADR-017 §7 step 2 heartbeat-root mismatch that records the
	// outstanding delta request — the same real entry point server.go wires via
	// heartbeatService.SetOnFragmentRoot(dnaHandler.HandleHeartbeatRoot).
	dnaHandler.HandleHeartbeatRoot(context.Background(), peerID, claimedRoot)

	stream := newWiringDNAStream(wiringPeerContext(t, ca, peerID), deltaChunksForTest(t, peerID, []*commonpb.Fragment{newFrag})...)
	require.NoError(t, dnaHandler.HandleGRPC(stream))
	require.NotNil(t, stream.resp)
	require.True(t, stream.resp.GetAccepted(), "a valid delta must be accepted")

	eid, err := egtypes.ParseEID("host:" + peerID + "/file:/etc/hosts")
	require.NoError(t, err)
	records, err := p.GetHistory(context.Background(), eid, wideTimeRange())
	require.NoError(t, err)
	require.NotEmpty(t, records,
		"the committed delta must produce entity-graph state once server.go wires WithEntityGraph")
}

// ─── TestWireDNAEntityGraph_ClusteredVMRecordedUnderClusterAuthority (REQUIRED TEST) ──
//
// A clustered entity reported by a steward must be recorded under its cluster
// authority (cluster:<name>/vm:<vmName>), not under host:<peerID> — the failure
// mode an unset ClusterMembership verifier causes per WithEntityGraph's doc
// comment. This pins that the verifier is not just passed, but actually consulted
// and actually changes where the observation lands.
func TestWireDNAEntityGraph_ClusteredVMRecordedUnderClusterAuthority(t *testing.T) {
	ca := newWiringTestCA(t)
	p := wiringEGProvider(t)
	const peerID = "steward-wiring-cluster"
	const clusterName = "prod-cluster"

	membership := dnasync.NewStaticClusterMembership(map[string][]string{
		clusterName: {peerID},
	})
	svc := newClusterTestServer(t, p, nil, membership)
	writer, err := svc.buildDNAEntityGraphWriter()
	require.NoError(t, err)
	svc.egDNAWriter = writer

	// The VM was previously reported standalone (no ha_role); the delta now
	// reports it as a member of clusterName.
	oldVMFrag := standaloneVMFragment(t, "web1")
	storedManifest := []*commonpb.ManifestEntry{{
		FragmentId:   oldVMFrag.GetFragmentId(),
		FragmentHash: stewarddna.FragmentHash(oldVMFrag.GetCanonicalBytes()),
	}}
	store := newWiringFragmentStore()
	store.SetManifest(peerID, storedManifest)

	newVMFrag := clusteredVMFragment(t, "web1", clusterName)
	prospective := mergeManifestEntriesForTest(storedManifest, []*commonpb.Fragment{newVMFrag})
	claimedRoot, err := stewarddna.AggregateRoot(prospective)
	require.NoError(t, err)

	dnaHandler := controllerTransport.NewDNAHandler(logging.NewNoopLogger(), controllerTransport.NewTenantQueue(), nil).
		WithPartialSync(store, wiringNoopPublisher{})
	svc.wireDNAEntityGraph(dnaHandler)

	dnaHandler.HandleHeartbeatRoot(context.Background(), peerID, claimedRoot)

	stream := newWiringDNAStream(wiringPeerContext(t, ca, peerID), deltaChunksForTest(t, peerID, []*commonpb.Fragment{newVMFrag})...)
	require.NoError(t, dnaHandler.HandleGRPC(stream))
	require.True(t, stream.resp.GetAccepted(), "a valid clustered-VM delta must be accepted")

	clusterEID, err := egtypes.ParseEID("cluster:" + clusterName + "/vm:web1")
	require.NoError(t, err)
	clusterRecords, err := p.GetHistory(context.Background(), clusterEID, wideTimeRange())
	require.NoError(t, err)
	require.NotEmpty(t, clusterRecords,
		"a clustered VM reported by a steward whose membership is verified must land under cluster authority")

	hostEID, err := egtypes.ParseEID("host:" + peerID + "/vm:web1")
	require.NoError(t, err)
	hostRecords, err := p.GetHistory(context.Background(), hostEID, wideTimeRange())
	require.NoError(t, err)
	assert.Empty(t, hostRecords,
		"a verified clustered VM must NOT also land under host:<peerID> — that is the unset-verifier failure mode")
}

// TestWireDNAEntityGraph_NilWriter_LogsWarningAndSkipsSilently pins the additive,
// fail-safe contract: a Server whose egDNAWriter is nil (the pre-fix state, or any
// future regression that reintroduces it) must not panic, must still accept DNA
// syncs normally, and must log a single warning identifying the misconfiguration —
// the visibility this story's AC requires, since the original defect produced no
// signal at all.
func TestWireDNAEntityGraph_NilWriter_LogsWarningAndSkipsSilently(t *testing.T) {
	logger := logging.NewCapturingLogger()
	svc := &Server{logger: logger}

	dnaHandler := controllerTransport.NewDNAHandler(logger, controllerTransport.NewTenantQueue(), nil)
	svc.wireDNAEntityGraph(dnaHandler)

	assert.Equal(t, 1, logger.WarnCount(),
		"wireDNAEntityGraph must log exactly one warning when the entity-graph write path is not wired")
	_, found := logger.FindWarn("dna-sync: entity-graph write path not wired; steward DNA will not reach the entity graph")
	assert.True(t, found, "the warning must identify the DNA-sync entity-graph write path by name")

	// A full sync must still be accepted without a nil-writer panic.
	frag := plainFragmentForTest(t, "file:/etc/hosts", map[string]interface{}{"content": "x"})
	transfer := &dptypes.DNATransfer{StewardID: "steward-nil-writer", TenantID: "t1", Fragments: []*commonpb.Fragment{frag}}
	payload, err := json.Marshal(transfer)
	require.NoError(t, err)
	chunks := []*transportpb.DNAChunk{{
		StewardId:   "steward-nil-writer",
		TenantId:    "t1",
		Data:        payload,
		ChunkIndex:  0,
		TotalChunks: 1,
	}}
	ca := newWiringTestCA(t)
	stream := newWiringDNAStream(wiringPeerContext(t, ca, "steward-nil-writer"), chunks...)
	require.NoError(t, dnaHandler.HandleGRPC(stream))
	require.True(t, stream.resp.GetAccepted())
}

// TestWireDNAEntityGraph_WiredPath_NoWarning is the complement of
// TestWireDNAEntityGraph_NilWriter_LogsWarningAndSkipsSilently: a Server whose
// egDNAWriter is actually wired (the normal, non-defect state) must NOT log the
// "not wired" warning. Without this, the warning added for visibility into the
// unwired case could regress into firing unconditionally and the nil-writer test
// alone would not catch it.
func TestWireDNAEntityGraph_WiredPath_NoWarning(t *testing.T) {
	logger := logging.NewCapturingLogger()
	p := wiringEGProvider(t)
	svc := &Server{egProvider: p, logger: logger}
	writer, err := svc.buildDNAEntityGraphWriter()
	require.NoError(t, err)
	svc.egDNAWriter = writer

	dnaHandler := controllerTransport.NewDNAHandler(logger, controllerTransport.NewTenantQueue(), nil)
	svc.wireDNAEntityGraph(dnaHandler)

	assert.Equal(t, 0, logger.WarnCount(),
		"wireDNAEntityGraph must not warn when the entity-graph write path is wired")
}
