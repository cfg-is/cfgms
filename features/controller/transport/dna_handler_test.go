// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	common "github.com/cfgis/cfgms/api/proto/common"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/service"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	dptypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// registeredService returns a real *service.ControllerService with stewardID
// registered, so its SyncDNA takes the genuine happy path. Used as the
// DNAPersister in the #2616 black-hole tests: the assertion that the reassembled
// DNA survived is read back out of the real service, never out of a test double.
func registeredService(t *testing.T, stewardID string) *service.ControllerService {
	t.Helper()
	svc := service.NewControllerService(logging.NewNoopLogger())
	require.NoError(t, svc.RegisterStewardWithAttributes(
		stewardID, "t1", "", "active",
		map[string]string{"hostname": "seed", "os": "linux"},
	))
	return svc
}

// syncedDNA reads the DNA the real ControllerService holds for stewardID.
func syncedDNA(t *testing.T, svc *service.ControllerService, stewardID string) *common.DNA {
	t.Helper()
	info, ok := svc.GetStewardInfo(stewardID)
	require.True(t, ok, "steward must be registered on the real controller service")
	return info.DNA
}

// identityFragmentBytes returns the proto-marshalled ADR-017 fragments that carry
// the core-identity fields the controller's required-field contract checks
// (features/controller/service/dna_integrity.go — the presence check reads
// DNA.Fragments, not the flat attribute map, since Issue #3319). A snapshot that
// carries hostname/os only as Attributes is a degenerate snapshot by that
// contract and is refused before persistence, so a fixture that wants to reach
// the persister must carry them as fragments — exactly as the steward send
// path does (features/steward/client/client_transport.go populates
// DNATransfer.FragmentBytes; Attributes is no longer populated, Issue #3322).
//
// Fragment kind per field, confirmed against the producers rather than assumed
// from the field name:
//   - os → "host:os", the gatherer-sourced fragment that lists "os" in its key
//     allowlist (features/steward/dna/fragments.go hostFactFragmentSpecs).
//   - hostname → "hostname", the stdlib hostname module's own kind. It is absent
//     from every host:* spec because PartitionHostFacts skips module-owned kinds,
//     and the module's state map keys the value as "hostname"
//     (features/modules/stdlib/hostname/module.go HostnameConfig.AsMap).
//
// Fields absent from attrs produce no fragment, so a caller can still build a
// snapshot that is deliberately missing a required field.
func identityFragmentBytes(t *testing.T, attrs map[string]string) [][]byte {
	t.Helper()
	specs := []struct {
		kind      string
		authority string
		field     string
	}{
		{kind: "hostname", authority: "hostname", field: "hostname"},
		{kind: "host:os", authority: "gatherer", field: "os"},
	}
	var out [][]byte
	for _, spec := range specs {
		v, ok := attrs[spec.field]
		if !ok {
			continue
		}
		frag, err := sdna.NewFragment(spec.kind, spec.authority,
			sdna.MapState(map[string]interface{}{spec.field: v}))
		require.NoError(t, err)
		b, err := proto.Marshal(frag)
		require.NoError(t, err)
		out = append(out, b)
	}
	return out
}

// dnaChunksFor marshals attrs as a full-snapshot DNATransfer — identity fragments
// only (Attributes is no longer populated, Issue #3322) — and splits the JSON
// into `parts` contiguous DNAChunks, mirroring the steward send path.
func dnaChunksFor(t *testing.T, stewardID string, attrs map[string]string, parts int) []*transportpb.DNAChunk {
	t.Helper()
	payload, err := json.Marshal(&dptypes.DNATransfer{
		StewardID:     stewardID,
		TenantID:      "t1",
		FragmentBytes: identityFragmentBytes(t, attrs),
	})
	require.NoError(t, err)
	if parts < 1 {
		parts = 1
	}
	size := (len(payload) + parts - 1) / parts
	chunks := make([]*transportpb.DNAChunk, 0, parts)
	for i := 0; i < parts; i++ {
		start := i * size
		end := start + size
		if end > len(payload) {
			end = len(payload)
		}
		if start > len(payload) {
			start = len(payload)
		}
		chunks = append(chunks, &transportpb.DNAChunk{
			StewardId: stewardID, TenantId: "t1",
			Data: payload[start:end], ChunkIndex: int32(i), TotalChunks: int32(parts),
		})
	}
	return chunks
}

// TestDNAHandler_PersistsReassembledDNA (REQUIRED, #2616): a full DNA snapshot
// streamed as chunks is reassembled and persisted with its attributes intact —
// proving the receiver no longer discards the DNA. The persister is a real
// *service.ControllerService and the result is read back from it.
func TestDNAHandler_PersistsReassembledDNA(t *testing.T) {
	ca := newTestCA(t)
	svc := registeredService(t, "steward-persist")
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), svc)

	attrs := map[string]string{"hostname": "cfg-70-02", "os": "windows", "cpu_count": "8"}
	ctx := peerContextWithCA(t, ca, "steward-persist")
	stream := newTestDNAStream(ctx, dnaChunksFor(t, "steward-persist", attrs, 1)...)

	require.NoError(t, h.HandleGRPC(stream))
	require.NotNil(t, stream.resp)
	assert.True(t, stream.resp.GetAccepted())

	stored := syncedDNA(t, svc, "steward-persist")
	require.NotNil(t, stored, "the reassembled DNA must reach the controller service, not be discarded")
	assert.Equal(t, "steward-persist", stored.GetId())
	// Fragments are the authoritative DNA representation (Issue #3322).
	assert.NotEmpty(t, stored.GetFragments(), "identity fragments from dnaChunksFor must survive reassembly")
	// The flat projection consumers read (role-policy selectors, fleet inventory,
	// attribute index) is derived from those fragments on demand. cpu_count is
	// absent because identityFragmentBytes emits no fragment for it — the
	// projection reflects the fragments, not the caller's attrs map.
	assert.Equal(t, map[string]string{"hostname": "cfg-70-02", "os": "windows"},
		sdna.FlattenFragments(stored.GetFragments()),
		"the flat projection must be exactly the received fragments' state")
	assert.Equal(t, int32(2), stored.GetAttributeCount())
}

// dnaChunksForTransfer marshals an arbitrary DNATransfer and splits the JSON into
// `parts` contiguous DNAChunks — the same send-side shape as dnaChunksFor, but
// letting a test set specific fields (e.g. Fragments, FragmentBytes).
func dnaChunksForTransfer(t *testing.T, transfer *dptypes.DNATransfer, parts int) []*transportpb.DNAChunk {
	t.Helper()
	payload, err := json.Marshal(transfer)
	require.NoError(t, err)
	if parts < 1 {
		parts = 1
	}
	size := (len(payload) + parts - 1) / parts
	chunks := make([]*transportpb.DNAChunk, 0, parts)
	for i := 0; i < parts; i++ {
		start := i * size
		end := start + size
		if end > len(payload) {
			end = len(payload)
		}
		if start > len(payload) {
			start = len(payload)
		}
		chunks = append(chunks, &transportpb.DNAChunk{
			StewardId: transfer.StewardID, TenantId: transfer.TenantID,
			Data: payload[start:end], ChunkIndex: int32(i), TotalChunks: int32(parts),
		})
	}
	return chunks
}

// TestDNAHandler_PersistsFragmentsFromTransfer (#2908): ADR-017 fragments carried
// on the sync_dna DNATransfer are deserialized into common.DNA.Fragments. Without
// this the controller-side cluster registry (clusterregistry.BuildRegistry) is
// always empty because DNA.Fragments never leaves the receiver populated.
func TestDNAHandler_PersistsFragmentsFromTransfer(t *testing.T) {
	frag := &common.Fragment{
		FragmentId:     "cluster:cfg-lab",
		Authority:      "hyperv",
		CanonicalBytes: []byte(`{"cno_owner_node":"CFG-70-02","member_nodes":"CFG-70-02,CFG-AB-02"}`),
		FragmentHash:   "sha256:deadbeef",
	}
	fragBytes, err := proto.Marshal(frag)
	require.NoError(t, err)

	// Wire protocol is Fragments-only: no Attributes field (Issue #3322).
	transfer := &dptypes.DNATransfer{
		StewardID:     "steward-frag",
		TenantID:      "t1",
		FragmentBytes: [][]byte{fragBytes},
	}

	dna, _, err := reassembleDNA(dnaChunksForTransfer(t, transfer, 2), "steward-frag")
	require.NoError(t, err)

	require.Len(t, dna.GetFragments(), 1, "the transfer's fragment must survive reassembly")
	got := dna.GetFragments()[0]
	assert.Equal(t, "cluster:cfg-lab", got.GetFragmentId())
	assert.Equal(t, "hyperv", got.GetAuthority())
	assert.Equal(t, frag.GetCanonicalBytes(), got.GetCanonicalBytes())
	assert.Equal(t, "sha256:deadbeef", got.GetFragmentHash())
}

// TestDNAHandler_MalformedFragmentSkipped (#2908): an undecodable fragment is
// dropped rather than failing the whole snapshot — the well-formed fragments
// must still reach the persister.
func TestDNAHandler_MalformedFragmentSkipped(t *testing.T) {
	good := &common.Fragment{FragmentId: "cluster:ok", CanonicalBytes: []byte(`{"a":"b"}`)}
	goodBytes, err := proto.Marshal(good)
	require.NoError(t, err)

	// Wire protocol is Fragments-only: no Attributes field (Issue #3322).
	transfer := &dptypes.DNATransfer{
		StewardID: "steward-badfrag",
		TenantID:  "t1",
		// 0x08 starts field 1 as a varint but the value bytes are truncated.
		FragmentBytes: [][]byte{{0x08}, goodBytes},
	}

	dna, _, err := reassembleDNA(dnaChunksForTransfer(t, transfer, 1), "steward-badfrag")
	require.NoError(t, err, "a malformed fragment must not fail the snapshot")
	require.Len(t, dna.GetFragments(), 1, "only the well-formed fragment is kept")
	assert.Equal(t, "cluster:ok", dna.GetFragments()[0].GetFragmentId())
}

// ─── Ingest-side DoS bounds on the sync_dna snapshot ─────────────────────────
//
// A steward runs on a host that may be compromised, so it can stream any chunk
// count, any total payload size, and any fragment count/size it likes. The gRPC
// maxRecvMsgSize bounds a single DNAChunk message, never the reassembled snapshot,
// so these bounds are the only thing between a hostile steward and unbounded
// controller heap use — and, because BuildRegistry re-decodes every persisted
// fragment on each cluster API read, unbounded *persisted* fragments are a
// repeatable amplifier rather than a one-shot cost.

// TestReassembleDNA_RejectsExcessiveFragmentCount: a snapshot declaring more than
// maxDNATransferFragments fragments is rejected outright rather than decoded and
// persisted.
func TestReassembleDNA_RejectsExcessiveFragmentCount(t *testing.T) {
	fragBytes, err := proto.Marshal(&common.Fragment{FragmentId: "cluster:x", CanonicalBytes: []byte{0, 0, 0, 0}})
	require.NoError(t, err)

	frags := make([][]byte, maxDNATransferFragments+1)
	for i := range frags {
		frags[i] = fragBytes
	}

	// Wire protocol is Fragments-only: no Attributes field (Issue #3322).
	_, _, err = reassembleDNA(dnaChunksForTransfer(t, &dptypes.DNATransfer{
		StewardID: "steward-fragflood", TenantID: "t1", FragmentBytes: frags,
	}, 1), "steward-fragflood")
	require.Error(t, err, "an unbounded fragment count must be rejected, not persisted")
	assert.Contains(t, err.Error(), "exceeds maximum")

	// The boundary itself is still accepted — the cap must not reject legitimate load.
	dna, _, err := reassembleDNA(dnaChunksForTransfer(t, &dptypes.DNATransfer{
		StewardID: "steward-fragmax", TenantID: "t1",
		FragmentBytes: frags[:maxDNATransferFragments],
	}, 1), "steward-fragmax")
	require.NoError(t, err)
	assert.Len(t, dna.GetFragments(), maxDNATransferFragments)
}

// TestReassembleDNA_RejectsOversizedFragment: a fragment larger than
// maxDNAFragmentBytes is rejected before proto.Unmarshal, so the ~19x decoder
// amplification factor can never be applied to an over-cap payload. The bound is
// tighter than the decoder's own dna.MaxCanonicalFragmentSize backstop, which is
// the point — see the maxDNAFragmentBytes doc comment.
func TestReassembleDNA_RejectsOversizedFragment(t *testing.T) {
	require.LessOrEqual(t, maxDNAFragmentBytes, sdna.MaxCanonicalFragmentSize,
		"the ingest bound must never be looser than the decoder backstop")

	// Wire protocol is Fragments-only: no Attributes field (Issue #3322).
	oversized := make([]byte, maxDNAFragmentBytes+1)
	_, _, err := reassembleDNA(chunksFromPayload(mustJSON(t, &dptypes.DNATransfer{
		StewardID: "s", TenantID: "t1", FragmentBytes: [][]byte{oversized},
	}), "s"), "s")
	require.Error(t, err, "an over-cap fragment must never reach the decoder")
	assert.Contains(t, err.Error(), "exceeds maximum")

	// A fragment exactly at the boundary is still accepted (well-formed or not), so
	// the bound cannot silently truncate legitimate load.
	atLimit, err := proto.Marshal(&common.Fragment{
		FragmentId:     "cluster:big",
		CanonicalBytes: make([]byte, maxDNAFragmentBytes-64),
	})
	require.NoError(t, err)
	require.LessOrEqual(t, len(atLimit), maxDNAFragmentBytes)

	dna, _, err := reassembleDNA(chunksFromPayload(mustJSON(t, &dptypes.DNATransfer{
		StewardID: "s", TenantID: "t1", FragmentBytes: [][]byte{atLimit},
	}), "s"), "s")
	require.NoError(t, err, "a fragment at the boundary must be accepted")
	require.Len(t, dna.GetFragments(), 1)
	assert.Equal(t, "cluster:big", dna.GetFragments()[0].GetFragmentId())
}

// TestDNAHandler_RejectsChunkFlood: a stream of more than maxDNAChunks chunks is
// refused with ResourceExhausted while it is still arriving, so the handler never
// buffers the flood.
func TestDNAHandler_RejectsChunkFlood(t *testing.T) {
	ca := newTestCA(t)
	persister := &stubPersister{}
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), persister)

	total := maxDNAChunks + 10
	chunks := make([]*transportpb.DNAChunk, 0, total)
	for i := 0; i < total; i++ {
		chunks = append(chunks, &transportpb.DNAChunk{
			StewardId: "steward-flood", TenantId: "t1", Data: []byte("x"),
			ChunkIndex: int32(i), TotalChunks: int32(total),
		})
	}

	stream := newTestDNAStream(peerContextWithCA(t, ca, "steward-flood"), chunks...)
	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Nil(t, persister.got, "a rejected flood must never reach the persister")
	assert.Equal(t, maxDNAChunks+1, stream.pos,
		"the flood must be cut off at the cap, not drained to EOF")
}

// TestDNAHandler_RejectsOversizedSnapshot: chunks whose concatenated payload
// exceeds maxReassembledDNABytes are refused with ResourceExhausted, closing the
// gap that maxRecvMsgSize (per-message only) leaves open.
func TestDNAHandler_RejectsOversizedSnapshot(t *testing.T) {
	ca := newTestCA(t)
	persister := &stubPersister{}
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), persister)

	const chunkSize = 64 * 1024
	total := (maxReassembledDNABytes / chunkSize) + 2 // just over the byte cap, under maxDNAChunks
	require.Less(t, total, maxDNAChunks, "this test must exercise the byte cap, not the chunk cap")

	chunks := make([]*transportpb.DNAChunk, 0, total)
	for i := 0; i < total; i++ {
		chunks = append(chunks, &transportpb.DNAChunk{
			StewardId: "steward-big", TenantId: "t1", Data: make([]byte, chunkSize),
			ChunkIndex: int32(i), TotalChunks: int32(total),
		})
	}

	err := h.HandleGRPC(newTestDNAStream(peerContextWithCA(t, ca, "steward-big"), chunks...))
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Nil(t, persister.got, "an over-cap snapshot must never reach the persister")
}

// mustJSON marshals v or fails the test.
func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// chunksFromPayload wraps an already-marshalled DNATransfer payload in a single chunk.
func chunksFromPayload(payload []byte, stewardID string) []*transportpb.DNAChunk {
	return []*transportpb.DNAChunk{{
		StewardId: stewardID, TenantId: "t1", Data: payload, ChunkIndex: 0, TotalChunks: 1,
	}}
}

// stubPersister is a minimal DNAPersister used by the ingest-side DoS bound
// tests to assert that a rejected flood/oversized snapshot never reaches
// persistence — it records the last DNA it was handed (nil if never called).
type stubPersister struct {
	got *common.DNA
}

func (p *stubPersister) SyncDNA(_ context.Context, dna *common.DNA) (*common.Status, error) {
	p.got = dna
	return &common.Status{Code: common.Status_OK}, nil
}

// TestDNAHandler_MultiChunkReassembly (#2616): a snapshot split across multiple
// chunks and delivered out of order reassembles correctly and lands in the real
// controller service.
func TestDNAHandler_MultiChunkReassembly(t *testing.T) {
	ca := newTestCA(t)
	svc := registeredService(t, "steward-multi")
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), svc)

	attrs := map[string]string{"hostname": "cfg-ab-02", "os": "windows", "primary_mac": "00:15:5d:ea:a3:35", "memory_bytes": "17179869184"}
	chunks := dnaChunksFor(t, "steward-multi", attrs, 3)
	// Deliver out of order — the handler must sort by ChunkIndex.
	chunks[0], chunks[2] = chunks[2], chunks[0]

	ctx := peerContextWithCA(t, ca, "steward-multi")
	require.NoError(t, h.HandleGRPC(newTestDNAStream(ctx, chunks...)))

	stored := syncedDNA(t, svc, "steward-multi")
	require.NotNil(t, stored, "reassembled DNA must reach the controller service")
	// Wire protocol is Fragments-only (Issue #3322): verify the identity fragments
	// produced by dnaChunksFor survive multi-chunk out-of-order reassembly, and
	// that their flat projection reaches the record intact.
	assert.NotEmpty(t, stored.GetFragments(), "identity fragments must survive multi-chunk reassembly")
	assert.Equal(t, map[string]string{"hostname": "cfg-ab-02", "os": "windows"},
		sdna.FlattenFragments(stored.GetFragments()),
		"fragment-derived attributes must survive multi-chunk out-of-order reassembly")
}

// TestDNAHandler_PersistStatusNotFound_FailsRPC (#2616, #2641): a persist failure
// must surface as an RPC error (the steward retries), never as a silent success.
//
// The real *service.ControllerService signals failure through the returned
// common.Status — for an unregistered steward, Status_NOT_FOUND with a nil Go
// error. That is its genuine failure surface, so this is the persist-failure
// regression: no test double is substituted to synthesize a different one.
func TestDNAHandler_PersistStatusNotFound_FailsRPC(t *testing.T) {
	ca := newTestCA(t)
	svc := service.NewControllerService(logging.NewNoopLogger())
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), svc)

	ctx := peerContextWithCA(t, ca, "steward-not-found")
	stream := newTestDNAStream(ctx, dnaChunksFor(t, "steward-not-found", map[string]string{"hostname": "h", "os": "linux"}, 1)...)

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Nil(t, stream.resp, "Accepted response must not be sent when persist was rejected")
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestDNAHandler_PersistStatusOK_Accepted (#2641): when the real
// ControllerService accepts the sync (Status_OK), behavior is unchanged — the
// steward is told Accepted: true.
//
// The persister is a real *service.ControllerService with "steward-ok"
// registered, so SyncDNA takes its genuine happy path (in-memory update).
func TestDNAHandler_PersistStatusOK_Accepted(t *testing.T) {
	ca := newTestCA(t)
	svc := service.NewControllerService(logging.NewNoopLogger())
	require.NoError(t, svc.RegisterStewardWithAttributes(
		"steward-ok", "t1", "", "active",
		map[string]string{"hostname": "h", "os": "linux"},
	))
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), svc)

	ctx := peerContextWithCA(t, ca, "steward-ok")
	stream := newTestDNAStream(ctx, dnaChunksFor(t, "steward-ok", map[string]string{"hostname": "h", "os": "linux"}, 1)...)

	require.NoError(t, h.HandleGRPC(stream))
	require.NotNil(t, stream.resp)
	assert.True(t, stream.resp.GetAccepted())
}

// ---------------------------------------------------------------------------
// In-process test stream (implements the generated gRPC stream interface only —
// no CFGMS component is substituted)
// ---------------------------------------------------------------------------

type testDNAStream struct {
	chunks  []*transportpb.DNAChunk
	pos     int
	resp    *transportpb.DNASyncResponse
	ctx     context.Context
	recvErr error
}

func newTestDNAStream(ctx context.Context, chunks ...*transportpb.DNAChunk) *testDNAStream {
	return &testDNAStream{chunks: chunks, ctx: ctx}
}

func (s *testDNAStream) Recv() (*transportpb.DNAChunk, error) {
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	if s.pos >= len(s.chunks) {
		return nil, io.EOF
	}
	chunk := s.chunks[s.pos]
	s.pos++
	return chunk, nil
}

func (s *testDNAStream) SendAndClose(resp *transportpb.DNASyncResponse) error {
	s.resp = resp
	return nil
}

func (s *testDNAStream) SetHeader(metadata.MD) error  { return nil }
func (s *testDNAStream) SendHeader(metadata.MD) error { return nil }
func (s *testDNAStream) SetTrailer(metadata.MD)       {}
func (s *testDNAStream) Context() context.Context     { return s.ctx }
func (s *testDNAStream) SendMsg(interface{}) error    { return nil }
func (s *testDNAStream) RecvMsg(interface{}) error    { return nil }

// Compile-time check: testDNAStream must implement the required interface.
var _ grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse] = (*testDNAStream)(nil)

// ---------------------------------------------------------------------------
// testTransportSrv — minimal StewardTransportServer for round-trip tests
// ---------------------------------------------------------------------------

type testTransportSrv struct {
	transportpb.UnimplementedStewardTransportServer
	dnaHandler  *DNAHandler
	bulkHandler *BulkHandler
}

func (s *testTransportSrv) SyncDNA(stream grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse]) error {
	return s.dnaHandler.HandleGRPC(stream)
}

func (s *testTransportSrv) BulkTransfer(stream grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
	return s.bulkHandler.HandleGRPC(stream)
}

// Compile-time check.
var _ transportpb.StewardTransportServer = (*testTransportSrv)(nil)

// ---------------------------------------------------------------------------
// roundTripEnv — gRPC-over-QUIC server+client pair
// ---------------------------------------------------------------------------

type roundTripEnv struct {
	client    transportpb.StewardTransportClient
	stewardID string
	cleanup   func()
}

// newRoundTripEnv starts a gRPC-over-QUIC server and returns a client whose
// mTLS certificate CN matches stewardID.
func newRoundTripEnv(t *testing.T, stewardID string) *roundTripEnv {
	t.Helper()

	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Transport Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	serverCert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	serverTLS, err := cfgcert.CreateServerTLSConfig(
		serverCert.CertificatePEM, serverCert.PrivateKeyPEM,
		caPEM, tls.VersionTLS13,
	)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}

	clientCert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   stewardID,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	clientTLS, err := cfgcert.CreateClientTLSConfig(
		clientCert.CertificatePEM, clientCert.PrivateKeyPEM,
		caPEM, "localhost", tls.VersionTLS13,
	)
	require.NoError(t, err)
	clientTLS.NextProtos = []string{quictransport.ALPNProtocol}

	ql, err := quictransport.Listen("127.0.0.1:0", serverTLS, nil)
	require.NoError(t, err)

	grpcSrv := grpc.NewServer(
		grpc.Creds(quictransport.TransportCredentials()),
		grpc.MaxRecvMsgSize(8*1024*1024),
	)
	queue := NewTenantQueue()
	srv := &testTransportSrv{
		dnaHandler:  NewDNAHandler(logging.NewNoopLogger(), queue, nil),
		bulkHandler: NewBulkHandler(logging.NewNoopLogger(), queue),
	}
	transportpb.RegisterStewardTransportServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(ql) }()

	dialer := quictransport.NewDialer(clientTLS, nil)
	conn, err := grpc.NewClient(
		ql.Addr().String(),
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(quictransport.TransportCredentials()),
	)
	require.NoError(t, err)

	return &roundTripEnv{
		client:    transportpb.NewStewardTransportClient(conn),
		stewardID: stewardID,
		cleanup: func() {
			_ = conn.Close()
			grpcSrv.GracefulStop()
			_ = ql.Close()
		},
	}
}

// ---------------------------------------------------------------------------
// Unit tests — mTLS peer validation
// ---------------------------------------------------------------------------

// TestDNAHandler_MissingPeerCert verifies that a request with no mTLS peer
// info in context is rejected with Unauthenticated.
func TestDNAHandler_MissingPeerCert(t *testing.T) {
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil)
	stream := newTestDNAStream(context.Background())

	err := h.HandleGRPC(stream)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestDNAHandler_StewardIDMismatch verifies that a chunk whose steward_id
// does not match the mTLS peer CN is rejected with PermissionDenied.
func TestDNAHandler_StewardIDMismatch(t *testing.T) {
	ca := newTestCA(t)
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil)

	ctx := peerContextWithCA(t, ca, "steward-alice")
	stream := newTestDNAStream(ctx, &transportpb.DNAChunk{
		StewardId:   "steward-bob",
		TenantId:    "tenant-1",
		Data:        []byte("dna"),
		ChunkIndex:  0,
		TotalChunks: 1,
	})

	err := h.HandleGRPC(stream)

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	msg := status.Convert(err).Message()
	assert.Equal(t, "steward ID mismatch", msg)
	assert.NotContains(t, msg, "steward-alice", "must not disclose peer CN")
	assert.NotContains(t, msg, "steward-bob", "must not disclose chunk steward ID")
}

// TestDNAHandler_MatchingStewardIDAccepted verifies that matching steward ID
// passes validation and the handler sends an accepted response.
func TestDNAHandler_MatchingStewardIDAccepted(t *testing.T) {
	ca := newTestCA(t)
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil)

	ctx := peerContextWithCA(t, ca, "steward-match")
	stream := newTestDNAStream(ctx,
		&transportpb.DNAChunk{StewardId: "steward-match", TenantId: "t1", Data: []byte("p1"), ChunkIndex: 0, TotalChunks: 2},
		&transportpb.DNAChunk{StewardId: "steward-match", TenantId: "t1", Data: []byte("p2"), ChunkIndex: 1, TotalChunks: 2},
	)

	err := h.HandleGRPC(stream)

	require.NoError(t, err)
	require.NotNil(t, stream.resp)
	assert.True(t, stream.resp.GetAccepted())
	assert.Equal(t, "accepted", stream.resp.GetMessage())
}

// TestDNAHandler_EmptyStream verifies that an empty stream (no chunks) is
// accepted and returns a valid response.
func TestDNAHandler_EmptyStream(t *testing.T) {
	ca := newTestCA(t)
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil)

	ctx := peerContextWithCA(t, ca, "steward-empty")
	stream := newTestDNAStream(ctx) // zero chunks

	err := h.HandleGRPC(stream)

	require.NoError(t, err)
	require.NotNil(t, stream.resp)
	assert.True(t, stream.resp.GetAccepted())
}

// TestDNAHandler_RecvError verifies that a Recv() error (not EOF) causes
// HandleGRPC to return a wrapped error with the expected message.
func TestDNAHandler_RecvError(t *testing.T) {
	ca := newTestCA(t)
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil)

	ctx := peerContextWithCA(t, ca, "steward-recv-err")
	injectedErr := errors.New("recv failed: connection reset by peer")
	stream := &testDNAStream{ctx: ctx, recvErr: injectedErr}

	err := h.HandleGRPC(stream)

	require.Error(t, err)
	assert.True(t, errors.Is(err, injectedErr), "error must wrap the injected recv error")
	assert.Contains(t, err.Error(), "failed to receive DNA chunk")
}

// TestDNAHandler_QueueFull_ReturnsResourceExhausted verifies that when a
// tenant's queue is at capacity the handler returns codes.ResourceExhausted.
func TestDNAHandler_QueueFull_ReturnsResourceExhausted(t *testing.T) {
	ca := newTestCA(t)
	queue := NewTenantQueue()
	h := NewDNAHandler(logging.NewNoopLogger(), queue, nil)

	for i := 0; i < MaxConcurrentPerTenant; i++ {
		require.NoError(t, queue.Acquire("tenant-full"))
	}

	ctx := peerContextWithCA(t, ca, "steward-full")
	stream := newTestDNAStream(ctx, &transportpb.DNAChunk{
		StewardId: "steward-full",
		TenantId:  "tenant-full",
	})

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

// ---------------------------------------------------------------------------
// Round-trip integration tests
// ---------------------------------------------------------------------------

// TestSyncDNA_RoundTrip verifies that a steward can stream DNA chunks over
// real gRPC-over-QUIC with mTLS and receive an accepted response.
func TestSyncDNA_RoundTrip(t *testing.T) {
	env := newRoundTripEnv(t, "steward-dna-rt")
	defer env.cleanup()

	stream, err := env.client.SyncDNA(context.Background())
	require.NoError(t, err)

	require.NoError(t, stream.Send(&transportpb.DNAChunk{
		StewardId:   env.stewardID,
		TenantId:    "tenant-rt",
		Data:        []byte(`{"os":"linux","arch":"amd64"}`),
		ChunkIndex:  0,
		TotalChunks: 1,
	}))

	resp, err := stream.CloseAndRecv()
	require.NoError(t, err)
	assert.True(t, resp.GetAccepted())
	assert.Equal(t, "accepted", resp.GetMessage())
}

// TestSyncDNA_RoundTrip_StewardIDMismatch verifies end-to-end rejection when
// the chunk steward_id does not match the client cert CN over real QUIC+mTLS.
func TestSyncDNA_RoundTrip_StewardIDMismatch(t *testing.T) {
	env := newRoundTripEnv(t, "steward-real")
	defer env.cleanup()

	stream, err := env.client.SyncDNA(context.Background())
	require.NoError(t, err)

	require.NoError(t, stream.Send(&transportpb.DNAChunk{
		StewardId:   "steward-impersonator",
		TenantId:    "tenant-rt",
		Data:        []byte("dna"),
		ChunkIndex:  0,
		TotalChunks: 1,
	}))

	_, err = stream.CloseAndRecv()
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestSyncDNA_FragmentsOnly_NoAttributesOnWire is the required integration test
// (Issue #3322 AC): a full steward→controller DNA sync succeeds with no
// Attributes bytes on the wire. The transfer carries only FragmentBytes; the
// controller must accept it and persist the fragments.
//
// The flat attribute view consumers still read is projected from the received
// fragments — TestReassembleDNA_IgnoresWireAttributes proves the wire field
// itself is never read.
//
// This test also covers the steward-identity check: the mTLS peer must match the
// StewardId in the first chunk; HandleGRPC enforces this before calling
// reassembleDNA (see TestSyncDNA_RoundTrip_StewardIDMismatch).
func TestSyncDNA_FragmentsOnly_NoAttributesOnWire(t *testing.T) {
	ca := newTestCA(t)
	svc := registeredService(t, "steward-frags-only")
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), svc)

	// Build a transfer with identity fragments (hostname + host:os) but no Attributes.
	// The identity fragments are required by the DNA integrity check in SyncDNA;
	// they are already what the steward sends via dnaChunksFor (Fragments-only, Issue #3322).
	attrs := map[string]string{"hostname": "cfg-frags-test", "os": "linux"}
	transfer := &dptypes.DNATransfer{
		StewardID:     "steward-frags-only",
		TenantID:      "t1",
		FragmentBytes: identityFragmentBytes(t, attrs),
		// Attributes intentionally nil — wire protocol is Fragments-only (Issue #3322).
	}
	require.Nil(t, transfer.Attributes, "test pre-condition: Attributes must be absent from the wire transfer")

	ctx := peerContextWithCA(t, ca, "steward-frags-only")
	stream := newTestDNAStream(ctx, dnaChunksForTransfer(t, transfer, 1)...)

	require.NoError(t, h.HandleGRPC(stream))
	require.NotNil(t, stream.resp)
	assert.True(t, stream.resp.GetAccepted(), "fragment-only transfer must be accepted")

	stored := syncedDNA(t, svc, "steward-frags-only")
	require.NotNil(t, stored)
	assert.Equal(t, "steward-frags-only", stored.GetId())
	// Fragments are the authoritative DNA representation (Issue #3322).
	assert.NotEmpty(t, stored.GetFragments(), "identity fragments must survive the full sync path")
	// A fragments-only wire transfer must still leave the flat consumers fed:
	// role-policy selectors, fleet inventory and the attribute index all read the
	// fragment projection, and SyncDNA replaces the record wholesale.
	assert.Equal(t, attrs, sdna.FlattenFragments(stored.GetFragments()),
		"a fragments-only sync must not blank the record's flat projection")
	assert.Equal(t, int32(len(attrs)), stored.GetAttributeCount())
}

// TestReassembleDNA_IgnoresWireAttributes pins the Issue #3322 wire contract from
// the hostile direction: DNATransfer.Attributes is never read, so a steward that
// keeps sending one (an old build, or a compromised host trying to assert
// attributes no fragment backs) cannot influence the reassembled record. The
// resulting flat map must be exactly the fragment projection.
func TestReassembleDNA_IgnoresWireAttributes(t *testing.T) {
	attrJSON, err := json.Marshal(map[string]string{
		"hostname": "attacker-claimed-host",
		"os":       "attacker-claimed-os",
		"role":     "domain-controller",
	})
	require.NoError(t, err)

	transfer := &dptypes.DNATransfer{
		StewardID:     "steward-wire-attrs",
		TenantID:      "t1",
		Attributes:    attrJSON,
		FragmentBytes: identityFragmentBytes(t, map[string]string{"hostname": "real-host", "os": "linux"}),
	}

	dna, _, err := reassembleDNA(dnaChunksForTransfer(t, transfer, 1), "steward-wire-attrs")
	require.NoError(t, err)
	flat := sdna.FlattenFragments(dna.GetFragments())
	assert.Equal(t, map[string]string{"hostname": "real-host", "os": "linux"}, flat,
		"attributes must come from fragments only; the wire blob must be ignored entirely")
	assert.NotContains(t, flat, "role",
		"a key present only in the wire blob must never enter the record")
	assert.Equal(t, int32(2), dna.GetAttributeCount())
}

// TestSyncDNA_OversizedMessageRejected verifies that the gRPC server enforces
// MaxRecvMsgSize for DNA chunks over QUIC (DoS protection).
func TestSyncDNA_OversizedMessageRejected(t *testing.T) {
	env := newRoundTripEnv(t, "steward-dos")
	defer env.cleanup()

	stream, err := env.client.SyncDNA(context.Background())
	require.NoError(t, err)

	sendErr := stream.Send(&transportpb.DNAChunk{
		StewardId: env.stewardID,
		Data:      make([]byte, 9*1024*1024), // 9 MB > 8 MB limit
	})
	if sendErr == nil {
		_, sendErr = stream.CloseAndRecv()
	}

	require.Error(t, sendErr)
	assert.Equal(t, codes.ResourceExhausted, status.Code(sendErr))
}

// ---------------------------------------------------------------------------
// Partial-sync protocol tests (ADR-017 §7, Issue #2906)
// ---------------------------------------------------------------------------

// deltaReceiveHandler wires a DNAHandler for the delta RECEIVE path (ADR-017 §7
// step 3) against store.
//
// No command publisher is wired because the receive path never publishes one:
// handleDeltaGRPC only reads the store and the recorded delta request. The dispatch
// half of the protocol is covered end to end against the real signing Publisher and
// a real steward command handler in dna_handler_partialsync_realcp_test.go, so
// nothing here needs to stand in for it.
func deltaReceiveHandler(store FragmentDeltaStore) *DNAHandler {
	return NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil).
		WithPartialSync(store, nil)
}

// deltaChunksFor encodes fragments in a DNATransfer and splits it into chunks
// with IsDelta=true — mirroring the steward's partial-sync send path.
func deltaChunksFor(t *testing.T, stewardID string, fragments []*common.Fragment) []*transportpb.DNAChunk {
	t.Helper()
	payload, err := json.Marshal(&dptypes.DNATransfer{
		StewardID: stewardID,
		TenantID:  "t1",
		Delta:     true,
		Fragments: fragments,
	})
	require.NoError(t, err)
	return []*transportpb.DNAChunk{{
		StewardId:   stewardID,
		TenantId:    "t1",
		Data:        payload,
		ChunkIndex:  0,
		TotalChunks: 1,
		IsDelta:     true,
	}}
}

// makeTestFragments returns N test fragments with stable fragment_id and computed hashes.
func makeTestFragments(n int) []*common.Fragment {
	frags := make([]*common.Fragment, n)
	for i := 0; i < n; i++ {
		canonical := []byte(fmt.Sprintf(`{"id":"%d","value":"v%d"}`, i, i))
		frags[i] = &common.Fragment{
			FragmentId:     fmt.Sprintf("frag-%d", i),
			Authority:      "test",
			CanonicalBytes: canonical,
			FragmentHash:   sdna.FragmentHash(canonical),
		}
	}
	return frags
}

// fragmentsToManifest converts fragments to a manifest (controller's stored view).
func fragmentsToManifest(fragments []*common.Fragment) []*common.ManifestEntry {
	m := make([]*common.ManifestEntry, len(fragments))
	for i, f := range fragments {
		m[i] = &common.ManifestEntry{
			FragmentId:   f.GetFragmentId(),
			FragmentHash: f.GetFragmentHash(),
		}
	}
	return m
}

// manifestIDs returns the fragment IDs of a manifest — the exact set
// HandleHeartbeatRoot requests from the steward on a root mismatch.
func manifestIDs(manifest []*common.ManifestEntry) []string {
	ids := make([]string, 0, len(manifest))
	for _, e := range manifest {
		ids = append(ids, e.GetFragmentId())
	}
	return ids
}

// TestDNAHandler_DeltaGRPC_ValidDelta_Accepted verifies the full delta round trip:
// received fragments merge with the stored manifest, root matches the claimed root,
// and ApplyDelta is called.
func TestDNAHandler_DeltaGRPC_ValidDelta_Accepted(t *testing.T) {
	ca := newTestCA(t)
	frags := makeTestFragments(3)
	manifest := fragmentsToManifest(frags)
	claimedRoot, err := sdna.AggregateRoot(manifest)
	require.NoError(t, err)

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-delta", manifest)

	h := deltaReceiveHandler(store)

	// Record the claimed root and the requested fragment IDs, exactly as
	// HandleHeartbeatRoot does on the ADR-017 §7 step-1 mismatch path.
	h.recordDeltaRequest("steward-delta", claimedRoot, manifestIDs(manifest))

	ctx := peerContextWithCA(t, ca, "steward-delta")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-delta", frags)...)

	require.NoError(t, h.HandleGRPC(stream))
	require.NotNil(t, stream.resp)
	assert.True(t, stream.resp.GetAccepted())
	assert.Equal(t, claimedRoot, stream.resp.GetNewHash())

	// Verify ApplyDelta was called (the pending request is consumed).
	_, stillPresent := h.pendingDeltas.Load("steward-delta")
	assert.False(t, stillPresent, "pendingDeltas entry must be cleared after successful apply")
}

// TestDNAHandler_DeltaGRPC_ForgedRoot_Rejected verifies that a delta where the
// received fragments do not produce the claimed root is rejected (SE threat #2).
func TestDNAHandler_DeltaGRPC_ForgedRoot_Rejected(t *testing.T) {
	ca := newTestCA(t)
	frags := makeTestFragments(3)
	manifest := fragmentsToManifest(frags)

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-forge", manifest)

	h := deltaReceiveHandler(store)

	// Claimed root is a forged value that does not match any real manifest.
	h.recordDeltaRequest("steward-forge", "forged-root-that-will-not-match", manifestIDs(manifest))

	ctx := peerContextWithCA(t, ca, "steward-forge")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-forge", frags)...)

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "aggregate root mismatch")
	assert.Nil(t, stream.resp, "no accepted response must be sent on revalidation failure")
}

// TestDNAHandler_DeltaGRPC_WithholdingAttack_Detected verifies that a steward
// claiming root R but witholding one changed fragment is detected (SE threat #2).
//
// Setup: controller has stored manifest [A:h1, B:h1]. The steward changes B to
// h2, claims root R = AggregateRoot([A:h1, B:h2]). The attacker sends only A
// (withholding the updated B). The controller merges: [A:h1, B:h1] (B is still
// old). Computed root R' ≠ R → rejected.
func TestDNAHandler_DeltaGRPC_WithholdingAttack_Detected(t *testing.T) {
	ca := newTestCA(t)

	// Steward's ACTUAL updated state: both A and B.
	fragA := &common.Fragment{
		FragmentId: "A", Authority: "test",
		CanonicalBytes: []byte(`{"v":"1"}`),
		FragmentHash:   sdna.FragmentHash([]byte(`{"v":"1"}`)),
	}
	fragBOld := &common.Fragment{
		FragmentId: "B", Authority: "test",
		CanonicalBytes: []byte(`{"v":"old"}`),
		FragmentHash:   sdna.FragmentHash([]byte(`{"v":"old"}`)),
	}
	fragBNew := &common.Fragment{
		FragmentId: "B", Authority: "test",
		CanonicalBytes: []byte(`{"v":"new"}`),
		FragmentHash:   sdna.FragmentHash([]byte(`{"v":"new"}`)),
	}

	// Controller has stored state: [A:h1, B:h_old].
	storedManifest := []*common.ManifestEntry{
		{FragmentId: "A", FragmentHash: fragA.GetFragmentHash()},
		{FragmentId: "B", FragmentHash: fragBOld.GetFragmentHash()},
	}
	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-withhold", storedManifest)

	h := deltaReceiveHandler(store)

	// Steward claims the correct updated root: [A:h1, B:h_new].
	updatedManifest := []*common.ManifestEntry{
		{FragmentId: "A", FragmentHash: fragA.GetFragmentHash()},
		{FragmentId: "B", FragmentHash: fragBNew.GetFragmentHash()},
	}
	claimedRoot, err := sdna.AggregateRoot(updatedManifest)
	require.NoError(t, err)
	h.recordDeltaRequest("steward-withhold", claimedRoot, manifestIDs(storedManifest))

	// Attacker sends ONLY A — withholding the updated B.
	ctx := peerContextWithCA(t, ca, "steward-withhold")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-withhold", []*common.Fragment{fragA})...)

	err = h.HandleGRPC(stream)
	require.Error(t, err, "withholding attack must be detected")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "aggregate root mismatch")
}

// TestDNAHandler_DeltaGRPC_NoClaim_Rejected verifies that a delta with no prior
// heartbeat claim on file is rejected with FailedPrecondition.
func TestDNAHandler_DeltaGRPC_NoClaim_Rejected(t *testing.T) {
	ca := newTestCA(t)
	frags := makeTestFragments(2)
	manifest := fragmentsToManifest(frags)

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-noclaim", manifest)

	h := deltaReceiveHandler(store)
	// No h.recordDeltaRequest call — no delta request on file.

	ctx := peerContextWithCA(t, ca, "steward-noclaim")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-noclaim", frags)...)

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// TestAggregateRoot_Deterministic verifies that two independent AggregateRoot
// computations over the same manifest entries produce identical roots regardless
// of input order (ADR-017 §6, SE threat #3).
func TestAggregateRoot_Deterministic(t *testing.T) {
	manifest := []*common.ManifestEntry{
		{FragmentId: "service:sshd", FragmentHash: "h1"},
		{FragmentId: "file:/etc/hosts", FragmentHash: "h2"},
		{FragmentId: "host:cpu", FragmentHash: "h3"},
	}
	reversed := []*common.ManifestEntry{manifest[2], manifest[1], manifest[0]}

	root1, err := sdna.AggregateRoot(manifest)
	require.NoError(t, err)
	root2, err := sdna.AggregateRoot(reversed)
	require.NoError(t, err)

	assert.Equal(t, root1, root2, "AggregateRoot must be order-independent")
	assert.NotEmpty(t, root1)
}

// TestDNAHandler_DeltaGRPC_ForgedLeafHash_Rejected is the regression for the
// leaf-hash binding gap: the steward ships canonical_bytes for its REAL (mutated)
// state while asserting the fragment_hash of the OLD state. Both the asserted
// leaf set and the claimed root are internally consistent, so a root check over
// steward-asserted leaves would accept it — letting a compromised steward mutate
// its host indefinitely behind a pinned root that never triggers a re-sync.
//
// The controller must recompute every leaf hash from canonical_bytes and reject.
func TestDNAHandler_DeltaGRPC_ForgedLeafHash_Rejected(t *testing.T) {
	ca := newTestCA(t)

	oldBytes := []byte(`{"v":"old"}`)
	newBytes := []byte(`{"v":"new"}`)

	fragA := &common.Fragment{
		FragmentId: "A", Authority: "test",
		CanonicalBytes: []byte(`{"v":"1"}`),
		FragmentHash:   sdna.FragmentHash([]byte(`{"v":"1"}`)),
	}
	// Forged: real (mutated) content, stale asserted hash.
	forgedB := &common.Fragment{
		FragmentId: "B", Authority: "test",
		CanonicalBytes: newBytes,
		FragmentHash:   sdna.FragmentHash(oldBytes),
	}

	storedManifest := []*common.ManifestEntry{
		{FragmentId: "A", FragmentHash: fragA.GetFragmentHash()},
		{FragmentId: "B", FragmentHash: sdna.FragmentHash(oldBytes)},
	}
	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-leafforge", storedManifest)

	h := deltaReceiveHandler(store)

	// The claimed root is consistent with the ASSERTED leaves, so the attack
	// survives any check that trusts Fragment.FragmentHash.
	claimedRoot, err := sdna.AggregateRoot(storedManifest)
	require.NoError(t, err)
	h.recordDeltaRequest("steward-leafforge", claimedRoot, manifestIDs(storedManifest))

	ctx := peerContextWithCA(t, ca, "steward-leafforge")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-leafforge",
		[]*common.Fragment{fragA, forgedB})...)

	err = h.HandleGRPC(stream)
	require.Error(t, err, "a leaf hash that does not match its canonical_bytes must be rejected")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "canonical_bytes")
	assert.Nil(t, stream.resp, "no accepted response on leaf-hash forgery")

	// The stale content must NOT have been committed.
	got, mErr := store.CurrentManifest("steward-leafforge")
	require.NoError(t, mErr)
	for _, e := range got {
		if e.GetFragmentId() == "B" {
			assert.Equal(t, sdna.FragmentHash(oldBytes), e.GetFragmentHash(),
				"the rejected delta must not have been applied")
		}
	}
}

// TestDNAHandler_DeltaGRPC_MissingCanonicalBytes_Rejected verifies that a fragment
// with no canonical_bytes is rejected: there is nothing to bind the leaf hash to,
// so accepting it would reintroduce the steward-asserted-hash trust gap.
func TestDNAHandler_DeltaGRPC_MissingCanonicalBytes_Rejected(t *testing.T) {
	ca := newTestCA(t)

	manifest := fragmentsToManifest(makeTestFragments(1))
	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-nobytes", manifest)

	h := deltaReceiveHandler(store)
	claimedRoot, err := sdna.AggregateRoot(manifest)
	require.NoError(t, err)
	h.recordDeltaRequest("steward-nobytes", claimedRoot, manifestIDs(manifest))

	hashOnly := []*common.Fragment{{
		FragmentId:   "frag-0",
		Authority:    "test",
		FragmentHash: manifest[0].GetFragmentHash(),
	}}

	ctx := peerContextWithCA(t, ca, "steward-nobytes")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-nobytes", hashOnly)...)

	err = h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "canonical_bytes")
	assert.Nil(t, stream.resp)
}

// TestDNAHandler_DeltaGRPC_PartialSyncNotConfigured_NotAccepted verifies the
// fail-CLOSED default: when no FragmentDeltaStore is wired (the configuration
// NewDNAHandler produces), a delta is rejected instead of receiving an
// unconditional success ack. A fail-open ack would let the steward believe its
// DNA is synced and permanently suppress its own DNA reporting while the
// controller holds nothing.
func TestDNAHandler_DeltaGRPC_PartialSyncNotConfigured_NotAccepted(t *testing.T) {
	ca := newTestCA(t)
	frags := makeTestFragments(2)

	// NewDNAHandler with no WithPartialSync — the default production wiring.
	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(),
		registeredService(t, "steward-unconfigured"))

	ctx := peerContextWithCA(t, ca, "steward-unconfigured")
	stream := newTestDNAStream(ctx, deltaChunksFor(t, "steward-unconfigured", frags)...)

	err := h.HandleGRPC(stream)
	require.Error(t, err, "a delta must not be accepted when partial sync is not configured")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Nil(t, stream.resp, "no success ack may be sent when the security check cannot run")
}

// ---------------------------------------------------------------------------
// Delta resource bounds (transport trust boundary)
// ---------------------------------------------------------------------------

// fragmentWithID builds a content-consistent fragment with an arbitrary ID.
func fragmentWithID(id string) *common.Fragment {
	canonical := []byte(`{"v":"1"}`)
	return &common.Fragment{
		FragmentId:     id,
		Authority:      "test",
		CanonicalBytes: canonical,
		FragmentHash:   sdna.FragmentHash(canonical),
	}
}

// deltaBoundsFixture wires a handler with a stored manifest of n fragments and
// records a delta request for exactly those IDs, then computes the aggregate root
// the merged manifest WOULD have if sent were accepted, and claims it. Every
// content check (leaf hashes, aggregate root) therefore passes: only the resource
// bounds can reject the delta.
func deltaBoundsFixture(t *testing.T, stewardID string, sent []*common.Fragment) (*DNAHandler, *InMemoryFragmentDeltaStore) {
	t.Helper()
	manifest := fragmentsToManifest(makeTestFragments(3))
	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest(stewardID, manifest)

	h := deltaReceiveHandler(store)

	root, err := sdna.AggregateRoot(mergeManifest(manifest, sent))
	require.NoError(t, err)
	h.recordDeltaRequest(stewardID, root, manifestIDs(manifest))
	return h, store
}

// TestDNAHandler_DeltaGRPC_UnrequestedFragmentID_Rejected: a compromised steward
// answers the SYNC_DNA request with an extra fragment the controller never asked
// for, and computes the claimed root over its own inflated manifest so the
// aggregate-root check is self-consistent and passes. The merge path never removes
// entries, so accepting this grows the controller's durable manifest permanently —
// one unrequested ID per stream. The requested-ID set must reject it.
func TestDNAHandler_DeltaGRPC_UnrequestedFragmentID_Rejected(t *testing.T) {
	ca := newTestCA(t)
	const stewardID = "steward-unrequested"

	sent := []*common.Fragment{
		fragmentWithID("frag-0"),
		fragmentWithID("host:injected-by-compromised-steward"),
	}
	h, store := deltaBoundsFixture(t, stewardID, sent)

	ctx := peerContextWithCA(t, ca, stewardID)
	stream := newTestDNAStream(ctx, deltaChunksFor(t, stewardID, sent)...)

	err := h.HandleGRPC(stream)
	require.Error(t, err, "a fragment ID outside the requested set must be rejected")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "was not requested")
	assert.Nil(t, stream.resp)

	got, mErr := store.CurrentManifest(stewardID)
	require.NoError(t, mErr)
	assert.ElementsMatch(t, []string{"frag-0", "frag-1", "frag-2"}, manifestIDs(got),
		"the rejected delta must not have grown the stored manifest")
}

// TestDNAHandler_DeltaGRPC_OversizedFragmentID_Rejected: one fragment with a
// megabyte-long fragment_id and one byte of content, with a matching claimed root.
// Unbounded fragment_id length is the memory/storage amplification vector the
// aggregate-root guard cannot see.
func TestDNAHandler_DeltaGRPC_OversizedFragmentID_Rejected(t *testing.T) {
	ca := newTestCA(t)
	const stewardID = "steward-bigid"

	sent := []*common.Fragment{fragmentWithID(strings.Repeat("a", 1<<20))}
	h, store := deltaBoundsFixture(t, stewardID, sent)

	ctx := peerContextWithCA(t, ca, stewardID)
	stream := newTestDNAStream(ctx, deltaChunksFor(t, stewardID, sent)...)

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "exceeds")
	assert.Nil(t, stream.resp)

	got, mErr := store.CurrentManifest(stewardID)
	require.NoError(t, mErr)
	assert.Len(t, got, 3, "the rejected delta must not have been applied")
}

// TestDNAHandler_DeltaGRPC_ControlCharFragmentID_Rejected: a fragment_id carrying
// CRLF must not reach storage keys or log records.
func TestDNAHandler_DeltaGRPC_ControlCharFragmentID_Rejected(t *testing.T) {
	ca := newTestCA(t)
	const stewardID = "steward-ctrlid"

	sent := []*common.Fragment{fragmentWithID("frag-0\r\nlevel=INFO msg=\"forged\"")}
	h, _ := deltaBoundsFixture(t, stewardID, sent)

	ctx := peerContextWithCA(t, ca, stewardID)
	stream := newTestDNAStream(ctx, deltaChunksFor(t, stewardID, sent)...)

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "control character")
	assert.Nil(t, stream.resp)
}

// TestDNAHandler_DeltaGRPC_OversizedStream_Rejected: a delta stream may carry any
// number of chunks, each individually under the gRPC per-message limit. The
// reassembly buffer must be capped so a steward cannot drive unbounded controller
// memory growth before any content check runs.
func TestDNAHandler_DeltaGRPC_OversizedStream_Rejected(t *testing.T) {
	ca := newTestCA(t)
	const stewardID = "steward-bigstream"

	h, _ := deltaBoundsFixture(t, stewardID, []*common.Fragment{fragmentWithID("frag-0")})

	const chunkSize = 8 << 20
	chunkCount := maxDeltaStreamBytes/chunkSize + 1
	chunks := make([]*transportpb.DNAChunk, 0, chunkCount)
	for i := 0; i < chunkCount; i++ {
		chunks = append(chunks, &transportpb.DNAChunk{
			StewardId:   stewardID,
			TenantId:    "t1",
			Data:        make([]byte, chunkSize),
			ChunkIndex:  int32(i),
			TotalChunks: int32(chunkCount),
			IsDelta:     true,
		})
	}

	ctx := peerContextWithCA(t, ca, stewardID)
	stream := newTestDNAStream(ctx, chunks...)

	err := h.HandleGRPC(stream)
	require.Error(t, err, "an oversized delta stream must be rejected during reassembly")
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Nil(t, stream.resp)
}

// TestValidateDeltaFragments covers the bound set directly, including the two
// dimensions (fragment count, aggregate canonical_bytes) whose end-to-end fixtures
// would require multi-megabyte streams.
func TestValidateDeltaFragments(t *testing.T) {
	requested := map[string]struct{}{"frag-0": {}, "frag-1": {}}

	t.Run("requested fragments accepted", func(t *testing.T) {
		require.NoError(t, validateDeltaFragments(
			[]*common.Fragment{fragmentWithID("frag-0"), fragmentWithID("frag-1")}, requested))
	})

	t.Run("unrequested id rejected", func(t *testing.T) {
		err := validateDeltaFragments([]*common.Fragment{fragmentWithID("frag-9")}, requested)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "was not requested")
	})

	t.Run("empty id rejected", func(t *testing.T) {
		err := validateDeltaFragments([]*common.Fragment{fragmentWithID("")}, requested)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be empty")
	})

	t.Run("id at the limit accepted, one over rejected", func(t *testing.T) {
		atLimit := strings.Repeat("a", maxFragmentIDLen)
		require.NoError(t, validateDeltaFragments(
			[]*common.Fragment{fragmentWithID(atLimit)}, map[string]struct{}{atLimit: {}}))

		over := strings.Repeat("a", maxFragmentIDLen+1)
		err := validateDeltaFragments(
			[]*common.Fragment{fragmentWithID(over)}, map[string]struct{}{over: {}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds")
	})

	t.Run("invalid utf8 id rejected", func(t *testing.T) {
		bad := string([]byte{'f', 0xff, 0xfe})
		err := validateDeltaFragments(
			[]*common.Fragment{fragmentWithID(bad)}, map[string]struct{}{bad: {}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "UTF-8")
	})

	t.Run("duplicate id rejected", func(t *testing.T) {
		err := validateDeltaFragments(
			[]*common.Fragment{fragmentWithID("frag-0"), fragmentWithID("frag-0")}, requested)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "repeats fragment")
	})

	t.Run("fragment count cap enforced", func(t *testing.T) {
		many := make([]*common.Fragment, maxDeltaFragments+1)
		allRequested := make(map[string]struct{}, len(many))
		for i := range many {
			id := fmt.Sprintf("frag-%d", i)
			many[i] = fragmentWithID(id)
			allRequested[id] = struct{}{}
		}
		err := validateDeltaFragments(many, allRequested)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "limit is")
	})

	t.Run("aggregate canonical_bytes cap enforced", func(t *testing.T) {
		// Two fragments whose summed canonical_bytes exceed the cap, each below the
		// per-chunk gRPC message limit — the case a per-message bound cannot catch.
		half := maxDeltaCanonicalBytes/2 + 1
		big := make([]*common.Fragment, 0, 2)
		allRequested := map[string]struct{}{}
		for i := 0; i < 2; i++ {
			id := fmt.Sprintf("frag-big-%d", i)
			canonical := make([]byte, half)
			big = append(big, &common.Fragment{
				FragmentId:     id,
				CanonicalBytes: canonical,
				FragmentHash:   sdna.FragmentHash(canonical),
			})
			allRequested[id] = struct{}{}
		}
		err := validateDeltaFragments(big, allRequested)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "canonical_bytes exceed")
	})
}

// TestIsValidAggregateRoot verifies the aggregate-root format guard accepts exactly
// what sdna.AggregateRoot produces and nothing else.
func TestIsValidAggregateRoot(t *testing.T) {
	realRoot, err := sdna.AggregateRoot(fragmentsToManifest(makeTestFragments(3)))
	require.NoError(t, err)
	assert.True(t, isValidAggregateRoot(realRoot),
		"a root produced by AggregateRoot must validate")
	assert.Len(t, realRoot, aggregateRootHexLen)

	assert.False(t, isValidAggregateRoot(""))
	assert.False(t, isValidAggregateRoot(realRoot[:len(realRoot)-1]))
	assert.False(t, isValidAggregateRoot(realRoot+"a"))
	assert.False(t, isValidAggregateRoot(strings.ToUpper(realRoot)))
	assert.False(t, isValidAggregateRoot(strings.Repeat("g", aggregateRootHexLen)))
	assert.False(t, isValidAggregateRoot(strings.Repeat("a", aggregateRootHexLen-2)+"\r\n"))
}
