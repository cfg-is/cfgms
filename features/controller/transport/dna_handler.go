// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	common "github.com/cfgis/cfgms/api/proto/common"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/commands"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dptypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// CommandPublisher is the narrow slice of *commands.Publisher needed by
// DNAHandler: publish one command to one steward.
//
// The partial-sync dispatch goes through the command Publisher rather than
// calling ControlPlaneProvider.SendCommand directly, because the Publisher is the
// single controller→steward dispatch point that SIGNS the command with the
// controller's configured signer and assigns its UUID command ID. A steward with
// a verifier configured — the production posture — rejects any command whose
// Signature is nil (features/steward/commands.Handler.HandleCommand returns
// ErrUnauthenticatedCommand), so a hand-built unsigned SignedCommand would be
// dropped on arrival and the requested delta would never be sent. Publishing also
// keeps this path consistent with the full-sync sibling, Publisher.TriggerDNASync.
type CommandPublisher interface {
	PublishCommand(ctx context.Context, stewardID string, cmdType cpTypes.CommandType, params map[string]interface{}) (string, error)
}

// Compile-time proof that the real controller command publisher satisfies the
// narrow interface DNAHandler depends on — so production wiring cannot drift onto
// an unsigned dispatch path without breaking the build.
var _ CommandPublisher = (*commands.Publisher)(nil)

// Ingest-side DoS bounds for a sync_dna snapshot.
//
// Stewards run on hosts that may be compromised (CLAUDE.md threat model), so every
// count and length a steward controls is bounded before the controller allocates,
// decodes, or persists it. The gRPC maxRecvMsgSize
// (pkg/dataplane/providers/grpc/limits.go) bounds a single DNAChunk message, NOT
// the snapshot: HandleGRPC reassembles an unbounded stream of ≤64 KB chunks, so
// without these bounds one RPC can drive the controller to arbitrary heap use.
//
// These mirror the equivalent validation the data plane provider already applies
// in its own reassembler (chunksToDNATransfer: assembled payload ≤ maxRecvMsgSize).
const (
	// maxReassembledDNABytes caps the concatenated chunk payload. 8 MB matches the
	// data plane maxRecvMsgSize; a real full snapshot (a few hundred flat attributes
	// plus curated fragments) is orders of magnitude smaller.
	maxReassembledDNABytes = 8 * 1024 * 1024

	// maxDNAChunks caps how many chunks one snapshot may span. A byte cap alone does
	// not bound the chunk slice itself: a flood of 1-byte chunks costs a DNAChunk
	// struct each. At the 64 KB send-side chunk size 8 MB is 128 chunks, so 256
	// leaves 2x headroom over any legitimate snapshot.
	maxDNAChunks = 256

	// maxDNATransferFragments caps the ADR-017 fragments accepted on one snapshot.
	// Real producers emit a handful (4 host:* kinds from PartitionHostFacts plus one
	// cluster:* fragment per monitored cluster), and every persisted fragment is
	// re-decoded by clusterregistry.BuildRegistry on every cluster API read — an
	// unbounded count is therefore a repeatable amplifier, not a one-shot cost.
	maxDNATransferFragments = 1024

	// maxDNAFragmentBytes caps a single proto-marshalled Fragment. It is deliberately
	// far below dna.MaxCanonicalFragmentSize: that constant is the decoder's own
	// backstop, and because DecodeCanonicalFragment amplifies canonical bytes roughly
	// 19x in live heap, the ingest bound — not the backstop — is the one that has to
	// be tight. Real fragments are curated key subsets measured in kilobytes (the
	// largest realistic shape, a cluster resource_owner map for a few thousand
	// resources, is well under 100 KB), so 1 MB is an order of magnitude of headroom.
	maxDNAFragmentBytes = 1 * 1024 * 1024
)

// Compile-time assertion that the ingest bound can never be looser than the
// decoder's own backstop: if maxDNAFragmentBytes is raised above
// dna.MaxCanonicalFragmentSize this constant expression goes negative and the
// package fails to build.
const _ = uint(sdna.MaxCanonicalFragmentSize - maxDNAFragmentBytes)

// DNAPersister persists a fully-reassembled DNA snapshot received over the data
// plane. It is implemented by *service.ControllerService (SyncDNA), which stores
// the snapshot durably (append-only version history) and fires the reconcile
// post-sync hook (#2524). A nil persister disables persistence (used by tests
// that exercise only the receive/validation behavior).
type DNAPersister interface {
	SyncDNA(ctx context.Context, dna *common.DNA) (*common.Status, error)
}

// DNAHandler handles DNA sync RPCs from stewards.
type DNAHandler struct {
	logger    logging.Logger
	queue     *TenantQueue
	persister DNAPersister

	// Partial-sync protocol fields (ADR-017 §7). Both nil when partial-sync
	// is not configured; only set via WithPartialSync.
	store     FragmentDeltaStore
	publisher CommandPublisher

	// pendingDeltas stores the outstanding delta request per steward
	// (stewardID → *deltaRequest): the aggregate root the steward claimed in its
	// most recent heartbeat and the exact fragment ID set the controller asked
	// for. Set in HandleHeartbeatRoot; consumed and cleared in the delta branch
	// of HandleGRPC.
	pendingDeltas sync.Map

	// Entity-graph writer fields (ADR-022 §9, Story #2907). Both nil when the
	// entity-graph write path is not wired; only set via WithEntityGraph.
	// The write is additive — alongside the existing ApplyDelta manifest path,
	// never replacing it.
	egWriter   *dnasync.Writer
	egTaxonomy *egtypes.Taxonomy
}

// deltaRequest is the controller-side record of one outstanding partial-sync
// request (ADR-017 §7 step 2).
//
// requestedIDs is retained — not discarded after the SYNC_DNA dispatch — because
// it is the only server-side bound on WHICH fragment IDs a delta may write.
// mergeManifest and the ApplyDelta contract add or replace entries but never
// remove them, so without the requested set a compromised steward could grow the
// controller's durable manifest with fragment IDs the controller never asked
// about, one delta at a time.
type deltaRequest struct {
	claimedRoot  string
	requestedIDs map[string]struct{}
}

// recordDeltaRequest stores the outstanding delta request for a steward,
// replacing any previous one. Called on the heartbeat root-mismatch path
// immediately before the SYNC_DNA dispatch.
func (h *DNAHandler) recordDeltaRequest(stewardID, claimedRoot string, requestedIDs []string) {
	set := make(map[string]struct{}, len(requestedIDs))
	for _, id := range requestedIDs {
		set[id] = struct{}{}
	}
	h.pendingDeltas.Store(stewardID, &deltaRequest{claimedRoot: claimedRoot, requestedIDs: set})
}

// NewDNAHandler creates a new DNA sync handler. persister may be nil to disable
// persistence (the handler then only receives + validates the stream).
func NewDNAHandler(logger logging.Logger, queue *TenantQueue, persister DNAPersister) *DNAHandler {
	return &DNAHandler{logger: logger, queue: queue, persister: persister}
}

// WithPartialSync wires the fragment store and command publisher required for the
// ADR-017 §7 partial-sync protocol. Returns h for chaining.
//
// Both arguments are load-bearing and the handler is fail-closed without either:
// HandleHeartbeatRoot dispatches nothing unless both are set, and the delta
// receive path rejects with FailedPrecondition when store is nil. Wire the
// controller's command Publisher (never a raw ControlPlaneProvider) so the
// SYNC_DNA request is signed — see CommandPublisher.
func (h *DNAHandler) WithPartialSync(store FragmentDeltaStore, publisher CommandPublisher) *DNAHandler {
	h.store = store
	h.publisher = publisher
	return h
}

// WithEntityGraph wires the DNA-sync → entity-graph writer and the taxonomy
// required for authority-class-based EID scoping (Story #2907, ADR-022 §9).
// Returns h for chaining.
//
// Both arguments must be non-nil. Calling with either nil is a no-op to avoid
// a nil-dereference in handleDeltaGRPC; the entity-graph write is then skipped
// silently (a missing writer is a configuration error, not a data error, and the
// caller's ApplyDelta write already committed the fragment manifest).
//
// The entity-graph write is ADDITIVE: it runs after ApplyDelta succeeds and
// on failure only emits a warning — the steward's stream is not failed and the
// committed manifest is not rolled back. Authority confusion (SE threat #1) is
// structurally impossible: the EID authority segment is built entirely from the
// mTLS-verified peerID, never from steward-supplied fragment data.
func (h *DNAHandler) WithEntityGraph(writer *dnasync.Writer, taxonomy *egtypes.Taxonomy) *DNAHandler {
	h.egWriter = writer
	h.egTaxonomy = taxonomy
	return h
}

// HandleHeartbeatRoot is called by the heartbeat service when a heartbeat
// carries a non-empty DNAAggregateRoot. It compares the claimed root to the
// controller's stored manifest root and, on mismatch, sends SYNC_DNA with
// fragment_ids to request only the changed fragments (ADR-017 §7 step 2).
//
// When the store has no manifest yet (first-time sync), the call is a no-op:
// the existing onDNAHashMismatch → full TriggerDNASync path handles that case.
// A malformed claimed root is dropped before it is stored or logged: the value
// is steward-supplied and otherwise unbounded (Story #396 input validation).
//
// The heartbeat's claimed tenant is deliberately NOT an argument and never reaches
// the issued command. A heartbeat is steward-supplied, so a compromised steward can
// claim any tenant path; Command.TenantID is part of the command signing payload
// (cpTypes.CommandSigningBytes), so copying the claim through would make the
// controller cryptographically attest to a tenant it never verified. SYNC_DNA is
// addressed to a single steward by its mTLS-verified identity and needs no tenant,
// so the field is left empty exactly as Publisher.PublishCommand leaves it for
// every other command. A tenant may only be attached here if it is resolved from
// controller-side state (the steward registry), never from the heartbeat.
func (h *DNAHandler) HandleHeartbeatRoot(ctx context.Context, stewardID, claimedRoot string) {
	if h.store == nil || h.publisher == nil {
		return
	}

	safeStewardID := logging.SanitizeLogValue(stewardID)

	// Validate the steward-supplied root BEFORE it reaches pendingDeltas or the
	// log sink. Anything but a 64-char lowercase hex SHA-256 digest is rejected:
	// storing arbitrary-length strings per steward is a memory-amplification
	// vector at 50k+ steward scale, and the raw value would otherwise reach the
	// log sink on the attacker-triggered mismatch path.
	if !isValidAggregateRoot(claimedRoot) {
		h.logger.Warn("partial-sync: rejecting malformed aggregate root",
			"steward_id", safeStewardID, "root_length", len(claimedRoot))
		return
	}

	manifest, err := h.store.CurrentManifest(stewardID)
	if err != nil {
		h.logger.Warn("partial-sync: failed to read stored manifest",
			"steward_id", safeStewardID, "error", err)
		return
	}
	if len(manifest) == 0 {
		// No stored manifest — need a full sync first.
		h.logger.Debug("partial-sync: no stored manifest; skipping root check",
			"steward_id", safeStewardID)
		return
	}

	storedRoot, err := sdna.AggregateRoot(manifest)
	if err != nil {
		h.logger.Warn("partial-sync: failed to compute stored root",
			"steward_id", safeStewardID, "error", err)
		return
	}
	if storedRoot == claimedRoot {
		h.logger.Debug("partial-sync: root matches; no sync needed", "steward_id", safeStewardID)
		return
	}

	// Root mismatch. Request all stored fragment IDs — the steward sends them
	// back, the controller recomputes the root from (stored_manifest + delta) and
	// validates it against claimedRoot before committing (ADR-017 §7 step 3).
	fragmentIDs := make([]string, 0, len(manifest))
	for _, entry := range manifest {
		fragmentIDs = append(fragmentIDs, entry.GetFragmentId())
	}
	fragmentIDsJSON, err := json.Marshal(fragmentIDs)
	if err != nil {
		h.logger.Warn("partial-sync: failed to marshal fragment_ids",
			"steward_id", safeStewardID, "error", err)
		return
	}

	// Record the claimed root AND the requested ID set for revalidation when the
	// delta arrives. Both halves are load-bearing: the root proves the merged
	// manifest matches what the steward reported, the ID set bounds which entries
	// the delta is allowed to write at all.
	h.recordDeltaRequest(stewardID, claimedRoot, fragmentIDs)

	// Publish through the command Publisher so the request is signed with the
	// controller's signer and carries a UUID command ID (the steward's replay
	// cache keys on it). An unsigned command is dropped by any steward running
	// with a verifier configured.
	commandID, sendErr := h.publisher.PublishCommand(ctx, stewardID, cpTypes.CommandSyncDNA,
		map[string]interface{}{"fragment_ids": string(fragmentIDsJSON)})
	if sendErr != nil {
		h.logger.Warn("partial-sync: failed to publish SYNC_DNA command",
			"steward_id", safeStewardID, "error", sendErr)
		h.pendingDeltas.Delete(stewardID)
		return
	}
	h.logger.Info("partial-sync: SYNC_DNA command published",
		"steward_id", safeStewardID,
		"command_id", commandID,
		"fragment_count", len(fragmentIDs))
}

// aggregateRootHexLen is the length of a SHA-256 digest rendered as lowercase hex.
const aggregateRootHexLen = 64

// isValidAggregateRoot reports whether s is a well-formed aggregate root: exactly
// 64 lowercase hexadecimal characters, the only encoding sdna.AggregateRoot
// produces (ADR-017 §6).
//
// The root arrives from the steward as an arbitrary, unbounded string. Validating
// it at the boundary keeps attacker-controlled data out of the per-steward
// pendingDeltas map (retained until a delta arrives — a memory-amplification
// vector at 50k+ steward scale) and out of the log sink.
func isValidAggregateRoot(s string) bool {
	if len(s) != aggregateRootHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// HandleGRPC processes a SyncDNA RPC on the shared gRPC-over-QUIC server.
//
// It extracts the steward ID from the peer's mTLS certificate and validates it
// against the steward_id field on the first DNA chunk to close the
// steward-impersonation gap. A mismatch returns codes.PermissionDenied with
// the message "steward ID mismatch" — consistent with ConfigHandler.
//
// Per-tenant back-pressure: after steward ID validation on the first chunk,
// Acquire is called with the chunk's tenant_id. If the tenant's queue is full
// (MaxConcurrentPerTenant in-flight), the RPC is rejected with ResourceExhausted.
//
// Branch on is_delta:
//   - false (full snapshot): reassembled and persisted via the configured DNAPersister.
//   - true (partial delta): fragments are merged with the stored manifest,
//     the aggregate root is recomputed and validated against the steward's last
//     claimed root (SE threat #2), and only then is ApplyDelta called.
func (h *DNAHandler) HandleGRPC(stream grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse]) error {
	ctx := stream.Context()

	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	peerID, err := quictransport.PeerStewardID(tlsInfo.State)
	if err != nil {
		return status.Error(codes.Unauthenticated, "mTLS certificate required")
	}

	// Receive the first chunk to validate steward identity and acquire the
	// per-tenant queue slot before draining the rest of the stream.
	firstChunk, err := stream.Recv()
	if err == io.EOF {
		// Empty stream is accepted without consuming a queue slot.
		h.logger.Info("DNA sync received", "chunks", 0, "peer_id", peerID)
		return stream.SendAndClose(&transportpb.DNASyncResponse{Accepted: true, Message: "accepted"})
	}
	if err != nil {
		return fmt.Errorf("failed to receive DNA chunk: %w", err)
	}

	if firstChunk.GetStewardId() != peerID {
		return status.Error(codes.PermissionDenied, "steward ID mismatch")
	}

	tenantID := firstChunk.GetTenantId()
	if qErr := h.queue.Acquire(tenantID); qErr != nil {
		return status.Error(codes.ResourceExhausted, "tenant queue full")
	}
	defer h.queue.Release(tenantID)

	// Route to delta handler when the first chunk signals is_delta=true.
	if firstChunk.GetIsDelta() {
		return h.handleDeltaGRPC(ctx, stream, firstChunk, peerID)
	}

	// Bound accumulation as chunks arrive so a hostile stream can never buffer more
	// than maxReassembledDNABytes / maxDNAChunks before it is rejected. Checking only
	// after the stream drains would already have paid the memory cost.
	chunks := []*transportpb.DNAChunk{firstChunk}
	payloadBytes := len(firstChunk.GetData())
	for {
		chunk, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return fmt.Errorf("failed to receive DNA chunk: %w", recvErr)
		}
		if len(chunks) >= maxDNAChunks {
			return status.Errorf(codes.ResourceExhausted,
				"DNA snapshot exceeds the %d chunk limit", maxDNAChunks)
		}
		if payloadBytes+len(chunk.GetData()) > maxReassembledDNABytes {
			return status.Errorf(codes.ResourceExhausted,
				"DNA snapshot exceeds the %d byte limit", maxReassembledDNABytes)
		}
		payloadBytes += len(chunk.GetData())
		chunks = append(chunks, chunk)
	}

	h.logger.Info("DNA sync received", "chunks", len(chunks), "peer_id", peerID)

	// No persistence configured (test / degenerate). Accept without reassembly —
	// production always wires a persister (server.go).
	if h.persister == nil {
		h.logger.Warn("DNA sync received but no persister configured; not stored", "peer_id", peerID)
		return stream.SendAndClose(&transportpb.DNASyncResponse{Accepted: true, Message: "accepted"})
	}

	dna, rErr := reassembleDNA(chunks, peerID)
	if rErr != nil {
		return status.Errorf(codes.InvalidArgument, "failed to reassemble DNA: %v", rErr)
	}

	persistStatus, pErr := h.persister.SyncDNA(ctx, dna)
	if pErr != nil {
		return fmt.Errorf("failed to persist synced DNA for %s: %w", peerID, pErr)
	}
	if persistStatus != nil && persistStatus.Code != common.Status_OK {
		return status.Errorf(codes.Unavailable, "DNA persist rejected: %s", persistStatus.Message)
	}

	h.logger.Info("DNA sync persisted", "peer_id", peerID,
		"attributes", dna.GetAttributeCount(), "fragments", len(dna.GetFragments()))

	return stream.SendAndClose(&transportpb.DNASyncResponse{
		Accepted: true,
		Message:  "accepted",
	})
}

// handleDeltaGRPC processes a fragment-delta DNA sync (ADR-017 §7 step 3).
//
// Security invariant (SE threat #2): the aggregate root is recomputed from
// server-side reconstructed state — stored manifest + received fragments — and
// compared to the steward's previously claimed root BEFORE ApplyDelta is called.
// A mismatch (including the withholding attack where the steward sends the correct
// root but omits a changed fragment) is rejected with InvalidArgument.
//
// The root binds to CONTENT, not to steward assertions: every received leaf hash
// is recomputed from its canonical_bytes before the merge (verifyFragmentLeaves),
// so a compromised steward cannot ship mutated bytes under a stale leaf hash to
// pin the reported root and suppress re-sync indefinitely.
//
// Resource invariant: the root check alone does NOT bound what a delta writes —
// the steward picks both the claimed root and the delta content, so the check only
// forces self-consistency. validateDeltaFragments therefore bounds fragment count,
// fragment_id length/charset and total canonical_bytes, and rejects any fragment ID
// the controller did not request, before ApplyDelta touches durable storage.
func (h *DNAHandler) handleDeltaGRPC(ctx context.Context, stream grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse], firstChunk *transportpb.DNAChunk, peerID string) error {
	safePeerID := logging.SanitizeLogValue(peerID)

	chunks := []*transportpb.DNAChunk{firstChunk}
	// A stream may carry any number of chunks, so the reassembly buffer itself
	// needs a cap: without it a steward drives unbounded controller memory growth
	// before a single content check has run.
	streamBytes := len(firstChunk.GetData())
	for {
		chunk, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return fmt.Errorf("failed to receive delta DNA chunk: %w", recvErr)
		}
		streamBytes += len(chunk.GetData())
		if streamBytes > maxDeltaStreamBytes {
			h.logger.Warn("delta rejected — stream exceeds the reassembly limit",
				"peer_id", safePeerID, "limit_bytes", maxDeltaStreamBytes)
			return status.Errorf(codes.ResourceExhausted,
				"delta stream exceeds the %d byte limit", maxDeltaStreamBytes)
		}
		chunks = append(chunks, chunk)
	}

	h.logger.Info("DNA delta received", "chunks", len(chunks), "peer_id", safePeerID)

	transfer, err := reassembleDNATransfer(chunks, peerID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to reassemble delta transfer: %v", err)
	}

	receivedFragments := transfer.Fragments
	if len(receivedFragments) == 0 {
		return status.Error(codes.InvalidArgument, "delta transfer contains no fragments")
	}

	if h.store == nil {
		return status.Error(codes.FailedPrecondition, "partial-sync not configured on this server")
	}

	// Retrieve the outstanding delta request recorded when the heartbeat root
	// mismatched. It carries both the root the steward claimed and the exact
	// fragment ID set the controller asked for.
	pendingRaw, ok := h.pendingDeltas.Load(peerID)
	if !ok {
		return status.Error(codes.FailedPrecondition, "no claimed root on file; send a heartbeat before a delta")
	}
	pending, ok := pendingRaw.(*deltaRequest)
	if !ok || pending == nil {
		h.pendingDeltas.Delete(peerID)
		return status.Error(codes.Internal, "delta request state unusable")
	}

	// Bound every attacker-controlled dimension of the delta BEFORE any of it can
	// reach durable storage: count, per-ID length and charset, total canonical
	// bytes, and membership in the requested ID set.
	if vErr := validateDeltaFragments(receivedFragments, pending.requestedIDs); vErr != nil {
		h.logger.Warn("delta rejected — fragment validation failed",
			"peer_id", safePeerID, "error", vErr)
		return status.Errorf(codes.InvalidArgument, "delta rejected: %v", vErr)
	}

	// Bind every leaf to its content BEFORE the merge. Skipping this would reduce
	// the root check to "the steward is consistent with its own claims".
	if leafErr := verifyFragmentLeaves(receivedFragments); leafErr != nil {
		h.logger.Warn("delta rejected — leaf hash does not match canonical bytes",
			"peer_id", safePeerID, "error", leafErr)
		return status.Errorf(codes.InvalidArgument, "delta rejected: %v", leafErr)
	}

	// Load stored manifest.
	storedManifest, err := h.store.CurrentManifest(peerID)
	if err != nil {
		return fmt.Errorf("failed to load stored manifest for delta validation: %w", err)
	}

	// Build prospective merged manifest (stored + received delta).
	prospective := mergeManifest(storedManifest, receivedFragments)

	// Recompute aggregate root from server-side state — never trust steward-asserted root.
	computedRoot, err := sdna.AggregateRoot(prospective)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to compute merged aggregate root: %v", err)
	}

	claimedRoot := pending.claimedRoot
	if computedRoot != claimedRoot {
		h.logger.Warn("delta revalidation failed — root mismatch (possible withholding attack)",
			"peer_id", safePeerID,
			"computed_root", logging.SanitizeLogValue(computedRoot),
			"claimed_root", logging.SanitizeLogValue(claimedRoot))
		return status.Error(codes.InvalidArgument, "delta revalidation failed: aggregate root mismatch")
	}

	// Root matches — safe to commit the delta.
	if applyErr := h.store.ApplyDelta(peerID, receivedFragments); applyErr != nil {
		return fmt.Errorf("failed to apply delta for %s: %w", safePeerID, applyErr)
	}
	h.pendingDeltas.Delete(peerID)

	// Entity-graph write (Story #2907, ADR-022 §9). Additive alongside ApplyDelta
	// — a write failure emits a warning but does NOT fail the stream or roll back
	// the committed manifest. peerID is the mTLS-verified identity; no fragment
	// field can influence the EID authority segment (SE threat #1).
	if h.egWriter != nil && h.egTaxonomy != nil {
		if egErr := h.egWriter.WriteFragmentDelta(ctx, peerID, receivedFragments, nil, h.egTaxonomy); egErr != nil {
			h.logger.Warn("entity-graph write failed for delta; manifest committed, graph may lag",
				"peer_id", safePeerID, "error", logging.SanitizeLogValue(egErr.Error()))
		}
	}

	h.logger.Info("DNA delta sync accepted",
		"peer_id", safePeerID, "fragment_count", len(receivedFragments))

	return stream.SendAndClose(&transportpb.DNASyncResponse{
		Accepted: true,
		Message:  "accepted",
		NewHash:  computedRoot,
	})
}

// Delta input bounds, enforced at the transport trust boundary. A steward is
// authenticated but may be compromised (CFGMS threat model), and the merge path
// only ever adds or replaces manifest entries — never removes — so an unbounded
// delta grows the controller's durable, tenant-shared manifest permanently.
const (
	// maxDeltaFragments bounds the fragments one delta may carry. It matches the
	// steward-side maxRequestedFragmentIDs cap on the SYNC_DNA fragment_ids list,
	// which is the largest delta an honest steward can ever be asked to produce.
	maxDeltaFragments = 10000

	// maxFragmentIDLen bounds a single fragment_id. Real IDs are taxonomy kinds or
	// authority-qualified paths ("host:cpu", "file:/etc/hosts"); 512 bytes leaves
	// room for long paths while keeping a per-entry storage bound.
	maxFragmentIDLen = 512

	// maxDeltaCanonicalBytes bounds the summed canonical_bytes of one delta,
	// matching the 8 MiB gRPC MaxRecvMsgSize the server applies per chunk. Without
	// an aggregate cap a multi-chunk stream is unbounded.
	maxDeltaCanonicalBytes = 8 << 20

	// maxDeltaStreamBytes bounds the bytes buffered while reassembling one delta
	// stream. canonical_bytes are base64-expanded (4/3) inside the JSON envelope,
	// so this sits above the largest legitimate maxDeltaCanonicalBytes payload
	// while still bounding controller memory per in-flight stream.
	maxDeltaStreamBytes = 32 << 20
)

// validateDeltaFragments enforces the delta input bounds before any received
// fragment can influence stored state.
//
// requestedIDs is the set the controller asked for in its SYNC_DNA command. An
// honest steward answers with exactly that set (it falls back to a full sync when
// it cannot), so rejecting non-members costs nothing functionally and is the only
// thing that stops a compromised steward from inventing fragment IDs — the merge
// never removes an entry, so every invented ID is permanent growth.
func validateDeltaFragments(received []*common.Fragment, requestedIDs map[string]struct{}) error {
	if len(received) > maxDeltaFragments {
		return fmt.Errorf("delta carries %d fragments, limit is %d", len(received), maxDeltaFragments)
	}

	totalBytes := 0
	seen := make(map[string]struct{}, len(received))
	for _, f := range received {
		id := f.GetFragmentId()
		if err := validateFragmentID(id); err != nil {
			return err
		}
		safeID := logging.SanitizeLogValue(id)
		if _, dup := seen[id]; dup {
			return fmt.Errorf("delta repeats fragment %q", safeID)
		}
		seen[id] = struct{}{}
		if _, requested := requestedIDs[id]; !requested {
			return fmt.Errorf("fragment %q was not requested", safeID)
		}
		totalBytes += len(f.GetCanonicalBytes())
		if totalBytes > maxDeltaCanonicalBytes {
			return fmt.Errorf("delta canonical_bytes exceed the %d byte limit", maxDeltaCanonicalBytes)
		}
	}
	return nil
}

// validateFragmentID reports whether a steward-supplied fragment_id is storable:
// non-empty, within maxFragmentIDLen, valid UTF-8, and free of control characters
// (which would otherwise reach storage keys and log records).
func validateFragmentID(id string) error {
	if id == "" {
		return fmt.Errorf("fragment_id must not be empty")
	}
	if len(id) > maxFragmentIDLen {
		return fmt.Errorf("fragment_id length %d exceeds the %d byte limit", len(id), maxFragmentIDLen)
	}
	if !utf8.ValidString(id) {
		return fmt.Errorf("fragment_id is not valid UTF-8")
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("fragment_id contains a control character")
		}
	}
	return nil
}

// verifyFragmentLeaves recomputes each received fragment's leaf hash from its
// canonical_bytes and rejects the delta when the steward-asserted fragment_hash
// disagrees, or when a fragment carries no canonical_bytes to hash.
//
// Without this the aggregate-root revalidation only proves the steward is
// internally consistent with its own claims: a compromised steward (explicitly in
// the CFGMS threat model) could send canonical_bytes for its real, mutated state
// while asserting the leaf hash of the old state, keep the reported root pinned
// forever, and thereby suppress every future re-sync — the same state-forgery
// attack the root check is meant to close, one level down the tree.
func verifyFragmentLeaves(received []*common.Fragment) error {
	for _, f := range received {
		fragmentID := logging.SanitizeLogValue(f.GetFragmentId())
		if len(f.GetCanonicalBytes()) == 0 {
			return fmt.Errorf("fragment %q carries no canonical_bytes to bind its hash to", fragmentID)
		}
		if sdna.FragmentHash(f.GetCanonicalBytes()) != f.GetFragmentHash() {
			return fmt.Errorf("fragment %q asserted hash does not match its canonical_bytes", fragmentID)
		}
	}
	return nil
}

// mergeManifest builds a prospective manifest from the stored entries plus the
// received fragment deltas. Stored entries for received fragment IDs are replaced;
// entries for IDs not present in the delta are kept unchanged.
//
// Leaf hashes are DERIVED from canonical_bytes, never copied from the
// steward-asserted fragment_hash field, so the recomputed aggregate root binds to
// content. verifyFragmentLeaves has already rejected any delta where the two
// disagree; deriving here keeps that invariant true even if a future caller
// forgets the check.
func mergeManifest(stored []*common.ManifestEntry, received []*common.Fragment) []*common.ManifestEntry {
	merged := make(map[string]*common.ManifestEntry, len(stored)+len(received))
	for _, e := range stored {
		merged[e.GetFragmentId()] = e
	}
	for _, f := range received {
		merged[f.GetFragmentId()] = &common.ManifestEntry{
			FragmentId:   f.GetFragmentId(),
			FragmentHash: sdna.FragmentHash(f.GetCanonicalBytes()),
		}
	}
	result := make([]*common.ManifestEntry, 0, len(merged))
	for _, e := range merged {
		result = append(result, e)
	}
	return result
}

// reassembleDNATransfer concatenates chunks (sorted by ChunkIndex) and
// JSON-decodes the payload into a DNATransfer. Called by both the full-snapshot
// path (via reassembleDNA) and the delta path (handleDeltaGRPC).
func reassembleDNATransfer(chunks []*transportpb.DNAChunk, stewardID string) (*dptypes.DNATransfer, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no DNA chunks")
	}
	total := int(chunks[0].GetTotalChunks())
	if total != len(chunks) {
		return nil, fmt.Errorf("chunk count %d does not match total_chunks %d", len(chunks), total)
	}
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].GetChunkIndex() < chunks[j].GetChunkIndex()
	})

	if len(chunks) > maxDNAChunks {
		return nil, fmt.Errorf("chunk count %d exceeds maximum %d", len(chunks), maxDNAChunks)
	}

	var payload []byte
	for i, c := range chunks {
		if int(c.GetChunkIndex()) != i {
			return nil, fmt.Errorf("non-contiguous chunk sequence: expected index %d, got %d", i, c.GetChunkIndex())
		}
		// Bounded before the append so the concatenation itself cannot exceed the cap.
		if len(payload)+len(c.GetData()) > maxReassembledDNABytes {
			return nil, fmt.Errorf("reassembled payload exceeds maximum %d bytes", maxReassembledDNABytes)
		}
		payload = append(payload, c.GetData()...)
	}

	if len(payload) == 0 {
		return &dptypes.DNATransfer{StewardID: stewardID, Delta: chunks[0].GetIsDelta()}, nil
	}

	var transfer dptypes.DNATransfer
	if err := json.Unmarshal(payload, &transfer); err != nil {
		return nil, fmt.Errorf("unmarshal DNATransfer: %w", err)
	}
	return &transfer, nil
}

// reassembleDNA concatenates the chunk payloads (ordered by ChunkIndex) into the
// JSON-encoded DNATransfer the steward streamed, then decodes its FragmentBytes into
// a common.DNA. The wire protocol is Fragments-only: the Attributes field of
// DNATransfer is no longer populated by stewards and is never read here — a
// transfer that carries an Attributes blob anyway has it ignored entirely
// (Issue #3322).
//
// # Why the returned DNA still carries a flat attribute map
//
// The returned common.DNA is not just a decode of the wire: it is the controller's
// canonical steward record. ControllerService.SyncDNA assigns it wholesale
// (steward.DNA = dna), so any field left unset here is *erased* from the record on
// the steward's first full sync. Several controller subsystems still read
// DNA.Attributes and have not yet been re-homed onto DNA.Fragments:
//
//   - role-policy selector matching (features/controller/service/config_service_v2.go
//     → fleet.matchesFilter), which is positive-match only, so a blank map silently
//     stops delivering role config — including security baselines;
//   - fleet inventory, attribute filters and the module list
//     (features/controller/api/handlers_stewards.go);
//   - the DNA fingerprint, attribute projection and attribute index
//     (features/controller/fleet/storage/), which os/platform-scoped patch and
//     vulnerability targeting resolve through;
//   - re-registration change detection, which compares AttributeCount
//     (features/controller/service/controller_service.go).
//
// So the flat map is rebuilt here *from the fragments themselves* via
// sdna.FlattenFragments — the same projection the required-field integrity check
// uses (features/controller/service/dna_integrity.go). The wire stays
// Fragments-only, the fragments stay authoritative, and no consumer goes blank
// mid-migration. When those consumers read fragments directly, this projection and
// the Attributes/AttributeCount fields go away together.
//
// The steward-identity check (firstChunk.GetStewardId() != peerID) is enforced in
// HandleGRPC before this function is called; reassembleDNA receives an
// already-verified stewardID.
func reassembleDNA(chunks []*transportpb.DNAChunk, stewardID string) (*common.DNA, error) {
	transfer, err := reassembleDNATransfer(chunks, stewardID)
	if err != nil {
		return nil, err
	}

	// Fragment count and per-fragment size are bounded BEFORE any decode. A
	// malformed fragment is skipped (rejecting the sync would black-hole an
	// otherwise valid DNA update), but an out-of-bounds count or size is
	// rejected outright: that is not the shape a healthy steward produces, and
	// persisting it would hand the controller a repeatable decode amplifier.
	if len(transfer.FragmentBytes) > maxDNATransferFragments {
		return nil, fmt.Errorf("fragment count %d exceeds maximum %d",
			len(transfer.FragmentBytes), maxDNATransferFragments)
	}
	var frags []*common.Fragment
	for _, fb := range transfer.FragmentBytes {
		if len(fb) > maxDNAFragmentBytes {
			return nil, fmt.Errorf("fragment of %d bytes exceeds maximum %d",
				len(fb), maxDNAFragmentBytes)
		}
		frag := &common.Fragment{}
		if err := proto.Unmarshal(fb, frag); err != nil {
			continue
		}
		frags = append(frags, frag)
	}

	// Flat projection of the fragments, for the not-yet-re-homed consumers listed
	// above. Derived from decoded fragment state — never from transfer.Attributes.
	attrs := sdna.FlattenFragments(frags)
	if len(attrs) > math.MaxInt32 {
		return nil, fmt.Errorf("DNA attribute count exceeds int32 limit")
	}

	// #nosec G115 -- attribute count is explicitly bounded by MaxInt32 above.
	return &common.DNA{
		Id:             stewardID,
		Fragments:      frags,
		Attributes:     attrs,
		AttributeCount: int32(len(attrs)),
	}, nil
}
