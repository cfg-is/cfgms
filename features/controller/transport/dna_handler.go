// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	common "github.com/cfgis/cfgms/api/proto/common"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	dptypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

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
}

// NewDNAHandler creates a new DNA sync handler. persister may be nil to disable
// persistence (the handler then only receives + validates the stream).
func NewDNAHandler(logger logging.Logger, queue *TenantQueue, persister DNAPersister) *DNAHandler {
	return &DNAHandler{logger: logger, queue: queue, persister: persister}
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
// The full snapshot streamed by the steward (sync_dna is always a full snapshot,
// Delta=false) is reassembled and PERSISTED via the configured DNAPersister —
// without this the controller-initiated reconcile (#2524) would loop forever
// because the synced DNA was never stored (Issue #2616).
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

	chunks := []*transportpb.DNAChunk{firstChunk}
	for {
		chunk, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return fmt.Errorf("failed to receive DNA chunk: %w", recvErr)
		}
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

	h.logger.Info("DNA sync persisted", "peer_id", peerID, "attributes", dna.GetAttributeCount())

	return stream.SendAndClose(&transportpb.DNASyncResponse{
		Accepted: true,
		Message:  "accepted",
	})
}

// reassembleDNA concatenates the chunk payloads (ordered by ChunkIndex) into the
// JSON-encoded DNATransfer the steward streamed, then decodes its Attributes into
// a common.DNA. It mirrors dnaTransferToChunks on the send side: the whole
// DNATransfer is JSON-marshalled and split into ≤64 KB DNAChunk.Data segments,
// and DNATransfer.Attributes is itself the JSON of the attribute map.
func reassembleDNA(chunks []*transportpb.DNAChunk, stewardID string) (*common.DNA, error) {
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

	var payload []byte
	for i, c := range chunks {
		if int(c.GetChunkIndex()) != i {
			return nil, fmt.Errorf("non-contiguous chunk sequence: expected index %d, got %d", i, c.GetChunkIndex())
		}
		payload = append(payload, c.GetData()...)
	}

	attrs := map[string]string{}
	if len(payload) > 0 {
		var transfer dptypes.DNATransfer
		if err := json.Unmarshal(payload, &transfer); err != nil {
			return nil, fmt.Errorf("unmarshal DNATransfer: %w", err)
		}
		if len(transfer.Attributes) > 0 {
			if err := json.Unmarshal(transfer.Attributes, &attrs); err != nil {
				return nil, fmt.Errorf("unmarshal DNA attributes: %w", err)
			}
		}
	}

	return &common.DNA{
		Id:             stewardID,
		Attributes:     attrs,
		AttributeCount: int32(len(attrs)), //nolint:gosec // attribute counts are far below int32 max
	}, nil
}
