// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transport

import (
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// DNAHandler handles DNA sync RPCs from stewards.
type DNAHandler struct {
	logger logging.Logger
	queue  *TenantQueue
}

// NewDNAHandler creates a new DNA sync handler.
func NewDNAHandler(logger logging.Logger, queue *TenantQueue) *DNAHandler {
	return &DNAHandler{logger: logger, queue: queue}
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

	chunkCount := 1
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to receive DNA chunk: %w", err)
		}
		chunkCount++
	}

	h.logger.Info("DNA sync received", "chunks", chunkCount, "peer_id", peerID)

	return stream.SendAndClose(&transportpb.DNASyncResponse{
		Accepted: true,
		Message:  "accepted",
	})
}
