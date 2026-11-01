// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
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

// BulkHandler handles bulk transfer RPCs.
//
// BulkChunk carries no steward_id or tenant_id fields; mTLS enforced by the
// gRPC server is the auth boundary for bulk RPCs. No field-level identity
// cross-check is performed here.
//
// Per-tenant back-pressure uses the mTLS peer CN as the queue key. If the
// peer CN is unavailable (e.g. in unit tests without mTLS), the empty string
// is used so that no request is rejected purely due to missing context.
type BulkHandler struct {
	logger logging.Logger
	queue  *TenantQueue
}

// NewBulkHandler creates a new bulk transfer handler.
func NewBulkHandler(logger logging.Logger, queue *TenantQueue) *BulkHandler {
	return &BulkHandler{logger: logger, queue: queue}
}

// HandleGRPC processes a BulkTransfer RPC on the shared gRPC-over-QUIC server.
func (h *BulkHandler) HandleGRPC(stream grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
	// Use the mTLS peer CN as the per-tenant queue key. BulkChunk carries no
	// identity fields; the peer cert is the sole identity source for bulk RPCs.
	queueKey := peerCNFromContext(stream.Context())
	if qErr := h.queue.Acquire(queueKey); qErr != nil {
		return status.Error(codes.ResourceExhausted, "tenant queue full")
	}
	defer h.queue.Release(queueKey)

	var chunkCount int
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to receive bulk chunk: %w", err)
		}
		chunkCount++
	}

	h.logger.Info("Bulk transfer received", "chunks", chunkCount)
	return nil
}

// peerCNFromContext extracts the mTLS peer CN from ctx. Returns "" if peer
// info or TLS credentials are not present — this keeps unit tests without mTLS
// working and routes them to a shared default slot rather than failing.
func peerCNFromContext(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ""
	}
	id, err := quictransport.PeerStewardID(tlsInfo.State)
	if err != nil {
		return ""
	}
	return id
}
