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
}

// NewDNAHandler creates a new DNA sync handler.
func NewDNAHandler(logger logging.Logger) *DNAHandler {
	return &DNAHandler{logger: logger}
}

// HandleGRPC processes a SyncDNA RPC on the shared gRPC-over-QUIC server.
//
// It extracts the steward ID from the peer's mTLS certificate and validates it
// against the steward_id field on the first DNA chunk to close the
// steward-impersonation gap. A mismatch returns codes.PermissionDenied with
// the message "steward ID mismatch" — consistent with ConfigHandler.
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

	var chunkCount int
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to receive DNA chunk: %w", err)
		}

		// Validate the steward ID in the first chunk against the mTLS peer CN.
		if chunkCount == 0 {
			if chunk.GetStewardId() != peerID {
				return status.Error(codes.PermissionDenied, "steward ID mismatch")
			}
		}
		chunkCount++
	}

	h.logger.Info("DNA sync received", "chunks", chunkCount, "peer_id", peerID)

	return stream.SendAndClose(&transportpb.DNASyncResponse{
		Accepted: true,
		Message:  "accepted",
	})
}
