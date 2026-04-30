// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transport

import (
	"fmt"
	"io"

	"google.golang.org/grpc"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/logging"
)

// BulkHandler handles bulk transfer RPCs.
//
// BulkChunk carries no steward_id or tenant_id fields; mTLS enforced by the
// gRPC server is the auth boundary for bulk RPCs. No field-level identity
// cross-check is performed here.
type BulkHandler struct {
	logger logging.Logger
}

// NewBulkHandler creates a new bulk transfer handler.
func NewBulkHandler(logger logging.Logger) *BulkHandler {
	return &BulkHandler{logger: logger}
}

// HandleGRPC processes a BulkTransfer RPC on the shared gRPC-over-QUIC server.
func (h *BulkHandler) HandleGRPC(stream grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
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
