// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package transport provides data plane handlers for controller operations.
package transport

import (
	"context"
	"fmt"
	"math"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/service"
	dataplaneTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	transportauth "github.com/cfgis/cfgms/pkg/transport/auth"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// ConfigSyncStreamID is the stream ID for configuration synchronization.
// Client-initiated bidirectional streams use IDs 0, 4, 8, 12... (multiples of 4)
// Stream 0 is handshake, so first data stream is 4.
const ConfigSyncStreamID = 4

// ConfigHandler handles configuration sync over data plane streams.
type ConfigHandler struct {
	configService *service.ConfigurationServiceV2
	logger        logging.Logger
	signer        signature.Signer
}

// NewConfigHandler creates a new config sync handler.
func NewConfigHandler(configService *service.ConfigurationServiceV2, logger logging.Logger, signer signature.Signer) *ConfigHandler {
	return &ConfigHandler{
		configService: configService,
		logger:        logger,
		signer:        signer,
	}
}

// HandleGRPC processes a SyncConfig RPC on the shared gRPC-over-QUIC server.
// This is the gRPC path used by the composite handler (Story #515).
//
// It extracts the steward ID from the request, looks up the configuration,
// signs it if a signer is available, and streams the result as ConfigChunks.
func (h *ConfigHandler) HandleGRPC(ctx context.Context, req *transportpb.ConfigSyncRequest, stream grpc.ServerStreamingServer[transportpb.ConfigChunk]) error {
	stewardID := req.GetStewardId()
	h.logger.Info("Handling gRPC config sync request",
		"steward_id", stewardID,
		"current_version", req.GetCurrentVersion())

	// Validate steward ID against the mTLS peer CN to close the steward-impersonation gap.
	// Try the fast-path first (identity already extracted by auth interceptor), then fall
	// back to raw peer extraction for callers that bypass the interceptor chain.
	var peerID string
	if identity, ok := transportauth.StewardIDFromContext(ctx); ok {
		peerID = identity.StewardID
	} else {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, "mTLS certificate required")
		}
		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			return status.Error(codes.Unauthenticated, "mTLS certificate required")
		}
		id, err := quictransport.PeerStewardID(tlsInfo.State)
		if err != nil {
			return status.Error(codes.Unauthenticated, "mTLS certificate required")
		}
		peerID = id
	}
	if stewardID != peerID {
		return status.Error(codes.PermissionDenied, "steward ID mismatch")
	}

	// Get configuration from service
	configReq := &controller.ConfigRequest{
		StewardId: stewardID,
	}

	configResp, err := h.configService.GetConfiguration(ctx, configReq)
	if err != nil {
		h.logger.Error("Failed to get configuration",
			"steward_id", stewardID,
			"error", err)
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Check status
	if configResp.Status.Code != 0 { // 0 = OK
		h.logger.Warn("Configuration request failed",
			"steward_id", stewardID,
			"status", configResp.Status.Code,
			"message", configResp.Status.Message)
		return fmt.Errorf("configuration request failed: %s", configResp.Status.Message)
	}

	// Sign the protobuf configuration if signer is available
	var finalConfig *controller.SignedConfig
	if h.signer != nil {
		signed, err := signature.SignProtoConfig(h.signer, configResp.Config.Config)
		if err != nil {
			h.logger.Error("Failed to sign configuration", "steward_id", stewardID, "error", err)
			return fmt.Errorf("failed to sign configuration: %w", err)
		}
		finalConfig = signed
		h.logger.Info("Configuration signed successfully",
			"steward_id", stewardID,
			"algorithm", h.signer.Algorithm(),
			"key_fingerprint", h.signer.KeyFingerprint())
	} else {
		finalConfig = configResp.Config
	}

	// Marshal to bytes
	configBytes, err := proto.Marshal(finalConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Chunk and stream
	totalChunks := (len(configBytes) + dataplaneTypes.DefaultChunkSize - 1) / dataplaneTypes.DefaultChunkSize
	if totalChunks == 0 {
		totalChunks = 1
	}
	if totalChunks > math.MaxInt32 {
		return status.Error(codes.ResourceExhausted, "configuration too large to stream")
	}

	for i := 0; i < totalChunks; i++ {
		start := i * dataplaneTypes.DefaultChunkSize
		end := start + dataplaneTypes.DefaultChunkSize
		if end > len(configBytes) {
			end = len(configBytes)
		}

		chunk := &transportpb.ConfigChunk{
			Data:        configBytes[start:end],
			ChunkIndex:  int32(i),           //nolint:gosec // G115: bounded by totalChunks > math.MaxInt32 check above
			TotalChunks: int32(totalChunks), //nolint:gosec // G115: bounded by totalChunks > math.MaxInt32 check above
			Version:     configResp.Version,
		}

		if err := stream.Send(chunk); err != nil {
			return fmt.Errorf("failed to send config chunk %d/%d: %w", i+1, totalChunks, err)
		}
	}

	h.logger.Info("gRPC config sync successful",
		"steward_id", stewardID,
		"version", configResp.Version,
		"chunks", totalChunks,
		"bytes", len(configBytes),
		"signed", h.signer != nil)

	return nil
}
