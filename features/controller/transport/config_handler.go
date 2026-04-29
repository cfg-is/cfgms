// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package transport provides data plane handlers for controller operations.
package transport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
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

// ConfigSyncRequest represents a configuration sync request over QUIC.
type ConfigSyncRequest struct {
	StewardID string   `json:"steward_id"`
	Modules   []string `json:"modules,omitempty"`
}

// ConfigSyncResponse represents the configuration sync response.
type ConfigSyncResponse struct {
	Success       bool   `json:"success"`
	Configuration string `json:"configuration,omitempty"`
	ConfigHash    string `json:"config_hash,omitempty"`
	Error         string `json:"error,omitempty"`
	StatusCode    string `json:"status_code,omitempty"`
}

// Handle processes configuration sync requests on a raw data plane stream.
// This is the legacy path used by the standalone QUIC provider.
func (h *ConfigHandler) Handle(ctx context.Context, session dataplaneInterfaces.DataPlaneSession, stream dataplaneInterfaces.Stream) error {
	h.logger.Info("Handling config sync request",
		"session_id", session.ID(),
		"peer_id", session.PeerID(),
		"stream_id", stream.ID())

	// Read request from stream
	requestData, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("failed to read request: %w", err)
	}

	var req ConfigSyncRequest
	if err := json.Unmarshal(requestData, &req); err != nil {
		return fmt.Errorf("failed to unmarshal request: %w", err)
	}

	// Validate steward ID matches session
	if req.StewardID != session.PeerID() {
		h.logger.Warn("Steward ID mismatch",
			"request_steward", req.StewardID,
			"session_steward", session.PeerID())

		resp := &ConfigSyncResponse{
			Success:    false,
			Error:      "steward ID mismatch",
			StatusCode: "UNAUTHORIZED",
		}
		return h.sendResponse(stream, resp)
	}

	// Get configuration from service
	grpcReq := &controller.ConfigRequest{
		StewardId: req.StewardID,
		Modules:   req.Modules,
	}

	grpcResp, err := h.configService.GetConfiguration(ctx, grpcReq)
	if err != nil {
		h.logger.Error("Failed to get configuration",
			"steward_id", req.StewardID,
			"error", err)

		resp := &ConfigSyncResponse{
			Success:    false,
			Error:      err.Error(),
			StatusCode: "INTERNAL_ERROR",
		}
		return h.sendResponse(stream, resp)
	}

	// Check status
	if grpcResp.Status.Code != 0 { // 0 = OK
		h.logger.Warn("Configuration request failed",
			"steward_id", req.StewardID,
			"status", grpcResp.Status.Code,
			"message", grpcResp.Status.Message)

		resp := &ConfigSyncResponse{
			Success:    false,
			Error:      grpcResp.Status.Message,
			StatusCode: grpcResp.Status.Code.String(),
		}
		return h.sendResponse(stream, resp)
	}

	// Sign the protobuf configuration if signer is available
	var finalConfig *controller.SignedConfig
	if h.signer != nil {
		// grpcResp.Config contains unsigned StewardConfig wrapped in SignedConfig (signature=nil)
		signed, err := signature.SignProtoConfig(h.signer, grpcResp.Config.Config)
		if err != nil {
			h.logger.Error("Failed to sign configuration",
				"steward_id", req.StewardID,
				"error", err)

			resp := &ConfigSyncResponse{
				Success:    false,
				Error:      "failed to sign configuration",
				StatusCode: "INTERNAL_ERROR",
			}
			return h.sendResponse(stream, resp)
		}
		finalConfig = signed
		h.logger.Info("Configuration signed successfully",
			"steward_id", req.StewardID,
			"algorithm", h.signer.Algorithm(),
			"key_fingerprint", h.signer.KeyFingerprint())
	} else {
		finalConfig = grpcResp.Config
	}

	// Marshal signed protobuf config to bytes
	configBytes, err := proto.Marshal(finalConfig)
	if err != nil {
		h.logger.Error("Failed to marshal signed configuration",
			"steward_id", req.StewardID,
			"error", err)

		resp := &ConfigSyncResponse{
			Success:    false,
			Error:      "failed to marshal configuration",
			StatusCode: "INTERNAL_ERROR",
		}
		return h.sendResponse(stream, resp)
	}

	// Base64 encode protobuf bytes for JSON transport (protobuf is binary, can't be safely passed as JSON string)
	configBase64 := base64.StdEncoding.EncodeToString(configBytes)

	// Send successful response
	resp := &ConfigSyncResponse{
		Success:       true,
		Configuration: configBase64,     // Base64-encoded protobuf
		ConfigHash:    grpcResp.Version, // Use version as config hash
		StatusCode:    "OK",
	}

	h.logger.Info("Configuration sync successful",
		"steward_id", req.StewardID,
		"version", grpcResp.Version,
		"signed", h.signer != nil)

	return h.sendResponse(stream, resp)
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

// sendResponse sends a response over the data plane stream.
func (h *ConfigHandler) sendResponse(stream dataplaneInterfaces.Stream, resp *ConfigSyncResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if _, err := stream.Write(data); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	return nil
}
