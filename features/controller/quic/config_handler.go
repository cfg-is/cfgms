// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package quic provides QUIC stream handlers for controller operations.
package quic

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
	quicServer "github.com/cfgis/cfgms/pkg/quic/server"
)

// ConfigSyncStreamID is the stream ID for configuration synchronization.
// Client-initiated bidirectional streams use IDs 0, 4, 8, 12... (multiples of 4)
// Stream 0 is handshake, so first data stream is 4.
const ConfigSyncStreamID = 4

// ConfigHandler handles configuration sync over QUIC streams.
type ConfigHandler struct {
	configService *service.ConfigurationService
	logger        logging.Logger
	signer        signature.Signer
}

// NewConfigHandler creates a new config sync handler.
func NewConfigHandler(configService *service.ConfigurationService, logger logging.Logger, signer signature.Signer) *ConfigHandler {
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

// Handle processes configuration sync requests on a QUIC stream.
func (h *ConfigHandler) Handle(ctx context.Context, session *quicServer.Session, stream *quic.Stream) error {
	fmt.Printf("[DEBUG] ConfigHandler.Handle() called, session_id=%s steward_id=%s stream_id=%d\n",
		session.ID, session.StewardID, (*stream).StreamID())
	h.logger.Info("Handling config sync request",
		"session_id", session.ID,
		"steward_id", session.StewardID,
		"stream_id", stream.StreamID())

	// Read request from stream
	fmt.Printf("[DEBUG] ConfigHandler reading from stream...\n")
	requestData, err := io.ReadAll(stream)
	if err != nil {
		fmt.Printf("[DEBUG] ConfigHandler read failed: %v\n", err)
		return fmt.Errorf("failed to read request: %w", err)
	}
	fmt.Printf("[DEBUG] ConfigHandler read %d bytes from stream\n", len(requestData))

	var req ConfigSyncRequest
	fmt.Printf("[DEBUG] ConfigHandler unmarshaling request...\n")
	if err := json.Unmarshal(requestData, &req); err != nil {
		fmt.Printf("[DEBUG] ConfigHandler unmarshal failed: %v\n", err)
		return fmt.Errorf("failed to unmarshal request: %w", err)
	}
	fmt.Printf("[DEBUG] ConfigHandler unmarshaled request: steward_id=%s modules=%v\n", req.StewardID, req.Modules)

	// Validate steward ID matches session
	fmt.Printf("[DEBUG] ConfigHandler validating steward ID: request=%s session=%s\n", req.StewardID, session.StewardID)
	if req.StewardID != session.StewardID {
		h.logger.Warn("Steward ID mismatch",
			"request_steward", req.StewardID,
			"session_steward", session.StewardID)

		resp := &ConfigSyncResponse{
			Success:    false,
			Error:      "steward ID mismatch",
			StatusCode: "UNAUTHORIZED",
		}
		return h.sendResponse(stream, resp)
	}

	// Get configuration from service
	fmt.Printf("[DEBUG] ConfigHandler creating config request for steward_id=%s\n", req.StewardID)
	grpcReq := &controller.ConfigRequest{
		StewardId: req.StewardID,
		Modules:   req.Modules,
	}

	fmt.Printf("[DEBUG] ConfigHandler calling GetConfiguration...\n")
	grpcResp, err := h.configService.GetConfiguration(ctx, grpcReq)
	fmt.Printf("[DEBUG] ConfigHandler GetConfiguration returned: err=%v\n", err)
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
	fmt.Printf("[DEBUG] ConfigHandler signer nil=%v\n", h.signer == nil)
	if h.signer != nil {
		// grpcResp.Config contains unsigned StewardConfig wrapped in SignedConfig (signature=nil)
		fmt.Printf("[DEBUG] ConfigHandler signing protobuf configuration with algorithm=%s\n", h.signer.Algorithm())
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
		fmt.Printf("[DEBUG] ConfigHandler signed successfully\n")
		h.logger.Info("Configuration signed successfully",
			"steward_id", req.StewardID,
			"algorithm", h.signer.Algorithm(),
			"key_fingerprint", h.signer.KeyFingerprint())
	} else {
		fmt.Printf("[DEBUG] ConfigHandler no signer available, sending unsigned config\n")
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
	fmt.Printf("[DEBUG] ConfigHandler preparing response: config_size=%d signed=%v base64_size=%d\n", len(configBytes), h.signer != nil, len(configBase64))
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

// sendResponse sends a response over the QUIC stream.
func (h *ConfigHandler) sendResponse(stream *quic.Stream, resp *ConfigSyncResponse) error {
	fmt.Printf("[DEBUG] ConfigHandler sendResponse called: success=%v error=%s\n", resp.Success, resp.Error)
	data, err := json.Marshal(resp)
	if err != nil {
		fmt.Printf("[DEBUG] ConfigHandler marshal failed: %v\n", err)
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	fmt.Printf("[DEBUG] ConfigHandler marshaled response: %d bytes\n", len(data))

	fmt.Printf("[DEBUG] ConfigHandler writing response to stream...\n")
	if _, err := stream.Write(data); err != nil {
		fmt.Printf("[DEBUG] ConfigHandler write failed: %v\n", err)
		return fmt.Errorf("failed to write response: %w", err)
	}
	fmt.Printf("[DEBUG] ConfigHandler response written successfully\n")

	return nil
}
