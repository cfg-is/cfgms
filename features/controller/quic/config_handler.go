// Package quic provides QUIC stream handlers for controller operations.
package quic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/quic-go/quic-go"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
	quicServer "github.com/cfgis/cfgms/pkg/quic/server"
)

// ConfigSyncStreamID is the stream ID for configuration synchronization.
const ConfigSyncStreamID = 1

// ConfigHandler handles configuration sync over QUIC streams.
type ConfigHandler struct {
	configService *service.ConfigurationService
	logger        logging.Logger
}

// NewConfigHandler creates a new config sync handler.
func NewConfigHandler(configService *service.ConfigurationService, logger logging.Logger) *ConfigHandler {
	return &ConfigHandler{
		configService: configService,
		logger:        logger,
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
	h.logger.Info("Handling config sync request",
		"session_id", session.ID,
		"steward_id", session.StewardID,
		"stream_id", stream.StreamID())

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

	// Send successful response
	resp := &ConfigSyncResponse{
		Success:       true,
		Configuration: string(grpcResp.Config), // Convert bytes to string
		ConfigHash:    grpcResp.Version,        // Use version as config hash
		StatusCode:    "OK",
	}

	h.logger.Info("Configuration sync successful",
		"steward_id", req.StewardID,
		"version", grpcResp.Version)

	return h.sendResponse(stream, resp)
}

// sendResponse sends a response over the QUIC stream.
func (h *ConfigHandler) sendResponse(stream *quic.Stream, resp *ConfigSyncResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if _, err := stream.Write(data); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	return nil
}
