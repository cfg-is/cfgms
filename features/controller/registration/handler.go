// Package registration provides controller-side registration token handling.
//
// This package implements MQTT-based registration using registration tokens.
package registration

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/pkg/logging"
	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
	"github.com/cfgis/cfgms/pkg/registration"
)

// Handler handles steward registration via MQTT using tokens.
type Handler struct {
	broker    mqttInterfaces.Broker
	validator *registration.Validator
	logger    logging.Logger
}

// Config holds registration handler configuration.
type Config struct {
	Broker    mqttInterfaces.Broker
	Validator *registration.Validator
	Logger    logging.Logger
}

// New creates a new registration handler.
func New(cfg *Config) (*Handler, error) {
	if cfg.Broker == nil {
		return nil, fmt.Errorf("MQTT broker is required")
	}
	if cfg.Validator == nil {
		return nil, fmt.Errorf("token validator is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &Handler{
		broker:    cfg.Broker,
		validator: cfg.Validator,
		logger:    cfg.Logger,
	}, nil
}

// RegistrationRequest represents a registration request from steward.
type RegistrationRequest struct {
	Token string `json:"token"`
}

// RegistrationResponse represents the response to a registration request.
type RegistrationResponse struct {
	Success       bool   `json:"success"`
	StewardID     string `json:"steward_id,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	ControllerURL string `json:"controller_url,omitempty"`
	Group         string `json:"group,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Start subscribes to registration requests.
func (h *Handler) Start(ctx context.Context) error {
	// Subscribe to registration requests
	if err := h.broker.Subscribe(ctx, "cfgms/register", 1, h.handleRegistration); err != nil {
		return fmt.Errorf("failed to subscribe to registration topic: %w", err)
	}

	h.logger.Info("Registration handler started", "topic", "cfgms/register")
	return nil
}

// Stop unsubscribes from registration topics.
func (h *Handler) Stop(ctx context.Context) error {
	if err := h.broker.Unsubscribe(ctx, "cfgms/register"); err != nil {
		h.logger.Warn("Failed to unsubscribe from registration topic", "error", err)
	}

	h.logger.Info("Registration handler stopped")
	return nil
}

// handleRegistration handles a registration request from a steward.
func (h *Handler) handleRegistration(topic string, payload []byte, qos byte, retained bool) error {
	var req RegistrationRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		h.logger.Error("Failed to parse registration request", "error", err)
		return fmt.Errorf("failed to parse registration request: %w", err)
	}

	h.logger.Info("Received registration request", "token_prefix", req.Token[:min(len(req.Token), 15)]+"...")

	// Generate steward ID
	stewardID := uuid.New().String()

	// Validate token
	valReq := &registration.TokenValidationRequest{
		Token:     req.Token,
		StewardID: stewardID,
	}

	valResp, err := h.validator.ValidateToken(context.Background(), valReq)
	if err != nil {
		h.logger.Error("Failed to validate token", "error", err)
		return h.sendRegistrationResponse("", &RegistrationResponse{
			Success: false,
			Error:   "internal error",
		})
	}

	if !valResp.Valid {
		h.logger.Warn("Invalid registration token", "reason", valResp.Reason)
		return h.sendRegistrationResponse("", &RegistrationResponse{
			Success: false,
			Error:   valResp.Reason,
		})
	}

	// Generate steward_id with tenant prefix
	stewardID = fmt.Sprintf("%s-%s", valResp.TenantID, uuid.New().String())

	h.logger.Info("Registration successful",
		"steward_id", stewardID,
		"tenant_id", valResp.TenantID,
		"group", valResp.Group)

	// Send success response
	return h.sendRegistrationResponse(stewardID, &RegistrationResponse{
		Success:       true,
		StewardID:     stewardID,
		TenantID:      valResp.TenantID,
		ControllerURL: valResp.ControllerURL,
		Group:         valResp.Group,
	})
}

// sendRegistrationResponse sends a registration response to the steward.
func (h *Handler) sendRegistrationResponse(stewardID string, resp *RegistrationResponse) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Determine response topic
	topic := "cfgms/register/response"
	if stewardID != "" {
		topic = fmt.Sprintf("cfgms/steward/%s/register/response", stewardID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5)
	defer cancel()

	if err := h.broker.Publish(ctx, topic, payload, 1, false); err != nil {
		return fmt.Errorf("failed to publish response: %w", err)
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
