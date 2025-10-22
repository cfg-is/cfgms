// Package registration provides steward-side registration using tokens.
package registration

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	mqttClient "github.com/cfgis/cfgms/pkg/mqtt/client"
)

// Client handles steward registration with the controller using tokens.
type Client struct {
	mqtt   *mqttClient.Client
	logger logging.Logger
}

// Config holds registration client configuration.
type Config struct {
	MQTT   *mqttClient.Client
	Logger logging.Logger
}

// New creates a new registration client.
func New(cfg *Config) (*Client, error) {
	if cfg.MQTT == nil {
		return nil, fmt.Errorf("MQTT client is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &Client{
		mqtt:   cfg.MQTT,
		logger: cfg.Logger,
	}, nil
}

// RegistrationRequest represents a registration request to the controller.
type RegistrationRequest struct {
	Token string `json:"token"`
}

// RegistrationResponse represents the response from the controller.
type RegistrationResponse struct {
	Success       bool   `json:"success"`
	StewardID     string `json:"steward_id,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	ControllerURL string `json:"controller_url,omitempty"`
	Group         string `json:"group,omitempty"`
	Error         string `json:"error,omitempty"`

	// HTTP registration fields (Story #198)
	MQTTBroker  string `json:"mqtt_broker,omitempty"`
	QUICAddress string `json:"quic_address,omitempty"`
	ClientCert  string `json:"client_cert,omitempty"`
	ClientKey   string `json:"client_key,omitempty"`
	CACert      string `json:"ca_cert,omitempty"`
}

// Register registers the steward with the controller using a token.
func (c *Client) Register(ctx context.Context, token string) (*RegistrationResponse, error) {
	c.logger.Info("Starting registration with controller",
		"token_prefix", token[:min(len(token), 15)]+"...")

	// Subscribe to registration response (generic topic for unregistered stewards)
	responseCh := make(chan *RegistrationResponse, 1)
	errCh := make(chan error, 1)

	handler := func(topic string, payload []byte) {
		var resp RegistrationResponse
		if err := json.Unmarshal(payload, &resp); err != nil {
			errCh <- fmt.Errorf("failed to parse response: %w", err)
			return
		}
		responseCh <- &resp
	}

	// Subscribe to response topic
	if err := c.mqtt.Subscribe(ctx, "cfgms/register/response", 1, handler); err != nil {
		return nil, fmt.Errorf("failed to subscribe to response: %w", err)
	}
	defer func() { _ = c.mqtt.Unsubscribe(ctx, "cfgms/register/response") }()

	// Publish registration request
	req := RegistrationRequest{
		Token: token,
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	if err := c.mqtt.Publish(ctx, "cfgms/register", payload, 1, false); err != nil {
		return nil, fmt.Errorf("failed to publish registration request: %w", err)
	}

	c.logger.Info("Registration request sent, waiting for response...")

	// Wait for response with timeout
	select {
	case resp := <-responseCh:
		if !resp.Success {
			return nil, fmt.Errorf("registration failed: %s", resp.Error)
		}

		c.logger.Info("Registration successful",
			"steward_id", resp.StewardID,
			"tenant_id", resp.TenantID,
			"group", resp.Group)

		return resp, nil

	case err := <-errCh:
		return nil, err

	case <-ctx.Done():
		return nil, fmt.Errorf("registration timeout")

	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("registration timeout after 30s")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
