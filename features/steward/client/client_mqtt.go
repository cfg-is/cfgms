// Package client provides MQTT+QUIC client functionality for steward-controller communication.
//
// This package implements the steward-side client for communicating with
// the CFGMS controller using MQTT (control plane) and QUIC (data plane).
// It replaces the legacy gRPC-based client (Story #198).
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/logging"
	mqttClient "github.com/cfgis/cfgms/pkg/mqtt/client"
	quicClient "github.com/cfgis/cfgms/pkg/quic/client"
)

// MQTTClient represents the new MQTT+QUIC-based steward client.
type MQTTClient struct {
	mu sync.RWMutex

	// Steward identification
	stewardID string
	tenantID  string
	group     string

	// MQTT client for control plane
	mqtt *mqttClient.Client

	// QUIC client for data plane
	quic *quicClient.Client

	// Registration client
	regClient *registration.Client

	// Command handler
	commandHandler *commands.Handler

	// Connection state
	connected     bool
	mqttConnected bool
	quicConnected bool

	// Heartbeat
	heartbeatInterval time.Duration
	heartbeatStop     chan struct{}

	// Logger
	logger logging.Logger
}

// MQTTConfig holds configuration for the MQTT+QUIC client.
type MQTTConfig struct {
	// ControllerURL is the MQTT broker URL (from registration token)
	ControllerURL string

	// RegistrationToken for initial registration
	RegistrationToken string

	// TLSCertPath for mTLS (optional if using token auth)
	TLSCertPath string

	// HeartbeatInterval for periodic heartbeats
	HeartbeatInterval time.Duration

	// Logger for client logging
	Logger logging.Logger
}

// NewMQTTClient creates a new MQTT+QUIC-based steward client.
func NewMQTTClient(cfg *MQTTConfig) (*MQTTClient, error) {
	if cfg.ControllerURL == "" {
		return nil, fmt.Errorf("controller URL is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	heartbeatInterval := cfg.HeartbeatInterval
	if heartbeatInterval == 0 {
		heartbeatInterval = 30 * time.Second
	}

	return &MQTTClient{
		heartbeatInterval: heartbeatInterval,
		heartbeatStop:     make(chan struct{}),
		logger:            cfg.Logger,
	}, nil
}

// RegisterWithToken registers the steward with the controller using a token.
func (c *MQTTClient) RegisterWithToken(ctx context.Context, token string, mqttBroker string) error {
	c.logger.Info("Starting registration with token", "broker", mqttBroker)

	// Initialize MQTT client for registration
	mqttCfg := &mqttClient.Config{
		BrokerURL: mqttBroker,
		ClientID:  "steward-register-" + token[:8], // Temporary client ID
		Logger:    c.logger,
	}

	mqtt, err := mqttClient.New(mqttCfg)
	if err != nil {
		return fmt.Errorf("failed to create MQTT client: %w", err)
	}

	// Connect to MQTT
	if err := mqtt.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to MQTT: %w", err)
	}

	// Create registration client
	regCfg := &registration.Config{
		Broker: mqtt,
		Logger: c.logger,
	}

	regClient, err := registration.New(regCfg)
	if err != nil {
		mqtt.Disconnect(ctx)
		return fmt.Errorf("failed to create registration client: %w", err)
	}

	// Register with token
	resp, err := regClient.Register(ctx, token)
	if err != nil {
		mqtt.Disconnect(ctx)
		return fmt.Errorf("registration failed: %w", err)
	}

	// Store registration response
	c.mu.Lock()
	c.stewardID = resp.StewardID
	c.tenantID = resp.TenantID
	c.group = resp.Group
	c.mqtt = mqtt
	c.mu.Unlock()

	c.logger.Info("Registration successful",
		"steward_id", c.stewardID,
		"tenant_id", c.tenantID,
		"group", c.group)

	return nil
}

// Connect establishes MQTT and QUIC connections to the controller.
func (c *MQTTClient) Connect(ctx context.Context) error {
	c.logger.Info("Connecting to controller via MQTT+QUIC")

	c.mu.RLock()
	stewardID := c.stewardID
	mqtt := c.mqtt
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered - call RegisterWithToken first")
	}

	if mqtt == nil || !mqtt.IsConnected() {
		return fmt.Errorf("MQTT not connected")
	}

	// Subscribe to command topics
	cmdTopic := fmt.Sprintf("cfgms/steward/%s/commands", stewardID)
	c.logger.Info("Subscribing to commands", "topic", cmdTopic)

	// TODO: Setup command handler and subscribe

	// Initialize QUIC client
	// TODO: Get QUIC address from configuration
	// TODO: Initialize and connect QUIC client

	c.mu.Lock()
	c.connected = true
	c.mqttConnected = true
	c.mu.Unlock()

	// Start heartbeat
	go c.startHeartbeat()

	c.logger.Info("Connected to controller successfully")
	return nil
}

// GetConfiguration retrieves configuration from the controller via QUIC.
func (c *MQTTClient) GetConfiguration(ctx context.Context, modules []string) ([]byte, string, error) {
	c.logger.Info("Requesting configuration via QUIC", "modules", modules)

	c.mu.RLock()
	quic := c.quic
	stewardID := c.stewardID
	c.mu.RUnlock()

	if quic == nil || !quic.IsConnected() {
		return nil, "", fmt.Errorf("QUIC not connected")
	}

	// Open QUIC stream for config sync (stream ID 1)
	stream, err := quic.OpenStream(ctx, 1)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open QUIC stream: %w", err)
	}
	defer quic.CloseStream(1)

	// Create request
	type ConfigRequest struct {
		StewardID string   `json:"steward_id"`
		Modules   []string `json:"modules,omitempty"`
	}

	req := ConfigRequest{
		StewardID: stewardID,
		Modules:   modules,
	}

	// Send request
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	if _, err := (*stream).Write(reqData); err != nil {
		return nil, "", fmt.Errorf("failed to write request: %w", err)
	}

	// Read response
	respData := make([]byte, 10*1024*1024) // 10MB max
	n, err := (*stream).Read(respData)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	type ConfigResponse struct {
		Success       bool   `json:"success"`
		Configuration string `json:"configuration,omitempty"`
		ConfigHash    string `json:"config_hash,omitempty"`
		Error         string `json:"error,omitempty"`
	}

	var resp ConfigResponse
	if err := json.Unmarshal(respData[:n], &resp); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !resp.Success {
		return nil, "", fmt.Errorf("config sync failed: %s", resp.Error)
	}

	c.logger.Info("Configuration retrieved successfully",
		"config_hash", resp.ConfigHash,
		"size", len(resp.Configuration))

	return []byte(resp.Configuration), resp.ConfigHash, nil
}

// SendHeartbeat sends a heartbeat to the controller via MQTT.
func (c *MQTTClient) SendHeartbeat(ctx context.Context, status string, metrics map[string]string) error {
	c.mu.RLock()
	stewardID := c.stewardID
	mqtt := c.mqtt
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered")
	}

	if mqtt == nil {
		return fmt.Errorf("MQTT not connected")
	}

	// Create heartbeat message
	type Heartbeat struct {
		StewardID string            `json:"steward_id"`
		Status    string            `json:"status"`
		Timestamp time.Time         `json:"timestamp"`
		Metrics   map[string]string `json:"metrics,omitempty"`
	}

	hb := Heartbeat{
		StewardID: stewardID,
		Status:    status,
		Timestamp: time.Now(),
		Metrics:   metrics,
	}

	payload, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	// Publish to heartbeat topic
	topic := fmt.Sprintf("cfgms/steward/%s/heartbeat", stewardID)
	if err := mqtt.Publish(ctx, topic, payload, 1, false); err != nil {
		return fmt.Errorf("failed to publish heartbeat: %w", err)
	}

	return nil
}

// PublishDNAUpdate publishes DNA changes to the controller via MQTT.
func (c *MQTTClient) PublishDNAUpdate(ctx context.Context, dna map[string]string, configHash, syncFingerprint string) error {
	c.mu.RLock()
	stewardID := c.stewardID
	mqtt := c.mqtt
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered")
	}

	if mqtt == nil {
		return fmt.Errorf("MQTT not connected")
	}

	// Create DNA update message
	type DNAUpdate struct {
		StewardID       string            `json:"steward_id"`
		Timestamp       time.Time         `json:"timestamp"`
		DNA             map[string]string `json:"dna"`
		ConfigHash      string            `json:"config_hash,omitempty"`
		SyncFingerprint string            `json:"sync_fingerprint,omitempty"`
	}

	update := DNAUpdate{
		StewardID:       stewardID,
		Timestamp:       time.Now(),
		DNA:             dna,
		ConfigHash:      configHash,
		SyncFingerprint: syncFingerprint,
	}

	payload, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("failed to marshal DNA update: %w", err)
	}

	// Publish to DNA topic
	topic := fmt.Sprintf("cfgms/steward/%s/dna", stewardID)
	if err := mqtt.Publish(ctx, topic, payload, 1, false); err != nil {
		return fmt.Errorf("failed to publish DNA update: %w", err)
	}

	c.logger.Info("Published DNA update", "attributes_count", len(dna))
	return nil
}

// Disconnect closes all connections to the controller.
func (c *MQTTClient) Disconnect(ctx context.Context) error {
	c.logger.Info("Disconnecting from controller")

	c.mu.Lock()
	defer c.mu.Unlock()

	// Stop heartbeat
	close(c.heartbeatStop)

	// Disconnect QUIC
	if c.quic != nil {
		if err := c.quic.Disconnect(); err != nil {
			c.logger.Warn("Failed to disconnect QUIC", "error", err)
		}
	}

	// Disconnect MQTT
	if c.mqtt != nil {
		if err := c.mqtt.Disconnect(ctx); err != nil {
			c.logger.Warn("Failed to disconnect MQTT", "error", err)
		}
	}

	c.connected = false
	c.mqttConnected = false
	c.quicConnected = false

	c.logger.Info("Disconnected from controller")
	return nil
}

// IsConnected returns whether the client is connected.
func (c *MQTTClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected && c.mqttConnected
}

// GetStewardID returns the steward ID.
func (c *MQTTClient) GetStewardID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stewardID
}

// GetTenantID returns the tenant ID.
func (c *MQTTClient) GetTenantID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tenantID
}

// startHeartbeat starts the periodic heartbeat goroutine.
func (c *MQTTClient) startHeartbeat() {
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.heartbeatStop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := c.SendHeartbeat(ctx, "healthy", nil); err != nil {
				c.logger.Warn("Failed to send heartbeat", "error", err)
			}
			cancel()
		}
	}
}
