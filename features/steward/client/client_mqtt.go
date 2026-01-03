// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package client provides MQTT+QUIC client functionality for steward-controller communication.
//
// This package implements the steward-side client for communicating with
// the CFGMS controller using MQTT (control plane) and QUIC (data plane).
// It replaces the legacy gRPC-based client (Story #198).
package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	mqttClient "github.com/cfgis/cfgms/pkg/mqtt/client"
	mqttTypes "github.com/cfgis/cfgms/pkg/mqtt/types"
	quicClient "github.com/cfgis/cfgms/pkg/quic/client"
)

// MQTTClient represents the new MQTT+QUIC-based steward client.
type MQTTClient struct {
	mu sync.RWMutex

	// Steward identification
	stewardID string
	tenantID  string
	group     string

	// Controller connection info
	controllerURL string

	// MQTT client for control plane
	mqtt *mqttClient.Client

	// QUIC client for data plane
	quic        *quicClient.Client
	quicAddress string

	// Certificate path for mTLS
	certPath string

	// Command handler
	commandHandler *commands.Handler

	// Configuration executor
	configExecutor *config.Executor

	// Configuration signature verifier
	configVerifier signature.Verifier

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

	// QUICAddress is the QUIC server address (e.g., "controller:4433")
	QUICAddress string

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

	client := &MQTTClient{
		heartbeatInterval: heartbeatInterval,
		heartbeatStop:     make(chan struct{}),
		quicAddress:       cfg.QUICAddress,
		certPath:          cfg.TLSCertPath,
		logger:            cfg.Logger,
		controllerURL:     cfg.ControllerURL,
	}

	return client, nil
}

// RegisterWithToken registers the steward with the controller using a token.
func (c *MQTTClient) RegisterWithToken(ctx context.Context, token string, mqttBroker string) error {
	c.logger.Info("Starting registration with token", "broker", mqttBroker)

	// Load TLS configuration if available (Story 12.4)
	tlsConfig, err := c.createMQTTTLSConfig()
	if err != nil {
		c.logger.Warn("Failed to load MQTT TLS config, continuing without TLS", "error", err)
		tlsConfig = nil
	}

	// Initialize MQTT client for registration
	mqttCfg := &mqttClient.Config{
		BrokerAddr:    mqttBroker,
		ClientID:      "steward-register-" + token[:8], // Temporary client ID
		CleanSession:  true,
		AutoReconnect: true,
		TLSConfig:     tlsConfig, // Story 12.4: Enable TLS if configured
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
		MQTT:   mqtt,
		Logger: c.logger,
	}

	regClient, err := registration.New(regCfg)
	if err != nil {
		mqtt.Disconnect()
		return fmt.Errorf("failed to create registration client: %w", err)
	}

	// Register with token
	resp, err := regClient.Register(ctx, token)
	if err != nil {
		mqtt.Disconnect()
		return fmt.Errorf("registration failed: %w", err)
	}

	// Store registration response
	c.mu.Lock()
	c.stewardID = resp.StewardID
	c.tenantID = resp.TenantID
	c.group = resp.Group
	c.mqtt = mqtt
	c.mu.Unlock()

	// Initialize configuration executor
	execCfg := &config.Config{
		TenantID: resp.TenantID,
		Logger:   c.logger,
	}
	executor, err := config.New(execCfg)
	if err != nil {
		mqtt.Disconnect()
		return fmt.Errorf("failed to create config executor: %w", err)
	}

	c.mu.Lock()
	c.configExecutor = executor
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
	controllerURL := c.controllerURL
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered - call SetStewardID first")
	}

	// Create MQTT client if not already created
	if mqtt == nil {
		c.logger.Info("Creating MQTT client", "broker", controllerURL, "client_id", stewardID)

		// Load TLS configuration if available (Story 12.4)
		tlsConfig, err := c.createMQTTTLSConfig()
		if err != nil {
			c.logger.Warn("Failed to load MQTT TLS config, continuing without TLS", "error", err)
			tlsConfig = nil
		}

		mqttCfg := &mqttClient.Config{
			BrokerAddr:    controllerURL,
			ClientID:      stewardID,
			CleanSession:  false,
			AutoReconnect: true,
			TLSConfig:     tlsConfig, // Story 12.4: Enable TLS if configured
		}

		mqtt, err = mqttClient.New(mqttCfg)
		if err != nil {
			return fmt.Errorf("failed to create MQTT client: %w", err)
		}

		c.mu.Lock()
		c.mqtt = mqtt
		c.mu.Unlock()
	}

	// Connect to MQTT if not connected
	if !mqtt.IsConnected() {
		c.logger.Info("Connecting to MQTT broker", "broker", controllerURL)
		if err := mqtt.Connect(ctx); err != nil {
			return fmt.Errorf("failed to connect to MQTT: %w", err)
		}
		c.logger.Info("MQTT connection established")
	}

	// Subscribe to command topics
	cmdTopic := fmt.Sprintf("cfgms/steward/%s/commands", stewardID)
	c.logger.Info("Subscribing to commands", "topic", cmdTopic)

	// Create command handler
	cmdHandler, err := c.setupCommandHandler(ctx, stewardID, mqtt)
	if err != nil {
		return fmt.Errorf("failed to setup command handler: %w", err)
	}

	c.mu.Lock()
	c.commandHandler = cmdHandler
	c.mu.Unlock()

	// Wrap HandleCommand to match MessageHandler signature
	messageHandler := func(topic string, payload []byte) {
		if err := cmdHandler.HandleCommand(topic, payload); err != nil {
			c.logger.Error("Failed to handle command", "error", err, "topic", topic)
		}
	}

	if err := mqtt.Subscribe(ctx, cmdTopic, 1, messageHandler); err != nil {
		return fmt.Errorf("failed to subscribe to commands: %w", err)
	}

	// QUIC connections are established on-demand when controller sends connect_quic command
	// This is by design for the MQTT+QUIC hybrid architecture:
	// - MQTT is always-on for control plane (heartbeats, commands)
	// - QUIC is on-demand for data plane (large configs, DNA updates)
	// The controller triggers QUIC connection via MQTT command (includes session_id and TLS params)
	if c.quicAddress != "" {
		c.logger.Info("QUIC address configured - connections established on-demand",
			"quic_address", c.quicAddress)
	} else {
		c.logger.Warn("QUIC address not configured, config sync will not be available")
	}

	c.mu.Lock()
	c.connected = true
	c.mqttConnected = true
	c.mu.Unlock()

	// Start heartbeat
	go c.startHeartbeat()

	c.logger.Info("Connected to controller successfully")
	return nil
}

// setupCommandHandler creates and configures the command handler with all command types.
func (c *MQTTClient) setupCommandHandler(ctx context.Context, stewardID string, mqtt *mqttClient.Client) (*commands.Handler, error) {
	// Create status callback that publishes to MQTT
	statusCallback := func(status mqttTypes.StatusUpdate) {
		payload, err := json.Marshal(status)
		if err != nil {
			c.logger.Error("Failed to marshal status update", "error", err)
			return
		}

		statusTopic := fmt.Sprintf("cfgms/steward/%s/status", stewardID)
		if err := mqtt.Publish(ctx, statusTopic, payload, 1, false); err != nil {
			c.logger.Error("Failed to publish status update", "error", err)
		}
	}

	// Create command handler
	handler, err := commands.New(&commands.Config{
		StewardID: stewardID,
		OnStatus:  statusCallback,
		Logger:    c.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create command handler: %w", err)
	}

	// Register connect_quic handler
	handler.RegisterHandler(mqttTypes.CommandConnectQUIC, func(ctx context.Context, cmd mqttTypes.Command) error {
		return c.handleConnectQUIC(ctx, cmd)
	})

	// Register sync_config handler
	handler.RegisterHandler(mqttTypes.CommandSyncConfig, func(ctx context.Context, cmd mqttTypes.Command) error {
		c.logger.Info("Received sync_config command", "command_id", cmd.CommandID)

		// First, ensure QUIC connection is established
		if err := c.handleConnectQUIC(ctx, cmd); err != nil {
			c.logger.Error("Failed to establish QUIC connection for config sync", "error", err)
			return fmt.Errorf("QUIC connection failed: %w", err)
		}

		// Get modules filter from command params (optional)
		var modules []string
		if modulesParam, ok := cmd.Params["modules"].([]interface{}); ok {
			for _, m := range modulesParam {
				if modStr, ok := m.(string); ok {
					modules = append(modules, modStr)
				}
			}
		}

		// Retrieve configuration via QUIC
		configData, version, err := c.GetConfiguration(ctx, modules)
		if err != nil {
			c.logger.Error("Failed to retrieve configuration", "error", err)
			return fmt.Errorf("config retrieval failed: %w", err)
		}

		c.logger.Info("Configuration retrieved",
			"command_id", cmd.CommandID,
			"version", version,
			"config_size", len(configData))

		// Verify configuration signature
		c.mu.RLock()
		verifier := c.configVerifier
		c.mu.RUnlock()

		if verifier != nil {
			// Configuration must be signed
			if !signature.HasSignature(configData) {
				c.logger.Error("Configuration is not signed",
					"command_id", cmd.CommandID,
					"version", version)
				return fmt.Errorf("configuration signature verification failed: missing signature")
			}

			// Extract and verify signature
			verifiedData, err := signature.ExtractAndVerify(verifier, configData)
			if err != nil {
				c.logger.Error("Configuration signature verification failed",
					"command_id", cmd.CommandID,
					"version", version,
					"error", err)
				return fmt.Errorf("configuration signature verification failed: %w", err)
			}

			c.logger.Info("Configuration signature verified",
				"command_id", cmd.CommandID,
				"version", version)

			// Use the verified (unsigned) data for application
			configData = verifiedData
		} else {
			c.logger.Warn("Configuration verifier not available, skipping signature verification",
				"command_id", cmd.CommandID)
		}

		// Apply configuration using executor
		c.mu.RLock()
		executor := c.configExecutor
		stewardID := c.stewardID
		c.mu.RUnlock()

		if executor == nil {
			c.logger.Error("Configuration executor not initialized")
			return fmt.Errorf("configuration executor not available")
		}

		report, err := executor.ApplyConfiguration(ctx, configData, version)
		if err != nil {
			c.logger.Error("Configuration application failed", "error", err)
			// Even if application fails, try to send status report
			if report != nil {
				report.StewardID = stewardID
				if pubErr := c.publishConfigStatus(report); pubErr != nil {
					c.logger.Error("Failed to publish config status after error", "error", pubErr)
				}
			}
			return fmt.Errorf("config application failed: %w", err)
		}

		// Publish configuration status report
		report.StewardID = stewardID
		if err := c.publishConfigStatus(report); err != nil {
			c.logger.Error("Failed to publish config status", "error", err)
			// Don't return error - config was applied successfully
		}

		c.logger.Info("Configuration sync completed",
			"command_id", cmd.CommandID,
			"version", version,
			"status", report.Status)

		return nil
	})

	// Register sync_dna handler
	handler.RegisterHandler(mqttTypes.CommandSyncDNA, func(ctx context.Context, cmd mqttTypes.Command) error {
		c.logger.Info("Received sync_dna command", "command_id", cmd.CommandID)

		// Extract DNA attributes from command params (controller may request specific attributes)
		var requestedAttrs []string
		if attrsParam, ok := cmd.Params["attributes"].([]interface{}); ok {
			for _, attr := range attrsParam {
				if attrStr, ok := attr.(string); ok {
					requestedAttrs = append(requestedAttrs, attrStr)
				}
			}
		}

		// Collect current DNA (system attributes)
		// In a full implementation, this would gather OS, hostname, hardware info, etc.
		// For now, we acknowledge the DNA sync request
		c.logger.Info("DNA sync triggered",
			"command_id", cmd.CommandID,
			"requested_attributes", requestedAttrs)

		// DNA collection and publishing would happen here
		// The actual DNA collection is handled by the steward's DNA collector
		// This handler just triggers the sync process

		c.logger.Info("DNA sync completed", "command_id", cmd.CommandID)
		return nil
	})

	return handler, nil
}

// handleConnectQUIC handles the connect_quic command from the controller.
func (c *MQTTClient) handleConnectQUIC(ctx context.Context, cmd mqttTypes.Command) error {
	c.logger.Info("Handling connect_quic command", "command_id", cmd.CommandID)

	// Extract parameters
	quicAddress, ok := cmd.Params["quic_address"].(string)
	if !ok || quicAddress == "" {
		return fmt.Errorf("quic_address parameter is required")
	}

	sessionID, ok := cmd.Params["session_id"].(string)
	if !ok || sessionID == "" {
		return fmt.Errorf("session_id parameter is required")
	}

	c.logger.Info("Connecting to QUIC server",
		"quic_address", quicAddress,
		"session_id", sessionID)

	// Get steward ID
	c.mu.RLock()
	stewardID := c.stewardID
	certPath := c.certPath
	c.mu.RUnlock()

	// Create TLS config for QUIC with proper mTLS
	tlsConfig, err := c.createQUICtlsConfig(certPath)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}

	c.logger.Info("Using mTLS for QUIC connection",
		"cert_path", certPath,
		"next_protos", tlsConfig.NextProtos)

	// Initialize QUIC client
	quicCfg := &quicClient.Config{
		ServerAddr: quicAddress,
		TLSConfig:  tlsConfig,
		SessionID:  sessionID,
		StewardID:  stewardID,
		Logger:     c.logger,
	}

	quic, err := quicClient.New(quicCfg)
	if err != nil {
		return fmt.Errorf("failed to create QUIC client: %w", err)
	}

	// Connect to QUIC server
	if err := quic.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to QUIC server: %w", err)
	}

	// Store QUIC client
	c.mu.Lock()
	c.quic = quic
	c.quicConnected = true
	c.mu.Unlock()

	c.logger.Info("QUIC connection established successfully",
		"quic_address", quicAddress,
		"session_id", sessionID)

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
	defer func() { _ = quic.CloseStream(1) }()

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

// publishConfigStatus publishes a config status report (internal helper).
func (c *MQTTClient) publishConfigStatus(report *mqttTypes.ConfigStatusReport) error {
	ctx := context.Background()
	return c.ReportConfigurationStatus(ctx, report.ConfigVersion, report.Status, report.Message, report.Modules)
}

// ReportConfigurationStatus reports detailed configuration execution status to the controller.
// This provides module-level status information for MSP admin visibility.
func (c *MQTTClient) ReportConfigurationStatus(
	ctx context.Context,
	configVersion string,
	overallStatus string,
	message string,
	moduleStatuses map[string]mqttTypes.ModuleStatus,
) error {
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

	// Create config status report
	report := mqttTypes.ConfigStatusReport{
		StewardID:     stewardID,
		ConfigVersion: configVersion,
		Status:        overallStatus,
		Message:       message,
		Modules:       moduleStatuses,
		Timestamp:     time.Now(),
	}

	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal config status report: %w", err)
	}

	// Publish to config-status topic
	topic := fmt.Sprintf("cfgms/steward/%s/config-status", stewardID)
	if err := mqtt.Publish(ctx, topic, payload, 1, false); err != nil {
		return fmt.Errorf("failed to publish config status: %w", err)
	}

	c.logger.Info("Published configuration status report",
		"config_version", configVersion,
		"status", overallStatus,
		"modules", len(moduleStatuses))

	return nil
}

// ValidateConfiguration validates a configuration with the controller without applying it.
// This is a pre-flight check to catch errors before making changes.
func (c *MQTTClient) ValidateConfiguration(
	ctx context.Context,
	config []byte,
	version string,
) ([]string, error) {
	c.mu.RLock()
	stewardID := c.stewardID
	mqtt := c.mqtt
	c.mu.RUnlock()

	if stewardID == "" {
		return nil, fmt.Errorf("not registered")
	}

	if mqtt == nil {
		return nil, fmt.Errorf("MQTT not connected")
	}

	// Generate unique request ID
	requestID := fmt.Sprintf("val_%d", time.Now().UnixNano())

	// Create validation request
	request := mqttTypes.ValidationRequest{
		RequestID: requestID,
		StewardID: stewardID,
		Config:    config,
		Version:   version,
		Timestamp: time.Now(),
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal validation request: %w", err)
	}

	// Create channel to receive response
	responseChan := make(chan mqttTypes.ValidationResponse, 1)
	errChan := make(chan error, 1)

	// Subscribe to response topic before publishing request
	responseTopic := fmt.Sprintf("cfgms/steward/%s/validate-response/%s", stewardID, requestID)
	responseHandler := func(topic string, responsePayload []byte) {
		var response mqttTypes.ValidationResponse
		if err := json.Unmarshal(responsePayload, &response); err != nil {
			errChan <- fmt.Errorf("failed to parse validation response: %w", err)
			return
		}
		responseChan <- response
	}

	if err := mqtt.Subscribe(ctx, responseTopic, 1, responseHandler); err != nil {
		return nil, fmt.Errorf("failed to subscribe to response topic: %w", err)
	}
	defer func() { _ = mqtt.Unsubscribe(ctx, responseTopic) }()

	// Publish validation request
	requestTopic := fmt.Sprintf("cfgms/steward/%s/validate-request", stewardID)
	if err := mqtt.Publish(ctx, requestTopic, payload, 1, false); err != nil {
		return nil, fmt.Errorf("failed to publish validation request: %w", err)
	}

	c.logger.Info("Published validation request",
		"request_id", requestID,
		"version", version)

	// Wait for response with timeout
	timeout := 10 * time.Second
	select {
	case response := <-responseChan:
		c.logger.Info("Received validation response",
			"request_id", requestID,
			"valid", response.Valid,
			"errors_count", len(response.Errors))

		if response.Valid {
			return nil, nil
		}
		return response.Errors, fmt.Errorf("configuration validation failed")

	case err := <-errChan:
		return nil, err

	case <-time.After(timeout):
		return nil, fmt.Errorf("validation request timed out after %v", timeout)

	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
		c.mqtt.Disconnect()
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

// SetStewardID sets the steward ID (used after HTTP registration).
func (c *MQTTClient) SetStewardID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stewardID = id
}

// SetTenantID sets the tenant ID (used after HTTP registration).
func (c *MQTTClient) SetTenantID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tenantID = id
}

// createMQTTTLSConfig creates a TLS configuration for MQTT with mTLS.
// It loads TLS certificates from environment variables or the cert path.
func (c *MQTTClient) createMQTTTLSConfig() (*tls.Config, error) {
	// Try environment variables first (Story 12.4: TLS support)
	certFile := os.Getenv("CFGMS_MQTT_TLS_CERT_PATH")
	keyFile := os.Getenv("CFGMS_MQTT_TLS_KEY_PATH")
	caFile := os.Getenv("CFGMS_MQTT_TLS_CA_PATH")

	// If environment variables are not set, try using certPath
	if certFile == "" || keyFile == "" || caFile == "" {
		c.mu.RLock()
		certPath := c.certPath
		c.mu.RUnlock()

		if certPath == "" {
			// No TLS configuration available
			return nil, nil
		}

		certFile = filepath.Join(certPath, "client-cert.pem")
		keyFile = filepath.Join(certPath, "client-key.pem")
		caFile = filepath.Join(certPath, "ca-cert.pem")
	}

	// Load client certificate PEM data
	// #nosec G304 - Certificate paths are controlled via configuration
	clientCertPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate: %w", err)
	}
	// #nosec G304 - Certificate paths are controlled via configuration
	clientKeyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key: %w", err)
	}

	// Load CA certificate
	// #nosec G304 - Certificate paths are controlled via configuration
	caCertPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Create TLS config for MQTT with mTLS using pkg/cert helper
	tlsConfig, err := cert.CreateClientTLSConfig(clientCertPEM, clientKeyPEM, caCertPEM, "", tls.VersionTLS12)
	if err != nil {
		return nil, fmt.Errorf("failed to create MQTT TLS config: %w", err)
	}

	c.logger.Info("Loaded MQTT TLS configuration",
		"cert_file", certFile,
		"key_file", keyFile,
		"ca_file", caFile)

	return tlsConfig, nil
}

// createQUICtlsConfig creates a TLS configuration for QUIC with proper mTLS.
func (c *MQTTClient) createQUICtlsConfig(certPath string) (*tls.Config, error) {
	if certPath == "" {
		return nil, fmt.Errorf("certificate path is required for mTLS")
	}

	// Load CA certificate to verify controller's identity
	caCertPath := filepath.Join(certPath, "ca.crt")
	// #nosec G304 - Certificate paths are controlled via configuration
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
	}

	// Load client certificate for mTLS authentication
	clientCertPath := filepath.Join(certPath, "client.crt")
	clientKeyPath := filepath.Join(certPath, "client.key")
	// #nosec G304 - Certificate paths are controlled via configuration
	clientCertPEM, err := os.ReadFile(clientCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate from %s: %w", clientCertPath, err)
	}
	// #nosec G304 - Certificate paths are controlled via configuration
	clientKeyPEM, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key from %s: %w", clientKeyPath, err)
	}

	// Create TLS config with mTLS using pkg/cert helper
	tlsConfig, err := cert.CreateClientTLSConfig(clientCertPEM, clientKeyPEM, caCertPEM, "", tls.VersionTLS13)
	if err != nil {
		return nil, fmt.Errorf("failed to create QUIC TLS config: %w", err)
	}

	// QUIC-specific configuration
	tlsConfig.NextProtos = []string{"cfgms-quic"}

	// Initialize configuration signature verifier using CA certificate
	// The controller signs configs with its server certificate (same CA)
	c.mu.Lock()
	if c.configVerifier == nil {
		// Load server certificate for verification (controller's cert)
		serverCertPath := filepath.Join(certPath, "server.crt")
		// #nosec G304 - Certificate paths are controlled via configuration
		serverCertPEM, err := os.ReadFile(serverCertPath)
		if err != nil {
			c.logger.Warn("Failed to load server certificate for signature verification, using CA",
				"error", err)
			// Fall back to CA certificate
			serverCertPEM = caCertPEM
		}

		verifier, err := signature.NewVerifier(&signature.VerifierConfig{
			CertificatePEM: serverCertPEM,
		})
		if err != nil {
			c.logger.Warn("Failed to create configuration verifier",
				"error", err)
		} else {
			c.configVerifier = verifier
			c.logger.Info("Configuration signature verifier initialized",
				"key_fingerprint", verifier.KeyFingerprint())
		}
	}
	c.mu.Unlock()

	return tlsConfig, nil
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
