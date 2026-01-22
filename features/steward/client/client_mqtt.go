// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client provides MQTT+QUIC client functionality for steward-controller communication.
//
// This package implements the steward-side client for communicating with
// the CFGMS controller using MQTT (control plane) and QUIC (data plane).
// It replaces the legacy gRPC-based client (Story #198).
package client

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/steward/commands"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
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

	// Certificate PEMs (from registration response)
	caCertPEM     string
	clientCertPEM string
	clientKeyPEM  string
	serverCertPEM string // Controller's server cert for config signature verification (Story #315)

	// Command handler
	commandHandler *commands.Handler

	// Configuration executor
	configExecutor *stewardconfig.Executor

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

	// CACertPEM is the CA certificate PEM (for TLS verification)
	CACertPEM string

	// ClientCertPEM is the client certificate PEM (for mTLS)
	ClientCertPEM string

	// ClientKeyPEM is the client private key PEM (for mTLS)
	ClientKeyPEM string

	// ServerCertPEM is the controller's server certificate PEM (for config signature verification)
	// Story #315: Used to verify configurations signed by the controller
	// In HA clusters, multiple controller certs may be trusted
	ServerCertPEM string

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
		caCertPEM:         cfg.CACertPEM,
		clientCertPEM:     cfg.ClientCertPEM,
		clientKeyPEM:      cfg.ClientKeyPEM,
		serverCertPEM:     cfg.ServerCertPEM,
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

	// Story #294 Phase 4: Auto-save certificates from registration
	// Enables automatic mTLS setup with zero manual configuration
	if resp.ClientCert != "" && resp.ClientKey != "" && resp.CACert != "" {
		if err := c.saveCertificates(resp.ClientCert, resp.ClientKey, resp.CACert); err != nil {
			c.logger.Warn("Failed to save certificates from registration", "error", err)
			// Don't fail registration - steward can still operate (will retry on next boot)
		} else {
			c.logger.Info("Saved certificates from registration", "steward_id", resp.StewardID)
		}
	}

	// Initialize configuration executor
	execCfg := &stewardconfig.Config{
		TenantID: resp.TenantID,
		Logger:   c.logger,
	}
	executor, err := stewardconfig.New(execCfg)
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

// InitializeConfigExecutor creates and initializes the configuration executor.
// This must be called after the MQTT client is connected but before config sync.
func (c *MQTTClient) InitializeConfigExecutor(tenantID string) error {
	execCfg := &stewardconfig.Config{
		TenantID: tenantID,
		Logger:   c.logger,
	}
	executor, err := stewardconfig.New(execCfg)
	if err != nil {
		return fmt.Errorf("failed to create config executor: %w", err)
	}

	c.mu.Lock()
	c.configExecutor = executor
	c.mu.Unlock()

	c.logger.Info("Configuration executor initialized", "tenant_id", tenantID)
	return nil
}

// Connect establishes MQTT and QUIC connections to the controller.
func (c *MQTTClient) Connect(ctx context.Context) error {
	fmt.Printf("[DEBUG] MQTTClient.Connect() called\n")
	c.logger.Info("Connecting to controller via MQTT+QUIC")

	c.mu.RLock()
	stewardID := c.stewardID
	mqtt := c.mqtt
	fmt.Printf("[DEBUG] stewardID=%s mqtt_client_nil=%v\n", stewardID, mqtt == nil)
	controllerURL := c.controllerURL
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered - call SetStewardID first")
	}

	// Create MQTT client if not already created
	if mqtt == nil {
		fmt.Printf("[DEBUG] Creating MQTT client for broker=%s client_id=%s\n", controllerURL, stewardID)
		c.logger.Info("Creating MQTT client", "broker", controllerURL, "client_id", stewardID)

		// Load TLS configuration if available (Story 12.4)
		tlsConfig, err := c.createMQTTTLSConfig()
		if err != nil {
			fmt.Printf("[DEBUG] TLS config failed: %v\n", err)
			c.logger.Warn("Failed to load MQTT TLS config, continuing without TLS", "error", err)
			tlsConfig = nil
		} else {
			fmt.Printf("[DEBUG] TLS config loaded successfully\n")
		}

		mqttCfg := &mqttClient.Config{
			BrokerAddr:    controllerURL,
			ClientID:      stewardID,
			CleanSession:  false,
			AutoReconnect: true,
			TLSConfig:     tlsConfig, // Story 12.4: Enable TLS if configured
		}

		fmt.Printf("[DEBUG] Creating new MQTT client...\n")
		mqtt, err = mqttClient.New(mqttCfg)
		if err != nil {
			fmt.Printf("[DEBUG] MQTT client creation failed: %v\n", err)
			return fmt.Errorf("failed to create MQTT client: %w", err)
		}
		fmt.Printf("[DEBUG] MQTT client created successfully\n")

		c.mu.Lock()
		c.mqtt = mqtt
		c.mu.Unlock()
	}

	// Connect to MQTT if not connected
	if !mqtt.IsConnected() {
		fmt.Printf("[DEBUG] Connecting to MQTT broker=%s\n", controllerURL)
		c.logger.Info("Connecting to MQTT broker", "broker", controllerURL)
		if err := mqtt.Connect(ctx); err != nil {
			fmt.Printf("[DEBUG] MQTT connect failed: %v\n", err)
			return fmt.Errorf("failed to connect to MQTT: %w", err)
		}
		fmt.Printf("[DEBUG] MQTT connection established\n")
		c.logger.Info("MQTT connection established")
	} else {
		fmt.Printf("[DEBUG] MQTT already connected\n")
	}

	// Subscribe to command topics
	cmdTopic := fmt.Sprintf("cfgms/steward/%s/commands", stewardID)
	fmt.Printf("[DEBUG] Command topic: %s\n", cmdTopic)
	c.logger.Info("Subscribing to commands", "topic", cmdTopic)

	// Create command handler
	fmt.Printf("[DEBUG] Setting up command handler...\n")
	cmdHandler, err := c.setupCommandHandler(ctx, stewardID, mqtt)
	if err != nil {
		fmt.Printf("[DEBUG] setupCommandHandler failed: %v\n", err)
		return fmt.Errorf("failed to setup command handler: %w", err)
	}
	fmt.Printf("[DEBUG] Command handler setup complete\n")

	c.mu.Lock()
	c.commandHandler = cmdHandler
	c.mu.Unlock()

	// Wrap HandleCommand to match MessageHandler signature
	messageHandler := func(topic string, payload []byte) {
		fmt.Printf("[DEBUG] Received message on topic=%s payload_size=%d\n", topic, len(payload))
		if err := cmdHandler.HandleCommand(topic, payload); err != nil {
			c.logger.Error("Failed to handle command", "error", err, "topic", topic)
		}
	}

	fmt.Printf("[DEBUG] Subscribing to %s...\n", cmdTopic)
	if err := mqtt.Subscribe(ctx, cmdTopic, 1, messageHandler); err != nil {
		fmt.Printf("[DEBUG] Subscribe failed: %v\n", err)
		return fmt.Errorf("failed to subscribe to commands: %w", err)
	}
	fmt.Printf("[DEBUG] Subscribed successfully to commands topic\n")

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
		fmt.Printf("[DEBUG] sync_config handler called, command_id=%s\n", cmd.CommandID)
		c.logger.Info("Received sync_config command", "command_id", cmd.CommandID, "params", cmd.Params)

		// Check if QUIC connection is already established
		c.mu.RLock()
		quicConnected := c.quicConnected
		quicAddress := c.quicAddress
		c.mu.RUnlock()

		fmt.Printf("[DEBUG] QUIC status: connected=%v address=%s\n", quicConnected, quicAddress)

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
		fmt.Printf("[DEBUG] Calling GetConfiguration via QUIC...\n")
		configData, version, err := c.GetConfiguration(ctx, modules)
		if err != nil {
			fmt.Printf("[DEBUG] GetConfiguration failed: %v\n", err)
			c.logger.Error("Failed to retrieve configuration", "error", err)
			return fmt.Errorf("config retrieval failed: %w", err)
		}

		fmt.Printf("[DEBUG] Configuration retrieved: version=%s size=%d bytes\n", version, len(configData))
		c.logger.Info("Configuration retrieved",
			"command_id", cmd.CommandID,
			"version", version,
			"config_size", len(configData))

		// Unmarshal protobuf SignedConfig
		fmt.Printf("[DEBUG] Unmarshaling protobuf SignedConfig...\n")
		var signedProtoConfig controller.SignedConfig
		if err := proto.Unmarshal(configData, &signedProtoConfig); err != nil {
			c.logger.Error("Failed to unmarshal protobuf configuration",
				"command_id", cmd.CommandID,
				"version", version,
				"error", err)
			return fmt.Errorf("failed to unmarshal protobuf config: %w", err)
		}

		// Verify configuration signature
		fmt.Printf("[DEBUG] Starting protobuf signature verification...\n")
		c.mu.RLock()
		verifier := c.configVerifier
		c.mu.RUnlock()

		var unsignedProtoConfig *controller.StewardConfig
		fmt.Printf("[DEBUG] Verifier is nil: %v\n", verifier == nil)
		if verifier != nil {
			fmt.Printf("[DEBUG] Verifier exists, checking signature...\n")
			// Configuration must be signed
			if signedProtoConfig.Signature == nil {
				fmt.Printf("[DEBUG] Configuration is NOT signed\n")
				c.logger.Error("Configuration is not signed",
					"command_id", cmd.CommandID,
					"version", version)
				return fmt.Errorf("configuration signature verification failed: missing signature")
			}

			fmt.Printf("[DEBUG] Configuration has signature, verifying protobuf...\n")
			fmt.Printf("[DEBUG] Config data size: %d bytes\n", len(configData))
			// Verify protobuf signature
			verified, err := signature.VerifyProtoConfig(verifier, &signedProtoConfig)
			if err != nil {
				fmt.Printf("[DEBUG] Signature verification FAILED: %v\n", err)
				c.logger.Error("Configuration signature verification failed",
					"command_id", cmd.CommandID,
					"version", version,
					"error", err)
				return fmt.Errorf("configuration signature verification failed: %w", err)
			}

			fmt.Printf("[DEBUG] Signature verified successfully\n")
			c.logger.Info("Configuration signature verified",
				"command_id", cmd.CommandID,
				"version", version)

			unsignedProtoConfig = verified
		} else {
			fmt.Printf("[DEBUG] No verifier, using unsigned config\n")
			c.logger.Warn("Configuration verifier not available, skipping signature verification",
				"command_id", cmd.CommandID)
			unsignedProtoConfig = signedProtoConfig.Config
		}

		// Convert protobuf to Go struct
		fmt.Printf("[DEBUG] Converting protobuf to Go struct...\n")
		goConfig, err := stewardconfig.FromProto(unsignedProtoConfig)
		if err != nil {
			c.logger.Error("Failed to convert protobuf to Go struct",
				"command_id", cmd.CommandID,
				"version", version,
				"error", err)
			return fmt.Errorf("failed to convert protobuf config: %w", err)
		}

		fmt.Printf("[DEBUG] Signature verification complete, checking executor...\n")
		// Apply configuration using executor
		c.mu.RLock()
		executor := c.configExecutor
		stewardID := c.stewardID
		c.mu.RUnlock()

		if executor == nil {
			fmt.Printf("[DEBUG] Configuration executor is nil!\n")
			c.logger.Error("Configuration executor not initialized")
			return fmt.Errorf("configuration executor not available")
		}

		// Executor now receives Go struct, marshal to YAML for ApplyConfiguration
		// TODO: Update executor to work directly with Go struct instead of bytes
		fmt.Printf("[DEBUG] Marshaling config to YAML for executor...\n")
		configYAML, err := yaml.Marshal(goConfig)
		if err != nil {
			c.logger.Error("Failed to marshal config to YAML",
				"command_id", cmd.CommandID,
				"version", version,
				"error", err)
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		fmt.Printf("[DEBUG] Applying configuration...\n")
		report, err := executor.ApplyConfiguration(ctx, configYAML, version)
		if err != nil {
			fmt.Printf("[DEBUG] ApplyConfiguration failed: %v\n", err)
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

		fmt.Printf("[DEBUG] Configuration applied successfully, publishing status report...\n")
		// Publish configuration status report
		report.StewardID = stewardID
		if err := c.publishConfigStatus(report); err != nil {
			fmt.Printf("[DEBUG] publishConfigStatus failed: %v\n", err)
			c.logger.Error("Failed to publish config status", "error", err)
			// Don't return error - config was applied successfully
		} else {
			fmt.Printf("[DEBUG] Config status published successfully\n")
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
	fmt.Printf("[DEBUG] GetConfiguration called with modules=%v\n", modules)
	c.logger.Info("Requesting configuration via QUIC", "modules", modules)

	c.mu.RLock()
	quic := c.quic
	stewardID := c.stewardID
	c.mu.RUnlock()

	fmt.Printf("[DEBUG] QUIC=%v (nil=%v) stewardID=%s\n", quic, quic == nil, stewardID)
	if quic == nil || !quic.IsConnected() {
		fmt.Printf("[DEBUG] QUIC not connected or nil\n")
		return nil, "", fmt.Errorf("QUIC not connected")
	}

	// Open QUIC stream for config sync (stream ID 4)
	// Client-initiated bidirectional streams use IDs 0, 4, 8, 12... (multiples of 4)
	// Stream 0 is handshake, so first data stream is 4
	fmt.Printf("[DEBUG] Opening QUIC stream 4...\n")
	stream, err := quic.OpenStream(ctx, 4)
	if err != nil {
		fmt.Printf("[DEBUG] Failed to open stream: %v\n", err)
		return nil, "", fmt.Errorf("failed to open QUIC stream: %w", err)
	}
	fmt.Printf("[DEBUG] Stream opened successfully\n")
	defer func() { _ = quic.CloseStream(4) }()

	// Create request
	type ConfigRequest struct {
		StewardID string   `json:"steward_id"`
		Modules   []string `json:"modules,omitempty"`
	}

	req := ConfigRequest{
		StewardID: stewardID,
		Modules:   modules,
	}

	fmt.Printf("[DEBUG] Marshaling request...\n")
	// Send request
	reqData, err := json.Marshal(req)
	if err != nil {
		fmt.Printf("[DEBUG] Marshal failed: %v\n", err)
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	fmt.Printf("[DEBUG] Writing request to stream (%d bytes)...\n", len(reqData))
	if _, err := (*stream).Write(reqData); err != nil {
		fmt.Printf("[DEBUG] Write failed: %v\n", err)
		return nil, "", fmt.Errorf("failed to write request: %w", err)
	}
	fmt.Printf("[DEBUG] Request written successfully\n")

	// Close write side to signal EOF to server
	if err := (*stream).Close(); err != nil {
		fmt.Printf("[DEBUG] Stream close failed: %v\n", err)
		return nil, "", fmt.Errorf("failed to close stream write side: %w", err)
	}
	fmt.Printf("[DEBUG] Stream write side closed\n")

	// Read response using io.ReadAll to read until EOF
	fmt.Printf("[DEBUG] Reading response from stream...\n")
	respData, err := io.ReadAll(stream)
	if err != nil {
		fmt.Printf("[DEBUG] Read failed: %v\n", err)
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}
	fmt.Printf("[DEBUG] Read %d bytes from response\n", len(respData))

	// Parse response
	type ConfigResponse struct {
		Success       bool   `json:"success"`
		Configuration string `json:"configuration,omitempty"`
		ConfigHash    string `json:"config_hash,omitempty"`
		Error         string `json:"error,omitempty"`
	}

	fmt.Printf("[DEBUG] Unmarshaling response...\n")
	var resp ConfigResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		fmt.Printf("[DEBUG] Unmarshal failed: %v\n", err)
		return nil, "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	fmt.Printf("[DEBUG] Response: success=%v error=%s\n", resp.Success, resp.Error)
	if !resp.Success {
		fmt.Printf("[DEBUG] Config sync failed: %s\n", resp.Error)
		return nil, "", fmt.Errorf("config sync failed: %s", resp.Error)
	}

	// Base64 decode the configuration (protobuf is binary, transported as base64 in JSON)
	configBytes, err := base64.StdEncoding.DecodeString(resp.Configuration)
	if err != nil {
		fmt.Printf("[DEBUG] Base64 decode failed: %v\n", err)
		return nil, "", fmt.Errorf("failed to decode base64 configuration: %w", err)
	}

	fmt.Printf("[DEBUG] Config retrieved successfully, base64_size=%d decoded_size=%d hash=%s\n",
		len(resp.Configuration), len(configBytes), resp.ConfigHash)

	c.logger.Info("Configuration retrieved successfully",
		"config_hash", resp.ConfigHash,
		"decoded_size", len(configBytes))

	return configBytes, resp.ConfigHash, nil
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
	c.mu.RLock()
	caCertPEM := c.caCertPEM
	clientCertPEM := c.clientCertPEM
	clientKeyPEM := c.clientKeyPEM
	certPath := c.certPath
	c.mu.RUnlock()

	// If PEM certificates are provided (from registration), use them directly
	if caCertPEM != "" && clientCertPEM != "" && clientKeyPEM != "" {
		c.logger.Info("Using TLS certificates from registration response")
		tlsConfig, err := cert.CreateClientTLSConfig([]byte(clientCertPEM), []byte(clientKeyPEM), []byte(caCertPEM), "", tls.VersionTLS12)
		if err != nil {
			return nil, fmt.Errorf("failed to create MQTT TLS config from PEM: %w", err)
		}
		return tlsConfig, nil
	}

	// Try environment variables first (Story 12.4: TLS support)
	certFile := os.Getenv("CFGMS_MQTT_TLS_CERT_PATH")
	keyFile := os.Getenv("CFGMS_MQTT_TLS_KEY_PATH")
	caFile := os.Getenv("CFGMS_MQTT_TLS_CA_PATH")

	// If environment variables are not set, try using certPath
	if certFile == "" || keyFile == "" || caFile == "" {
		if certPath == "" {
			// No TLS configuration available
			return nil, nil
		}

		// Story #294 Phase 4: Use standard certificate names (matches saveCertificates)
		certFile = filepath.Join(certPath, "client.crt")
		keyFile = filepath.Join(certPath, "client.key")
		caFile = filepath.Join(certPath, "ca.crt")
	}

	// Load client certificate PEM data
	// #nosec G304 - Certificate paths are controlled via configuration
	clientCertBytes, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate: %w", err)
	}
	// #nosec G304 - Certificate paths are controlled via configuration
	clientKeyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key: %w", err)
	}

	// Load CA certificate
	// #nosec G304 - Certificate paths are controlled via configuration
	caCertBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Create TLS config for MQTT with mTLS using pkg/cert helper
	tlsConfig, err := cert.CreateClientTLSConfig(clientCertBytes, clientKeyBytes, caCertBytes, "", tls.VersionTLS12)
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
	c.mu.RLock()
	caCertPEMStr := c.caCertPEM
	clientCertPEMStr := c.clientCertPEM
	clientKeyPEMStr := c.clientKeyPEM
	c.mu.RUnlock()

	var caCertPEM, clientCertPEM, clientKeyPEM []byte
	var err error

	// If PEM certificates are provided (from registration), use them directly
	if caCertPEMStr != "" && clientCertPEMStr != "" && clientKeyPEMStr != "" {
		c.logger.Info("Using TLS certificates from registration response for QUIC")
		caCertPEM = []byte(caCertPEMStr)
		clientCertPEM = []byte(clientCertPEMStr)
		clientKeyPEM = []byte(clientKeyPEMStr)
	} else {
		// Fall back to reading from files
		if certPath == "" {
			return nil, fmt.Errorf("certificate path is required for mTLS")
		}

		// Load CA certificate to verify controller's identity
		caCertPath := filepath.Join(certPath, "ca.crt")
		// #nosec G304 - Certificate paths are controlled via configuration
		caCertPEM, err = os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
		}

		// Load client certificate for mTLS authentication
		clientCertPath := filepath.Join(certPath, "client.crt")
		clientKeyPath := filepath.Join(certPath, "client.key")
		// #nosec G304 - Certificate paths are controlled via configuration
		clientCertPEM, err = os.ReadFile(clientCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client certificate from %s: %w", clientCertPath, err)
		}
		// #nosec G304 - Certificate paths are controlled via configuration
		clientKeyPEM, err = os.ReadFile(clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client key from %s: %w", clientKeyPath, err)
		}
	}

	// Create TLS config with mTLS using pkg/cert helper
	tlsConfig, err := cert.CreateClientTLSConfig(clientCertPEM, clientKeyPEM, caCertPEM, "", tls.VersionTLS13)
	if err != nil {
		return nil, fmt.Errorf("failed to create QUIC TLS config: %w", err)
	}

	// QUIC-specific configuration
	tlsConfig.NextProtos = []string{"cfgms-quic"}

	// Initialize configuration signature verifier using controller's server certificate
	// Story #315: Use server cert from registration for signature verification
	// The controller signs configs with its server certificate
	c.mu.Lock()
	fmt.Printf("[DEBUG] createQUICtlsConfig: Initializing verifier, current verifier nil=%v\n", c.configVerifier == nil)
	fmt.Printf("[DEBUG] createQUICtlsConfig: serverCertPEM length=%d\n", len(c.serverCertPEM))
	if c.configVerifier == nil {
		var serverCertPEM []byte

		// Priority 1: Use server certificate from registration response
		if c.serverCertPEM != "" {
			serverCertPEM = []byte(c.serverCertPEM)
			fmt.Printf("[DEBUG] createQUICtlsConfig: Using server cert from registration, size=%d\n", len(serverCertPEM))
			c.logger.Info("Using server certificate from registration for signature verification")
		} else if certPath != "" {
			// Priority 2: Load server certificate from disk (backwards compatibility)
			serverCertPath := filepath.Join(certPath, "server.crt")
			// #nosec G304 - Certificate paths are controlled via configuration
			var err error
			serverCertPEM, err = os.ReadFile(serverCertPath)
			if err != nil {
				c.logger.Warn("Failed to load server certificate for signature verification, using CA",
					"error", err)
				// Priority 3: Fall back to CA certificate
				serverCertPEM = caCertPEM
			}
		} else {
			// Priority 3: Use CA certificate if nothing else available
			c.logger.Warn("No server certificate available, using CA for signature verification")
			serverCertPEM = caCertPEM
		}

		if len(serverCertPEM) > 0 {
			fmt.Printf("[DEBUG] createQUICtlsConfig: Creating verifier with cert size=%d\n", len(serverCertPEM))
			verifier, err := signature.NewVerifier(&signature.VerifierConfig{
				CertificatePEM: serverCertPEM,
			})
			if err != nil {
				fmt.Printf("[DEBUG] createQUICtlsConfig: Failed to create verifier: %v\n", err)
				c.logger.Warn("Failed to create configuration verifier",
					"error", err)
			} else {
				c.configVerifier = verifier
				fmt.Printf("[DEBUG] createQUICtlsConfig: Verifier created successfully, fingerprint=%s\n", verifier.KeyFingerprint())
				c.logger.Info("Configuration signature verifier initialized",
					"key_fingerprint", verifier.KeyFingerprint())
			}
		} else {
			fmt.Printf("[DEBUG] createQUICtlsConfig: No server cert PEM available\n")
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

// saveCertificates saves client certificates from registration to disk
// Story #294 Phase 4: Enable automatic certificate distribution at scale
func (c *MQTTClient) saveCertificates(clientCert, clientKey, caCert string) error {
	// Determine certificate directory
	certDir := os.Getenv("CFGMS_CERT_PATH")
	if certDir == "" {
		certDir = "/etc/cfgms/certs" // Default path
	}

	// Create directory with restricted permissions
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Certificate files with standard naming (matches documentation)
	files := map[string]struct {
		content string
		perm    os.FileMode
	}{
		"client.crt": {clientCert, 0600}, // Private: client certificate
		"client.key": {clientKey, 0600},  // Private: client private key
		"ca.crt":     {caCert, 0644},     // Public: CA certificate
	}

	// Write all certificate files
	for filename, file := range files {
		path := filepath.Join(certDir, filename)
		if err := os.WriteFile(path, []byte(file.content), file.perm); err != nil {
			return fmt.Errorf("failed to save %s: %w", filename, err)
		}
		c.logger.Debug("Saved certificate file", "path", path)
	}

	return nil
}
