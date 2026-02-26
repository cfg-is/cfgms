// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client provides control plane client functionality for steward-controller communication.
//
// This package implements the steward-side client for communicating with
// the CFGMS controller using the ControlPlaneProvider abstraction (control plane)
// and DataPlaneProvider (data plane). Story #363 migrated from direct pkg/mqtt/client
// usage to the pluggable ControlPlaneProvider interface.
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
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneMQTT "github.com/cfgis/cfgms/pkg/controlplane/providers/mqtt"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	_ "github.com/cfgis/cfgms/pkg/dataplane/providers/quic" // Register QUIC data plane provider
	dataplaneTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// MQTTClient represents the steward client using ControlPlaneProvider (control plane)
// and DataPlaneProvider (data plane) for controller communication.
// Story #363: Migrated from direct pkg/mqtt/client to ControlPlaneProvider.
type MQTTClient struct {
	mu sync.RWMutex

	// Steward identification
	stewardID string
	tenantID  string
	group     string

	// Controller connection info
	controllerURL string

	// Control plane provider (Story #363: replaces direct mqtt *client.Client)
	controlPlane controlplaneInterfaces.ControlPlaneProvider

	// QUIC data plane via provider (Story #363)
	dataPlaneSession dataplaneInterfaces.DataPlaneSession
	quicAddress      string

	// Certificate path for mTLS
	certPath string

	// Certificate PEMs (from registration response)
	caCertPEM      string
	clientCertPEM  string
	clientKeyPEM   string
	serverCertPEM  string // Controller's server cert for config signature verification (Story #315)
	signingCertPEM string // Story #377: Dedicated signing cert (preferred over serverCertPEM)

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

	// SigningCertPEM is the controller's dedicated signing certificate PEM (Story #377)
	// When present, preferred over ServerCertPEM for config signature verification
	SigningCertPEM string

	// HeartbeatInterval for periodic heartbeats
	HeartbeatInterval time.Duration

	// Logger for client logging
	Logger logging.Logger
}

// NewMQTTClient creates a new steward client.
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
		signingCertPEM:    cfg.SigningCertPEM,
		logger:            cfg.Logger,
		controllerURL:     cfg.ControllerURL,
	}

	return client, nil
}

// RegisterWithToken registers the steward with the controller using a token.
// Story #363: Accepts a registration.MessageClient for the temporary MQTT connection
// instead of creating a direct pkg/mqtt/client.Client internally.
func (c *MQTTClient) RegisterWithToken(ctx context.Context, token string, mqttBroker string, msgClient registration.MessageClient) error {
	c.logger.Info("Starting registration with token", "broker", mqttBroker)

	// Create registration client using the provided MessageClient
	regCfg := &registration.Config{
		MQTT:   msgClient,
		Logger: c.logger,
	}

	regClient, err := registration.New(regCfg)
	if err != nil {
		return fmt.Errorf("failed to create registration client: %w", err)
	}

	// Register with token
	resp, err := regClient.Register(ctx, token)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Store registration response
	c.mu.Lock()
	c.stewardID = resp.StewardID
	c.tenantID = resp.TenantID
	c.group = resp.Group
	c.controllerURL = mqttBroker
	c.mu.Unlock()

	// Story #294 Phase 4: Auto-save certificates from registration
	if resp.ClientCert != "" && resp.ClientKey != "" && resp.CACert != "" {
		if err := c.saveCertificates(resp.ClientCert, resp.ClientKey, resp.CACert); err != nil {
			c.logger.Warn("Failed to save certificates from registration", "error", err)
		} else {
			c.logger.Info("Saved certificates from registration", "steward_id", resp.StewardID)
		}
	}

	// Story #377: Store signing certificate if provided (separated architecture)
	if resp.SigningCert != "" {
		c.mu.Lock()
		c.signingCertPEM = resp.SigningCert
		c.mu.Unlock()
		c.logger.Info("Received dedicated signing certificate from controller", "steward_id", resp.StewardID)

		// Persist signing.crt alongside other cert files
		if err := c.saveSigningCertificate(resp.SigningCert); err != nil {
			c.logger.Warn("Failed to save signing certificate", "error", err)
		}
	}

	// Initialize configuration executor
	execCfg := &stewardconfig.Config{
		TenantID: resp.TenantID,
		Logger:   c.logger,
	}
	executor, err := stewardconfig.New(execCfg)
	if err != nil {
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
// This must be called after the client is connected but before config sync.
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

// Connect establishes control plane and data plane connections to the controller.
// Story #363: Uses ControlPlaneProvider instead of direct MQTT client.
func (c *MQTTClient) Connect(ctx context.Context) error {
	c.logger.Info("Connecting to controller via control plane")

	c.mu.RLock()
	stewardID := c.stewardID
	controlPlane := c.controlPlane
	controllerURL := c.controllerURL
	tenantID := c.tenantID
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered - call SetStewardID first")
	}

	// Create ControlPlaneProvider if not already created
	if controlPlane == nil {
		c.logger.Info("Creating MQTT control plane provider", "broker", controllerURL, "steward_id", stewardID)

		// Create MQTT control plane provider in client mode
		provider := controlplaneMQTT.New(controlplaneMQTT.ModeClient)

		// Load TLS configuration if available
		tlsConfig, err := c.createMQTTTLSConfig()
		if err != nil {
			c.logger.Warn("Failed to load MQTT TLS config, continuing without TLS", "error", err)
			tlsConfig = nil
		}

		// Initialize provider with connection config
		providerCfg := map[string]interface{}{
			"broker_addr": controllerURL,
			"client_id":   stewardID,
			"steward_id":  stewardID,
		}
		if tenantID != "" {
			providerCfg["tenant_id"] = tenantID
		}
		if tlsConfig != nil {
			providerCfg["tls_config"] = tlsConfig
		}

		if err := provider.Initialize(ctx, providerCfg); err != nil {
			return fmt.Errorf("failed to initialize control plane provider: %w", err)
		}

		controlPlane = provider
		c.mu.Lock()
		c.controlPlane = controlPlane
		c.mu.Unlock()
	}

	// Start the provider (connects to MQTT broker)
	if !controlPlane.IsConnected() {
		c.logger.Info("Connecting to MQTT broker", "broker", controllerURL)
		if err := controlPlane.Start(ctx); err != nil {
			return fmt.Errorf("failed to start control plane: %w", err)
		}
		c.logger.Info("Control plane connection established")
	}

	// Setup command handler
	cmdHandler, err := c.setupCommandHandler(ctx, stewardID)
	if err != nil {
		return fmt.Errorf("failed to setup command handler: %w", err)
	}

	c.mu.Lock()
	c.commandHandler = cmdHandler
	c.mu.Unlock()

	// Subscribe to commands via ControlPlaneProvider
	c.logger.Info("Subscribing to commands", "steward_id", stewardID)
	if err := controlPlane.SubscribeCommands(ctx, stewardID, func(ctx context.Context, cmd *cpTypes.Command) error {
		return cmdHandler.HandleCommand(ctx, cmd)
	}); err != nil {
		return fmt.Errorf("failed to subscribe to commands: %w", err)
	}

	// QUIC connections are established on-demand when controller sends connect_dataplane command
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
// Story #363: Status updates are now published as events via ControlPlaneProvider.
func (c *MQTTClient) setupCommandHandler(ctx context.Context, stewardID string) (*commands.Handler, error) {
	// Create status callback that publishes events via ControlPlaneProvider
	statusCallback := func(ctx context.Context, event *cpTypes.Event) {
		c.mu.RLock()
		cp := c.controlPlane
		c.mu.RUnlock()

		if cp != nil {
			if err := cp.PublishEvent(ctx, event); err != nil {
				c.logger.Error("Failed to publish status event", "error", err)
			}
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

	// Register connect_dataplane handler (backward compat: also handles "connect_quic")
	connectHandler := func(ctx context.Context, cmd *cpTypes.Command) error {
		return c.handleConnectQUIC(ctx, cmd)
	}
	handler.RegisterHandler(cpTypes.CommandConnectDataPlane, connectHandler)
	handler.RegisterHandler(cpTypes.CommandType("connect_quic"), connectHandler) // backward compatibility

	// Register sync_config handler
	handler.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, cmd *cpTypes.Command) error {
		c.logger.Info("Received sync_config command", "command_id", cmd.ID, "params", cmd.Params)

		// Check if QUIC connection is already established
		c.mu.RLock()
		quicConnected := c.quicConnected
		quicAddress := c.quicAddress
		c.mu.RUnlock()

		_ = quicConnected // Used for logging context
		_ = quicAddress

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
			"command_id", cmd.ID,
			"version", version,
			"config_size", len(configData))

		// Unmarshal protobuf SignedConfig
		var signedProtoConfig controller.SignedConfig
		if err := proto.Unmarshal(configData, &signedProtoConfig); err != nil {
			c.logger.Error("Failed to unmarshal protobuf configuration",
				"command_id", cmd.ID,
				"version", version,
				"error", err)
			return fmt.Errorf("failed to unmarshal protobuf config: %w", err)
		}

		// Verify configuration signature
		c.mu.RLock()
		verifier := c.configVerifier
		c.mu.RUnlock()

		var unsignedProtoConfig *controller.StewardConfig
		if verifier != nil {
			if signedProtoConfig.Signature == nil {
				c.logger.Error("Configuration is not signed",
					"command_id", cmd.ID,
					"version", version)
				return fmt.Errorf("configuration signature verification failed: missing signature")
			}

			verified, err := signature.VerifyProtoConfig(verifier, &signedProtoConfig)
			if err != nil {
				c.logger.Error("Configuration signature verification failed",
					"command_id", cmd.ID,
					"version", version,
					"error", err)
				return fmt.Errorf("configuration signature verification failed: %w", err)
			}

			c.logger.Info("Configuration signature verified",
				"command_id", cmd.ID,
				"version", version)

			unsignedProtoConfig = verified
		} else {
			c.logger.Warn("Configuration verifier not available, skipping signature verification",
				"command_id", cmd.ID)
			unsignedProtoConfig = signedProtoConfig.Config
		}

		// Convert protobuf to Go struct
		goConfig, err := stewardconfig.FromProto(unsignedProtoConfig)
		if err != nil {
			c.logger.Error("Failed to convert protobuf to Go struct",
				"command_id", cmd.ID,
				"version", version,
				"error", err)
			return fmt.Errorf("failed to convert protobuf config: %w", err)
		}

		// Apply configuration using executor
		c.mu.RLock()
		executor := c.configExecutor
		sid := c.stewardID
		c.mu.RUnlock()

		if executor == nil {
			c.logger.Error("Configuration executor not initialized")
			return fmt.Errorf("configuration executor not available")
		}

		// Marshal to YAML for executor
		configYAML, err := yaml.Marshal(goConfig)
		if err != nil {
			c.logger.Error("Failed to marshal config to YAML",
				"command_id", cmd.ID,
				"version", version,
				"error", err)
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		report, err := executor.ApplyConfiguration(ctx, configYAML, version)
		if err != nil {
			c.logger.Error("Configuration application failed", "error", err)
			if report != nil {
				report.StewardID = sid
				if pubErr := c.publishConfigStatus(report); pubErr != nil {
					c.logger.Error("Failed to publish config status after error", "error", pubErr)
				}
			}
			return fmt.Errorf("config application failed: %w", err)
		}

		// Publish configuration status report
		report.StewardID = sid
		if err := c.publishConfigStatus(report); err != nil {
			c.logger.Error("Failed to publish config status", "error", err)
		}

		c.logger.Info("Configuration sync completed",
			"command_id", cmd.ID,
			"version", version,
			"status", report.Status)

		return nil
	})

	// Register sync_dna handler
	handler.RegisterHandler(cpTypes.CommandSyncDNA, func(ctx context.Context, cmd *cpTypes.Command) error {
		c.logger.Info("Received sync_dna command", "command_id", cmd.ID)

		var requestedAttrs []string
		if attrsParam, ok := cmd.Params["attributes"].([]interface{}); ok {
			for _, attr := range attrsParam {
				if attrStr, ok := attr.(string); ok {
					requestedAttrs = append(requestedAttrs, attrStr)
				}
			}
		}

		c.logger.Info("DNA sync triggered",
			"command_id", cmd.ID,
			"requested_attributes", requestedAttrs)

		c.logger.Info("DNA sync completed", "command_id", cmd.ID)
		return nil
	})

	return handler, nil
}

// handleConnectQUIC handles the connect_dataplane (or legacy connect_quic) command.
func (c *MQTTClient) handleConnectQUIC(ctx context.Context, cmd *cpTypes.Command) error {
	c.logger.Info("Handling connect_dataplane command", "command_id", cmd.ID)

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

	// Story #363: Use DataPlaneProvider instead of direct QUIC client
	c.mu.RLock()
	dataPlane := c.dataPlaneSession
	c.mu.RUnlock()

	if dataPlane == nil {
		dataPlaneProvider := dataplaneInterfaces.GetProvider("quic")
		if dataPlaneProvider == nil {
			return fmt.Errorf("QUIC data plane provider not available")
		}

		providerCfg := map[string]interface{}{
			"mode":        "client", // Issue #382: Steward is a client connecting to controller's QUIC server
			"server_addr": quicAddress,
			"tls_config":  tlsConfig,
			"steward_id":  stewardID,
		}

		if err := dataPlaneProvider.Initialize(ctx, providerCfg); err != nil {
			return fmt.Errorf("failed to initialize data plane provider: %w", err)
		}

		session, err := dataPlaneProvider.Connect(ctx, quicAddress)
		if err != nil {
			return fmt.Errorf("failed to connect to data plane: %w", err)
		}

		c.mu.Lock()
		c.dataPlaneSession = session
		c.quicConnected = true
		c.mu.Unlock()
	}

	c.logger.Info("QUIC connection established successfully",
		"quic_address", quicAddress,
		"session_id", sessionID)

	return nil
}

// GetConfiguration retrieves configuration from the controller via data plane.
func (c *MQTTClient) GetConfiguration(ctx context.Context, modules []string) ([]byte, string, error) {
	c.logger.Info("Requesting configuration via data plane", "modules", modules)

	c.mu.RLock()
	session := c.dataPlaneSession
	stewardID := c.stewardID
	c.mu.RUnlock()

	if session == nil || session.IsClosed() {
		return nil, "", fmt.Errorf("data plane session not available")
	}

	stream, err := session.OpenStream(ctx, dataplaneTypes.StreamConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open data plane stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	type ConfigRequest struct {
		StewardID string   `json:"steward_id"`
		Modules   []string `json:"modules,omitempty"`
	}

	req := ConfigRequest{
		StewardID: stewardID,
		Modules:   modules,
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	if _, err := stream.Write(reqData); err != nil {
		return nil, "", fmt.Errorf("failed to write request: %w", err)
	}

	if err := stream.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close stream write side: %w", err)
	}

	respData, err := io.ReadAll(stream)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}

	type ConfigResponse struct {
		Success       bool   `json:"success"`
		Configuration string `json:"configuration,omitempty"`
		ConfigHash    string `json:"config_hash,omitempty"`
		Error         string `json:"error,omitempty"`
	}

	var resp ConfigResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !resp.Success {
		return nil, "", fmt.Errorf("config sync failed: %s", resp.Error)
	}

	configBytes, err := base64.StdEncoding.DecodeString(resp.Configuration)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode base64 configuration: %w", err)
	}

	c.logger.Info("Configuration retrieved successfully",
		"config_hash", resp.ConfigHash,
		"decoded_size", len(configBytes))

	return configBytes, resp.ConfigHash, nil
}

// SendHeartbeat sends a heartbeat to the controller via the control plane provider.
// Story #363: Uses ControlPlaneProvider.SendHeartbeat() instead of direct MQTT publish.
func (c *MQTTClient) SendHeartbeat(ctx context.Context, status string, metrics map[string]string) error {
	c.mu.RLock()
	stewardID := c.stewardID
	tenantID := c.tenantID
	cp := c.controlPlane
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered")
	}

	if cp == nil {
		return fmt.Errorf("control plane not connected")
	}

	// Convert string metrics to interface{} map for the Heartbeat type
	var metricsMap map[string]interface{}
	if metrics != nil {
		metricsMap = make(map[string]interface{}, len(metrics))
		for k, v := range metrics {
			metricsMap[k] = v
		}
	}

	heartbeat := &cpTypes.Heartbeat{
		StewardID: stewardID,
		TenantID:  tenantID,
		Status:    cpTypes.HeartbeatStatus(status),
		Timestamp: time.Now(),
		Metrics:   metricsMap,
	}

	if err := cp.SendHeartbeat(ctx, heartbeat); err != nil {
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}

	return nil
}

// PublishDNAUpdate publishes DNA changes to the controller via the control plane provider.
// Story #363: Uses ControlPlaneProvider.PublishEvent() instead of direct MQTT publish.
func (c *MQTTClient) PublishDNAUpdate(ctx context.Context, dna map[string]string, configHash, syncFingerprint string) error {
	c.mu.RLock()
	stewardID := c.stewardID
	tenantID := c.tenantID
	cp := c.controlPlane
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered")
	}

	if cp == nil {
		return fmt.Errorf("control plane not connected")
	}

	event := &cpTypes.Event{
		ID:        fmt.Sprintf("evt_dna_%d", time.Now().UnixNano()),
		Type:      cpTypes.EventDNAChanged,
		StewardID: stewardID,
		TenantID:  tenantID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"dna":              dna,
			"config_hash":      configHash,
			"sync_fingerprint": syncFingerprint,
		},
	}

	if err := cp.PublishEvent(ctx, event); err != nil {
		return fmt.Errorf("failed to publish DNA update: %w", err)
	}

	c.logger.Info("Published DNA update", "attributes_count", len(dna))
	return nil
}

// publishConfigStatus publishes a config status report as an event (internal helper).
func (c *MQTTClient) publishConfigStatus(report *cpTypes.ConfigStatusReport) error {
	ctx := context.Background()
	return c.ReportConfigurationStatus(ctx, report.ConfigVersion, report.Status, report.Message, report.Modules)
}

// ReportConfigurationStatus reports detailed configuration execution status to the controller.
// Story #363: Uses ControlPlaneProvider.PublishEvent() instead of direct MQTT publish.
func (c *MQTTClient) ReportConfigurationStatus(
	ctx context.Context,
	configVersion string,
	overallStatus string,
	message string,
	moduleStatuses map[string]cpTypes.ModuleStatus,
) error {
	c.mu.RLock()
	stewardID := c.stewardID
	tenantID := c.tenantID
	cp := c.controlPlane
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered")
	}

	if cp == nil {
		return fmt.Errorf("control plane not connected")
	}

	event := &cpTypes.Event{
		ID:        fmt.Sprintf("evt_cfg_%d", time.Now().UnixNano()),
		Type:      cpTypes.EventConfigApplied,
		StewardID: stewardID,
		TenantID:  tenantID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"config_version": configVersion,
			"status":         overallStatus,
			"message":        message,
			"modules":        moduleStatuses,
		},
	}

	if err := cp.PublishEvent(ctx, event); err != nil {
		return fmt.Errorf("failed to publish config status: %w", err)
	}

	c.logger.Info("Published configuration status report",
		"config_version", configVersion,
		"status", overallStatus,
		"modules", len(moduleStatuses))

	return nil
}

// ValidateConfiguration validates a configuration with the controller without applying it.
// Story #363: Not yet supported via ControlPlaneProvider (requires provider extension for
// request/response patterns from steward to controller).
// TODO: Add validation support to ControlPlaneProvider interface.
func (c *MQTTClient) ValidateConfiguration(
	ctx context.Context,
	config []byte,
	version string,
) ([]string, error) {
	return nil, fmt.Errorf("configuration validation not yet supported via control plane provider (Story #363 TODO)")
}

// Disconnect closes all connections to the controller.
// Story #363: Uses ControlPlaneProvider.Stop() instead of direct MQTT disconnect.
func (c *MQTTClient) Disconnect(ctx context.Context) error {
	c.logger.Info("Disconnecting from controller")

	c.mu.Lock()
	defer c.mu.Unlock()

	// Stop heartbeat
	close(c.heartbeatStop)

	// Disconnect data plane session
	if c.dataPlaneSession != nil {
		if err := c.dataPlaneSession.Close(ctx); err != nil {
			c.logger.Warn("Failed to close data plane session", "error", err)
		}
	}

	// Stop control plane provider
	if c.controlPlane != nil {
		if err := c.controlPlane.Stop(ctx); err != nil {
			c.logger.Warn("Failed to stop control plane", "error", err)
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

	// Try environment variables first
	certFile := os.Getenv("CFGMS_MQTT_TLS_CERT_PATH")
	keyFile := os.Getenv("CFGMS_MQTT_TLS_KEY_PATH")
	caFile := os.Getenv("CFGMS_MQTT_TLS_CA_PATH")

	if certFile == "" || keyFile == "" || caFile == "" {
		if certPath == "" {
			return nil, nil
		}
		certFile = filepath.Join(certPath, "client.crt")
		keyFile = filepath.Join(certPath, "client.key")
		caFile = filepath.Join(certPath, "ca.crt")
	}

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
	// #nosec G304 - Certificate paths are controlled via configuration
	caCertBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

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

	if caCertPEMStr != "" && clientCertPEMStr != "" && clientKeyPEMStr != "" {
		c.logger.Info("Using TLS certificates from registration response for QUIC")
		caCertPEM = []byte(caCertPEMStr)
		clientCertPEM = []byte(clientCertPEMStr)
		clientKeyPEM = []byte(clientKeyPEMStr)
	} else {
		if certPath == "" {
			return nil, fmt.Errorf("certificate path is required for mTLS")
		}

		caCertPath := filepath.Join(certPath, "ca.crt")
		// #nosec G304 - Certificate paths are controlled via configuration
		caCertPEM, err = os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
		}

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

	tlsConfig, err := cert.CreateClientTLSConfig(clientCertPEM, clientKeyPEM, caCertPEM, "", tls.VersionTLS13)
	if err != nil {
		return nil, fmt.Errorf("failed to create QUIC TLS config: %w", err)
	}

	tlsConfig.NextProtos = []string{"cfgms-quic"}

	// Initialize configuration signature verifier using controller's certificate
	// Story #377: Prefer dedicated signing cert over server cert
	c.mu.Lock()
	if c.configVerifier == nil {
		var serverCertPEM []byte

		if c.signingCertPEM != "" {
			serverCertPEM = []byte(c.signingCertPEM)
			c.logger.Info("Using dedicated signing certificate for signature verification")
		} else if c.serverCertPEM != "" {
			serverCertPEM = []byte(c.serverCertPEM)
			c.logger.Info("Using server certificate from registration for signature verification")
		} else if certPath != "" {
			// Story #377: Try signing.crt first, fall back to server.crt
			signingCertPath := filepath.Join(certPath, "signing.crt")
			serverCertPath := filepath.Join(certPath, "server.crt")

			// #nosec G304 - Certificate paths are controlled via configuration
			var readErr error
			serverCertPEM, readErr = os.ReadFile(signingCertPath)
			if readErr != nil {
				// Fall back to server.crt
				// #nosec G304 - Certificate paths are controlled via configuration
				serverCertPEM, readErr = os.ReadFile(serverCertPath)
				if readErr != nil {
					c.logger.Warn("Failed to load signing/server certificate for signature verification, using CA",
						"error", readErr)
					serverCertPEM = caCertPEM
				}
			} else {
				c.logger.Info("Using signing.crt from disk for signature verification")
			}
		} else {
			c.logger.Warn("No server certificate available, using CA for signature verification")
			serverCertPEM = caCertPEM
		}

		if len(serverCertPEM) > 0 {
			verifier, verErr := signature.NewVerifier(&signature.VerifierConfig{
				CertificatePEM: serverCertPEM,
			})
			if verErr != nil {
				c.logger.Warn("Failed to create configuration verifier",
					"error", verErr)
			} else {
				c.configVerifier = verifier
				c.logger.Info("Configuration signature verifier initialized",
					"key_fingerprint", verifier.KeyFingerprint())
			}
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
func (c *MQTTClient) saveCertificates(clientCert, clientKey, caCert string) error {
	certDir := os.Getenv("CFGMS_CERT_PATH")
	if certDir == "" {
		certDir = "/etc/cfgms/certs"
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	files := map[string]struct {
		content string
		perm    os.FileMode
	}{
		"client.crt": {clientCert, 0600},
		"client.key": {clientKey, 0600},
		"ca.crt":     {caCert, 0644},
	}

	for filename, file := range files {
		path := filepath.Join(certDir, filename)
		if err := os.WriteFile(path, []byte(file.content), file.perm); err != nil {
			return fmt.Errorf("failed to save %s: %w", filename, err)
		}
		c.logger.Debug("Saved certificate file", "path", path)
	}

	return nil
}

// saveSigningCertificate persists the dedicated signing certificate to disk
func (c *MQTTClient) saveSigningCertificate(signingCert string) error {
	certDir := os.Getenv("CFGMS_CERT_PATH")
	if certDir == "" {
		certDir = "/etc/cfgms/certs"
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	path := filepath.Join(certDir, "signing.crt")
	if err := os.WriteFile(path, []byte(signingCert), 0644); err != nil {
		return fmt.Errorf("failed to save signing certificate: %w", err)
	}

	c.logger.Debug("Saved signing certificate file", "path", path)
	return nil
}
