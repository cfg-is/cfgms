// Package client provides MQTT+QUIC client functionality for steward-controller communication.
//
// This package implements the steward-side client for communicating with
// the CFGMS controller using MQTT (control plane) and QUIC (data plane).
// It replaces the legacy gRPC-based client (Story #198).
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/features/steward/registration"
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

	// MQTT client for control plane
	mqtt *mqttClient.Client

	// QUIC client for data plane
	quic *quicClient.Client
	quicAddress string

	// Certificate path for mTLS
	certPath string

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

	return &MQTTClient{
		heartbeatInterval: heartbeatInterval,
		heartbeatStop:     make(chan struct{}),
		quicAddress:       cfg.QUICAddress,
		certPath:          cfg.TLSCertPath,
		logger:            cfg.Logger,
	}, nil
}

// RegisterWithToken registers the steward with the controller using a token.
func (c *MQTTClient) RegisterWithToken(ctx context.Context, token string, mqttBroker string) error {
	c.logger.Info("Starting registration with token", "broker", mqttBroker)

	// Initialize MQTT client for registration
	mqttCfg := &mqttClient.Config{
		BrokerAddr:   mqttBroker,
		ClientID:     "steward-register-" + token[:8], // Temporary client ID
		CleanSession: true,
		AutoReconnect: true,
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

	// Initialize QUIC client if address configured
	if c.quicAddress != "" {
		c.logger.Info("Initializing QUIC connection", "address", c.quicAddress)

		// TODO: For now, skip QUIC initialization since it requires:
		// 1. TLS config (mTLS certificates)
		// 2. Session ID (from MQTT connect_quic command)
		// Will be implemented when full mTLS flow is ready
		c.logger.Warn("QUIC initialization deferred - needs TLS and session ID")

		// Future implementation:
		// quicCfg := &quicClient.Config{
		//     ServerAddr: c.quicAddress,
		//     TLSConfig:  tlsConfig,
		//     SessionID:  sessionID,
		//     StewardID:  stewardID,
		//     Logger:     c.logger,
		// }
		// quicCli, err := quicClient.New(quicCfg)
		// if err := quicCli.Connect(ctx); err != nil { ... }
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
		// TODO: Implement config sync trigger
		return nil
	})

	// Register sync_dna handler
	handler.RegisterHandler(mqttTypes.CommandSyncDNA, func(ctx context.Context, cmd mqttTypes.Command) error {
		c.logger.Info("Received sync_dna command", "command_id", cmd.CommandID)
		// TODO: Implement DNA sync trigger
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

// createQUICtlsConfig creates a TLS configuration for QUIC with proper mTLS.
func (c *MQTTClient) createQUICtlsConfig(certPath string) (*tls.Config, error) {
	if certPath == "" {
		return nil, fmt.Errorf("certificate path is required for mTLS")
	}

	// Load CA certificate to verify controller's identity
	caCertPath := filepath.Join(certPath, "ca.crt")
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Load client certificate for mTLS authentication
	clientCertPath := filepath.Join(certPath, "client.crt")
	clientKeyPath := filepath.Join(certPath, "client.key")
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate from %s: %w", clientCertPath, err)
	}

	// Create TLS config with mTLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13, // QUIC requires TLS 1.3
		NextProtos:   []string{"cfgms-quic"},
	}

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
