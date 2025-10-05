// Package client provides gRPC client functionality for steward-controller communication.
//
// This package implements the steward-side gRPC client for communicating with
// the CFGMS controller. It handles mTLS authentication, registration, heartbeats,
// and DNA synchronization.
//
// Basic usage:
//
//	client, err := client.New(controllerAddr, certPath, logger)
//	if err != nil {
//		log.Fatal(err)
//	}
//	
//	ctx := context.Background()
//	err = client.Connect(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//	
//	// Register with controller
//	stewardID, err := client.Register(ctx, version, dna)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// #nosec G304 - Steward client requires file access for configuration and certificate management
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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
	mqttClient "github.com/cfgis/cfgms/pkg/mqtt/client"
	mqttTypes "github.com/cfgis/cfgms/pkg/mqtt/types"
)

// Client provides gRPC client functionality for steward-controller communication.
//
// The client handles mTLS authentication, registration with the controller,
// heartbeat mechanism, and DNA synchronization. All operations are thread-safe
// and support context cancellation.
type Client struct {
	mu sync.RWMutex

	// Connection details
	controllerAddr string
	certPath       string
	logger         logging.Logger

	// gRPC connection and client
	conn         *grpc.ClientConn
	client       controllerpb.ControllerClient
	configClient controllerpb.ConfigurationServiceClient

	// Authentication state
	credentials *commonpb.Credentials
	token       *commonpb.Token
	stewardID   string

	// Connection state
	connected bool
	
	// Health and heartbeat
	lastHeartbeat time.Time
	heartbeatInterval time.Duration
	heartbeatStop chan struct{}
	heartbeatRunning bool

	// MQTT client for heartbeats and commands (Story #198)
	mqttClient *mqttClient.Client
	mqttEnabled bool
	commandHandler *commands.Handler
	
	// Sync tracking
	lastSyncFingerprint string
	lastSyncTime        time.Time
	isReconnection      bool
	
	// Health monitoring callback (optional)
	healthCallback func(connected bool, success bool)
}

// New creates a new gRPC client for controller communication.
//
// The client will use mTLS authentication with certificates from the specified
// certPath directory. The directory should contain:
//   - client.crt: Client certificate
//   - client.key: Client private key  
//   - ca.crt: Certificate authority certificate
//
// Returns an error if certificate loading fails or if required parameters are missing.
func New(controllerAddr, certPath string, logger logging.Logger) (*Client, error) {
	if controllerAddr == "" {
		return nil, fmt.Errorf("controller address is required")
	}
	if certPath == "" {
		return nil, fmt.Errorf("certificate path is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Load credentials from certificate files
	creds, err := loadCredentials(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}

	return &Client{
		controllerAddr:    controllerAddr,
		certPath:          certPath,
		logger:            logger,
		credentials:       creds,
		heartbeatInterval: 30 * time.Second,
		heartbeatStop:     make(chan struct{}),
	}, nil
}

// Connect establishes a gRPC connection to the controller with mTLS authentication.
//
// This method loads the client certificates and establishes a secure connection
// to the controller. The connection includes keepalive settings for reliability.
//
// Returns an error if certificate loading or connection establishment fails.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil // Already connected
	}

	c.logger.Info("Connecting to controller", "addr", c.controllerAddr)

	// Load TLS credentials
	tlsCreds, err := c.loadTLSCredentials()
	if err != nil {
		return fmt.Errorf("failed to load TLS credentials: %w", err)
	}

	// Set up gRPC connection with keepalive
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	conn, err := grpc.NewClient(c.controllerAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to controller: %w", err)
	}

	c.conn = conn
	c.client = controllerpb.NewControllerClient(conn)
	c.configClient = controllerpb.NewConfigurationServiceClient(conn)
	c.connected = true

	c.logger.Info("Connected to controller successfully")
	return nil
}

// initMQTTClient initializes the MQTT client for heartbeat and command communication (Story #198).
func (c *Client) initMQTTClient(ctx context.Context) error {
	// Parse controller address to get MQTT broker address
	// Assuming controller gRPC is on :50051, MQTT is on :1883
	// This should be configurable in production
	mqttAddr := "tcp://controller:1883" // TODO: Make configurable

	// Create will message for disconnect detection
	willPayload, err := json.Marshal(map[string]interface{}{
		"steward_id": c.stewardID,
		"status":     "disconnected",
		"timestamp":  time.Now().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("failed to create will message: %w", err)
	}

	mqttCfg := &mqttClient.Config{
		BrokerAddr:   mqttAddr,
		ClientID:     fmt.Sprintf("steward-%s", c.stewardID),
		StewardID:    c.stewardID,
		CertFile:     filepath.Join(c.certPath, "client.crt"),
		KeyFile:      filepath.Join(c.certPath, "client.key"),
		CAFile:       filepath.Join(c.certPath, "ca.crt"),
		CleanSession: false,
		KeepAlive:    30 * time.Second,
		AutoReconnect: true,
		MaxReconnectInt: 60 * time.Second,
		WillEnabled:  true,
		WillTopic:    fmt.Sprintf("cfgms/steward/%s/will", c.stewardID),
		WillPayload:  willPayload,
		WillQoS:      1,
		WillRetain:   false,
		OnConnect: func() {
			c.logger.Info("MQTT client connected to broker")
		},
		OnDisconnect: func() {
			c.logger.Warn("MQTT client disconnected from broker")
		},
	}

	client, err := mqttClient.New(mqttCfg)
	if err != nil {
		return fmt.Errorf("failed to create MQTT client: %w", err)
	}

	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect MQTT client: %w", err)
	}

	c.mqttClient = client

	// Initialize command handler (Story #198)
	commandHandler, err := commands.New(&commands.Config{
		StewardID: c.stewardID,
		OnStatus:  c.publishStatus,
		Logger:    c.logger,
	})
	if err != nil {
		return fmt.Errorf("failed to create command handler: %w", err)
	}

	// Register default command handlers
	c.registerCommandHandlers(commandHandler)

	c.commandHandler = commandHandler

	// Subscribe to command topic
	commandTopic := fmt.Sprintf("cfgms/steward/%s/commands", c.stewardID)
	if err := client.Subscribe(ctx, commandTopic, 1, c.handleMQTTCommand); err != nil {
		return fmt.Errorf("failed to subscribe to commands: %w", err)
	}

	c.logger.Info("MQTT command handler initialized", "topic", commandTopic)

	return nil
}

// handleMQTTCommand receives MQTT command messages and forwards to handler.
func (c *Client) handleMQTTCommand(topic string, payload []byte) {
	if c.commandHandler != nil {
		if err := c.commandHandler.HandleCommand(topic, payload); err != nil {
			c.logger.Error("Failed to handle command", "error", err, "topic", topic)
		}
	}
}

// publishStatus publishes a status update to the controller via MQTT.
func (c *Client) publishStatus(status mqttTypes.StatusUpdate) {
	if c.mqttClient == nil || !c.mqttClient.IsConnected() {
		c.logger.Warn("Cannot publish status, MQTT not connected", "event", status.Event)
		return
	}

	payload, err := json.Marshal(status)
	if err != nil {
		c.logger.Error("Failed to marshal status update", "error", err)
		return
	}

	topic := fmt.Sprintf("cfgms/steward/%s/status", c.stewardID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.mqttClient.Publish(ctx, topic, payload, 1, false); err != nil {
		c.logger.Error("Failed to publish status update", "error", err, "topic", topic)
	} else {
		c.logger.Debug("Published status update", "event", status.Event, "command_id", status.CommandID)
	}
}

// registerCommandHandlers registers default command handlers.
func (c *Client) registerCommandHandlers(handler *commands.Handler) {
	// Register sync_config handler
	handler.RegisterHandler(mqttTypes.CommandSyncConfig, func(ctx context.Context, cmd mqttTypes.Command) error {
		c.logger.Info("Received sync_config command", "command_id", cmd.CommandID)
		// TODO: Implement QUIC-based configuration sync
		return fmt.Errorf("QUIC configuration sync not yet implemented")
	})

	// Register sync_dna handler
	handler.RegisterHandler(mqttTypes.CommandSyncDNA, func(ctx context.Context, cmd mqttTypes.Command) error {
		c.logger.Info("Received sync_dna command", "command_id", cmd.CommandID)
		// TODO: Implement QUIC-based DNA sync
		return fmt.Errorf("QUIC DNA sync not yet implemented")
	})

	// Register connect_quic handler
	handler.RegisterHandler(mqttTypes.CommandConnectQUIC, func(ctx context.Context, cmd mqttTypes.Command) error {
		c.logger.Info("Received connect_quic command", "command_id", cmd.CommandID)
		// TODO: Implement QUIC connection establishment
		return fmt.Errorf("QUIC connection not yet implemented")
	})

	// Register shutdown handler
	handler.RegisterHandler(mqttTypes.CommandShutdown, func(ctx context.Context, cmd mqttTypes.Command) error {
		c.logger.Info("Received shutdown command", "command_id", cmd.CommandID)
		// Graceful shutdown
		return c.Disconnect()
	})
}

// Disconnect closes the gRPC connection to the controller.
//
// This method stops the heartbeat mechanism and closes the connection.
// It's safe to call multiple times.
func (c *Client) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil // Already disconnected
	}

	c.logger.Info("Disconnecting from controller")

	// Stop heartbeat if running
	if c.heartbeatRunning {
		select {
		case <-c.heartbeatStop:
			// Already closed
		default:
			close(c.heartbeatStop)
		}
		c.heartbeatRunning = false
	}

	// Disconnect MQTT client if connected (Story #198)
	if c.mqttClient != nil {
		c.logger.Info("Disconnecting MQTT client")
		c.mqttClient.Disconnect()
		c.mqttClient = nil
		c.mqttEnabled = false
	}

	// Close connection
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		c.configClient = nil

		if err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}

	// Always set connected to false, even if conn was nil
	c.connected = false

	c.logger.Info("Disconnected from controller")
	return nil
}

// Register registers this steward with the controller.
//
// This method sends the steward's version information and initial DNA to the
// controller for registration. On success, it returns the assigned steward ID
// and starts the heartbeat mechanism.
//
// Returns an error if registration fails or if not connected to the controller.
func (c *Client) Register(ctx context.Context, version string, dna *commonpb.DNA) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return "", fmt.Errorf("not connected to controller")
	}

	c.logger.Info("Registering with controller", 
		"version", version, 
		"is_reconnection", c.isReconnection,
		"dna_id", dna.Id)

	req := &controllerpb.RegisterRequest{
		Version:      version,
		InitialDna:   dna,
		Credentials:  c.credentials,
		IsReconnection: c.isReconnection,
	}
	
	// Add sync verification data for reconnections
	if c.isReconnection && c.lastSyncFingerprint != "" {
		req.ExpectedSyncFingerprint = c.lastSyncFingerprint
		req.LastKnownSync = timestamppb.New(c.lastSyncTime)
	}

	resp, err := c.client.AcceptRegistration(ctx, req)
	if err != nil {
		return "", fmt.Errorf("registration failed: %w", err)
	}

	if resp.Status.Code != commonpb.Status_OK {
		return "", fmt.Errorf("registration rejected: %s", resp.Status.Message)
	}

	c.stewardID = resp.StewardId
	c.token = resp.Token

	// Update sync tracking
	if resp.SyncStatus != nil {
		c.lastSyncFingerprint = resp.SyncStatus.SyncFingerprint
		if resp.SyncStatus.LastSyncTime != nil {
			c.lastSyncTime = resp.SyncStatus.LastSyncTime.AsTime()
		}
	}

	c.logger.Info("Registered successfully", 
		"steward_id", c.stewardID,
		"in_sync", resp.SyncStatus != nil && resp.SyncStatus.IsInSync,
		"requires_dna_resync", resp.RequiresDnaResync,
		"requires_config_resync", resp.RequiresConfigResync)

	// Handle required resyncs
	if resp.RequiresDnaResync || resp.RequiresConfigResync {
		c.logger.Warn("Server indicates resync required",
			"dna_resync", resp.RequiresDnaResync,
			"config_resync", resp.RequiresConfigResync,
			"reason", resp.SyncStatus.Reason)
		
		// TODO: Trigger resync operations based on flags
		// This would be handled by the calling steward
	}

	// Story #198: Initialize MQTT client for heartbeats (if MQTT broker is available)
	// Note: MQTT connection is optional - if it fails, we fall back to gRPC heartbeats
	if err := c.initMQTTClient(ctx); err != nil {
		c.logger.Warn("Failed to initialize MQTT client, will use gRPC heartbeats", "error", err)
		c.mqttEnabled = false
	} else {
		c.mqttEnabled = true
		c.logger.Info("MQTT client initialized successfully for heartbeats")
	}

	// Start heartbeat mechanism if not already running
	if !c.heartbeatRunning {
		c.heartbeatStop = make(chan struct{})
		c.heartbeatRunning = true
		go c.startHeartbeat()
	}

	return c.stewardID, nil
}

// SendHeartbeat sends a heartbeat to the controller with current health metrics.
//
// This method is called automatically by the heartbeat mechanism but can also
// be called manually to send immediate status updates.
//
// Story #198: Uses MQTT when available for push-based heartbeats, falls back to gRPC.
//
// Returns an error if the heartbeat fails or if not registered with the controller.
func (c *Client) SendHeartbeat(ctx context.Context, status string, metrics map[string]string) error {
	c.mu.RLock()
	stewardID := c.stewardID
	mqttClient := c.mqttClient
	mqttEnabled := c.mqttEnabled
	grpcClient := c.client
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return fmt.Errorf("not connected to controller")
	}
	if stewardID == "" {
		return fmt.Errorf("not registered with controller")
	}

	// Story #198: Use MQTT for heartbeats when available
	if mqttEnabled && mqttClient != nil && mqttClient.IsConnected() {
		return c.sendMQTTHeartbeat(ctx, stewardID, status, metrics)
	}

	// Fallback to gRPC heartbeat
	req := &controllerpb.HeartbeatRequest{
		StewardId: stewardID,
		Status:    status,
		Metrics:   metrics,
	}

	resp, err := grpcClient.ProcessHeartbeat(ctx, req)
	if err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}

	if resp.Code != commonpb.Status_OK {
		return fmt.Errorf("heartbeat rejected: %s", resp.Message)
	}

	c.mu.Lock()
	c.lastHeartbeat = time.Now()
	c.mu.Unlock()

	return nil
}

// sendMQTTHeartbeat publishes a heartbeat message to MQTT broker.
func (c *Client) sendMQTTHeartbeat(ctx context.Context, stewardID, status string, metrics map[string]string) error {
	// Map status string to HeartbeatStatus type
	var hbStatus mqttTypes.HeartbeatStatus
	switch status {
	case "healthy":
		hbStatus = mqttTypes.StatusHealthy
	case "degraded":
		hbStatus = mqttTypes.StatusDegraded
	case "error":
		hbStatus = mqttTypes.StatusError
	default:
		hbStatus = mqttTypes.StatusHealthy
	}

	// Create heartbeat message using typed struct
	heartbeat := mqttTypes.Heartbeat{
		StewardID: stewardID,
		Status:    hbStatus,
		Timestamp: time.Now(),
		Metrics:   metrics,
	}

	payload, err := json.Marshal(heartbeat)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	// Publish to steward-specific heartbeat topic
	topic := fmt.Sprintf("cfgms/steward/%s/heartbeat", stewardID)
	if err := c.mqttClient.Publish(ctx, topic, payload, 1, false); err != nil {
		return fmt.Errorf("failed to publish MQTT heartbeat: %w", err)
	}

	c.mu.Lock()
	c.lastHeartbeat = time.Now()
	c.mu.Unlock()

	return nil
}

// SyncDNA synchronizes the steward's DNA with the controller.
//
// This method sends the current DNA to the controller for synchronization.
// The controller may use this information for configuration targeting.
//
// Returns an error if synchronization fails or if not connected to the controller.
func (c *Client) SyncDNA(ctx context.Context, dna *commonpb.DNA) error {
	c.mu.RLock()
	client := c.client
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return fmt.Errorf("not connected to controller")
	}

	resp, err := client.SyncDNA(ctx, dna)
	if err != nil {
		return fmt.Errorf("DNA sync failed: %w", err)
	}

	if resp.Code != commonpb.Status_OK {
		return fmt.Errorf("DNA sync rejected: %s", resp.Message)
	}

	c.logger.Debug("DNA synchronized successfully")
	return nil
}

// IsConnected returns true if the client is connected to the controller.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// IsRegistered returns true if the steward is registered with the controller.
func (c *Client) IsRegistered() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stewardID != ""
}

// GetStewardID returns the assigned steward ID, or empty string if not registered.
func (c *Client) GetStewardID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stewardID
}

// GetLastHeartbeat returns the timestamp of the last successful heartbeat.
func (c *Client) GetLastHeartbeat() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastHeartbeat
}

// SetHealthCallback sets a callback function for health monitoring updates.
//
// The callback will be called with the connection status and heartbeat success/failure.
// This is useful for integrating with the steward's health monitoring system.
func (c *Client) SetHealthCallback(callback func(connected bool, success bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.healthCallback = callback
}

// startHeartbeat starts the automatic heartbeat mechanism.
//
// This method runs in a separate goroutine and sends periodic heartbeats
// to the controller. It stops when the heartbeatStop channel is closed.
func (c *Client) startHeartbeat() {
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()

	c.logger.Info("Starting heartbeat mechanism", "interval", c.heartbeatInterval)

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			
			// Create basic health metrics
			metrics := map[string]string{
				"last_heartbeat": c.lastHeartbeat.Format(time.RFC3339),
				"uptime":         time.Since(c.lastHeartbeat).String(),
			}
			
			err := c.SendHeartbeat(ctx, "healthy", metrics)
			
			// Notify health monitoring system
			c.mu.RLock()
			callback := c.healthCallback
			connected := c.connected
			c.mu.RUnlock()
			
			if callback != nil {
				callback(connected, err == nil)
			}
			
			if err != nil {
				c.logger.Error("Heartbeat failed", "error", err)
			}
			
			cancel()
			
		case <-c.heartbeatStop:
			c.logger.Info("Heartbeat mechanism stopped")
			// Note: heartbeatRunning flag will be set to false by Disconnect()
			return
		}
	}
}

// loadTLSCredentials loads the TLS credentials for mTLS authentication.
//
// This method loads the client certificate, private key, and CA certificate
// from the certificate directory and creates gRPC transport credentials.
func (c *Client) loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(
		filepath.Join(c.certPath, "client.crt"),
		filepath.Join(c.certPath, "client.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(filepath.Join(c.certPath, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "cfgms-controller", // Should match certificate
		MinVersion:   tls.VersionTLS12,   // Enforce minimum TLS 1.2
	}

	return credentials.NewTLS(tlsConfig), nil
}

// loadCredentials loads the credentials from certificate files.
//
// This method reads the client certificate and creates the credentials
// structure required for authentication with the controller.
func loadCredentials(certPath string) (*commonpb.Credentials, error) {
	// Load client certificate
	clientCertData, err := os.ReadFile(filepath.Join(certPath, "client.crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate: %w", err)
	}

	// For now, use placeholder values for tenant_id and client_id
	// These would normally be extracted from the certificate or configuration
	return &commonpb.Credentials{
		TenantId:    "default",
		ClientId:    "steward-client",
		Certificate: clientCertData,
	}, nil
}

// GetConfiguration retrieves configuration from the controller.
//
// This method requests configuration from the controller for the registered steward.
// Optionally, specific modules can be requested to filter the configuration.
//
// Returns the configuration and version, or an error if retrieval fails.
func (c *Client) GetConfiguration(ctx context.Context, modules []string) (*config.StewardConfig, string, error) {
	c.mu.RLock()
	configClient := c.configClient
	connected := c.connected
	stewardID := c.stewardID
	c.mu.RUnlock()

	if !connected {
		return nil, "", fmt.Errorf("not connected to controller")
	}
	if stewardID == "" {
		return nil, "", fmt.Errorf("not registered with controller")
	}

	req := &controllerpb.ConfigRequest{
		StewardId: stewardID,
		Modules:   modules,
	}

	resp, err := configClient.GetConfiguration(ctx, req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get configuration: %w", err)
	}

	if resp.Status.Code != commonpb.Status_OK {
		return nil, "", fmt.Errorf("configuration request failed: %s", resp.Status.Message)
	}

	// Parse the configuration
	var stewardConfig config.StewardConfig
	if err := json.Unmarshal(resp.Config, &stewardConfig); err != nil {
		return nil, "", fmt.Errorf("failed to parse configuration: %w", err)
	}

	c.logger.Info("Configuration retrieved successfully", "version", resp.Version, "resources", len(stewardConfig.Resources))
	return &stewardConfig, resp.Version, nil
}

// ReportConfigurationStatus reports the status of configuration execution to the controller.
//
// This method sends a status report to the controller about the execution of
// configuration resources, including overall status and per-module details.
//
// Returns an error if the report fails to be sent or is rejected by the controller.
func (c *Client) ReportConfigurationStatus(ctx context.Context, configVersion string, status commonpb.Status_Code, message string, moduleStatuses map[string]*controllerpb.ModuleStatus) error {
	c.mu.RLock()
	configClient := c.configClient
	connected := c.connected
	stewardID := c.stewardID
	c.mu.RUnlock()

	if !connected {
		return fmt.Errorf("not connected to controller")
	}
	if stewardID == "" {
		return fmt.Errorf("not registered with controller")
	}

	// Convert module statuses to slice
	var modules []*controllerpb.ModuleStatus
	for _, moduleStatus := range moduleStatuses {
		modules = append(modules, moduleStatus)
	}

	req := &controllerpb.ConfigStatusReport{
		StewardId:     stewardID,
		ConfigVersion: configVersion,
		Status: &commonpb.Status{
			Code:    status,
			Message: message,
		},
		Modules: modules,
	}

	resp, err := configClient.ReportConfigStatus(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to report configuration status: %w", err)
	}

	if resp.Code != commonpb.Status_OK {
		return fmt.Errorf("configuration status report rejected: %s", resp.Message)
	}

	c.logger.Debug("Configuration status reported successfully", "version", configVersion, "status", status)
	return nil
}

// ValidateConfiguration validates a configuration with the controller.
//
// This method sends a configuration to the controller for validation
// without actually applying it. Useful for pre-flight checks.
//
// Returns validation errors if any, or nil if the configuration is valid.
func (c *Client) ValidateConfiguration(ctx context.Context, stewardConfig *config.StewardConfig, version string) ([]string, error) {
	c.mu.RLock()
	configClient := c.configClient
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return nil, fmt.Errorf("not connected to controller")
	}

	// Marshal configuration
	configData, err := json.Marshal(stewardConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configuration: %w", err)
	}

	req := &controllerpb.ConfigValidationRequest{
		Config:  configData,
		Version: version,
	}

	resp, err := configClient.ValidateConfig(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to validate configuration: %w", err)
	}

	if resp.Status.Code != commonpb.Status_OK {
		var errorMessages []string
		for _, validationError := range resp.Errors {
			errorMessages = append(errorMessages, fmt.Sprintf("%s: %s", validationError.Field, validationError.Message))
		}
		return errorMessages, fmt.Errorf("configuration validation failed: %s", resp.Status.Message)
	}

	c.logger.Debug("Configuration validation successful", "version", version)
	return nil, nil
}

// SetReconnectionMode marks this client as a reconnection with previous sync state.
//
// This should be called before Register() when the steward is reconnecting
// to the controller after a disconnect, to enable sync verification.
func (c *Client) SetReconnectionMode(lastSyncFingerprint string, lastSyncTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.isReconnection = true
	c.lastSyncFingerprint = lastSyncFingerprint
	c.lastSyncTime = lastSyncTime
	
	c.logger.Debug("Set reconnection mode", 
		"fingerprint", lastSyncFingerprint,
		"last_sync", lastSyncTime.Format(time.RFC3339))
}

// GetSyncStatus returns the current sync status information.
//
// This provides access to the latest sync fingerprint and timestamp
// for persistence and reconnection scenarios.
func (c *Client) GetSyncStatus() (string, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	return c.lastSyncFingerprint, c.lastSyncTime
}

// UpdateSyncState updates the client's sync tracking when DNA or config changes.
//
// This should be called by the steward when DNA is updated or configuration
// changes to maintain accurate sync state.
func (c *Client) UpdateSyncState(syncFingerprint string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.lastSyncFingerprint = syncFingerprint
	c.lastSyncTime = time.Now()
	
	c.logger.Debug("Updated sync state", 
		"fingerprint", syncFingerprint,
		"timestamp", c.lastSyncTime.Format(time.RFC3339))
}