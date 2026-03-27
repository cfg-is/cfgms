// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client provides transport client functionality for steward-controller communication.
//
// This package implements the steward-side client for communicating with
// the CFGMS controller using the gRPC-over-QUIC ControlPlaneProvider (control plane)
// and gRPC DataPlaneProvider (data plane). Both share the same transport_address
// received from the HTTP registration response.
// Story #516: Introduced TransportClient using gRPC providers.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
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
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	_ "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc" // Register gRPC control plane provider
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	_ "github.com/cfgis/cfgms/pkg/dataplane/providers/grpc" // Register gRPC data plane provider
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// TransportClient represents the steward client using gRPC-over-QUIC for both
// control plane and data plane communication with the controller.
// Story #516: Connects once to transport_address for both CP and DP.
type TransportClient struct {
	mu sync.RWMutex

	// Steward identification
	stewardID string
	tenantID  string

	// Transport address (gRPC-over-QUIC, from registration response)
	transportAddress string

	// Control plane provider (gRPC, Story #516)
	controlPlane controlplaneInterfaces.ControlPlaneProvider

	// Data plane session (gRPC, Story #516)
	dataPlaneSession dataplaneInterfaces.DataPlaneSession

	// Certificate path for mTLS (disk-based fallback when PEM certs unavailable)
	certPath string

	// Certificate PEMs (from registration response)
	caCertPEM      string
	clientCertPEM  string
	clientKeyPEM   string
	serverCertPEM  string // Controller's server cert for config signature verification (Story #315)
	signingCertPEM string // Story #377: Dedicated signing cert (preferred over serverCertPEM)

	// Command handler
	commandHandler *commands.Handler

	// Configuration executor (unified engine — same as standalone mode)
	configExecutor *execution.Executor

	// Configuration signature verifier
	configVerifier signature.Verifier

	// Last configuration received from the controller (for scheduled re-convergence)
	lastConfigYAML    []byte
	lastConfigMu      sync.RWMutex
	lastConfigVersion string

	// Convergence loop control
	convergenceStop chan struct{}

	// Connection state — single flag for unified gRPC transport
	connected bool

	// Heartbeat
	heartbeatInterval time.Duration
	heartbeatStop     chan struct{}

	// Logger
	logger logging.Logger
}

// TransportConfig holds configuration for the gRPC-over-QUIC transport client.
type TransportConfig struct {
	// ControllerURL is the gRPC-over-QUIC transport address (e.g., "controller:4433").
	// Received from the registration response as transport_address.
	ControllerURL string

	// RegistrationToken for initial registration
	RegistrationToken string

	// TLSCertPath for mTLS (optional if PEM certs provided from registration)
	TLSCertPath string

	// CACertPEM is the CA certificate PEM (for TLS verification)
	CACertPEM string

	// ClientCertPEM is the client certificate PEM (for mTLS)
	ClientCertPEM string

	// ClientKeyPEM is the client private key PEM (for mTLS)
	ClientKeyPEM string

	// ServerCertPEM is the controller's server certificate PEM (for config signature verification)
	// Story #315: Used to verify configurations signed by the controller
	ServerCertPEM string

	// SigningCertPEM is the controller's dedicated signing certificate PEM (Story #377)
	// When present, preferred over ServerCertPEM for config signature verification
	SigningCertPEM string

	// HeartbeatInterval for periodic heartbeats
	HeartbeatInterval time.Duration

	// Logger for client logging
	Logger logging.Logger
}

// NewTransportClient creates a new steward transport client.
func NewTransportClient(cfg *TransportConfig) (*TransportClient, error) {
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

	c := &TransportClient{
		heartbeatInterval: heartbeatInterval,
		heartbeatStop:     make(chan struct{}),
		convergenceStop:   make(chan struct{}),
		transportAddress:  cfg.ControllerURL,
		certPath:          cfg.TLSCertPath,
		caCertPEM:         cfg.CACertPEM,
		clientCertPEM:     cfg.ClientCertPEM,
		clientKeyPEM:      cfg.ClientKeyPEM,
		serverCertPEM:     cfg.ServerCertPEM,
		signingCertPEM:    cfg.SigningCertPEM,
		logger:            cfg.Logger,
	}

	return c, nil
}

// InitializeConfigExecutor creates and initializes the configuration executor.
// This must be called after the client is connected but before config sync.
// Uses the unified execution engine (all 7 modules, Get→Compare→Set→Verify).
func (c *TransportClient) InitializeConfigExecutor(tenantID string) error {
	execCfg := &execution.ExecutorConfig{
		TenantID: tenantID,
		Logger:   c.logger,
	}
	executor, err := execution.NewExecutor(execCfg)
	if err != nil {
		return fmt.Errorf("failed to create config executor: %w", err)
	}

	c.mu.Lock()
	c.configExecutor = executor
	c.mu.Unlock()

	c.logger.Info("Configuration executor initialized", "tenant_id", tenantID)
	return nil
}

// Connect establishes gRPC control plane and data plane connections to the controller.
// Both use the unified transport_address over QUIC. The data plane is initialized
// eagerly alongside the control plane — no lazy connect_dataplane command required.
// Story #516: Unified gRPC-over-QUIC connection for both control and data plane.
func (c *TransportClient) Connect(ctx context.Context) error {
	c.logger.Info("Connecting to controller via gRPC transport")

	c.mu.RLock()
	stewardID := c.stewardID
	controlPlane := c.controlPlane
	transportAddress := c.transportAddress
	tenantID := c.tenantID
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered - call SetStewardID first")
	}

	// Create TLS configuration for gRPC-over-QUIC
	tlsConfig, err := c.createTLSConfig()
	if err != nil {
		c.logger.Warn("Failed to load TLS config, continuing without TLS", "error", err)
		tlsConfig = nil
	}

	// Initialize gRPC control plane provider if not already set
	if controlPlane == nil {
		c.logger.Info("Initializing gRPC control plane provider",
			"addr", transportAddress, "steward_id", stewardID)

		provider := controlplaneInterfaces.GetProvider("grpc")
		if provider == nil {
			return fmt.Errorf("gRPC control plane provider not registered")
		}

		providerCfg := map[string]interface{}{
			"mode":       "client",
			"addr":       transportAddress,
			"steward_id": stewardID,
		}
		if tenantID != "" {
			providerCfg["tenant_id"] = tenantID
		}
		if tlsConfig != nil {
			providerCfg["tls_config"] = tlsConfig
		}

		if err := provider.Initialize(ctx, providerCfg); err != nil {
			return fmt.Errorf("failed to initialize gRPC control plane provider: %w", err)
		}

		controlPlane = provider
		c.mu.Lock()
		c.controlPlane = controlPlane
		c.mu.Unlock()
	}

	// Start the control plane (connects to gRPC server over QUIC)
	if !controlPlane.IsConnected() {
		c.logger.Info("Starting gRPC control plane connection", "addr", transportAddress)
		if err := controlPlane.Start(ctx); err != nil {
			return fmt.Errorf("failed to start gRPC control plane: %w", err)
		}
		c.logger.Info("gRPC control plane connection established")
	}

	// Initialize gRPC data plane provider eagerly — shares the same transport_address
	c.logger.Info("Initializing gRPC data plane provider", "addr", transportAddress)
	dpProvider := dataplaneInterfaces.GetProvider("grpc")
	if dpProvider == nil {
		return fmt.Errorf("gRPC data plane provider not registered")
	}

	dpCfg := map[string]interface{}{
		"mode":        "client",
		"server_addr": transportAddress,
		"steward_id":  stewardID,
	}
	if tlsConfig != nil {
		dpCfg["tls_config"] = tlsConfig
	}

	if err := dpProvider.Initialize(ctx, dpCfg); err != nil {
		return fmt.Errorf("failed to initialize gRPC data plane provider: %w", err)
	}

	if err := dpProvider.Start(ctx); err != nil {
		return fmt.Errorf("failed to start gRPC data plane provider: %w", err)
	}

	session, err := dpProvider.Connect(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to establish data plane session: %w", err)
	}

	c.mu.Lock()
	c.dataPlaneSession = session
	c.mu.Unlock()

	c.logger.Info("gRPC data plane initialized", "session_id", session.ID())

	// Setup command handler
	cmdHandler, err := c.setupCommandHandler(ctx, stewardID)
	if err != nil {
		return fmt.Errorf("failed to setup command handler: %w", err)
	}

	c.mu.Lock()
	c.commandHandler = cmdHandler
	c.mu.Unlock()

	// Subscribe to commands via gRPC control plane provider
	c.logger.Info("Subscribing to commands", "steward_id", stewardID)
	if err := controlPlane.SubscribeCommands(ctx, stewardID, func(ctx context.Context, cmd *cpTypes.Command) error {
		return cmdHandler.HandleCommand(ctx, cmd)
	}); err != nil {
		return fmt.Errorf("failed to subscribe to commands: %w", err)
	}

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	// Start heartbeat
	go c.startHeartbeat()

	c.logger.Info("Connected to controller successfully via gRPC transport")
	return nil
}

// setupCommandHandler creates and configures the command handler with all command types.
// Story #516: connect_dataplane handler removed — DP is initialized eagerly in Connect().
func (c *TransportClient) setupCommandHandler(ctx context.Context, stewardID string) (*commands.Handler, error) {
	// Create status callback that publishes events via gRPC control plane provider
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

	// Register sync_config handler — retrieves config via gRPC data plane ReceiveConfig()
	handler.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, cmd *cpTypes.Command) error {
		c.logger.Info("Received sync_config command", "command_id", cmd.ID, "params", cmd.Params)

		// Get modules filter from command params (optional, passed as context but not used in gRPC request)
		var modules []string
		if modulesParam, ok := cmd.Params["modules"].([]interface{}); ok {
			for _, m := range modulesParam {
				if modStr, ok := m.(string); ok {
					modules = append(modules, modStr)
				}
			}
		}

		// Retrieve configuration via gRPC data plane
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

		// Store validated config for scheduled re-convergence runs.
		// This is set before Apply so that even if Apply fails, the next
		// scheduled convergence attempt uses the latest verified cfg.
		c.lastConfigMu.Lock()
		c.lastConfigYAML = configYAML
		c.lastConfigVersion = version
		c.lastConfigMu.Unlock()

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

// GetConfiguration retrieves configuration from the controller via gRPC data plane.
// Story #516: Uses DataPlaneSession.ReceiveConfig() over gRPC instead of raw QUIC streams.
func (c *TransportClient) GetConfiguration(ctx context.Context, modules []string) ([]byte, string, error) {
	c.logger.Info("Requesting configuration via gRPC data plane")

	c.mu.RLock()
	session := c.dataPlaneSession
	c.mu.RUnlock()

	if session == nil || session.IsClosed() {
		return nil, "", fmt.Errorf("data plane session not available")
	}

	transfer, err := session.ReceiveConfig(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to receive configuration: %w", err)
	}

	c.logger.Info("Configuration received",
		"version", transfer.Version,
		"data_size", len(transfer.Data))

	return transfer.Data, transfer.Version, nil
}

// SendHeartbeat sends a heartbeat to the controller via the gRPC control plane provider.
func (c *TransportClient) SendHeartbeat(ctx context.Context, status string, metrics map[string]string) error {
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

// PublishDNAUpdate publishes DNA changes to the controller via the gRPC control plane provider.
func (c *TransportClient) PublishDNAUpdate(ctx context.Context, dna map[string]string, configHash, syncFingerprint string) error {
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
func (c *TransportClient) publishConfigStatus(report *cpTypes.ConfigStatusReport) error {
	ctx := context.Background()
	return c.ReportConfigurationStatus(ctx, report.ConfigVersion, report.Status, report.Message, report.Modules)
}

// ReportConfigurationStatus reports detailed configuration execution status to the controller.
func (c *TransportClient) ReportConfigurationStatus(
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
// TODO: Add validation support to ControlPlaneProvider interface (Story #363 carried forward).
func (c *TransportClient) ValidateConfiguration(
	ctx context.Context,
	config []byte,
	version string,
) ([]string, error) {
	return nil, fmt.Errorf("configuration validation not yet supported via control plane provider")
}

// StartConvergenceLoop starts a background goroutine that re-converges against
// the last-received cfg on the given interval.
//
// On each tick the loop calls TriggerConvergence, which re-applies the last
// verified cfg using the unified execution engine. If no cfg has been received
// yet the tick is skipped silently and the loop waits for the next interval.
//
// The loop stops when ctx is cancelled or Disconnect is called.
func (c *TransportClient) StartConvergenceLoop(ctx context.Context, interval time.Duration) {
	c.logger.Info("Starting scheduled convergence loop", "interval", interval)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.convergenceStop:
				return
			case <-ticker.C:
				c.logger.Info("Scheduled convergence triggered", "interval", interval)
				if err := c.TriggerConvergence(ctx); err != nil {
					c.logger.Warn("Scheduled convergence failed", "error", err)
				}
			}
		}
	}()
}

// TriggerConvergence re-applies the last configuration received from the controller.
//
// This is called both by the scheduled convergence loop and can be used directly
// for immediate convergence outside the normal schedule (e.g. after reconnecting).
// Returns nil without error if no cfg has been received yet.
func (c *TransportClient) TriggerConvergence(ctx context.Context) error {
	c.lastConfigMu.RLock()
	lastCfg := c.lastConfigYAML
	lastVersion := c.lastConfigVersion
	c.lastConfigMu.RUnlock()

	if len(lastCfg) == 0 {
		c.logger.Info("No configuration available yet, skipping convergence run")
		return nil
	}

	c.mu.RLock()
	executor := c.configExecutor
	sid := c.stewardID
	c.mu.RUnlock()

	if executor == nil {
		return fmt.Errorf("configuration executor not available")
	}

	c.logger.Info("Running convergence against last-received cfg", "version", lastVersion)

	report, err := executor.ApplyConfiguration(ctx, lastCfg, lastVersion)
	if err != nil {
		return fmt.Errorf("convergence failed: %w", err)
	}

	if report != nil {
		report.StewardID = sid
		if pubErr := c.publishConfigStatus(report); pubErr != nil {
			c.logger.Warn("Failed to publish convergence status", "error", pubErr)
		}
	}

	c.logger.Info("Convergence run completed", "version", lastVersion, "status", report.Status)
	return nil
}

// Disconnect closes all gRPC connections to the controller.
func (c *TransportClient) Disconnect(ctx context.Context) error {
	c.logger.Info("Disconnecting from controller")

	c.mu.Lock()
	defer c.mu.Unlock()

	// Stop heartbeat and convergence loop
	close(c.heartbeatStop)
	close(c.convergenceStop)

	// Close data plane session
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

	c.logger.Info("Disconnected from controller")
	return nil
}

// IsConnected returns whether the client is connected.
func (c *TransportClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetStewardID returns the steward ID.
func (c *TransportClient) GetStewardID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stewardID
}

// GetTenantID returns the tenant ID.
func (c *TransportClient) GetTenantID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tenantID
}

// SetStewardID sets the steward ID (used after HTTP registration).
func (c *TransportClient) SetStewardID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stewardID = id
}

// SetTenantID sets the tenant ID (used after HTTP registration).
func (c *TransportClient) SetTenantID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tenantID = id
}

// createTLSConfig creates a TLS configuration for gRPC-over-QUIC with mTLS.
// Sets ALPN to "cfgms-grpc" required by the QUIC transport layer.
// Sources: PEM certs from registration (preferred), disk path, or environment variables.
func (c *TransportClient) createTLSConfig() (*tls.Config, error) {
	c.mu.RLock()
	caCertPEMStr := c.caCertPEM
	clientCertPEMStr := c.clientCertPEM
	clientKeyPEMStr := c.clientKeyPEM
	certPath := c.certPath
	c.mu.RUnlock()

	var caCertPEM, clientCertPEM, clientKeyPEM []byte
	var err error

	if caCertPEMStr != "" && clientCertPEMStr != "" && clientKeyPEMStr != "" {
		// Primary path: PEM certs from HTTP registration response
		c.logger.Info("Using TLS certificates from registration response")
		caCertPEM = []byte(caCertPEMStr)
		clientCertPEM = []byte(clientCertPEMStr)
		clientKeyPEM = []byte(clientKeyPEMStr)
	} else if certPath != "" {
		// Secondary path: certificates on disk
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

		c.logger.Info("Loaded TLS configuration from disk", "cert_path", certPath)
	} else {
		// Tertiary path: environment variables
		certFile := os.Getenv("CFGMS_TLS_CERT_PATH")
		keyFile := os.Getenv("CFGMS_TLS_KEY_PATH")
		caFile := os.Getenv("CFGMS_TLS_CA_PATH")

		if certFile == "" || keyFile == "" || caFile == "" {
			// No TLS config available — provider will connect without mTLS
			return nil, nil
		}

		// #nosec G304 - Certificate paths are controlled via configuration
		clientCertPEM, err = os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client certificate: %w", err)
		}
		// #nosec G304 - Certificate paths are controlled via configuration
		clientKeyPEM, err = os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client key: %w", err)
		}
		// #nosec G304 - Certificate paths are controlled via configuration
		caCertPEM, err = os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		c.logger.Info("Loaded TLS configuration from environment variables")
	}

	tlsConfig, err := cert.CreateClientTLSConfig(clientCertPEM, clientKeyPEM, caCertPEM, "", tls.VersionTLS13)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	// gRPC-over-QUIC requires the cfgms-grpc ALPN protocol
	tlsConfig.NextProtos = []string{quictransport.ALPNProtocol}

	// Initialize configuration signature verifier using controller's certificate.
	// Story #377: Prefer dedicated signing cert over server cert.
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
					c.logger.Warn("Failed to load signing/server certificate for signature verification, using CA")
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
				c.logger.Warn("Failed to create configuration verifier", "error", verErr)
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
func (c *TransportClient) startHeartbeat() {
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
