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
	"encoding/json"
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
	dna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	_ "github.com/cfgis/cfgms/pkg/dataplane/providers/grpc" // Register gRPC data plane provider
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
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
	convergenceStop  chan struct{}
	convergeInterval time.Duration // cfg-driven; updated on each sync_config

	// Connection state — single flag for unified gRPC transport
	connected bool

	// Heartbeat
	heartbeatInterval time.Duration
	heartbeatStop     chan struct{}

	// offlineQueue persists reports locally when the controller is unreachable.
	// Issue #419: drained in order after a successful reconnect.
	offlineQueue *OfflineQueue

	// DNA state for hash-based sync (Issue #418).
	// dnaMu guards currentDNAHash and lastPublishedDNA.
	dnaMu            sync.RWMutex
	currentDNAHash   string            // SHA-256 hash of most-recently observed DNA
	lastPublishedDNA map[string]string // full DNA from the last PublishDNAUpdate call

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

	// QueueDir is the directory used to persist the offline report queue.
	// If empty the queue operates in-memory only (events are lost on restart).
	// Issue #419: set this to a stable path (e.g. steward data directory) for
	// durable offline queueing across restarts.
	QueueDir string

	// MaxQueueSize is the maximum number of events to retain in the offline
	// queue before the oldest is evicted. Defaults to 1000.
	MaxQueueSize int

	// MaxQueueAge is the maximum time an event is kept in the offline queue
	// before being discarded. Defaults to 24 hours.
	MaxQueueAge time.Duration

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

	// Initialize offline queue for durable report persistence (Issue #419).
	offlineQueue, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     cfg.QueueDir,
		MaxSize: cfg.MaxQueueSize,
		MaxAge:  cfg.MaxQueueAge,
		Logger:  cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize offline queue: %w", err)
	}

	c := &TransportClient{
		heartbeatInterval: heartbeatInterval,
		heartbeatStop:     make(chan struct{}),
		convergenceStop:   make(chan struct{}),
		convergeInterval:  30 * time.Minute,
		transportAddress:  cfg.ControllerURL,
		certPath:          cfg.TLSCertPath,
		caCertPEM:         cfg.CACertPEM,
		clientCertPEM:     cfg.ClientCertPEM,
		clientKeyPEM:      cfg.ClientKeyPEM,
		serverCertPEM:     cfg.ServerCertPEM,
		signingCertPEM:    cfg.SigningCertPEM,
		offlineQueue:      offlineQueue,
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

		provider := grpcCP.New(grpcCP.ModeClient)

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
	if err := controlPlane.SubscribeCommands(ctx, stewardID, func(ctx context.Context, sc *cpTypes.SignedCommand) error {
		return cmdHandler.HandleCommand(ctx, sc)
	}); err != nil {
		return fmt.Errorf("failed to subscribe to commands: %w", err)
	}

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	// Drain any events queued during the offline period (Issue #419).
	// Done synchronously before starting the heartbeat so the controller
	// receives a complete history before the next heartbeat arrives.
	c.drainOfflineQueue(ctx)

	// Start heartbeat
	go c.startHeartbeat()

	c.logger.Info("Connected to controller successfully via gRPC transport")
	return nil
}

// setupCommandHandler creates and configures the command handler with all command types.
// Story #516: connect_dataplane handler removed — DP is initialized eagerly in Connect().
func (c *TransportClient) setupCommandHandler(ctx context.Context, stewardID string) (*commands.Handler, error) {
	// Create status callback that publishes events via the offline-queued path
	// so events are not lost if the controller is temporarily unreachable (Issue #419).
	statusCallback := func(ctx context.Context, event *cpTypes.Event) {
		if err := c.publishEventWithQueue(ctx, event); err != nil {
			c.logger.Error("Failed to publish status event", "error", err)
		}
	}

	// Create command handler with the same verifier used for config signature
	// verification (Story #919). Replay window and params limit are read from
	// the steward config when available; defaults apply otherwise.
	c.mu.RLock()
	verifier := c.configVerifier
	c.mu.RUnlock()

	handler, err := commands.New(&commands.Config{
		StewardID: stewardID,
		OnStatus:  statusCallback,
		Logger:    c.logger,
		Verifier:  verifier,
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

		// Update convergence interval from the received cfg so the scheduled
		// loop respects the controller-delivered converge_interval value.
		newInterval := stewardconfig.GetConvergeInterval(*goConfig)
		c.mu.Lock()
		c.convergeInterval = newInterval
		c.mu.Unlock()

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

	// Register sync_dna handler — sends full DNA over the data plane.
	// Triggered by the controller on initial registration or when it detects a
	// hash mismatch from a heartbeat (i.e. deltas were missed).
	handler.RegisterHandler(cpTypes.CommandSyncDNA, func(ctx context.Context, cmd *cpTypes.Command) error {
		c.logger.Info("Received sync_dna command, initiating full DNA sync via data plane", "command_id", cmd.ID)

		c.mu.RLock()
		session := c.dataPlaneSession
		sid := c.stewardID
		tid := c.tenantID
		c.mu.RUnlock()

		if session == nil || session.IsClosed() {
			return fmt.Errorf("data plane session not available for DNA sync")
		}

		// Read the current DNA snapshot accumulated by PublishDNAUpdate calls.
		c.dnaMu.RLock()
		currentDNA := copyStringMap(c.lastPublishedDNA)
		c.dnaMu.RUnlock()

		if len(currentDNA) == 0 {
			return fmt.Errorf("no DNA state available for full sync — call PublishDNAUpdate first")
		}

		// Serialize attributes as JSON for the DNATransfer payload.
		attrJSON, err := json.Marshal(currentDNA)
		if err != nil {
			return fmt.Errorf("failed to serialize DNA attributes: %w", err)
		}

		transfer := &dpTypes.DNATransfer{
			ID:         fmt.Sprintf("dna_full_%d", time.Now().UnixNano()),
			StewardID:  sid,
			TenantID:   tid,
			Timestamp:  time.Now(),
			Attributes: attrJSON,
			Delta:      false, // full snapshot
			Metadata: map[string]string{
				"command_id": cmd.ID,
				"dna_hash":   dna.ComputeHash(currentDNA),
				"attr_count": fmt.Sprintf("%d", len(currentDNA)),
			},
		}

		if err := session.SendDNA(ctx, transfer); err != nil {
			return fmt.Errorf("failed to send full DNA via data plane: %w", err)
		}

		c.logger.Info("Full DNA sync completed via data plane",
			"command_id", cmd.ID,
			"attributes", len(currentDNA))
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

	c.dnaMu.RLock()
	currentDNAHash := c.currentDNAHash
	c.dnaMu.RUnlock()

	heartbeat := &cpTypes.Heartbeat{
		StewardID: stewardID,
		TenantID:  tenantID,
		Status:    cpTypes.HeartbeatStatus(status),
		Timestamp: time.Now(),
		Metrics:   metricsMap,
		DNAHash:   currentDNAHash,
	}

	if err := cp.SendHeartbeat(ctx, heartbeat); err != nil {
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}

	return nil
}

// PublishDNAUpdate publishes DNA changes to the controller via the gRPC control plane provider.
//
// Only changed attributes (delta) are sent over the control plane — unchanged
// attributes are suppressed to minimise bandwidth. On the first call after
// connection there is no previous state, so all attributes are treated as new.
// Full DNA is never sent here; full syncs are triggered by CommandSyncDNA over
// the data plane.
// If the controller is unreachable the event is queued locally and delivered on reconnect (Issue #419).
func (c *TransportClient) PublishDNAUpdate(ctx context.Context, dnaAttrs map[string]string, configHash, syncFingerprint string) error {
	// Always update local DNA state first so the hash is available for heartbeats
	// even when the control plane is temporarily unavailable.
	c.dnaMu.Lock()
	delta := computeDelta(c.lastPublishedDNA, dnaAttrs)
	newHash := dna.ComputeHash(dnaAttrs)
	c.lastPublishedDNA = copyStringMap(dnaAttrs)
	c.currentDNAHash = newHash
	c.dnaMu.Unlock()

	// Skip publish when nothing changed — no need to validate the connection.
	if len(delta) == 0 {
		c.logger.Debug("No DNA changes detected, skipping control plane publish")
		return nil
	}

	c.mu.RLock()
	stewardID := c.stewardID
	tenantID := c.tenantID
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered")
	}

	event := &cpTypes.Event{
		ID:        fmt.Sprintf("evt_dna_%d", time.Now().UnixNano()),
		Type:      cpTypes.EventDNAChanged,
		StewardID: stewardID,
		TenantID:  tenantID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"dna":              delta, // delta only — not full DNA
			"dna_hash":         newHash,
			"config_hash":      configHash,
			"sync_fingerprint": syncFingerprint,
			"is_delta":         true,
			"total_count":      len(dnaAttrs),
		},
	}

	if err := c.publishEventWithQueue(ctx, event); err != nil {
		return fmt.Errorf("failed to publish DNA delta: %w", err)
	}

	c.logger.Info("Published DNA delta",
		"delta_count", len(delta),
		"total_count", len(dnaAttrs),
		"dna_hash", newHash)
	return nil
}

// publishConfigStatus publishes a config status report as an event (internal helper).
func (c *TransportClient) publishConfigStatus(report *cpTypes.ConfigStatusReport) error {
	ctx := context.Background()
	return c.ReportConfigurationStatus(ctx, report.ConfigVersion, report.Status, report.Message, report.Modules)
}

// ReportConfigurationStatus reports detailed configuration execution status to the controller.
// If the controller is unreachable the report is queued locally and delivered on reconnect (Issue #419).
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
	c.mu.RUnlock()

	if stewardID == "" {
		return fmt.Errorf("not registered")
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

	if err := c.publishEventWithQueue(ctx, event); err != nil {
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
// the last-received cfg on a schedule driven by the cfg's converge_interval field.
//
// The initial interval defaults to 30 minutes and is updated automatically
// whenever a sync_config command delivers a cfg with a different converge_interval
// value. The ticker is reset when the interval changes so that the new value
// takes effect on the next tick.
//
// On each tick the loop calls TriggerConvergence, which re-applies the last
// verified cfg using the unified execution engine. If no cfg has been received
// yet the tick is skipped silently and the loop waits for the next interval.
//
// The loop stops when ctx is cancelled or Disconnect is called.
func (c *TransportClient) StartConvergenceLoop(ctx context.Context) {
	c.mu.RLock()
	interval := c.convergeInterval
	c.mu.RUnlock()

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
				// Re-read the interval on every tick so that a cfg delivery
				// with a different converge_interval takes effect promptly.
				c.mu.RLock()
				current := c.convergeInterval
				c.mu.RUnlock()
				if current != interval {
					interval = current
					ticker.Reset(interval)
					c.logger.Info("Convergence interval updated", "interval", interval)
				}
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
		c.logger.Info("Convergence run completed", "version", lastVersion, "status", report.Status)
	} else {
		c.logger.Info("Convergence run completed", "version", lastVersion)
	}
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

// publishEventWithQueue attempts to publish an event via the control plane.
// If the control plane is unavailable or the publish fails, the event is
// queued locally for delivery when the connection is restored (Issue #419).
//
// Returns nil when the event was either published or queued successfully.
// Returns an error only when the control plane is unavailable AND no offline
// queue is configured.
func (c *TransportClient) publishEventWithQueue(ctx context.Context, event *cpTypes.Event) error {
	c.mu.RLock()
	cp := c.controlPlane
	q := c.offlineQueue
	c.mu.RUnlock()

	if cp != nil {
		if err := cp.PublishEvent(ctx, event); err == nil {
			return nil
		}
		// Fall through to queue the event.
		c.logger.Warn("Failed to publish event to controller, queuing for later delivery",
			"event_id", event.ID, "event_type", event.Type)
	}

	if q != nil {
		if q.Enqueue(event) {
			c.logger.Info("Event queued for offline delivery",
				"event_id", event.ID, "event_type", event.Type, "queue_depth", q.Len())
		}
		return nil
	}

	return fmt.Errorf("control plane unavailable and no offline queue configured")
}

// drainOfflineQueue delivers all queued events to the controller in order.
// Called immediately after a successful Connect() to resync reports that
// accumulated during any offline period (Issue #419).
func (c *TransportClient) drainOfflineQueue(ctx context.Context) {
	c.mu.RLock()
	q := c.offlineQueue
	cp := c.controlPlane
	c.mu.RUnlock()

	if q == nil || q.Len() == 0 {
		return
	}

	depth := q.Len()
	c.logger.Info("Draining offline event queue after reconnect", "depth", depth)

	delivered := q.Drain(func(event *cpTypes.Event) error {
		return cp.PublishEvent(ctx, event)
	})

	c.logger.Info("Offline queue drain complete",
		"delivered", delivered, "remaining", q.Len())
}

// startHeartbeat starts the periodic heartbeat goroutine.
// After each successful heartbeat, any events queued during a transient
// offline period are drained so the controller receives them promptly (Issue #419).
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
			} else {
				// Heartbeat succeeded — drain any events queued during a
				// transient disconnect that did not trigger a full reconnect.
				c.drainOfflineQueue(ctx)
			}
			cancel()
		}
	}
}

// ---------------------------------------------------------------------------
// DNA sync helpers (Issue #418)
// ---------------------------------------------------------------------------

// computeDelta returns attributes that changed between oldAttrs and newAttrs.
// Added or updated keys carry their new value.  Keys present in oldAttrs but
// absent from newAttrs (deletions) are emitted with an empty-string sentinel so
// the controller can unset them rather than silently accumulating stale state.
// When oldAttrs is nil or empty every attribute in newAttrs is returned.
//
// The returned map is always an independent copy — mutating it does not affect
// either input map.
func computeDelta(oldAttrs, newAttrs map[string]string) map[string]string {
	delta := make(map[string]string)
	for k, v := range newAttrs {
		if oldV, exists := oldAttrs[k]; !exists || oldV != v {
			delta[k] = v
		}
	}
	// Emit sentinel (empty string) for keys deleted from newAttrs.
	for k := range oldAttrs {
		if _, exists := newAttrs[k]; !exists {
			delta[k] = ""
		}
	}
	return delta
}

// copyStringMap returns a shallow copy of a string→string map.
// Returns nil when the input is nil.
func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
