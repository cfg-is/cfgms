// SPDX-License-Identifier: AGPL-3.0-only
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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
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
	serverCertPEM  string   // Controller's server cert for config signature verification (Story #315)
	signingCertPEMs []string // Issue #1816: mutable set of signing certs (rotation support)
	overlapExpiresAt *time.Time // Issue #1816: rotation overlap deadline for client-side expiry

	// identityPersistFunc is called by the push-signing-cert handler to atomically
	// persist updated signing cert PEMs before in-memory state is updated (Issue #1816).
	// If nil, persistence is skipped and the cert is learned in memory only.
	identityPersistFunc func(signingCertPEMs []string, overlapExpiresAt *time.Time) error

	// certManager provides on-demand client certificate loading per TLS handshake (Issue #920).
	// When non-nil, GetClientCertificate is used instead of static PEM certs.
	certManager *cert.Manager

	// Command handler
	commandHandler *commands.Handler

	// Configuration executor (unified engine — same as standalone mode)
	configExecutor *execution.Executor

	// Command authentication settings (Story #919)
	commandReplayWindow   time.Duration
	commandMaxParamsBytes int

	// Script signature verification policy (Issue #1671). Wired into the command
	// handler by setupCommandHandler so CommandExecuteScript signature enforcement
	// is active in controller-connected deployments, not just standalone mode.
	scriptSigning stewardconfig.ScriptSigningConfig

	// Last configuration received from the controller (for scheduled re-convergence)
	lastConfigYAML    []byte
	lastConfigMu      sync.RWMutex
	lastConfigVersion string

	// Convergence loop control
	convergenceStop  chan struct{}
	convergeInterval time.Duration // cfg-driven; updated on each sync_config
	// convergeIntervalCh wakes the convergence loop when convergeInterval
	// changes so it resets its ticker immediately. Without it the running
	// ticker keeps its stale period (the 30-minute startup default) until the
	// next tick fires — a cfg lowering converge_interval would not take effect
	// for up to 30 minutes. Buffered (1) so senders never block.
	convergeIntervalCh chan struct{}

	// Connection state — single flag for unified gRPC transport
	connected bool

	// Heartbeat
	heartbeatInterval time.Duration
	heartbeatStop     chan struct{}
	// rng is the per-instance RNG for per-tick heartbeat jitter (epic #1664).
	// Only accessed from the startHeartbeat goroutine; no mutex required.
	rng *rand.Rand

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

	// ServerCertPEM is the controller's server certificate PEM (for config signature verification)
	// Story #315: Used to verify configurations signed by the controller
	ServerCertPEM string

	// SigningCertPEM is the controller's dedicated signing certificate PEM (Story #377).
	// When present and SigningCertPEMs is empty, it seeds the runtime signingCertPEMs slice
	// in NewTransportClient for backward compatibility. Registration call sites need not change.
	SigningCertPEM string

	// SigningCertPEMs is the mutable set of signing certs (Issue #1816).
	// When non-empty, takes precedence over SigningCertPEM for seeding signingCertPEMs.
	SigningCertPEMs []string

	// IdentityPersistFunc is called by the push-signing-cert handler to atomically
	// persist updated signing cert PEMs before the in-memory state is updated (Issue #1816).
	// If nil, persistence is skipped (cert learned in memory only).
	IdentityPersistFunc func(signingCertPEMs []string, overlapExpiresAt *time.Time) error

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

	// SignedCommandReplayWindow is the maximum age of an accepted command timestamp.
	// Commands older than this are rejected as potential replays.
	// Zero means the commands.Handler default (5 minutes) applies.
	SignedCommandReplayWindow time.Duration

	// SignedCommandMaxParamsBytes is the maximum JSON-serialized size of Command.Params.
	// Zero means the commands.Handler default (65536 bytes) applies.
	SignedCommandMaxParamsBytes int

	// ScriptSigning is the steward-level script signing policy loaded from the
	// local steward config. It is wired into the command handler so that
	// CommandExecuteScript signature verification (library-script TrustedKeys
	// enforcement, require_signed_adhoc, operator-cert CA chaining) is active in
	// controller-connected production deployments (Issue #1671). The zero value
	// means signing enforcement is inactive (policy: none).
	ScriptSigning stewardconfig.ScriptSigningConfig

	// CertManager provides on-demand client certificate loading for TLS handshakes
	// (Issue #920). When non-nil, GetClientCertificate is used per handshake so
	// certificate rotations are picked up automatically. When nil the client falls
	// back to disk-path or environment-variable certificate loading.
	CertManager *cert.Manager

	// SecretStore is used by the offline queue to persist its AES-256-GCM
	// encryption key across restarts (Issue #920). May be nil.
	SecretStore secretsif.SecretStore

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
		heartbeatInterval = 20 * time.Second // epic #1664: 20s base + [0,10s) jitter
	}

	// Per-instance RNG for per-tick heartbeat jitter (epic #1664).
	rng := rand.New(rand.NewSource(time.Now().UnixNano())) //#nosec G404 -- non-crypto jitter

	// Initialize offline queue for durable report persistence (Issue #419).
	// Pass the SecretStore so the encryption key is persisted across restarts (Issue #920).
	offlineQueue, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:         cfg.QueueDir,
		MaxSize:     cfg.MaxQueueSize,
		MaxAge:      cfg.MaxQueueAge,
		SecretStore: cfg.SecretStore,
		Logger:      cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize offline queue: %w", err)
	}

	// Seed signingCertPEMs from the multi-cert field if provided; otherwise
	// fall back to the singular SigningCertPEM for backward compatibility.
	signingCertPEMs := cfg.SigningCertPEMs
	if len(signingCertPEMs) == 0 && cfg.SigningCertPEM != "" {
		signingCertPEMs = []string{cfg.SigningCertPEM}
	}

	c := &TransportClient{
		heartbeatInterval:     heartbeatInterval,
		rng:                   rng,
		heartbeatStop:         make(chan struct{}),
		convergenceStop:       make(chan struct{}),
		convergeInterval:      30 * time.Minute,
		convergeIntervalCh:    make(chan struct{}, 1),
		transportAddress:      cfg.ControllerURL,
		certPath:              cfg.TLSCertPath,
		caCertPEM:             cfg.CACertPEM,
		serverCertPEM:         cfg.ServerCertPEM,
		signingCertPEMs:       signingCertPEMs,
		certManager:           cfg.CertManager,
		offlineQueue:          offlineQueue,
		commandReplayWindow:   cfg.SignedCommandReplayWindow,
		commandMaxParamsBytes: cfg.SignedCommandMaxParamsBytes,
		scriptSigning:         cfg.ScriptSigning,
		identityPersistFunc:   cfg.IdentityPersistFunc,
		logger:                cfg.Logger,
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
			"addr", transportAddress, "steward_id", logging.RedactedID(stewardID))

		provider := grpcCP.New(grpcCP.ModeClient)

		providerCfg := map[string]interface{}{
			"mode":       "client",
			"addr":       transportAddress,
			"steward_id": stewardID,
			"logger":     c.logger,
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

	c.logger.Info("gRPC data plane initialized", "session_id", logging.RedactedID(session.ID()))

	// Setup command handler
	cmdHandler, err := c.setupCommandHandler(ctx, stewardID)
	if err != nil {
		return fmt.Errorf("failed to setup command handler: %w", err)
	}

	c.mu.Lock()
	c.commandHandler = cmdHandler
	c.mu.Unlock()

	// Subscribe to commands via gRPC control plane provider
	c.logger.Info("Subscribing to commands", "steward_id", logging.RedactedID(stewardID))
	if err := controlPlane.SubscribeCommands(ctx, stewardID, func(ctx context.Context, sc *cpTypes.SignedCommand) error {
		return cmdHandler.HandleCommand(ctx, sc)
	}); err != nil {
		return fmt.Errorf("failed to subscribe to commands: %w", err)
	}

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	// Auto-initialize the config executor when the tenant ID is already known
	// and no executor has been set. This lets the on-connect sync below run
	// without the caller needing to call InitializeConfigExecutor first. (Issue #1720)
	c.mu.RLock()
	hasExecutor := c.configExecutor != nil
	knownTenant := c.tenantID
	c.mu.RUnlock()
	if !hasExecutor && knownTenant != "" {
		if initErr := c.InitializeConfigExecutor(knownTenant); initErr != nil {
			c.logger.Warn("Could not auto-initialize config executor during connect", "error", initErr)
		}
	}

	// Drain any events queued during the offline period (Issue #419).
	// Done synchronously before starting the heartbeat so the controller
	// receives a complete history before the next heartbeat arrives.
	c.drainOfflineQueue(ctx)

	// Pull any config stored while this steward was offline (Issue #1720).
	// Runs in a background goroutine so Connect() returns promptly. A non-nil
	// error (e.g. no config stored yet) is logged at Info level and ignored —
	// the absence of config is a valid first-connect state.
	go func() {
		syncCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.syncConfigNow(syncCtx, "on-connect", nil); err != nil {
			c.logger.Info("On-connect config sync skipped", "error", err)
		}
	}()

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

	// Build the verifier on demand from the stored signing/server cert PEMs.
	// Not cached — Issue #920 removes the configVerifier field.
	verifier := c.buildVerifierOnDemand()

	// Wire script signature verification into the command handler (Issue #1671).
	// Without this, CommandExecuteScript signing enforcement is inactive in
	// controller-connected deployments: require_signed_adhoc is ignored, library
	// scripts fail TrustedKeys verification, and operator-cert CA chaining is skipped.
	c.mu.RLock()
	scriptSigning := c.scriptSigning
	caCertPEM := c.caCertPEM
	c.mu.RUnlock()

	signingConfig := stewardconfig.BuildModuleSigningConfig(scriptSigning)

	// controllerCARoots verifies operator-signed inline command certs chain to the
	// controller CA — the same CA bundle used for mTLS. Left nil when no CA PEM is
	// available, which the handler treats as "skip operator-cert CA verification".
	var controllerCARoots *x509.CertPool
	if caCertPEM != "" {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(caCertPEM)) {
			controllerCARoots = pool
		} else {
			c.logger.Warn("Failed to parse controller CA PEM for operator certificate verification")
		}
	}

	// Surface the weaker security posture when require_signed_adhoc is enabled but
	// no CA roots could be built: inline operator-cert CA-chain verification is then
	// skipped (cryptographic signature verification still runs).
	if controllerCARoots == nil && scriptSigning.RequireSignedAdhoc {
		c.logger.Warn("require_signed_adhoc is enabled but no controller CA roots are available; " +
			"operator certificate CA-chain verification of inline signed commands will be skipped")
	}

	handler, err := commands.New(&commands.Config{
		StewardID:          stewardID,
		OnStatus:           statusCallback,
		Logger:             c.logger,
		Verifier:           verifier,
		ReplayWindow:       c.commandReplayWindow,
		MaxParamsBytes:     c.commandMaxParamsBytes,
		SigningConfig:      signingConfig,
		RequireSignedAdhoc: scriptSigning.RequireSignedAdhoc,
		ControllerCARoots:  controllerCARoots,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create command handler: %w", err)
	}

	// Register sync_config handler — delegates to syncConfigNow for both
	// command-triggered syncs and the on-connect pull (Issue #1720).
	handler.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, cmd *cpTypes.Command) error {
		c.logger.Info("Received sync_config command", "command_id", cmd.ID, "params_keys", paramKeys(cmd.Params))

		// Extract optional module filter from command params.
		var modules []string
		if modulesParam, ok := cmd.Params["modules"].([]interface{}); ok {
			for _, m := range modulesParam {
				if modStr, ok := m.(string); ok {
					modules = append(modules, modStr)
				}
			}
		}

		return c.syncConfigNow(ctx, cmd.ID, modules)
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

	// Register reconnect handler — closes the current gRPC connection and launches
	// the backoff-reconnect loop so the steward re-establishes its ControlChannel
	// against the new Raft leader after an HA failover.
	handler.RegisterHandler(cpTypes.CommandReconnect, func(ctx context.Context, cmd *cpTypes.Command) error {
		c.logger.Info("Received reconnect command, reconnecting to controller",
			"command_id", logging.SanitizeLogValue(cmd.ID))
		c.mu.RLock()
		cp := c.controlPlane
		c.mu.RUnlock()
		if cp == nil {
			return fmt.Errorf("control plane not connected")
		}
		if err := cp.Reconnect(ctx); err != nil {
			return fmt.Errorf("reconnect failed: %w", err)
		}
		return nil
	})

	// Register execute_script handler — dispatches controller-sent scripts through
	// the script module executor and publishes EventScriptCompleted (Issue #1669).
	handler.RegisterExecuteScriptHandler()

	// Register push_signing_cert handler — controller pushes current signing cert on connect
	// or after rotation. The handler persists before updating in-memory state (Issue #1816).
	handler.RegisterHandler(cpTypes.CommandPushSigningCert, func(ctx context.Context, cmd *cpTypes.Command) error {
		return c.handlePushSigningCert(ctx, cmd)
	})

	return handler, nil
}

// syncConfigNow pulls the latest config from the controller via the data plane and
// applies it. It is the shared implementation for the CommandSyncConfig handler and
// the on-(re)connect pull triggered in Connect() (Issue #1720).
//
// commandID is used only for log correlation; pass "" when triggered outside of a
// command context. modules filters which modules to sync; nil means all.
func (c *TransportClient) syncConfigNow(ctx context.Context, commandID string, modules []string) error {
	// Retrieve configuration via gRPC data plane.
	configData, version, err := c.GetConfiguration(ctx, modules)
	if err != nil {
		c.logger.Error("Failed to retrieve configuration", "command_id", commandID, "error", err)
		return fmt.Errorf("config retrieval failed: %w", err)
	}

	c.logger.Info("Configuration retrieved",
		"command_id", commandID,
		"version", version,
		"config_size", len(configData))

	// Compute SHA-256 of the raw wire bytes for DNA delivery verification (Issue #1316).
	configHash := fmt.Sprintf("%x", sha256.Sum256(configData))

	// Unmarshal protobuf SignedConfig.
	var signedProtoConfig controller.SignedConfig
	if err := proto.Unmarshal(configData, &signedProtoConfig); err != nil {
		c.logger.Error("Failed to unmarshal protobuf configuration",
			"command_id", commandID,
			"version", version,
			"error", err)
		return fmt.Errorf("failed to unmarshal protobuf config: %w", err)
	}

	// Verify configuration signature — verifier obtained on demand (Issue #920).
	verifier := c.buildVerifierOnDemand()

	var unsignedProtoConfig *controller.StewardConfig
	if verifier != nil {
		if signedProtoConfig.Signature == nil {
			c.logger.Error("Configuration is not signed",
				"command_id", commandID,
				"version", version)
			return fmt.Errorf("configuration signature verification failed: missing signature")
		}

		verified, err := signature.VerifyProtoConfig(verifier, &signedProtoConfig)
		if err != nil {
			c.logger.Error("Configuration signature verification failed",
				"command_id", commandID,
				"version", version,
				"error", err)
			return fmt.Errorf("configuration signature verification failed: %w", err)
		}

		c.logger.Info("Configuration signature verified",
			"command_id", commandID,
			"version", version)

		unsignedProtoConfig = verified
	} else {
		c.logger.Warn("Configuration verifier not available, skipping signature verification",
			"command_id", commandID)
		unsignedProtoConfig = signedProtoConfig.Config
	}

	// Convert protobuf to Go struct.
	goConfig, err := stewardconfig.FromProto(unsignedProtoConfig)
	if err != nil {
		c.logger.Error("Failed to convert protobuf to Go struct",
			"command_id", commandID,
			"version", version,
			"error", err)
		return fmt.Errorf("failed to convert protobuf config: %w", err)
	}

	// Apply configuration using executor.
	c.mu.RLock()
	executor := c.configExecutor
	sid := c.stewardID
	c.mu.RUnlock()

	if executor == nil {
		c.logger.Error("Configuration executor not initialized", "command_id", commandID)
		return fmt.Errorf("configuration executor not available")
	}

	// Update convergence interval from the received cfg so the scheduled loop
	// respects the controller-delivered converge_interval value.
	newInterval := stewardconfig.GetConvergeInterval(*goConfig)
	c.mu.Lock()
	intervalChanged := c.convergeInterval != newInterval
	c.convergeInterval = newInterval
	c.mu.Unlock()
	if intervalChanged {
		// Wake the convergence loop so it resets its ticker to the new interval now,
		// rather than after the next (stale) tick fires.
		select {
		case c.convergeIntervalCh <- struct{}{}:
		default:
		}
	}

	// Thread drift mode from the controller-delivered cfg into the executor.
	// This is the only authorised source of DriftMode — local steward.cfg
	// cannot set it (the local-file loading path clears the field).
	executor.SetDriftMode(applyDriftModeDefault(goConfig.Steward.DriftMode))

	// Marshal to YAML for executor.
	configYAML, err := yaml.Marshal(goConfig)
	if err != nil {
		c.logger.Error("Failed to marshal config to YAML",
			"command_id", commandID,
			"version", version,
			"error", err)
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Store validated config for scheduled re-convergence runs.
	// Set before Apply so a failed apply still updates the retry baseline.
	c.lastConfigMu.Lock()
	c.lastConfigYAML = configYAML
	c.lastConfigVersion = version
	c.lastConfigMu.Unlock()

	report, err := executor.ApplyConfiguration(ctx, configYAML, version)
	if err != nil {
		c.logger.Error("Configuration application failed", "command_id", commandID, "error", err)
		if report != nil {
			report.StewardID = sid
			if pubErr := c.publishConfigStatus(report); pubErr != nil {
				c.logger.Error("Failed to publish config status after error", "error", pubErr)
			}
		}
		return fmt.Errorf("config application failed: %w", err)
	}

	// Publish configuration status report.
	report.StewardID = sid
	if err := c.publishConfigStatus(report); err != nil {
		c.logger.Error("Failed to publish config status", "error", err)
	}

	c.logger.Info("Configuration sync completed",
		"command_id", commandID,
		"version", version,
		"status", report.Status)

	// Publish DNA update carrying the config hash so the controller can verify
	// delivery via heartbeats (Issue #1316).
	c.dnaMu.RLock()
	currentDNA := copyStringMap(c.lastPublishedDNA)
	c.dnaMu.RUnlock()
	if currentDNA == nil {
		currentDNA = make(map[string]string)
	}
	currentDNA["config_hash"] = configHash
	if pubErr := c.PublishDNAUpdate(ctx, currentDNA, configHash, ""); pubErr != nil {
		c.logger.Info("DNA update after config apply skipped", "error", pubErr)
	}

	return nil
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

	// Verify the transport-level signature when both a verifier and signature are present.
	// Skip silently when either is absent for backward compatibility with unsigned controllers.
	if len(transfer.Signature) > 0 {
		verifier := c.buildVerifierOnDemand()
		if verifier != nil {
			var sig signature.ConfigSignature
			if err := json.Unmarshal(transfer.Signature, &sig); err != nil {
				return nil, "", status.Error(codes.DataLoss, "config signature verification failed")
			}
			if err := verifier.Verify(transfer.Data, &sig); err != nil {
				c.logger.Error("Config transfer signature verification failed",
					"version", transfer.Version,
					"error", err)
				return nil, "", status.Error(codes.DataLoss, "config signature verification failed")
			}
		}
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

	activeSessions := int32(0)
	connectionState := "disconnected"
	if cp.IsConnected() {
		activeSessions = 1
		connectionState = "connected"
	}

	heartbeat := &cpTypes.Heartbeat{
		StewardID:       stewardID,
		TenantID:        tenantID,
		Status:          cpTypes.HeartbeatStatus(status),
		Timestamp:       time.Now(),
		Metrics:         metricsMap,
		DNAHash:         currentDNAHash,
		ActiveSessions:  activeSessions,
		ConnectionState: connectionState,
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

// applyDriftModeDefault returns DriftModeApply when mode is empty.
// The proto does not carry drift_mode, so FromProto always returns "".
// Apply is the fleet default; this makes the intent explicit and testable.
func applyDriftModeDefault(mode stewardconfig.DriftMode) stewardconfig.DriftMode {
	if mode == "" {
		return stewardconfig.DriftModeApply
	}
	return mode
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
			case <-c.convergeIntervalCh:
				// A sync_config delivery changed converge_interval. Reset the
				// ticker now so the new interval takes effect on the next tick
				// instead of waiting out the stale (possibly 30-minute) period.
				c.mu.RLock()
				current := c.convergeInterval
				c.mu.RUnlock()
				if current != interval {
					interval = current
					ticker.Reset(interval)
					c.logger.Info("Convergence interval updated", "interval", interval)
				}
			case <-ticker.C:
				// Re-read the interval on every tick as a fallback in case an
				// interval-change signal was missed.
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
//
// Source priority (Issue #920):
//  1. certManager path: GetClientCertificate callback (on-demand per handshake)
//  2. Disk path (TLSCertPath): static cert loaded from files
//  3. Environment variables: CFGMS_TLS_CERT_PATH / KEY / CA
func (c *TransportClient) createTLSConfig() (*tls.Config, error) {
	c.mu.RLock()
	caCertPEMStr := c.caCertPEM
	certPath := c.certPath
	certMgr := c.certManager
	c.mu.RUnlock()

	var tlsConfig *tls.Config
	var caCertPEM []byte // used for CA pool and verifier fallback
	var err error

	if certMgr != nil {
		// Primary path (Issue #920): on-demand client cert per TLS handshake.
		c.logger.Info("Using on-demand TLS certificate loading via CertManager")
		if caCertPEMStr != "" {
			caCertPEM = []byte(caCertPEMStr)
		}
		tlsConfig, err = certMgr.CreateOnDemandClientTLSConfig(caCertPEM, tls.VersionTLS13)
		if err != nil {
			return nil, fmt.Errorf("failed to create on-demand TLS config: %w", err)
		}
		tlsConfig.NextProtos = []string{quictransport.ALPNProtocol}
		return tlsConfig, nil
	}

	// Fallback paths: build TLS config from static cert files.
	var clientCertPEM, clientKeyPEM []byte

	if certPath != "" {
		// Secondary path: certificates on disk.
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
		// Tertiary path: environment variables.
		certFile := os.Getenv("CFGMS_TLS_CERT_PATH")
		keyFile := os.Getenv("CFGMS_TLS_KEY_PATH")
		caFile := os.Getenv("CFGMS_TLS_CA_PATH")

		if certFile == "" || keyFile == "" || caFile == "" {
			// No TLS config available — provider will connect without mTLS.
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

	tlsConfig, err = cert.CreateClientTLSConfig(clientCertPEM, clientKeyPEM, caCertPEM, "", tls.VersionTLS13)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	// gRPC-over-QUIC requires the cfgms-grpc ALPN protocol.
	tlsConfig.NextProtos = []string{quictransport.ALPNProtocol}

	return tlsConfig, nil
}

// handlePushSigningCert processes a COMMAND_TYPE_PUSH_SIGNING_CERT command from the
// controller. It validates the pushed cert, persists it atomically (persist-before-ack),
// then updates the in-memory signing cert set and rebuilds the MultiVerifier (Issue #1816).
func (c *TransportClient) handlePushSigningCert(_ context.Context, cmd *cpTypes.Command) error {
	c.logger.Info("Received push_signing_cert command", "command_id", cmd.ID)

	// Extract cert_pem (base64-encoded PEM) from params.
	certPEMB64, ok := cmd.Params["cert_pem"].(string)
	if !ok || certPEMB64 == "" {
		return fmt.Errorf("push_signing_cert: missing or empty cert_pem param")
	}

	// Decode base64 → PEM bytes.
	pemBytes, err := decodeBase64(certPEMB64)
	if err != nil {
		return fmt.Errorf("push_signing_cert: decode cert_pem: %w", err)
	}

	// Parse and validate the cert.
	x509Cert, err := cert.ParseCertificateFromPEM(pemBytes)
	if err != nil {
		return fmt.Errorf("push_signing_cert: parse cert: %w", err)
	}
	if time.Now().After(x509Cert.NotAfter) {
		return fmt.Errorf("push_signing_cert: pushed cert is expired (NotAfter=%s)", x509Cert.NotAfter.Format(time.RFC3339))
	}
	hasCodeSigning := false
	for _, eku := range x509Cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
			break
		}
	}
	if !hasCodeSigning {
		return fmt.Errorf("push_signing_cert: cert missing ExtKeyUsageCodeSigning")
	}

	// Parse optional overlap_expires_at (RFC3339).
	var overlapExpiresAt *time.Time
	if raw, ok := cmd.Params["overlap_expires_at"].(string); ok && raw != "" {
		t, parseErr := time.Parse(time.RFC3339, raw)
		if parseErr != nil {
			return fmt.Errorf("push_signing_cert: parse overlap_expires_at %q: %w", raw, parseErr)
		}
		overlapExpiresAt = &t
	}

	// Build updated cert PEMs slice: retire_old=true replaces; otherwise append.
	retireOld, _ := cmd.Params["retire_old"].(bool)

	c.mu.RLock()
	existing := make([]string, len(c.signingCertPEMs))
	copy(existing, c.signingCertPEMs)
	c.mu.RUnlock()

	var newPEMs []string
	newPEMStr := string(pemBytes)
	if retireOld {
		newPEMs = []string{newPEMStr}
	} else {
		newPEMs = append(existing, newPEMStr)
	}

	// Persist BEFORE updating in-memory state (persist-before-ack).
	// If persist fails, return error — controller will retry.
	if c.identityPersistFunc != nil {
		if err := c.identityPersistFunc(newPEMs, overlapExpiresAt); err != nil {
			return fmt.Errorf("push_signing_cert: persist identity: %w", err)
		}
	}

	// Update in-memory state under lock only after successful persistence.
	c.mu.Lock()
	c.signingCertPEMs = newPEMs
	c.overlapExpiresAt = overlapExpiresAt
	c.mu.Unlock()

	c.logger.Info("Signing cert push applied",
		"command_id", cmd.ID,
		"cert_count", len(newPEMs),
		"retire_old", retireOld)
	return nil
}

// decodeBase64 decodes a standard base64-encoded string, accepting both padded
// and unpadded variants.
func decodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	return b, err
}

// buildVerifierOnDemand constructs a config/command signature verifier from the
// controller's certificate PEMs stored in the client. Returns nil when no
// certificate is available — callers treat a nil verifier as "skip verification".
//
// When signingCertPEMs contains multiple entries (rotation overlap window), a
// MultiVerifier is returned so either cert can verify a signature. When
// overlapExpiresAt is set and in the past, only the newest cert is included.
//
// The verifier is NOT cached (Issue #920 removes the configVerifier field).
// The cost is trivial — each call parses a PEM block and builds a verifier struct.
func (c *TransportClient) buildVerifierOnDemand() signature.Verifier {
	c.mu.RLock()
	signingCertPEMs := make([]string, len(c.signingCertPEMs))
	copy(signingCertPEMs, c.signingCertPEMs)
	overlapAt := c.overlapExpiresAt
	serverCertPEM := c.serverCertPEM
	caCertPEM := c.caCertPEM
	certPath := c.certPath
	c.mu.RUnlock()

	// Build verifier from the signing cert set when available.
	if len(signingCertPEMs) > 0 {
		// Client-side overlap expiry: when the overlap window has passed, drop all
		// but the most recently pushed cert to close the replay-attack window.
		activePEMs := signingCertPEMs
		if overlapAt != nil && time.Now().After(*overlapAt) && len(signingCertPEMs) > 1 {
			activePEMs = signingCertPEMs[len(signingCertPEMs)-1:]
		}

		if len(activePEMs) == 1 {
			verifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: []byte(activePEMs[0])})
			if err != nil {
				c.logger.Warn("Failed to create signing cert verifier", "error", err)
				return nil
			}
			c.logger.Debug("Signing cert verifier built", "key_fingerprint", verifier.KeyFingerprint())
			return verifier
		}

		// Multiple active certs — build MultiVerifier for OR-semantics during overlap window.
		var certs []*x509.Certificate
		for _, pem := range activePEMs {
			x509Cert, parseErr := cert.ParseCertificateFromPEM([]byte(pem))
			if parseErr != nil {
				c.logger.Warn("Failed to parse signing cert PEM for verifier", "error", parseErr)
				continue
			}
			certs = append(certs, x509Cert)
		}
		if len(certs) == 0 {
			return nil
		}
		mv, err := signature.NewMultiVerifier(certs)
		if err != nil {
			c.logger.Warn("Failed to create multi-signing-cert verifier", "error", err)
			return nil
		}
		c.logger.Debug("Multi-signing-cert verifier built", "cert_count", len(certs), "key_fingerprint", mv.KeyFingerprint())
		return mv
	}

	// Legacy fallback paths (serverCertPEM, disk signing.crt, caCertPEM).
	var certPEM []byte

	switch {
	case serverCertPEM != "":
		certPEM = []byte(serverCertPEM)
		c.logger.Debug("Using server certificate for signature verification")
	case certPath != "":
		// Story #377: prefer signing.crt, fall back to server.crt.
		signingPath := filepath.Join(certPath, "signing.crt")
		serverPath := filepath.Join(certPath, "server.crt")
		// #nosec G304 - Certificate paths are controlled via configuration
		if raw, err := os.ReadFile(signingPath); err == nil {
			certPEM = raw
			c.logger.Debug("Using signing.crt from disk for signature verification")
		} else if raw, err := os.ReadFile(serverPath); err == nil {
			certPEM = raw
		} else if caCertPEM != "" {
			certPEM = []byte(caCertPEM)
			c.logger.Warn("Signing/server certificate not found; falling back to CA for signature verification")
		}
	case caCertPEM != "":
		certPEM = []byte(caCertPEM)
		c.logger.Warn("No server certificate available; using CA for signature verification")
	}

	if len(certPEM) == 0 {
		return nil
	}

	verifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: certPEM})
	if err != nil {
		c.logger.Warn("Failed to create configuration verifier", "error", err)
		return nil
	}
	c.logger.Debug("Configuration signature verifier built", "key_fingerprint", verifier.KeyFingerprint())
	return verifier
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
// Each tick fires after base + uniform jitter in [0, 10 s) so the effective
// interval is always in [20 s, 30 s). Jitter keeps 50k stewards from
// synchronising their heartbeats and spiking controller CPU (epic #1664).
// After each successful heartbeat, queued offline events are drained so the
// controller receives them promptly (Issue #419).
func (c *TransportClient) startHeartbeat() {
	const (
		jitterMax = 10 * time.Second
	)

	rng := c.rng
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano())) //#nosec G404 -- non-crypto jitter
	}

	nextInterval := func() time.Duration {
		return c.heartbeatInterval + time.Duration(rng.Int63n(int64(jitterMax)))
	}

	timer := time.NewTimer(nextInterval())
	defer timer.Stop()

	for {
		select {
		case <-c.heartbeatStop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := c.SendHeartbeat(ctx, "healthy", nil); err != nil {
				c.logger.Warn("Failed to send heartbeat", "error", err)
			} else {
				// Heartbeat succeeded — drain any events queued during a
				// transient disconnect that did not trigger a full reconnect.
				c.drainOfflineQueue(ctx)
			}
			cancel()
			timer.Reset(nextInterval())
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

// paramKeys returns the sorted key names from a command params map.
// Values are not logged — they may contain secret fingerprints, tokens, or paths.
func paramKeys(params map[string]interface{}) []string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
