// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package mqtt provides an MQTT-based control plane provider implementation.
//
// This provider wraps the existing pkg/mqtt infrastructure to implement
// the semantic ControlPlaneProvider interface, hiding MQTT-specific details
// like topics, QoS levels, and subscriptions from business logic.
package mqtt

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	mqttClient "github.com/cfgis/cfgms/pkg/mqtt/client" //nolint:staticcheck // SA1019: Provider wraps deprecated package
	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
)

// Provider implements the ControlPlaneProvider interface using MQTT as the transport.
//
// This provider supports both server-side (controller) and client-side (steward) modes:
//   - Server mode: Wraps mqttInterfaces.Broker for accepting connections
//   - Client mode: Wraps mqttClient.Client for connecting to controller
type Provider struct {
	mu sync.RWMutex

	// Provider metadata
	name        string
	description string

	// Mode determines server vs client operation
	mode Mode

	// Server-side components (controller)
	broker mqttInterfaces.Broker

	// Client-side components (steward)
	client *mqttClient.Client

	// Configuration
	config     map[string]interface{}
	stewardID  string // For client mode
	brokerAddr string
	tlsConfig  *tls.Config
	clientID   string
	startTime  time.Time

	// Subscription handlers
	commandHandlers   map[string]interfaces.CommandHandler
	eventHandlers     []eventSubscription
	heartbeatHandlers []interfaces.HeartbeatHandler

	// Response tracking (for WaitForResponse)
	pendingResponses map[string]chan *types.Response
	responseMu       sync.RWMutex

	// Statistics
	stats *types.ControlPlaneStats
}

// Mode defines the provider operating mode.
type Mode string

const (
	// ModeServer indicates controller (server) mode
	ModeServer Mode = "server"

	// ModeClient indicates steward (client) mode
	ModeClient Mode = "client"
)

// eventSubscription represents an event subscription with filter.
type eventSubscription struct {
	filter  *types.EventFilter
	handler interfaces.EventHandler
}

// Topic patterns for MQTT routing.
const (
	// Command topics: commands/{steward_id} for unicast, commands/{tenant_id}/broadcast for multicast
	topicCommandPrefix      = "cfgms/commands/"
	topicCommandBroadcast   = "cfgms/commands/+/broadcast"  // Wildcard subscription
	topicCommandUnicast     = "cfgms/commands/%s"           // Format: cfgms/commands/{steward_id}
	topicCommandTenantBcast = "cfgms/commands/%s/broadcast" // Format: cfgms/commands/{tenant_id}/broadcast

	// Event topics: events/{steward_id}
	topicEventPrefix = "cfgms/events/"
	topicEventAll    = "cfgms/events/+"  // Subscribe to all events
	topicEvent       = "cfgms/events/%s" // Format: cfgms/events/{steward_id}

	// Heartbeat topics: heartbeats/{steward_id}
	topicHeartbeatPrefix = "cfgms/heartbeats/"
	topicHeartbeatAll    = "cfgms/heartbeats/+"  // Subscribe to all heartbeats
	topicHeartbeat       = "cfgms/heartbeats/%s" // Format: cfgms/heartbeats/{steward_id}

	// Response topics: responses/{command_id}
	topicResponsePrefix = "cfgms/responses/"
	topicResponse       = "cfgms/responses/%s" // Format: cfgms/responses/{command_id}
)

// New creates a new MQTT control plane provider.
//
// Use mode parameter to specify server (controller) or client (steward) operation.
func New(mode Mode) *Provider {
	return &Provider{
		name:              "mqtt",
		description:       "MQTT-based control plane provider using mochi-mqtt",
		mode:              mode,
		commandHandlers:   make(map[string]interfaces.CommandHandler),
		eventHandlers:     []eventSubscription{},
		heartbeatHandlers: []interfaces.HeartbeatHandler{},
		pendingResponses:  make(map[string]chan *types.Response),
		stats:             &types.ControlPlaneStats{},
	}
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return p.name
}

// Description returns a human-readable description.
func (p *Provider) Description() string {
	return p.description
}

// Initialize configures the provider.
//
// Expected config keys:
//   - "mode": string - "server" or "client" (optional if set in New())
//   - "broker": mqttInterfaces.Broker - Existing broker instance (server mode)
//   - "broker_addr": string - Broker address (client mode)
//   - "client_id": string - MQTT client ID (client mode)
//   - "steward_id": string - Steward ID (client mode)
//   - "tenant_id": string - Tenant ID (client mode, for broadcast filtering)
//   - "tls_config": *tls.Config - TLS configuration (client mode)
//   - "cert_file": string - Certificate file path (client mode)
//   - "key_file": string - Key file path (client mode)
//   - "ca_file": string - CA file path (client mode)
func (p *Provider) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config

	// Determine mode if specified in config
	if modeStr, ok := config["mode"].(string); ok {
		p.mode = Mode(modeStr)
	}

	switch p.mode {
	case ModeServer:
		return p.initializeServer(ctx, config)
	case ModeClient:
		return p.initializeClient(ctx, config)
	default:
		return fmt.Errorf("invalid mode: %s (must be 'server' or 'client')", p.mode)
	}
}

// initializeServer sets up server (controller) mode.
func (p *Provider) initializeServer(ctx context.Context, config map[string]interface{}) error {
	// Expect an existing broker instance
	broker, ok := config["broker"].(mqttInterfaces.Broker)
	if !ok {
		return fmt.Errorf("server mode requires 'broker' (mqttInterfaces.Broker) in config")
	}

	p.broker = broker

	// Broker should already be initialized by controller startup
	// We just wrap it for semantic control plane operations

	return nil
}

// initializeClient sets up client (steward) mode.
func (p *Provider) initializeClient(ctx context.Context, config map[string]interface{}) error {
	// Extract required config
	brokerAddr, ok := config["broker_addr"].(string)
	if !ok {
		return fmt.Errorf("client mode requires 'broker_addr' (string) in config")
	}
	p.brokerAddr = brokerAddr

	clientID, ok := config["client_id"].(string)
	if !ok {
		return fmt.Errorf("client mode requires 'client_id' (string) in config")
	}
	p.clientID = clientID

	stewardID, ok := config["steward_id"].(string)
	if !ok {
		return fmt.Errorf("client mode requires 'steward_id' (string) in config")
	}
	p.stewardID = stewardID

	// Extract TLS config (preferred) or cert paths
	if tlsCfg, ok := config["tls_config"].(*tls.Config); ok {
		p.tlsConfig = tlsCfg
	}

	// Create MQTT client
	clientCfg := &mqttClient.Config{
		BrokerAddr:    brokerAddr,
		ClientID:      clientID,
		StewardID:     stewardID,
		TLSConfig:     p.tlsConfig,
		CleanSession:  false, // Preserve session for reliability
		AutoReconnect: true,
		OnConnect: func() {
			// Re-subscribe on reconnect
			p.resubscribe()
		},
	}

	// Handle cert file paths if TLS config not provided
	if p.tlsConfig == nil {
		if certFile, ok := config["cert_file"].(string); ok {
			clientCfg.CertFile = certFile
		}
		if keyFile, ok := config["key_file"].(string); ok {
			clientCfg.KeyFile = keyFile
		}
		if caFile, ok := config["ca_file"].(string); ok {
			clientCfg.CAFile = caFile
		}
	}

	client, err := mqttClient.New(clientCfg)
	if err != nil {
		return fmt.Errorf("failed to create MQTT client: %w", err)
	}

	p.client = client

	return nil
}

// Start begins control plane operation.
func (p *Provider) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.startTime = time.Now()

	switch p.mode {
	case ModeServer:
		return p.startServer(ctx)
	case ModeClient:
		return p.startClient(ctx)
	default:
		return fmt.Errorf("provider not initialized")
	}
}

// startServer starts server (controller) mode.
func (p *Provider) startServer(ctx context.Context) error {
	if p.broker == nil {
		return fmt.Errorf("broker not initialized")
	}

	// Broker should already be started by controller
	// Just verify it's available
	available, err := p.broker.Available()
	if !available {
		return fmt.Errorf("broker not available: %w", err)
	}

	return nil
}

// startClient starts client (steward) mode.
func (p *Provider) startClient(ctx context.Context) error {
	if p.client == nil {
		return fmt.Errorf("client not initialized")
	}

	// Connect to broker
	if err := p.client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to broker: %w", err)
	}

	return nil
}

// Stop gracefully shuts down the control plane.
func (p *Provider) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch p.mode {
	case ModeServer:
		return p.stopServer(ctx)
	case ModeClient:
		return p.stopClient(ctx)
	default:
		return nil
	}
}

// stopServer stops server mode.
func (p *Provider) stopServer(ctx context.Context) error {
	// Broker lifecycle is managed by controller
	// We don't stop it here, just clean up our state
	p.commandHandlers = make(map[string]interfaces.CommandHandler)
	p.eventHandlers = []eventSubscription{}
	p.heartbeatHandlers = []interfaces.HeartbeatHandler{}

	return nil
}

// stopClient stops client mode.
func (p *Provider) stopClient(ctx context.Context) error {
	if p.client == nil {
		return nil
	}

	// Disconnect from broker
	p.client.Disconnect()

	return nil
}

// Available checks if the provider can be started.
func (p *Provider) Available() (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch p.mode {
	case ModeServer:
		if p.broker == nil {
			return false, fmt.Errorf("broker not initialized")
		}
		return p.broker.Available()
	case ModeClient:
		if p.client == nil {
			return false, fmt.Errorf("client not initialized")
		}
		// Client is available if configured (actual connection happens in Start)
		return p.brokerAddr != "" && p.clientID != "" && p.stewardID != "", nil
	default:
		return false, fmt.Errorf("provider not initialized")
	}
}

// IsConnected reports connection status.
func (p *Provider) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch p.mode {
	case ModeServer:
		// Server is connected if broker is running
		if p.broker == nil {
			return false
		}
		// Check broker stats to see if it's operational
		_, err := p.broker.GetStats(context.Background())
		return err == nil
	case ModeClient:
		if p.client == nil {
			return false
		}
		return p.client.IsConnected()
	default:
		return false
	}
}

// GetStats returns operational statistics.
func (p *Provider) GetStats(ctx context.Context) (*types.ControlPlaneStats, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Calculate uptime
	if !p.startTime.IsZero() {
		p.stats.Uptime = time.Since(p.startTime)
	}

	// Add provider-specific metrics from broker
	if p.mode == ModeServer && p.broker != nil {
		brokerStats, err := p.broker.GetStats(ctx)
		if err == nil {
			p.stats.ProviderMetrics = map[string]interface{}{
				"broker_clients_connected": brokerStats.ClientsConnected,
				"broker_messages_sent":     brokerStats.MessagesSent,
				"broker_messages_received": brokerStats.MessagesReceived,
				"broker_bytes_sent":        brokerStats.BytesSent,
				"broker_bytes_received":    brokerStats.BytesReceived,
			}
		}
	}

	return p.stats, nil
}

// resubscribe re-establishes subscriptions after reconnection.
func (p *Provider) resubscribe() {
	p.mu.Lock()
	defer p.mu.Unlock()

	ctx := context.Background()

	// Re-subscribe to commands
	for stewardID := range p.commandHandlers {
		topic := fmt.Sprintf(topicCommandUnicast, stewardID)
		_ = p.client.Subscribe(ctx, topic, 1, p.handleCommandMessage)
	}

	// Note: Events and heartbeats are only subscribed server-side (broker)
	// Client (steward) publishes these, doesn't subscribe to them
}

// marshalMessage converts a struct to JSON for MQTT payload.
func marshalMessage(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// unmarshalMessage converts JSON MQTT payload to a struct.
func unmarshalMessage(payload []byte, v interface{}) error {
	return json.Unmarshal(payload, v)
}

// init registers this provider with the control plane provider registry.
func init() {
	// Register server mode provider
	interfaces.RegisterProvider(New(ModeServer))
}
