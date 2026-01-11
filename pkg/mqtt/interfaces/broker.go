// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines the pluggable MQTT broker abstraction for CFGMS.
//
// This package provides a broker-agnostic interface that allows CFGMS to work
// with different MQTT broker implementations (mochi-mqtt embedded, EMQX external, etc.)
// following the same pluggable pattern used for storage and logging providers.
package interfaces

import (
	"context"
	"time"
)

// Broker defines the interface for MQTT broker implementations.
//
// Implementations must be thread-safe and support concurrent operations.
// The broker handles client connections, message routing, and access control.
type Broker interface {
	// Name returns the broker provider name (e.g., "mochi", "emqx")
	Name() string

	// Description returns a human-readable description of the broker
	Description() string

	// Initialize configures the broker with provider-specific settings
	Initialize(config map[string]interface{}) error

	// Start begins accepting client connections
	//
	// Returns an error if the broker is already running or fails to bind to the listen address.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the broker
	//
	// Disconnects all clients and stops accepting new connections.
	// The context can be used to force shutdown if graceful shutdown times out.
	Stop(ctx context.Context) error

	// Publish sends a message to a topic
	//
	// This is for internal/system messages (e.g., broadcast commands).
	// Client messages are handled automatically by the broker.
	Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error

	// Subscribe subscribes to a topic pattern
	//
	// The callback will be invoked for each matching message.
	// Returns an error if subscription fails.
	Subscribe(ctx context.Context, topic string, qos byte, callback MessageHandler) error

	// Unsubscribe removes a topic subscription
	Unsubscribe(ctx context.Context, topic string) error

	// GetStats returns broker operational statistics
	GetStats(ctx context.Context) (BrokerStats, error)

	// Available checks if the broker can be started
	//
	// Returns false and an error if prerequisites are missing (e.g., certificates).
	Available() (bool, error)

	// GetCapabilities returns broker feature support
	GetCapabilities() BrokerCapabilities

	// GetListenAddress returns the actual listen address (useful when using port 0)
	GetListenAddress() string

	// SetAuthHandler sets the authentication hook
	//
	// The handler is called for each client connection attempt.
	// Return true to allow, false to reject.
	SetAuthHandler(handler AuthenticationHandler)

	// SetACLHandler sets the authorization hook
	//
	// The handler is called for each publish/subscribe operation.
	// Return true to allow, false to reject.
	SetACLHandler(handler AuthorizationHandler)
}

// MessageHandler is called when a subscribed message is received.
type MessageHandler func(topic string, payload []byte, qos byte, retained bool) error

// AuthenticationHandler verifies client credentials during connection.
//
// clientID: The MQTT client identifier
// username: Client-provided username
// password: Client-provided password (or certificate CN for mTLS)
// Returns true if authentication succeeds, false otherwise
type AuthenticationHandler func(clientID, username, password string) bool

// AuthorizationHandler checks if a client can publish/subscribe to a topic.
//
// clientID: The authenticated MQTT client identifier
// topic: The topic being accessed
// operation: "publish" or "subscribe"
// Returns true if authorized, false otherwise
type AuthorizationHandler func(clientID, topic, operation string) bool

// BrokerStats contains operational metrics for monitoring.
type BrokerStats struct {
	// Total number of connected clients
	ClientsConnected int64

	// Total clients ever connected (lifetime)
	ClientsTotal int64

	// Maximum clients connected concurrently
	ClientsMax int64

	// Messages received from clients
	MessagesReceived int64

	// Messages sent to clients
	MessagesSent int64

	// Messages dropped (queue full, offline client, etc.)
	MessagesDropped int64

	// Bytes received
	BytesReceived int64

	// Bytes sent
	BytesSent int64

	// Active subscriptions
	Subscriptions int64

	// Retained messages stored
	RetainedMessages int64

	// Uptime since broker start
	Uptime time.Duration

	// Memory usage in bytes (provider-specific)
	MemoryUsed int64
}

// BrokerCapabilities describes broker feature support.
type BrokerCapabilities struct {
	// Maximum concurrent client connections
	MaxClients int

	// Supports MQTT v3.1.1
	SupportsMQTT311 bool

	// Supports MQTT v5.0
	SupportsMQTT5 bool

	// Supports WebSocket transport
	SupportsWebSocket bool

	// Supports TLS/mTLS
	SupportsTLS bool

	// Supports message persistence
	SupportsPersistence bool

	// Supports clustering (multiple broker nodes)
	SupportsClustering bool

	// Supports shared subscriptions
	SupportsSharedSubscriptions bool

	// Maximum message size in bytes (0 = unlimited)
	MaxMessageSize int64

	// Maximum QoS level supported (0, 1, or 2)
	MaxQoS byte

	// Supports retained messages
	SupportsRetainedMessages bool

	// Supports will messages
	SupportsWillMessages bool
}

// BrokerRegistry manages broker provider registration and discovery.
var brokerRegistry = make(map[string]Broker)

// RegisterBroker registers a broker implementation.
//
// This should be called from init() functions in broker provider packages.
// Panics if a broker with the same name is already registered.
func RegisterBroker(broker Broker) {
	name := broker.Name()
	if _, exists := brokerRegistry[name]; exists {
		panic("broker already registered: " + name)
	}
	brokerRegistry[name] = broker
}

// GetBroker retrieves a registered broker by name.
//
// Returns nil if no broker with that name exists.
func GetBroker(name string) Broker {
	return brokerRegistry[name]
}

// GetAvailableBrokers returns all registered broker names.
func GetAvailableBrokers() []string {
	names := make([]string, 0, len(brokerRegistry))
	for name := range brokerRegistry {
		names = append(names, name)
	}
	return names
}
