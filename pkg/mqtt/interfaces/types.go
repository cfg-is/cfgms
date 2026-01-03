// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package interfaces

import "time"

// Message represents an MQTT message.
type Message struct {
	// Topic the message was published to
	Topic string

	// Payload contains the message data
	Payload []byte

	// QoS level (0, 1, or 2)
	QoS byte

	// Retained flag - if true, broker stores for new subscribers
	Retained bool

	// Timestamp when message was received
	Timestamp time.Time

	// ClientID of the publishing client
	ClientID string
}

// ClientInfo contains information about a connected MQTT client.
type ClientInfo struct {
	// Client identifier
	ClientID string

	// Username used for authentication
	Username string

	// Remote address of the client
	RemoteAddr string

	// Protocol version (3 or 5)
	ProtocolVersion byte

	// When the client connected
	ConnectedAt time.Time

	// Last activity timestamp
	LastActivity time.Time

	// Clean session flag
	CleanSession bool

	// Will message configuration (if any)
	Will *WillMessage
}

// WillMessage defines an MQTT last will and testament message.
type WillMessage struct {
	Topic    string
	Payload  []byte
	QoS      byte
	Retained bool
}

// SubscriptionInfo contains information about a topic subscription.
type SubscriptionInfo struct {
	// Client that owns this subscription
	ClientID string

	// Topic filter (may contain wildcards)
	Topic string

	// Requested QoS level
	QoS byte

	// When the subscription was created
	CreatedAt time.Time
}

// BrokerConfig holds common configuration for MQTT brokers.
type BrokerConfig struct {
	// Listen address for MQTT (e.g., "0.0.0.0:1883")
	ListenAddr string `json:"listen_addr" yaml:"listen_addr"`

	// Listen address for MQTT over WebSocket (optional)
	WebSocketAddr string `json:"websocket_addr,omitempty" yaml:"websocket_addr,omitempty"`

	// Enable TLS
	EnableTLS bool `json:"enable_tls" yaml:"enable_tls"`

	// TLS certificate path (if EnableTLS is true)
	TLSCertPath string `json:"tls_cert_path,omitempty" yaml:"tls_cert_path,omitempty"`

	// TLS key path (if EnableTLS is true)
	TLSKeyPath string `json:"tls_key_path,omitempty" yaml:"tls_key_path,omitempty"`

	// CA certificate path for client certificate verification (mTLS)
	TLSCAPath string `json:"tls_ca_path,omitempty" yaml:"tls_ca_path,omitempty"`

	// Require client certificates (mTLS)
	RequireClientCert bool `json:"require_client_cert" yaml:"require_client_cert"`

	// Maximum concurrent clients (0 = unlimited)
	MaxClients int `json:"max_clients" yaml:"max_clients"`

	// Maximum message size in bytes (0 = unlimited)
	MaxMessageSize int64 `json:"max_message_size" yaml:"max_message_size"`

	// Session expiry interval in seconds (MQTT 5.0)
	SessionExpiryInterval int64 `json:"session_expiry_interval" yaml:"session_expiry_interval"`

	// Keepalive multiplier (disconnect if no activity for keepalive * multiplier)
	KeepaliveMultiplier float64 `json:"keepalive_multiplier" yaml:"keepalive_multiplier"`

	// Enable message persistence
	EnablePersistence bool `json:"enable_persistence" yaml:"enable_persistence"`

	// Persistence storage path (if EnablePersistence is true)
	PersistencePath string `json:"persistence_path,omitempty" yaml:"persistence_path,omitempty"`

	// Enable statistics collection
	EnableStats bool `json:"enable_stats" yaml:"enable_stats"`

	// Statistics collection interval
	StatsInterval time.Duration `json:"stats_interval" yaml:"stats_interval"`
}

// DefaultBrokerConfig returns sensible defaults for MQTT broker configuration.
func DefaultBrokerConfig() *BrokerConfig {
	return &BrokerConfig{
		ListenAddr:            "0.0.0.0:1883",
		WebSocketAddr:         "", // Disabled by default
		EnableTLS:             true,
		RequireClientCert:     true, // mTLS for security
		MaxClients:            10000,
		MaxMessageSize:        1024 * 1024, // 1MB
		SessionExpiryInterval: 3600,        // 1 hour
		KeepaliveMultiplier:   1.5,
		EnablePersistence:     false, // Disabled for embedded broker
		EnableStats:           true,
		StatsInterval:         10 * time.Second,
	}
}
