// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package mochi implements an embedded MQTT broker using mochi-mqtt v2.
//
// This provider offers a lightweight, high-performance MQTT broker suitable
// for embedded deployments supporting up to 10,000+ concurrent connections.
package mochi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/listeners"

	"github.com/cfgis/cfgms/pkg/mqtt/interfaces"
)

// Broker implements the interfaces.Broker using mochi-mqtt v2.
type Broker struct {
	mu sync.RWMutex

	// Configuration
	config *Config

	// mochi-mqtt server instance
	server *mqtt.Server

	// Connection state
	running   bool
	startTime time.Time

	// Authentication and authorization hooks
	authHandler interfaces.AuthenticationHandler
	aclHandler  interfaces.AuthorizationHandler

	// Subscriptions for internal use
	subscriptions map[string]interfaces.MessageHandler

	// Actual listen address (useful when using port 0)
	listenAddr string
}

// New creates a new mochi-mqtt broker instance.
func New() *Broker {
	return &Broker{
		config:        DefaultConfig(),
		subscriptions: make(map[string]interfaces.MessageHandler),
	}
}

// Name returns the broker provider name.
func (b *Broker) Name() string {
	return "mochi"
}

// Description returns a human-readable description.
func (b *Broker) Description() string {
	return "Embedded mochi-mqtt v2 broker for high-performance MQTT messaging"
}

// Initialize configures the broker with provider-specific settings.
func (b *Broker) Initialize(rawConfig map[string]interface{}) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return fmt.Errorf("cannot initialize while broker is running")
	}

	cfg, err := ParseConfig(rawConfig)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	b.config = cfg
	return nil
}

// Start begins accepting client connections.
func (b *Broker) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return fmt.Errorf("broker already running")
	}

	// Create mochi-mqtt server with options
	options := &mqtt.Options{
		InlineClient: b.config.InlineClient,
		Capabilities: mqtt.NewDefaultServerCapabilities(),
	}

	// Set custom capabilities
	options.Capabilities.MaximumMessageExpiryInterval = int64(b.config.InflightExpiry.Seconds())
	options.Capabilities.MaximumClientWritesPending = 1024

	// Cap SessionExpiryInterval at uint32 max per MQTT spec (4,294,967,295 seconds ~= 136 years)
	sessionExpiry := b.config.SessionExpiryInterval
	if sessionExpiry > 0xFFFFFFFF {
		sessionExpiry = 0xFFFFFFFF // Cap at uint32 max to prevent overflow
	}
	options.Capabilities.MaximumSessionExpiryInterval = uint32(sessionExpiry) //#nosec G115 -- Bounds checked above
	options.Capabilities.Compatibilities.ObscureNotAuthorized = true

	b.server = mqtt.New(options)

	// Add authentication hook if configured
	if b.authHandler != nil || b.aclHandler != nil {
		hook := &cfgmsAuthHook{
			authHandler: b.authHandler,
			aclHandler:  b.aclHandler,
		}
		if err := b.server.AddHook(hook, nil); err != nil {
			return fmt.Errorf("failed to add auth hook: %w", err)
		}
	} else {
		// Use allow-all hook for development/testing
		if err := b.server.AddHook(new(auth.AllowHook), nil); err != nil {
			return fmt.Errorf("failed to add allow hook: %w", err)
		}
	}

	// Create TCP listener
	var tcpListener *listeners.TCP

	if b.config.EnableTLS {
		// Load TLS configuration for mTLS
		tlsConfig, err := b.loadTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to load TLS config: %w", err)
		}

		tcpListener = listeners.NewTCP(listeners.Config{
			ID:        "tcp",
			Address:   b.config.ListenAddr,
			TLSConfig: tlsConfig,
		})

		if err := b.server.AddListener(tcpListener); err != nil {
			return fmt.Errorf("failed to add TLS listener: %w", err)
		}
	} else {
		// Plain TCP (not recommended for production)
		tcpListener = listeners.NewTCP(listeners.Config{
			ID:      "tcp",
			Address: b.config.ListenAddr,
		})

		if err := b.server.AddListener(tcpListener); err != nil {
			return fmt.Errorf("failed to add TCP listener: %w", err)
		}
	}

	// Store actual listen address (use configured address as listener starts async)
	b.listenAddr = b.config.ListenAddr

	// Start the server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := b.server.Serve(); err != nil {
			errChan <- fmt.Errorf("broker serve error: %w", err)
		}
	}()

	// Wait briefly to ensure server started successfully
	select {
	case err := <-errChan:
		return err
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
	}

	b.running = true
	b.startTime = time.Now()

	return nil
}

// Stop gracefully shuts down the broker.
func (b *Broker) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return nil // Already stopped
	}

	// Close the server (graceful shutdown)
	if err := b.server.Close(); err != nil {
		return fmt.Errorf("failed to stop broker: %w", err)
	}

	b.running = false
	return nil
}

// Publish sends a message to a topic using the inline client.
func (b *Broker) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	b.mu.RLock()
	server := b.server
	running := b.running
	b.mu.RUnlock()

	if !running || server == nil {
		return fmt.Errorf("broker not running")
	}

	// Use inline client to publish
	if err := server.Publish(topic, payload, retain, qos); err != nil {
		return fmt.Errorf("publish failed: %w", err)
	}

	return nil
}

// Subscribe subscribes to a topic pattern.
//
// Note: mochi-mqtt doesn't support server-side subscriptions out of the box,
// so this would require using an inline client or custom hook.
// For now, this is a simplified implementation.
func (b *Broker) Subscribe(ctx context.Context, topic string, qos byte, callback interfaces.MessageHandler) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return fmt.Errorf("broker not running")
	}

	// Store subscription for internal tracking
	b.subscriptions[topic] = callback

	// TODO: Implement actual subscription mechanism using inline client
	// This would require extending mochi-mqtt's inline client capabilities

	return nil
}

// Unsubscribe removes a topic subscription.
func (b *Broker) Unsubscribe(ctx context.Context, topic string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.subscriptions, topic)
	return nil
}

// GetStats returns broker operational statistics.
func (b *Broker) GetStats(ctx context.Context) (interfaces.BrokerStats, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	stats := interfaces.BrokerStats{}

	if !b.running || b.server == nil {
		return stats, fmt.Errorf("broker not running")
	}

	// Get stats from mochi-mqtt server (Clone() for thread-safe copy)
	info := b.server.Info.Clone()

	stats.ClientsConnected = info.ClientsConnected
	stats.ClientsTotal = info.ClientsTotal
	stats.ClientsMax = info.ClientsMaximum
	stats.MessagesReceived = info.MessagesReceived
	stats.MessagesSent = info.MessagesSent
	stats.MessagesDropped = info.MessagesDropped
	stats.BytesReceived = info.BytesReceived
	stats.BytesSent = info.BytesSent
	stats.Subscriptions = info.Subscriptions
	stats.RetainedMessages = info.Retained
	stats.Uptime = time.Since(b.startTime)
	stats.MemoryUsed = info.MemoryAlloc

	return stats, nil
}

// Available checks if the broker can be started.
func (b *Broker) Available() (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Check TLS prerequisites if enabled
	if b.config.EnableTLS {
		if b.config.TLSCertPath == "" || b.config.TLSKeyPath == "" {
			return false, fmt.Errorf("TLS enabled but certificate paths not configured")
		}

		// Verify cert files exist
		if _, err := os.Stat(b.config.TLSCertPath); err != nil {
			return false, fmt.Errorf("TLS certificate not found: %w", err)
		}
		if _, err := os.Stat(b.config.TLSKeyPath); err != nil {
			return false, fmt.Errorf("TLS key not found: %w", err)
		}

		// Verify CA if mTLS is required
		if b.config.RequireClientCert && b.config.TLSCAPath != "" {
			if _, err := os.Stat(b.config.TLSCAPath); err != nil {
				return false, fmt.Errorf("TLS CA certificate not found: %w", err)
			}
		}
	}

	return true, nil
}

// GetCapabilities returns broker feature support.
func (b *Broker) GetCapabilities() interfaces.BrokerCapabilities {
	return interfaces.BrokerCapabilities{
		MaxClients:                  b.config.MaxClients,
		SupportsMQTT311:             true,
		SupportsMQTT5:               true,
		SupportsWebSocket:           b.config.WebSocketAddr != "",
		SupportsTLS:                 true,
		SupportsPersistence:         false, // mochi-mqtt doesn't support persistence
		SupportsClustering:          false, // Single-node only
		SupportsSharedSubscriptions: true,
		MaxMessageSize:              b.config.MaxMessageSize,
		MaxQoS:                      2, // Supports QoS 0, 1, and 2
		SupportsRetainedMessages:    true,
		SupportsWillMessages:        true,
	}
}

// GetListenAddress returns the actual listen address.
func (b *Broker) GetListenAddress() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.listenAddr
}

// SetAuthHandler sets the authentication hook.
func (b *Broker) SetAuthHandler(handler interfaces.AuthenticationHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.authHandler = handler
}

// SetACLHandler sets the authorization hook.
func (b *Broker) SetACLHandler(handler interfaces.AuthorizationHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.aclHandler = handler
}

// loadTLSConfig creates TLS configuration for mTLS.
func (b *Broker) loadTLSConfig() (*tls.Config, error) {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(b.config.TLSCertPath, b.config.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Load CA certificate for client verification (mTLS)
	if b.config.RequireClientCert && b.config.TLSCAPath != "" {
		caCert, err := os.ReadFile(b.config.TLSCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// init registers the mochi broker provider.
func init() {
	interfaces.RegisterBroker(New())
}
