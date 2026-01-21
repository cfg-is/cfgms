// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client provides an MQTT client wrapper for CFGMS steward communication.
//
// This package wraps the paho MQTT client to provide a simple, CFGMS-specific
// interface for publishing heartbeats and receiving commands.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Client represents an MQTT client for steward communication.
type Client struct {
	mu sync.RWMutex

	// MQTT client
	client mqtt.Client

	// Connection state
	connected bool
	stewardID string

	// Configuration
	brokerAddr string
	clientID   string

	// Callbacks
	onMessage    MessageHandler
	onConnect    func()
	onDisconnect func()
}

// Config holds MQTT client configuration.
type Config struct {
	// Broker address (e.g., "tcp://controller:1883" or "ssl://controller:8883")
	BrokerAddr string

	// Client ID (unique identifier for this client)
	ClientID string

	// Steward ID for topic subscription
	StewardID string

	// TLS configuration
	TLSConfig *tls.Config

	// Certificate paths (alternative to TLSConfig)
	CertFile string
	KeyFile  string
	CAFile   string

	// Connection options
	CleanSession    bool
	KeepAlive       time.Duration
	ConnectTimeout  time.Duration
	AutoReconnect   bool
	MaxReconnectInt time.Duration

	// Will message (last will and testament)
	WillEnabled bool
	WillTopic   string
	WillPayload []byte
	WillQoS     byte
	WillRetain  bool

	// Callbacks
	OnMessage    MessageHandler
	OnConnect    func()
	OnDisconnect func()
}

// MessageHandler is called when a message is received.
type MessageHandler func(topic string, payload []byte)

// New creates a new MQTT client.
func New(cfg *Config) (*Client, error) {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(cfg.BrokerAddr)
	opts.SetClientID(cfg.ClientID)
	opts.SetCleanSession(cfg.CleanSession)
	opts.SetAutoReconnect(cfg.AutoReconnect)

	if cfg.KeepAlive > 0 {
		opts.SetKeepAlive(cfg.KeepAlive)
	} else {
		opts.SetKeepAlive(30 * time.Second) // Default 30s keepalive
	}

	if cfg.ConnectTimeout > 0 {
		opts.SetConnectTimeout(cfg.ConnectTimeout)
	} else {
		opts.SetConnectTimeout(10 * time.Second) // Default 10s timeout
	}

	if cfg.MaxReconnectInt > 0 {
		opts.SetMaxReconnectInterval(cfg.MaxReconnectInt)
	}

	// Setup TLS if configured
	if cfg.TLSConfig != nil {
		opts.SetTLSConfig(cfg.TLSConfig)
	} else if cfg.CertFile != "" && cfg.KeyFile != "" && cfg.CAFile != "" {
		tlsConfig, err := loadTLSConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS config: %w", err)
		}
		opts.SetTLSConfig(tlsConfig)
	}

	// Setup will message if enabled
	if cfg.WillEnabled && cfg.WillTopic != "" {
		opts.SetWill(cfg.WillTopic, string(cfg.WillPayload), cfg.WillQoS, cfg.WillRetain)
	}

	client := &Client{
		brokerAddr:   cfg.BrokerAddr,
		clientID:     cfg.ClientID,
		stewardID:    cfg.StewardID,
		onMessage:    cfg.OnMessage,
		onConnect:    cfg.OnConnect,
		onDisconnect: cfg.OnDisconnect,
	}

	// Set connection callbacks
	opts.SetOnConnectHandler(func(c mqtt.Client) {
		client.mu.Lock()
		client.connected = true
		client.mu.Unlock()

		if client.onConnect != nil {
			client.onConnect()
		}
	})

	opts.SetConnectionLostHandler(func(c mqtt.Client, err error) {
		client.mu.Lock()
		client.connected = false
		client.mu.Unlock()

		if client.onDisconnect != nil {
			client.onDisconnect()
		}
	})

	// Set default message handler
	opts.SetDefaultPublishHandler(func(c mqtt.Client, msg mqtt.Message) {
		if client.onMessage != nil {
			client.onMessage(msg.Topic(), msg.Payload())
		}
	})

	client.client = mqtt.NewClient(opts)

	return client, nil
}

// Connect connects to the MQTT broker.
func (c *Client) Connect(ctx context.Context) error {
	token := c.client.Connect()

	// Wait for connection with context timeout
	select {
	case <-token.Done():
		if token.Error() != nil {
			return fmt.Errorf("failed to connect: %w", token.Error())
		}
		// Mark as connected after successful connection
		c.mu.Lock()
		c.connected = true
		c.mu.Unlock()
		return nil
	case <-ctx.Done():
		return fmt.Errorf("connection timeout: %w", ctx.Err())
	}
}

// Disconnect disconnects from the MQTT broker.
func (c *Client) Disconnect() {
	c.client.Disconnect(250) // 250ms quiesce time
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
}

// Publish publishes a message to a topic.
func (c *Client) Publish(ctx context.Context, topic string, payload []byte, qos byte, retained bool) error {
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return fmt.Errorf("not connected to broker")
	}

	token := c.client.Publish(topic, qos, retained, payload)

	// Wait for publish with context timeout
	select {
	case <-token.Done():
		if token.Error() != nil {
			return fmt.Errorf("failed to publish: %w", token.Error())
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("publish timeout: %w", ctx.Err())
	}
}

// Subscribe subscribes to a topic.
func (c *Client) Subscribe(ctx context.Context, topic string, qos byte, callback MessageHandler) error {
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return fmt.Errorf("not connected to broker")
	}

	token := c.client.Subscribe(topic, qos, func(client mqtt.Client, msg mqtt.Message) {
		if callback != nil {
			callback(msg.Topic(), msg.Payload())
		}
	})

	// Wait for subscription with context timeout
	select {
	case <-token.Done():
		if token.Error() != nil {
			return fmt.Errorf("failed to subscribe: %w", token.Error())
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("subscribe timeout: %w", ctx.Err())
	}
}

// Unsubscribe unsubscribes from a topic.
func (c *Client) Unsubscribe(ctx context.Context, topic string) error {
	token := c.client.Unsubscribe(topic)

	// Wait for unsubscribe with context timeout
	select {
	case <-token.Done():
		if token.Error() != nil {
			return fmt.Errorf("failed to unsubscribe: %w", token.Error())
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("unsubscribe timeout: %w", ctx.Err())
	}
}

// IsConnected returns whether the client is connected.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetStewardID returns the steward ID.
func (c *Client) GetStewardID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stewardID
}

// loadTLSConfig loads TLS configuration from certificate files.
func loadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA cert
	caCert, err := os.ReadFile(caFile) // #nosec G304 -- Path from trusted configuration file
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}
