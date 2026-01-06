// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package mochi

import (
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/mqtt/interfaces"
)

// Config holds mochi-mqtt specific configuration.
type Config struct {
	// Base broker configuration
	*interfaces.BrokerConfig

	// InlineClient enables the inline client for system messages
	InlineClient bool `json:"inline_client" yaml:"inline_client"`

	// SysTopicResendInterval for $SYS topic updates
	SysTopicResendInterval time.Duration `json:"sys_topic_resend_interval" yaml:"sys_topic_resend_interval"`

	// InflightResendInterval for QoS 1/2 message retransmission
	InflightResendInterval time.Duration `json:"inflight_resend_interval" yaml:"inflight_resend_interval"`

	// InflightExpiry for QoS 1/2 message expiration
	InflightExpiry time.Duration `json:"inflight_expiry" yaml:"inflight_expiry"`
}

// DefaultConfig returns sensible defaults for mochi-mqtt broker.
func DefaultConfig() *Config {
	return &Config{
		BrokerConfig:           interfaces.DefaultBrokerConfig(),
		InlineClient:           true,
		SysTopicResendInterval: 10 * time.Second,
		InflightResendInterval: 10 * time.Second,
		InflightExpiry:         60 * time.Second,
	}
}

// ParseConfig creates a Config from a generic map.
func ParseConfig(raw map[string]interface{}) (*Config, error) {
	cfg := DefaultConfig()

	if v, ok := raw["listen_addr"].(string); ok {
		cfg.ListenAddr = v
	}
	if v, ok := raw["websocket_addr"].(string); ok {
		cfg.WebSocketAddr = v
	}
	if v, ok := raw["enable_tls"].(bool); ok {
		cfg.EnableTLS = v
	}
	if v, ok := raw["tls_cert_path"].(string); ok {
		cfg.TLSCertPath = v
	}
	if v, ok := raw["tls_key_path"].(string); ok {
		cfg.TLSKeyPath = v
	}
	if v, ok := raw["tls_ca_path"].(string); ok {
		cfg.TLSCAPath = v
	}
	if v, ok := raw["require_client_cert"].(bool); ok {
		cfg.RequireClientCert = v
	}
	if v, ok := raw["max_clients"].(int); ok {
		cfg.MaxClients = v
	} else if v, ok := raw["max_clients"].(float64); ok {
		cfg.MaxClients = int(v)
	}
	if v, ok := raw["max_message_size"].(int64); ok {
		cfg.MaxMessageSize = v
	} else if v, ok := raw["max_message_size"].(float64); ok {
		cfg.MaxMessageSize = int64(v)
	}
	if v, ok := raw["inline_client"].(bool); ok {
		cfg.InlineClient = v
	}

	// Parse duration fields
	if v, ok := raw["sys_topic_resend_interval"].(string); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid sys_topic_resend_interval: %w", err)
		}
		cfg.SysTopicResendInterval = d
	}
	if v, ok := raw["inflight_resend_interval"].(string); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid inflight_resend_interval: %w", err)
		}
		cfg.InflightResendInterval = d
	}
	if v, ok := raw["inflight_expiry"].(string); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid inflight_expiry: %w", err)
		}
		cfg.InflightExpiry = d
	}

	return cfg, nil
}
