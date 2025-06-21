package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cfgis/cfgms/features/modules"
	"gopkg.in/yaml.v3"
)

// firewallModule implements the Module interface for firewall management
type firewallModule struct {
	mu    sync.RWMutex
	rules map[string]firewallConfig
}

// New creates a new instance of the Firewall module
func New() modules.Module {
	return &firewallModule{
		rules: make(map[string]firewallConfig),
	}
}

// firewallConfig represents the configuration for a firewall rule
type firewallConfig struct {
	Name        string `yaml:"name"`
	Action      string `yaml:"action"`
	Protocol    string `yaml:"protocol,omitempty"`
	Service     string `yaml:"service,omitempty"`
	Port        int    `yaml:"port,omitempty"`
	Ports       []int  `yaml:"ports,omitempty"`
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
	Description string `yaml:"description,omitempty"`
	Enabled     bool   `yaml:"enabled,omitempty"`
}

// validateConfig checks if the configuration is valid
func (c *firewallConfig) validate() error {
	// Validate name
	if c.Name == "" {
		return ErrInvalidName
	}

	// Validate action
	if c.Action != "allow" && c.Action != "deny" {
		return ErrInvalidAction
	}

	// Validate protocol or service
	if c.Service == "" {
		if c.Protocol == "" {
			return ErrInvalidProtocol
		}
		if c.Protocol != "tcp" && c.Protocol != "udp" && c.Protocol != "icmp" {
			return ErrInvalidProtocol
		}
	}

	// Validate port(s)
	if c.Service == "" {
		if c.Port == 0 && len(c.Ports) == 0 {
			return ErrInvalidPort
		}
		if c.Port < 0 || c.Port > 65535 {
			return ErrInvalidPort
		}
		for _, port := range c.Ports {
			if port < 0 || port > 65535 {
				return ErrInvalidPort
			}
		}
	}

	// Validate source and destination
	if c.Source == "" {
		return ErrInvalidSource
	}
	if c.Destination == "" {
		return ErrInvalidDestination
	}

	// Validate IP addresses or CIDR ranges
	if !isValidIPOrCIDR(c.Source) {
		return ErrInvalidSource
	}
	if !isValidIPOrCIDR(c.Destination) {
		return ErrInvalidDestination
	}

	return nil
}

// isValidIPOrCIDR checks if a string is a valid IP address or CIDR range
func isValidIPOrCIDR(s string) bool {
	// Check if it's a CIDR
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	// Check if it's an IP address
	return net.ParseIP(s) != nil
}

// Set creates or updates a firewall rule according to the configuration
func (m *firewallModule) Set(ctx context.Context, resourceID string, configData string) error {
	var config firewallConfig
	if err := yaml.Unmarshal([]byte(configData), &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate configuration
	if err := config.validate(); err != nil {
		return err
	}

	// Store the rule
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[resourceID] = config

	return nil
}

// Get retrieves the current configuration of a firewall rule
func (m *firewallModule) Get(ctx context.Context, resourceID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the rule
	rule, exists := m.rules[resourceID]
	if !exists {
		return "", ErrRuleNotFound
	}

	// Convert to YAML
	data, err := yaml.Marshal(rule)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	return string(data), nil
}

// Test verifies if the current firewall rule state matches the desired configuration
func (m *firewallModule) Test(ctx context.Context, resourceID string, configData string) (bool, error) {
	var desiredConfig firewallConfig
	if err := yaml.Unmarshal([]byte(configData), &desiredConfig); err != nil {
		return false, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate desired configuration
	if err := desiredConfig.validate(); err != nil {
		return false, err
	}

	// Get current state
	currentConfig, err := m.Get(ctx, resourceID)
	if err != nil {
		return false, err
	}

	var currentState firewallConfig
	if err := yaml.Unmarshal([]byte(currentConfig), &currentState); err != nil {
		return false, fmt.Errorf("failed to parse current state: %w", err)
	}

	// Compare configurations
	if desiredConfig.Name != currentState.Name {
		return false, nil
	}
	if desiredConfig.Action != currentState.Action {
		return false, nil
	}
	if desiredConfig.Protocol != currentState.Protocol {
		return false, nil
	}
	if desiredConfig.Service != currentState.Service {
		return false, nil
	}
	if desiredConfig.Port != currentState.Port {
		return false, nil
	}
	if len(desiredConfig.Ports) != len(currentState.Ports) {
		return false, nil
	}
	for i, port := range desiredConfig.Ports {
		if port != currentState.Ports[i] {
			return false, nil
		}
	}
	if desiredConfig.Source != currentState.Source {
		return false, nil
	}
	if desiredConfig.Destination != currentState.Destination {
		return false, nil
	}
	if desiredConfig.Description != currentState.Description {
		return false, nil
	}
	if desiredConfig.Enabled != currentState.Enabled {
		return false, nil
	}

	return true, nil
}
