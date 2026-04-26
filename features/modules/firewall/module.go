// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package firewall

import (
	"context"
	"net"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// firewallModule implements the Module interface for firewall management
type firewallModule struct {
	mu       sync.RWMutex
	rules    map[string]firewallConfig
	executor firewallExecutor
	// Embed default logging support for automatic injection capability
	modules.DefaultLoggingSupport
}

// New creates a new instance of the Firewall module
func New() modules.Module {
	return &firewallModule{
		rules:    make(map[string]firewallConfig),
		executor: newExecutor(),
	}
}

// firewallConfig represents the configuration for a firewall rule
type firewallConfig struct {
	Name        string `yaml:"name"`
	Action      string `yaml:"action"`
	Direction   string `yaml:"direction"`
	Protocol    string `yaml:"protocol,omitempty"`
	Service     string `yaml:"service,omitempty"`
	Port        int    `yaml:"port,omitempty"`
	Ports       []int  `yaml:"ports,omitempty"`
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
	Description string `yaml:"description,omitempty"`
	Enabled     bool   `yaml:"enabled,omitempty"`
	// State signals the desired lifecycle: "present" (default) creates/updates;
	// "absent" deletes the rule. Not stored in m.rules after application.
	State string `yaml:"state,omitempty"`
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *firewallConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"name":        c.Name,
		"action":      c.Action,
		"direction":   c.Direction,
		"source":      c.Source,
		"destination": c.Destination,
		"enabled":     c.Enabled,
	}

	if c.Protocol != "" {
		result["protocol"] = c.Protocol
	}
	if c.Service != "" {
		result["service"] = c.Service
	}
	if c.Port != 0 {
		result["port"] = c.Port
	}
	if len(c.Ports) > 0 {
		result["ports"] = c.Ports
	}
	if c.Description != "" {
		result["description"] = c.Description
	}
	if c.State != "" {
		result["state"] = c.State
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *firewallConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *firewallConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *firewallConfig) Validate() error {
	return c.validate()
}

// GetManagedFields returns the list of fields this configuration manages
func (c *firewallConfig) GetManagedFields() []string {
	fields := []string{"name", "action", "direction", "source", "destination", "enabled"}

	if c.Protocol != "" {
		fields = append(fields, "protocol")
	}
	if c.Service != "" {
		fields = append(fields, "service")
	}
	if c.Port != 0 {
		fields = append(fields, "port")
	}
	if len(c.Ports) > 0 {
		fields = append(fields, "ports")
	}
	if c.Description != "" {
		fields = append(fields, "description")
	}

	return fields
}

// validateConfig checks if the configuration is valid
func (c *firewallConfig) validate() error {
	// Validate name
	if c.Name == "" {
		return ErrInvalidName
	}

	// Validate direction — chain selection is explicit, never inferred from addresses
	switch c.Direction {
	case "input", "output", "forward":
		// valid
	default:
		return ErrInvalidDirection
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

// Set creates, updates, or deletes a firewall rule according to the configuration.
// Write-through cache semantics: the OS executor is called first; m.rules is
// updated only on executor success.
func (m *firewallModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if config == nil {
		return ErrInvalidName // reuse existing error for invalid input
	}

	// Convert ConfigState to firewallConfig
	configMap := config.AsMap()
	firewallConf := &firewallConfig{}

	if name, ok := configMap["name"].(string); ok {
		firewallConf.Name = name
	}
	if action, ok := configMap["action"].(string); ok {
		firewallConf.Action = action
	}
	if direction, ok := configMap["direction"].(string); ok {
		firewallConf.Direction = direction
	}
	if protocol, ok := configMap["protocol"].(string); ok {
		firewallConf.Protocol = protocol
	}
	if service, ok := configMap["service"].(string); ok {
		firewallConf.Service = service
	}
	if port, ok := configMap["port"].(int); ok {
		firewallConf.Port = port
	}
	if ports, ok := configMap["ports"].([]int); ok {
		firewallConf.Ports = ports
	} else if portsInterface, ok := configMap["ports"].([]interface{}); ok {
		// Handle YAML unmarshaling which might give []interface{}
		for _, p := range portsInterface {
			if portInt, ok := p.(int); ok {
				firewallConf.Ports = append(firewallConf.Ports, portInt)
			}
		}
	}
	if source, ok := configMap["source"].(string); ok {
		firewallConf.Source = source
	}
	if destination, ok := configMap["destination"].(string); ok {
		firewallConf.Destination = destination
	}
	if description, ok := configMap["description"].(string); ok {
		firewallConf.Description = description
	}
	if enabled, ok := configMap["enabled"].(bool); ok {
		firewallConf.Enabled = enabled
	}
	if state, ok := configMap["state"].(string); ok {
		firewallConf.State = state
	}

	// Handle deletion path
	if firewallConf.State == "absent" {
		m.mu.Lock()
		defer m.mu.Unlock()

		rule, ok := m.rules[resourceID]
		if !ok {
			return ErrRuleNotFound
		}
		if err := m.executor.deleteRule(rule); err != nil {
			return err
		}
		delete(m.rules, resourceID)
		return nil
	}

	// Validate configuration before applying
	if err := firewallConf.validate(); err != nil {
		return err
	}

	// Write-through: apply to OS first, update cache only on success
	if err := m.executor.applyRule(*firewallConf); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[resourceID] = *firewallConf

	return nil
}

// Get retrieves the current configuration of a firewall rule.
// It consults the OS executor first: if the rule is absent from the OS,
// ErrRuleNotFound is returned regardless of m.rules contents.
func (m *firewallModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	exists, err := m.executor.ruleExists(resourceID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrRuleNotFound
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	rule, ok := m.rules[resourceID]
	if !ok {
		return nil, ErrRuleNotFound
	}

	ruleCopy := rule
	return &ruleCopy, nil
}
