package firewall

import (
	"context"
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
	// Embed default logging support for automatic injection capability
	modules.DefaultLoggingSupport
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

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *firewallConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"name":        c.Name,
		"action":      c.Action,
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
	fields := []string{"name", "action", "source", "destination", "enabled"}

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

	// Validate configuration
	if err := firewallConf.validate(); err != nil {
		return err
	}

	// Store the rule
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[resourceID] = *firewallConf

	return nil
}

// Get retrieves the current configuration of a firewall rule
func (m *firewallModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the rule
	rule, exists := m.rules[resourceID]
	if !exists {
		return nil, ErrRuleNotFound
	}

	// Return a copy of the rule as ConfigState
	ruleCopy := rule
	return &ruleCopy, nil
}
