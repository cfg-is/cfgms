// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package service

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// ServiceConfig represents the desired state of an OS service resource.
type ServiceConfig struct {
	// State is the desired runtime state: "running" or "stopped".
	State string `yaml:"state"`
	// Enabled controls whether the service starts automatically on boot.
	Enabled bool `yaml:"enabled"`
	// RestartOn is an optional hint for the resource dependency system to
	// restart this service when a named related resource changes. The module
	// itself does not act on this field; it is reserved for the steward's
	// resource dependency engine.
	RestartOn string `yaml:"restart_on,omitempty"`
}

// AsMap returns the configuration as a map for field-by-field comparison.
// RestartOn is omitted because it is a dependency hint, not observable state.
func (c *ServiceConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"enabled": c.Enabled,
	}
	if c.State != "" {
		result["state"] = c.State
	} else {
		result["state"] = "stopped"
	}
	return result
}

// ToYAML serializes the configuration to YAML.
func (c *ServiceConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration.
func (c *ServiceConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate checks that the configuration is valid before applying it.
func (c *ServiceConfig) Validate() error {
	switch c.State {
	case "running", "stopped":
		// valid
	case "":
		return fmt.Errorf("%w: state is required (running or stopped)", modules.ErrInvalidInput)
	default:
		return fmt.Errorf("%w: state must be 'running' or 'stopped', got %q", modules.ErrInvalidInput, c.State)
	}
	return nil
}

// GetManagedFields returns the list of fields this configuration manages.
func (c *ServiceConfig) GetManagedFields() []string {
	return []string{"state", "enabled"}
}
