// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package file

import (
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// FileConfig represents the configuration for a file resource
type FileConfig struct {
	State       string `yaml:"state"`                 // "present" or "absent"
	Content     string `yaml:"content,omitempty"`     // File content (required when state is "present")
	Permissions int    `yaml:"permissions,omitempty"` // File permissions (e.g., 0644)
	Owner       string `yaml:"owner,omitempty"`       // File owner
	Group       string `yaml:"group,omitempty"`       // File group
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *FileConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{}

	// Always include state
	if c.State != "" {
		result["state"] = c.State
	} else {
		result["state"] = "present" // Default to present
	}

	// Only include content/permissions for present state
	if c.State != "absent" {
		result["content"] = c.Content
		result["permissions"] = c.Permissions
	}

	if c.Owner != "" {
		result["owner"] = c.Owner
	}
	if c.Group != "" {
		result["group"] = c.Group
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *FileConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *FileConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *FileConfig) Validate() error {
	// State "absent" doesn't require content or permissions
	if c.State == "absent" {
		return nil
	}

	// For "present" state (default), content is required
	if c.Content == "" {
		return modules.ErrInvalidInput
	}

	// Validate permissions (must be reasonable values)
	// Allow both decimal and octal representations
	if c.Permissions < 0 || c.Permissions > 0777 {
		return modules.ErrInvalidInput
	}

	return nil
}

// GetManagedFields returns the list of fields this configuration manages
func (c *FileConfig) GetManagedFields() []string {
	fields := []string{"state"}

	if c.State != "absent" {
		fields = append(fields, "content", "permissions")
	}

	if c.Owner != "" {
		fields = append(fields, "owner")
	}
	if c.Group != "" {
		fields = append(fields, "group")
	}

	return fields
}
