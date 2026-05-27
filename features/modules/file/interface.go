// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package file

import (
	"fmt"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// FileConfig represents the configuration for a file resource
type FileConfig struct {
	State           string              `yaml:"state"`                 // "present" or "absent"
	Content         string              `yaml:"content,omitempty"`     // File content (required when state is "present")
	Permissions     int                 `yaml:"permissions,omitempty"` // File permissions (e.g., 0644); mutually exclusive with WindowsACL
	Owner           string              `yaml:"owner,omitempty"`       // File owner
	Group           string              `yaml:"group,omitempty"`       // File group
	AllowedBasePath string              `yaml:"allowed_base_path"`     // Required: absolute base path constraining all OS calls
	WindowsACL      *modules.WindowsACL `yaml:"windows_acl,omitempty"` // Windows NTFS ACL; mutually exclusive with Permissions; Windows only
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

	// Always include the required security base path
	result["allowed_base_path"] = c.AllowedBasePath

	// Only include content/permissions for present state
	if c.State != "absent" {
		result["content"] = c.Content
		result["permissions"] = c.Permissions
		// mode mirrors permissions as an octal string. Set() accepts either
		// "permissions" (int) or the "mode" (octal-string) alias, so Get() must
		// emit both — otherwise a config declared with "mode" compares against a
		// state map that lacks it and the comparator reports a phantom added
		// field that no Set() can ever resolve.
		result["mode"] = fmt.Sprintf("%#o", c.Permissions)
	}

	if c.Owner != "" {
		result["owner"] = c.Owner
	}
	if c.Group != "" {
		result["group"] = c.Group
	}

	if c.WindowsACL != nil {
		result["windows_acl"] = c.WindowsACL
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
	// AllowedBasePath is required and must be an absolute path for all states.
	if c.AllowedBasePath == "" || !filepath.IsAbs(c.AllowedBasePath) {
		return ErrAllowedBasePathRequired
	}

	// windows_acl and permissions are mutually exclusive.
	if c.Permissions != 0 && c.WindowsACL != nil {
		return fmt.Errorf("windows_acl and permissions are mutually exclusive; use windows_acl on Windows or permissions on Unix")
	}

	// windows_acl is only valid on Windows.
	if c.WindowsACL != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("windows_acl is only supported on Windows (GOOS=%s); use the permissions field instead", runtime.GOOS)
	}

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
		fields = append(fields, "content")
		if platformSupportsPermissions() {
			fields = append(fields, "permissions")
		}
	}

	if c.Owner != "" {
		fields = append(fields, "owner")
	}
	if c.Group != "" {
		fields = append(fields, "group")
	}

	if c.WindowsACL != nil && runtime.GOOS == "windows" {
		fields = append(fields, "windows_acl")
	}

	return fields
}
