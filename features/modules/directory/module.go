// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package directory

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// directoryModule implements the Module interface for directory management
type directoryModule struct {
	// Embed default logging support for automatic injection capability
	modules.DefaultLoggingSupport
}

// New creates a new instance of the Directory module
func New() modules.Module {
	return &directoryModule{}
}

// directoryConfig represents the configuration for a directory
type directoryConfig struct {
	State       string `yaml:"state"`                 // "present" or "absent"
	Path        string `yaml:"path"`                  // Directory path
	Permissions int    `yaml:"permissions,omitempty"` // Directory permissions (e.g., 0755)
	Owner       string `yaml:"owner,omitempty"`       // Directory owner
	Group       string `yaml:"group,omitempty"`       // Directory group
	Recursive   bool   `yaml:"recursive,omitempty"`   // Create parent directories if needed
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *directoryConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{}

	// Always include state
	if c.State != "" {
		result["state"] = c.State
	} else {
		result["state"] = "present" // Default to present
	}

	// Always include path
	result["path"] = c.Path

	// Only include permissions for present state
	if c.State != "absent" {
		result["permissions"] = c.Permissions
	}

	if c.Owner != "" {
		result["owner"] = c.Owner
	}
	if c.Group != "" {
		result["group"] = c.Group
	}
	if c.Recursive {
		result["recursive"] = c.Recursive
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *directoryConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *directoryConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *directoryConfig) Validate() error {
	return c.validate()
}

// GetManagedFields returns the list of fields this configuration manages
func (c *directoryConfig) GetManagedFields() []string {
	fields := []string{"state", "path"}

	if c.State != "absent" && platformSupportsPermissions() {
		fields = append(fields, "permissions")
	}

	if c.Owner != "" {
		fields = append(fields, "owner")
	}
	if c.Group != "" {
		fields = append(fields, "group")
	}

	return fields
}

// validateConfig checks if the configuration is valid
func (c *directoryConfig) validate() error {
	// Validate path is always required
	if c.Path == "" {
		return ErrInvalidPath
	}
	if !filepath.IsAbs(c.Path) {
		return ErrInvalidPath
	}

	// State "absent" doesn't require permissions
	if c.State == "absent" {
		return nil
	}

	// Validate permissions (must be between 0 and 0777) for present state
	if c.Permissions < 0 || c.Permissions > 0777 {
		return ErrInvalidPermissions
	}

	// Validate owner if specified
	if c.Owner != "" {
		if _, err := user.Lookup(c.Owner); err != nil {
			return ErrInvalidOwner
		}
	}

	// Validate group if specified
	if c.Group != "" {
		if _, err := user.LookupGroup(c.Group); err != nil {
			return ErrInvalidGroup
		}
	}

	return nil
}

// Set creates or updates a directory according to the configuration
func (m *directoryModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	// Get effective logger (injected or fallback)
	logger := m.GetEffectiveLogger(logging.ForModule("directory"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Starting directory configuration",
		"operation", "directory_set",
		"resource_id", resourceID,
		"tenant_id", tenantID,
		"resource_type", "directory")
	// Convert ConfigState to directoryConfig
	configMap := config.AsMap()
	dirConfig := &directoryConfig{}

	if path, ok := configMap["path"].(string); ok {
		dirConfig.Path = path
	}
	// Support both "permissions" and "mode" field names for flexibility
	if perms, ok := configMap["permissions"].(int); ok {
		dirConfig.Permissions = perms
	} else if mode, ok := configMap["mode"].(string); ok {
		// Parse mode as octal string (e.g., "0755")
		var modeInt int
		_, err := fmt.Sscanf(mode, "%o", &modeInt)
		if err == nil {
			dirConfig.Permissions = modeInt
		}
	} else if mode, ok := configMap["mode"].(int); ok {
		dirConfig.Permissions = mode
	}
	if owner, ok := configMap["owner"].(string); ok {
		dirConfig.Owner = owner
	}
	if group, ok := configMap["group"].(string); ok {
		dirConfig.Group = group
	}
	if recursive, ok := configMap["recursive"].(bool); ok {
		dirConfig.Recursive = recursive
	}

	// Platform-specific permissions handling
	if !platformSupportsPermissions() && dirConfig.Permissions != 0 {
		return fmt.Errorf("Unix-style permissions are not supported on this platform (NTFS uses ACLs); remove the permissions field from your configuration")
	}

	// Apply default permissions if not specified
	if dirConfig.Permissions == 0 {
		dirConfig.Permissions = int(defaultDirectoryMode())
	}

	// Validate configuration
	if err := dirConfig.validate(); err != nil {
		logger.ErrorCtx(ctx, "Directory configuration validation failed",
			"operation", "directory_set",
			"resource_id", resourceID,
			"tenant_id", tenantID,
			"resource_type", "directory",
			"error_code", "CONFIG_VALIDATION_FAILED",
			"error_details", err.Error())
		return err
	}

	// Check if path exists and is a directory
	info, err := os.Stat(dirConfig.Path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat path: %w", err)
		}
		// Path doesn't exist, create it
		// Validate permissions are within os.FileMode range
		// Validate and safely convert permissions to os.FileMode
		if dirConfig.Permissions < 0 || dirConfig.Permissions > 0777 {
			return modules.ErrInvalidInput
		}
		fileMode := os.FileMode(dirConfig.Permissions) // Safe: bounds validated above

		if dirConfig.Recursive {
			if err := os.MkdirAll(dirConfig.Path, fileMode); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		} else {
			parent := filepath.Dir(dirConfig.Path)
			if _, err := os.Stat(parent); err != nil {
				if os.IsNotExist(err) {
					return ErrRecursiveRequired
				}
				return fmt.Errorf("failed to stat parent directory: %w", err)
			}
			if err := os.Mkdir(dirConfig.Path, fileMode); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		}
	} else if !info.IsDir() {
		return ErrNotADirectory
	}

	// Set permissions (only meaningful on platforms that support Unix permission bits)
	if platformSupportsPermissions() {
		// Validate permissions are within os.FileMode range (check again for existing directories)
		if dirConfig.Permissions < 0 || dirConfig.Permissions > 0777 {
			return modules.ErrInvalidInput
		}
		fileMode := os.FileMode(dirConfig.Permissions) // Safe: bounds validated above
		if err := os.Chmod(dirConfig.Path, fileMode); err != nil {
			return fmt.Errorf("failed to set permissions: %w", err)
		}
	}

	// Set ownership if specified
	if dirConfig.Owner != "" || dirConfig.Group != "" {
		var uid, gid int
		if dirConfig.Owner != "" {
			u, err := user.Lookup(dirConfig.Owner)
			if err != nil {
				return ErrInvalidOwner
			}
			uid, _ = strconv.Atoi(u.Uid)
		} else {
			uid = -1
		}

		if dirConfig.Group != "" {
			g, err := user.LookupGroup(dirConfig.Group)
			if err != nil {
				return ErrInvalidGroup
			}
			gid, _ = strconv.Atoi(g.Gid)
		} else {
			gid = -1
		}

		if err := os.Chown(dirConfig.Path, uid, gid); err != nil {
			logger.ErrorCtx(ctx, "Failed to set directory ownership",
				"operation", "directory_set",
				"resource_id", resourceID,
				"tenant_id", tenantID,
				"resource_type", "directory",
				"error_code", "OWNERSHIP_FAILED",
				"path", dirConfig.Path,
				"owner", dirConfig.Owner,
				"group", dirConfig.Group,
				"error_details", err.Error())
			return fmt.Errorf("failed to set ownership: %w", err)
		}
	}

	logger.InfoCtx(ctx, "Directory configuration completed successfully",
		"operation", "directory_set",
		"resource_id", resourceID,
		"tenant_id", tenantID,
		"resource_type", "directory",
		"path", dirConfig.Path,
		"permissions", fmt.Sprintf("0%o", dirConfig.Permissions),
		"status", "completed")

	return nil
}

// Get retrieves the current configuration of a directory.
//
// If the directory does not exist, returns a directoryConfig with State: "absent".
// This allows the execution engine to detect that the directory needs to be created.
func (m *directoryModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	info, err := os.Stat(resourceID)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist - return state: absent
			return &directoryConfig{
				State: "absent",
				Path:  resourceID,
			}, nil
		}
		return nil, fmt.Errorf("failed to stat directory: %w", err)
	}
	if !info.IsDir() {
		return nil, ErrNotADirectory
	}

	// Get current permissions (platform-aware)
	perms := getDirectoryPermissions(info)

	// Get current ownership (cross-platform)
	ownerName, groupName, err := getFileOwnership(info)
	if err != nil {
		return nil, fmt.Errorf("failed to get file ownership: %w", err)
	}

	config := &directoryConfig{
		State:       "present",
		Path:        resourceID,
		Permissions: perms,
		Owner:       ownerName,
		Group:       groupName,
	}

	return config, nil
}
