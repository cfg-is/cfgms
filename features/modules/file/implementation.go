// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// #nosec G304 - File module requires file system access for configuration management
package file

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// fileModule implements the Module interface for file management
type fileModule struct {
	// Embed default logging support for automatic injection capability
	modules.DefaultLoggingSupport
}

// New creates a new instance of the file module
func New() modules.Module {
	return &fileModule{}
}

// Get returns the current configuration of the file.
//
// If the file does not exist, returns a FileConfig with State: "absent".
// This allows the execution engine to detect that the file needs to be created.
func (m *fileModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, modules.ErrInvalidResourceID
	}

	info, err := os.Stat(resourceID)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist - return state: absent
			return &FileConfig{
				State: "absent",
			}, nil
		}
		return nil, err
	}

	content, err := os.ReadFile(resourceID)
	if err != nil {
		return nil, err
	}

	// Get owner and group (cross-platform)
	owner, group, err := getFileOwnership(info)
	if err != nil {
		return nil, err
	}

	config := &FileConfig{
		State:       "present",
		Content:     string(content),
		Permissions: getFilePermissions(info),
		Owner:       owner,
		Group:       group,
	}

	return config, nil
}

// Set updates the file content and attributes
func (m *fileModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	// Get effective logger (injected or fallback)
	logger := m.GetEffectiveLogger(logging.ForModule("file"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Starting file configuration",
		"operation", "file_set",
		"resource_id", resourceID,
		"tenant_id", tenantID,
		"resource_type", "file")
	if resourceID == "" {
		return modules.ErrInvalidResourceID
	}

	if config == nil {
		return modules.ErrInvalidInput
	}

	// Convert ConfigState to FileConfig
	configMap := config.AsMap()
	fileConfig := &FileConfig{}

	if state, ok := configMap["state"].(string); ok {
		fileConfig.State = state
	}
	if content, ok := configMap["content"].(string); ok {
		fileConfig.Content = content
	}
	// Support both "permissions" and "mode" field names for flexibility
	if perms, ok := configMap["permissions"].(int); ok {
		fileConfig.Permissions = perms
	} else if mode, ok := configMap["mode"].(string); ok {
		// Parse mode as octal string (e.g., "0644")
		var modeInt int
		_, err := fmt.Sscanf(mode, "%o", &modeInt)
		if err == nil {
			fileConfig.Permissions = modeInt
		}
	} else if mode, ok := configMap["mode"].(int); ok {
		fileConfig.Permissions = mode
	}
	if owner, ok := configMap["owner"].(string); ok {
		fileConfig.Owner = owner
	}
	if group, ok := configMap["group"].(string); ok {
		fileConfig.Group = group
	}

	// Handle state: absent - delete the file
	if fileConfig.State == "absent" {
		if err := os.Remove(resourceID); err != nil {
			if os.IsNotExist(err) {
				// File already doesn't exist - desired state achieved
				logger.InfoCtx(ctx, "File already absent",
					"operation", "file_set",
					"resource_id", resourceID,
					"status", "no_change")
				return nil
			}
			logger.ErrorCtx(ctx, "Failed to remove file",
				"operation", "file_set",
				"resource_id", resourceID,
				"error_code", "FILE_REMOVAL_FAILED",
				"error_details", err.Error())
			return err
		}
		logger.InfoCtx(ctx, "File removed successfully",
			"operation", "file_set",
			"resource_id", resourceID,
			"status", "completed")
		return nil
	}

	// Platform-specific permissions handling
	if !platformSupportsPermissions() && fileConfig.Permissions != 0 {
		return fmt.Errorf("Unix-style permissions are not supported on this platform (NTFS uses ACLs); remove the permissions field from your configuration")
	}

	// Apply default permissions if not specified
	if fileConfig.Permissions == 0 {
		fileConfig.Permissions = int(defaultFileMode())
	}

	// Validate configuration for present state
	if err := fileConfig.Validate(); err != nil {
		logger.ErrorCtx(ctx, "File configuration validation failed",
			"operation", "file_set",
			"resource_id", resourceID,
			"error_code", "CONFIG_VALIDATION_FAILED",
			"error_details", err.Error())
		return err
	}

	// Write file with content
	// Validate permissions are within os.FileMode range
	if fileConfig.Permissions < 0 || fileConfig.Permissions > 0777 {
		return modules.ErrInvalidInput
	}
	if err := os.WriteFile(resourceID, []byte(fileConfig.Content), os.FileMode(fileConfig.Permissions)); err != nil {
		return err
	}

	// Set owner and group if specified
	if fileConfig.Owner != "" || fileConfig.Group != "" {
		switch runtime.GOOS {
		case "linux", "darwin":
			// Get UID and GID for the specified owner and group
			var uid, gid = -1, -1
			if fileConfig.Owner != "" {
				userInfo, err := user.Lookup(fileConfig.Owner)
				if err != nil {
					return err
				}
				uid, _ = strconv.Atoi(userInfo.Uid)
			}
			if fileConfig.Group != "" {
				groupInfo, err := user.LookupGroup(fileConfig.Group)
				if err != nil {
					return err
				}
				gid, _ = strconv.Atoi(groupInfo.Gid)
			}

			// Change owner and group
			if err := os.Chown(resourceID, uid, gid); err != nil {
				return err
			}
		case "windows":
			// Windows doesn't support chown in the same way as Unix
			// We'll just verify the owner exists
			if fileConfig.Owner != "" {
				_, err := user.Lookup(fileConfig.Owner)
				if err != nil {
					return err
				}
			}
		default:
			// Unsupported platform
			logger.ErrorCtx(ctx, "Unsupported platform for file ownership",
				"operation", "file_set",
				"resource_id", resourceID,
				"error_code", "UNSUPPORTED_PLATFORM",
				"platform", runtime.GOOS)
			return modules.ErrUnsupportedPlatform
		}
	}

	logger.InfoCtx(ctx, "File configuration completed successfully",
		"operation", "file_set",
		"resource_id", resourceID,
		"file_size", len(fileConfig.Content),
		"permissions", fmt.Sprintf("0%o", fileConfig.Permissions),
		"status", "completed")

	return nil
}
