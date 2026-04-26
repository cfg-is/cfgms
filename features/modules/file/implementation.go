// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package file

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/security"
)

// fileModule implements the Module interface for file management
type fileModule struct {
	// Embed default logging support for automatic injection capability
	modules.DefaultLoggingSupport
	// configuredBasePath is populated by Set() from the operator's AllowedBasePath YAML field.
	// It has no default — Get() returns ErrAllowedBasePathRequired until Set() is called.
	configuredBasePath string
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

	if m.configuredBasePath == "" {
		return nil, ErrAllowedBasePathRequired
	}

	// NOTE: symlink escapes not blocked by ValidateAndCleanPath
	cleanPath, err := security.ValidateAndCleanPath(m.configuredBasePath, resourceID)
	if err != nil {
		return nil, err
	}

	// #nosec G304 -- path validated by security.ValidateAndCleanPath above
	info, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist - return state: absent
			return &FileConfig{
				State: "absent",
			}, nil
		}
		return nil, err
	}

	// NOTE: symlink escapes not blocked by ValidateAndCleanPath
	content, err := security.SecureReadFile(m.configuredBasePath, resourceID)
	if err != nil {
		return nil, err
	}

	// Get owner and group (cross-platform)
	owner, group, err := getFileOwnership(info)
	if err != nil {
		return nil, err
	}

	config := &FileConfig{
		State:           "present",
		Content:         string(content),
		Permissions:     getFilePermissions(info),
		Owner:           owner,
		Group:           group,
		AllowedBasePath: m.configuredBasePath,
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
	if basePath, ok := configMap["allowed_base_path"].(string); ok {
		fileConfig.AllowedBasePath = basePath
	}

	// AllowedBasePath must be validated before any OS call, including os.Remove in the absent branch.
	if fileConfig.AllowedBasePath == "" || !filepath.IsAbs(fileConfig.AllowedBasePath) {
		return ErrAllowedBasePathRequired
	}

	// NOTE: symlink escapes not blocked by ValidateAndCleanPath
	cleanPath, err := security.ValidateAndCleanPath(fileConfig.AllowedBasePath, resourceID)
	if err != nil {
		return err
	}
	m.configuredBasePath = fileConfig.AllowedBasePath

	// Handle state: absent - delete the file
	if fileConfig.State == "absent" {
		// #nosec G304 -- path validated by security.ValidateAndCleanPath above
		if err := os.Remove(cleanPath); err != nil {
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
		return fmt.Errorf("unix-style permissions are not supported on this platform (NTFS uses ACLs); remove the permissions field from your configuration")
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
	// NOTE: symlink escapes not blocked by ValidateAndCleanPath
	if err := security.SecureWriteFileWithPerms(fileConfig.AllowedBasePath, resourceID, []byte(fileConfig.Content), os.FileMode(fileConfig.Permissions)); err != nil {
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
			// #nosec G304 -- path validated by security.ValidateAndCleanPath above
			if err := os.Chown(cleanPath, uid, gid); err != nil {
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
