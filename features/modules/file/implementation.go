// SPDX-License-Identifier: AGPL-3.0-only
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

// fileModule implements the Module interface for file, directory, and symlink management.
type fileModule struct {
	// Embed default logging support for automatic injection capability
	modules.DefaultLoggingSupport
	// configuredBasePath is populated by Set() from the operator's AllowedBasePath YAML field.
	// It has no default — Get() returns ErrAllowedBasePathRequired until Set() or Configure() is called.
	configuredBasePath string
}

// New creates a new instance of the file module
func New() modules.Module {
	return &fileModule{}
}

// Configure extracts AllowedBasePath from the operator config so that Get() can
// safely read the current resource state before Set() is called.
// This implements modules.Configurable and is called by the execution engine
// before the Get→Compare→Set→Verify cycle begins.
func (m *fileModule) Configure(config modules.ConfigState) error {
	if config == nil {
		return ErrAllowedBasePathRequired
	}
	configMap := config.AsMap()
	basePath, _ := configMap["allowed_base_path"].(string)
	if basePath == "" || !filepath.IsAbs(basePath) {
		return ErrAllowedBasePathRequired
	}
	m.configuredBasePath = basePath
	return nil
}

// Get returns the current state of the resource at resourceID.
//
// The returned FileConfig reflects the on-disk type:
//   - Regular file → Type "file" with content, permissions, ownership
//   - Directory    → Type "directory" with permissions, ownership
//   - Absent       → State "absent"
func (m *fileModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, modules.ErrInvalidResourceID
	}

	if m.configuredBasePath == "" {
		return nil, ErrAllowedBasePathRequired
	}

	cleanPath, err := security.ValidateAndCleanPath(m.configuredBasePath, resourceID)
	if err != nil {
		return nil, err
	}

	// #nosec G304 -- path validated by security.ValidateAndCleanPath above
	info, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &FileConfig{
				State:           "absent",
				AllowedBasePath: m.configuredBasePath,
			}, nil
		}
		return nil, err
	}

	if info.IsDir() {
		return m.getDirectory(cleanPath, resourceID)
	}
	return m.getFile(cleanPath, resourceID)
}

func (m *fileModule) getFile(cleanPath, resourceID string) (modules.ConfigState, error) {
	content, err := security.SecureReadFile(m.configuredBasePath, resourceID)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}

	owner, group, err := getFileOwnership(info)
	if err != nil {
		return nil, err
	}

	aclData, err := getFileACL(cleanPath)
	if err != nil {
		return nil, err
	}

	return &FileConfig{
		Type:            "file",
		State:           "present",
		Content:         string(content),
		Permissions:     getFilePermissions(info),
		Owner:           owner,
		Group:           group,
		AllowedBasePath: m.configuredBasePath,
		WindowsACL:      aclData,
	}, nil
}

func (m *fileModule) getDirectory(cleanPath, resourceID string) (modules.ConfigState, error) {
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}

	perms := getFilePermissions(info)

	ownerName, groupName, err := getFileOwnership(info)
	if err != nil {
		return nil, fmt.Errorf("failed to get directory ownership: %w", err)
	}

	aclData, err := getFileACL(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("getDirectoryACL: %w", err)
	}

	return &FileConfig{
		Type:            "directory",
		State:           "present",
		Path:            resourceID,
		Permissions:     perms,
		Owner:           ownerName,
		Group:           groupName,
		AllowedBasePath: m.configuredBasePath,
		WindowsACL:      aclData,
	}, nil
}

// Set creates or updates the resource described by config at resourceID.
// Dispatches to the file, directory, or symlink implementation based on config.Type.
func (m *fileModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if resourceID == "" {
		return modules.ErrInvalidResourceID
	}
	if config == nil {
		return modules.ErrInvalidInput
	}

	configMap := config.AsMap()
	fileConfig := extractFileConfig(configMap)

	if fileConfig.AllowedBasePath == "" || !filepath.IsAbs(fileConfig.AllowedBasePath) {
		return ErrAllowedBasePathRequired
	}

	cleanPath, err := security.ValidateAndCleanPath(fileConfig.AllowedBasePath, resourceID)
	if err != nil {
		return err
	}
	m.configuredBasePath = fileConfig.AllowedBasePath

	switch fileConfig.resolvedType() {
	case "symlink":
		return modules.ErrNotImplemented
	case "directory":
		return m.setDirectory(ctx, resourceID, cleanPath, fileConfig)
	default: // "file"
		return m.setFile(ctx, resourceID, cleanPath, fileConfig)
	}
}

// extractFileConfig builds a FileConfig from the config map produced by AsMap().
func extractFileConfig(configMap map[string]interface{}) *FileConfig {
	fc := &FileConfig{}

	if v, ok := configMap["type"].(string); ok {
		fc.Type = v
	}
	if v, ok := configMap["state"].(string); ok {
		fc.State = v
	}
	if v, ok := configMap["content"].(string); ok {
		fc.Content = v
	}
	if v, ok := configMap["permissions"].(int); ok {
		fc.Permissions = v
	} else if v, ok := configMap["mode"].(string); ok {
		var modeInt int
		if _, err := fmt.Sscanf(v, "%o", &modeInt); err == nil {
			fc.Permissions = modeInt
		}
	} else if v, ok := configMap["mode"].(int); ok {
		fc.Permissions = v
	}
	if v, ok := configMap["owner"].(string); ok {
		fc.Owner = v
	}
	if v, ok := configMap["group"].(string); ok {
		fc.Group = v
	}
	if v, ok := configMap["allowed_base_path"].(string); ok {
		fc.AllowedBasePath = v
	}
	if v, ok := configMap["windows_acl"].(*modules.WindowsACL); ok {
		fc.WindowsACL = v
	}
	if v, ok := configMap["path"].(string); ok {
		fc.Path = v
	}
	if v, ok := configMap["recursive"].(bool); ok {
		fc.Recursive = v
	}

	return fc
}

// setFile writes or removes a regular file.
func (m *fileModule) setFile(ctx context.Context, resourceID, cleanPath string, fileConfig *FileConfig) error {
	logger := m.GetEffectiveLogger(logging.ForModule("file"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Starting file configuration",
		"operation", "file_set",
		"resource_id", resourceID,
		"tenant_id", tenantID,
		"resource_type", "file")

	if fileConfig.State == "absent" {
		// #nosec G304 -- path validated by security.ValidateAndCleanPath above
		if err := os.Remove(cleanPath); err != nil {
			if os.IsNotExist(err) {
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

	if !platformSupportsPermissions() && fileConfig.Permissions != 0 {
		logger.WarnCtx(ctx, "unix-style permissions ignored on this platform (NTFS uses ACLs)",
			"operation", "file_set",
			"resource_id", resourceID)
		fileConfig.Permissions = 0
	}

	if fileConfig.Permissions == 0 && fileConfig.WindowsACL == nil {
		fileConfig.Permissions = int(defaultFileMode())
	}

	if err := fileConfig.Validate(); err != nil {
		logger.ErrorCtx(ctx, "File configuration validation failed",
			"operation", "file_set",
			"resource_id", resourceID,
			"error_code", "CONFIG_VALIDATION_FAILED",
			"error_details", err.Error())
		return err
	}

	if fileConfig.Permissions < 0 || fileConfig.Permissions > 0777 {
		return modules.ErrInvalidInput
	}
	if err := security.SecureWriteFileWithPerms(fileConfig.AllowedBasePath, resourceID, []byte(fileConfig.Content), os.FileMode(fileConfig.Permissions)); err != nil {
		return err
	}

	if err := setOwnership(ctx, cleanPath, fileConfig.Owner, fileConfig.Group, logger, resourceID); err != nil {
		return err
	}

	if fileConfig.WindowsACL != nil {
		if err := setFileACL(cleanPath, fileConfig.WindowsACL); err != nil {
			logger.ErrorCtx(ctx, "Failed to set Windows ACL",
				"operation", "file_set",
				"resource_id", resourceID,
				"error_code", "WINDOWS_ACL_FAILED",
				"error_details", err.Error())
			return err
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

// setDirectory creates or updates a directory.
func (m *fileModule) setDirectory(ctx context.Context, resourceID, cleanPath string, fileConfig *FileConfig) error {
	logger := m.GetEffectiveLogger(logging.ForModule("file"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Starting directory configuration",
		"operation", "directory_set",
		"resource_id", resourceID,
		"tenant_id", tenantID,
		"resource_type", "directory")

	if fileConfig.State == "absent" {
		return fmt.Errorf("directory deletion is not supported: %w", modules.ErrNotImplemented)
	}

	if !platformSupportsPermissions() && fileConfig.Permissions != 0 {
		logger.WarnCtx(ctx, "unix-style permissions ignored on this platform (NTFS uses ACLs)",
			"operation", "directory_set",
			"resource_id", resourceID)
		fileConfig.Permissions = 0
	}

	if fileConfig.Permissions == 0 && fileConfig.WindowsACL == nil {
		fileConfig.Permissions = int(defaultDirectoryMode())
	}

	if err := fileConfig.Validate(); err != nil {
		logger.ErrorCtx(ctx, "Directory configuration validation failed",
			"operation", "directory_set",
			"resource_id", resourceID,
			"error_code", "CONFIG_VALIDATION_FAILED",
			"error_details", err.Error())
		return err
	}

	if fileConfig.Permissions < 0 || fileConfig.Permissions > 0777 {
		return modules.ErrInvalidInput
	}
	fileMode := os.FileMode(fileConfig.Permissions)

	info, err := os.Stat(cleanPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat path: %w", err)
		}
		if fileConfig.Recursive {
			if err := os.MkdirAll(cleanPath, fileMode); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		} else {
			parent := filepath.Dir(cleanPath)
			if _, err := os.Stat(parent); err != nil {
				if os.IsNotExist(err) {
					return ErrRecursiveRequired
				}
				return fmt.Errorf("failed to stat parent directory: %w", err)
			}
			if err := os.Mkdir(cleanPath, fileMode); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		}
	} else if !info.IsDir() {
		return ErrNotADirectory
	}

	if platformSupportsPermissions() {
		if err := os.Chmod(cleanPath, fileMode); err != nil {
			return fmt.Errorf("failed to set permissions: %w", err)
		}
	}

	if err := setOwnership(ctx, cleanPath, fileConfig.Owner, fileConfig.Group, logger, resourceID); err != nil {
		return err
	}

	if fileConfig.WindowsACL != nil {
		if err := setFileACL(cleanPath, fileConfig.WindowsACL); err != nil {
			logger.ErrorCtx(ctx, "Failed to set Windows ACL",
				"operation", "directory_set",
				"resource_id", resourceID,
				"error_code", "WINDOWS_ACL_FAILED",
				"error_details", err.Error())
			return fmt.Errorf("setDirectoryACL: %w", err)
		}
	}

	logger.InfoCtx(ctx, "Directory configuration completed successfully",
		"operation", "directory_set",
		"resource_id", resourceID,
		"tenant_id", tenantID,
		"resource_type", "directory",
		"path", cleanPath,
		"permissions", fmt.Sprintf("0%o", fileConfig.Permissions),
		"status", "completed")

	return nil
}

// setOwnership applies the owner and group to cleanPath. No-op when both are empty.
func setOwnership(ctx context.Context, cleanPath, owner, group string, logger logging.Logger, resourceID string) error {
	if owner == "" && group == "" {
		return nil
	}

	switch runtime.GOOS {
	case "linux", "darwin":
		uid, gid := -1, -1
		if owner != "" {
			u, err := user.Lookup(owner)
			if err != nil {
				return ErrInvalidOwner
			}
			parsedUID, err := strconv.Atoi(u.Uid)
			if err != nil {
				return fmt.Errorf("failed to parse UID for owner %q: %w", owner, err)
			}
			uid = parsedUID
		}
		if group != "" {
			g, err := user.LookupGroup(group)
			if err != nil {
				return ErrInvalidGroup
			}
			parsedGID, err := strconv.Atoi(g.Gid)
			if err != nil {
				return fmt.Errorf("failed to parse GID for group %q: %w", group, err)
			}
			gid = parsedGID
		}
		// #nosec G304 -- cleanPath validated by security.ValidateAndCleanPath before this call
		if err := os.Chown(cleanPath, uid, gid); err != nil {
			logger.ErrorCtx(ctx, "Failed to set ownership",
				"resource_id", resourceID,
				"error_code", "OWNERSHIP_FAILED",
				"path", cleanPath,
				"owner", owner,
				"group", group,
				"error_details", err.Error())
			return fmt.Errorf("failed to set ownership: %w", err)
		}

	case "windows":
		if owner != "" {
			if _, err := user.Lookup(owner); err != nil {
				return ErrInvalidOwner
			}
		}

	default:
		logger.ErrorCtx(ctx, "Unsupported platform for ownership",
			"resource_id", resourceID,
			"error_code", "UNSUPPORTED_PLATFORM",
			"platform", runtime.GOOS)
		return modules.ErrUnsupportedPlatform
	}

	return nil
}

// defaultDirectoryMode returns the default directory mode for this platform.
func defaultDirectoryMode() os.FileMode {
	if platformSupportsPermissions() {
		return 0755
	}
	return 0777
}
