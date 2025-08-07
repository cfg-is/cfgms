// #nosec G304 - File module requires file system access for configuration management
package file

import (
	"context"
	"os"
	"os/user"
	"runtime"
	"strconv"

	"github.com/cfgis/cfgms/features/modules"
)

// fileModule implements the Module interface for file management
type fileModule struct{}

// New creates a new instance of the file module
func New() modules.Module {
	return &fileModule{}
}

// Get returns the current configuration of the file
func (m *fileModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, modules.ErrInvalidResourceID
	}

	info, err := os.Stat(resourceID)
	if err != nil {
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
		Content:     string(content),
		Permissions: int(info.Mode().Perm()),
		Owner:       owner,
		Group:       group,
	}

	return config, nil
}

// Set updates the file content and attributes
func (m *fileModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if resourceID == "" {
		return modules.ErrInvalidResourceID
	}

	if config == nil {
		return modules.ErrInvalidInput
	}

	// Convert ConfigState to FileConfig
	configMap := config.AsMap()
	fileConfig := &FileConfig{}

	if content, ok := configMap["content"].(string); ok {
		fileConfig.Content = content
	}
	if perms, ok := configMap["permissions"].(int); ok {
		fileConfig.Permissions = perms
	}
	if owner, ok := configMap["owner"].(string); ok {
		fileConfig.Owner = owner
	}
	if group, ok := configMap["group"].(string); ok {
		fileConfig.Group = group
	}

	// Validate configuration
	if err := fileConfig.Validate(); err != nil {
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
			return modules.ErrUnsupportedPlatform
		}
	}

	return nil
}
