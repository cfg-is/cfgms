package file

import (
	"context"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	"github.com/cfgis/cfgms/features/modules"
)

// fileModule implements the Module interface for file management
type fileModule struct{}

// New creates a new instance of the file module
func New() Module {
	return &fileModule{}
}

// Get returns the current configuration of the file
func (m *fileModule) Get(ctx context.Context, resourceID string) (FileConfig, error) {
	if resourceID == "" {
		return FileConfig{}, modules.ErrInvalidResourceID
	}

	info, err := os.Stat(resourceID)
	if err != nil {
		return FileConfig{}, err
	}

	content, err := os.ReadFile(resourceID)
	if err != nil {
		return FileConfig{}, err
	}

	// Get owner and group
	var owner, group string
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		ownerUser, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
		if err == nil {
			owner = ownerUser.Username
		}

		groupUser, err := user.LookupGroupId(strconv.FormatUint(uint64(stat.Gid), 10))
		if err == nil {
			group = groupUser.Name
		}
	}

	return FileConfig{
		Content:     string(content),
		Permissions: info.Mode().Perm(),
		Owner:       owner,
		Group:       group,
	}, nil
}

// Set updates the file content and attributes
func (m *fileModule) Set(ctx context.Context, resourceID string, config FileConfig) error {
	if resourceID == "" || config.Content == "" {
		return modules.ErrInvalidInput
	}

	// Write file with content
	if err := os.WriteFile(resourceID, []byte(config.Content), config.Permissions); err != nil {
		return err
	}

	// Set owner and group if specified
	if config.Owner != "" || config.Group != "" {
		switch runtime.GOOS {
		case "linux", "darwin":
			// Get UID and GID for the specified owner and group
			var uid, gid int
			if config.Owner != "" {
				userInfo, err := user.Lookup(config.Owner)
				if err != nil {
					return err
				}
				uid, _ = strconv.Atoi(userInfo.Uid)
			}
			if config.Group != "" {
				groupInfo, err := user.LookupGroup(config.Group)
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
			if config.Owner != "" {
				_, err := user.Lookup(config.Owner)
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

// Test checks if the file content and attributes match the desired state
func (m *fileModule) Test(ctx context.Context, resourceID string, config FileConfig) (bool, error) {
	if resourceID == "" || config.Content == "" {
		return false, modules.ErrInvalidInput
	}

	current, err := m.Get(ctx, resourceID)
	if err != nil {
		return false, err
	}

	// Compare content and permissions
	contentMatch := current.Content == config.Content
	permMatch := current.Permissions == config.Permissions

	// Compare owner and group only if specified in config
	ownerMatch := true
	groupMatch := true

	if config.Owner != "" || config.Group != "" {
		switch runtime.GOOS {
		case "linux", "darwin":
			if config.Owner != "" {
				ownerMatch = current.Owner == config.Owner
			}
			if config.Group != "" {
				groupMatch = current.Group == config.Group
			}
		case "windows":
			// Windows only supports owner comparison
			if config.Owner != "" {
				ownerMatch = current.Owner == config.Owner
			}
		default:
			// Unsupported platform
			return false, modules.ErrUnsupportedPlatform
		}
	}

	return contentMatch && permMatch && ownerMatch && groupMatch, nil
}
