package directory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/cfgis/cfgms/features/modules"
	"gopkg.in/yaml.v3"
)

// directoryModule implements the Module interface for directory management
type directoryModule struct{}

// New creates a new instance of the Directory module
func New() modules.Module {
	return &directoryModule{}
}

// directoryConfig represents the configuration for a directory
type directoryConfig struct {
	Path        string `yaml:"path"`
	Permissions int    `yaml:"permissions"`
	Owner       string `yaml:"owner,omitempty"`
	Group       string `yaml:"group,omitempty"`
	Recursive   bool   `yaml:"recursive,omitempty"`
}

// validateConfig checks if the configuration is valid
func (c *directoryConfig) validate() error {
	// Validate path
	if c.Path == "" {
		return ErrInvalidPath
	}
	if !filepath.IsAbs(c.Path) {
		return ErrInvalidPath
	}

	// Validate permissions (must be between 0 and 0777)
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
func (m *directoryModule) Set(ctx context.Context, resourceID string, configData string) error {
	var config directoryConfig
	if err := yaml.Unmarshal([]byte(configData), &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate configuration
	if err := config.validate(); err != nil {
		return err
	}

	// Check if path exists and is a directory
	info, err := os.Stat(config.Path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat path: %w", err)
		}
		// Path doesn't exist, create it
		if config.Recursive {
			if err := os.MkdirAll(config.Path, os.FileMode(config.Permissions)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		} else {
			parent := filepath.Dir(config.Path)
			if _, err := os.Stat(parent); err != nil {
				if os.IsNotExist(err) {
					return ErrRecursiveRequired
				}
				return fmt.Errorf("failed to stat parent directory: %w", err)
			}
			if err := os.Mkdir(config.Path, os.FileMode(config.Permissions)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		}
	} else if !info.IsDir() {
		return ErrNotADirectory
	}

	// Set permissions
	if err := os.Chmod(config.Path, os.FileMode(config.Permissions)); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Set ownership if specified
	if config.Owner != "" || config.Group != "" {
		var uid, gid int
		if config.Owner != "" {
			u, err := user.Lookup(config.Owner)
			if err != nil {
				return ErrInvalidOwner
			}
			uid, _ = strconv.Atoi(u.Uid)
		} else {
			uid = -1
		}

		if config.Group != "" {
			g, err := user.LookupGroup(config.Group)
			if err != nil {
				return ErrInvalidGroup
			}
			gid, _ = strconv.Atoi(g.Gid)
		} else {
			gid = -1
		}

		if err := os.Chown(config.Path, uid, gid); err != nil {
			return fmt.Errorf("failed to set ownership: %w", err)
		}
	}

	return nil
}

// Get retrieves the current configuration of a directory
func (m *directoryModule) Get(ctx context.Context, resourceID string) (string, error) {
	info, err := os.Stat(resourceID)
	if err != nil {
		return "", fmt.Errorf("failed to stat directory: %w", err)
	}
	if !info.IsDir() {
		return "", ErrNotADirectory
	}

	// Get current permissions
	perms := info.Mode().Perm()

	// Get current ownership
	stat := info.Sys().(*syscall.Stat_t)
	owner, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
	if err != nil {
		return "", fmt.Errorf("failed to lookup owner: %w", err)
	}
	group, err := user.LookupGroupId(strconv.FormatUint(uint64(stat.Gid), 10))
	if err != nil {
		return "", fmt.Errorf("failed to lookup group: %w", err)
	}

	config := directoryConfig{
		Path:        resourceID,
		Permissions: int(perms),
		Owner:       owner.Username,
		Group:       group.Name,
	}

	configData, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	return string(configData), nil
}

// Test verifies if the current directory state matches the desired configuration
func (m *directoryModule) Test(ctx context.Context, resourceID string, configData string) (bool, error) {
	var desiredConfig directoryConfig
	if err := yaml.Unmarshal([]byte(configData), &desiredConfig); err != nil {
		return false, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate desired configuration
	if err := desiredConfig.validate(); err != nil {
		return false, err
	}

	// Get current state
	currentConfig, err := m.Get(ctx, resourceID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	var currentState directoryConfig
	if err := yaml.Unmarshal([]byte(currentConfig), &currentState); err != nil {
		return false, fmt.Errorf("failed to parse current state: %w", err)
	}

	// Compare only specified fields
	if desiredConfig.Path != currentState.Path {
		return false, nil
	}
	if desiredConfig.Permissions != currentState.Permissions {
		return false, nil
	}
	if desiredConfig.Owner != "" && desiredConfig.Owner != currentState.Owner {
		return false, nil
	}
	if desiredConfig.Group != "" && desiredConfig.Group != currentState.Group {
		return false, nil
	}

	return true, nil
}
