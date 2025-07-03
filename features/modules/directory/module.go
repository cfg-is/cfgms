package directory

import (
	"context"
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

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *directoryConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"path":        c.Path,
		"permissions": c.Permissions,
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
	fields := []string{"path", "permissions"}
	
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
func (m *directoryModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	// Convert ConfigState to directoryConfig
	configMap := config.AsMap()
	dirConfig := &directoryConfig{}
	
	if path, ok := configMap["path"].(string); ok {
		dirConfig.Path = path
	}
	if perms, ok := configMap["permissions"].(int); ok {
		dirConfig.Permissions = perms
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

	// Validate configuration
	if err := dirConfig.validate(); err != nil {
		return err
	}

	// Check if path exists and is a directory
	info, err := os.Stat(dirConfig.Path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat path: %w", err)
		}
		// Path doesn't exist, create it
		if dirConfig.Recursive {
			if err := os.MkdirAll(dirConfig.Path, os.FileMode(dirConfig.Permissions)); err != nil {
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
			if err := os.Mkdir(dirConfig.Path, os.FileMode(dirConfig.Permissions)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		}
	} else if !info.IsDir() {
		return ErrNotADirectory
	}

	// Set permissions
	if err := os.Chmod(dirConfig.Path, os.FileMode(dirConfig.Permissions)); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
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
			return fmt.Errorf("failed to set ownership: %w", err)
		}
	}

	return nil
}

// Get retrieves the current configuration of a directory
func (m *directoryModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	info, err := os.Stat(resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to stat directory: %w", err)
	}
	if !info.IsDir() {
		return nil, ErrNotADirectory
	}

	// Get current permissions
	perms := info.Mode().Perm()

	// Get current ownership
	stat := info.Sys().(*syscall.Stat_t)
	owner, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
	if err != nil {
		return nil, fmt.Errorf("failed to lookup owner: %w", err)
	}
	group, err := user.LookupGroupId(strconv.FormatUint(uint64(stat.Gid), 10))
	if err != nil {
		return nil, fmt.Errorf("failed to lookup group: %w", err)
	}

	config := &directoryConfig{
		Path:        resourceID,
		Permissions: int(perms),
		Owner:       owner.Username,
		Group:       group.Name,
	}

	return config, nil
}

