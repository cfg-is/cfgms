package file

import (
	"github.com/cfgis/cfgms/features/modules"
	"gopkg.in/yaml.v3"
)

// FileConfig represents the configuration for a file resource
type FileConfig struct {
	Content     string `yaml:"content"`
	Permissions int    `yaml:"permissions"`
	Owner       string `yaml:"owner,omitempty"`
	Group       string `yaml:"group,omitempty"`
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *FileConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"content":     c.Content,
		"permissions": c.Permissions,
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
	fields := []string{"content", "permissions"}

	if c.Owner != "" {
		fields = append(fields, "owner")
	}
	if c.Group != "" {
		fields = append(fields, "group")
	}

	return fields
}
