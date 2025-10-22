// #nosec G304 - Module metadata system requires file access for loading module definitions
package modules

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ModuleMetadata represents the complete metadata for a module
// This extends the existing module.yaml format with dependency management
type ModuleMetadata struct {
	// Basic module information
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	Description string `yaml:"description" json:"description"`
	Author      string `yaml:"author,omitempty" json:"author,omitempty"`
	License     string `yaml:"license,omitempty" json:"license,omitempty"`

	// Module dependencies (NEW - for inter-module dependencies)
	ModuleDependencies []ModuleDependency `yaml:"module_dependencies,omitempty" json:"module_dependencies,omitempty"`

	// Legacy dependencies field (for Go package dependencies)
	// This maintains backwards compatibility with existing modules
	Dependencies []interface{} `yaml:"dependencies,omitempty" json:"dependencies,omitempty"`

	// Platform and system requirements
	Requirements *ModuleRequirements `yaml:"requirements,omitempty" json:"requirements,omitempty"`
	Platforms    []string            `yaml:"platforms,omitempty" json:"platforms,omitempty"`

	// Module capabilities and interfaces
	Interfaces []string `yaml:"interfaces,omitempty" json:"interfaces,omitempty"`

	// Security requirements
	Security *ModuleSecurity `yaml:"security,omitempty" json:"security,omitempty"`

	// Documentation references
	Documentation *ModuleDocumentation `yaml:"documentation,omitempty" json:"documentation,omitempty"`

	// Schema file reference for configuration validation
	Schema string `yaml:"schema,omitempty" json:"schema,omitempty"`
}

// ModuleRequirements defines system requirements for a module
type ModuleRequirements struct {
	OS        []string `yaml:"os,omitempty" json:"os,omitempty"`
	Arch      []string `yaml:"arch,omitempty" json:"arch,omitempty"`
	MinMemory string   `yaml:"min_memory,omitempty" json:"min_memory,omitempty"`
	MinDisk   string   `yaml:"min_disk,omitempty" json:"min_disk,omitempty"`
}

// ModuleSecurity defines security requirements and capabilities
type ModuleSecurity struct {
	RequiresRoot bool     `yaml:"requires_root,omitempty" json:"requires_root,omitempty"`
	Capabilities []string `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Ports        []int    `yaml:"ports,omitempty" json:"ports,omitempty"`
}

// ModuleDocumentation defines documentation references
type ModuleDocumentation struct {
	API      string `yaml:"api,omitempty" json:"api,omitempty"`
	Examples string `yaml:"examples,omitempty" json:"examples,omitempty"`
	README   string `yaml:"readme,omitempty" json:"readme,omitempty"`
}

// LoadModuleMetadata loads module metadata from a module.yaml file
func LoadModuleMetadata(filePath string) (*ModuleMetadata, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open module metadata file %s: %v", filePath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log error but don't override original error - best effort cleanup
			_ = err
		}
	}()

	return ParseModuleMetadata(file)
}

// ParseModuleMetadata parses module metadata from a YAML reader
func ParseModuleMetadata(reader io.Reader) (*ModuleMetadata, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read module metadata: %v", err)
	}

	var metadata ModuleMetadata
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse module metadata YAML: %v", err)
	}

	// Validate required fields
	if metadata.Name == "" {
		return nil, fmt.Errorf("module name is required")
	}

	if metadata.Version == "" {
		return nil, fmt.Errorf("module version is required")
	}

	// Validate version format
	if _, err := ParseVersion(metadata.Version); err != nil {
		return nil, fmt.Errorf("invalid module version '%s': %v", metadata.Version, err)
	}

	// Validate dependency version constraints
	for i, dep := range metadata.ModuleDependencies {
		if dep.Name == "" {
			return nil, fmt.Errorf("dependency %d: name is required", i)
		}

		if dep.Version != "" {
			// Test version constraint by checking against a dummy version
			if _, err := IsVersionCompatible("1.0.0", dep.Version); err != nil {
				return nil, fmt.Errorf("dependency %d (%s): invalid version constraint '%s': %v",
					i, dep.Name, dep.Version, err)
			}
		}
	}

	return &metadata, nil
}

// SaveModuleMetadata saves module metadata to a module.yaml file
func (m *ModuleMetadata) SaveModuleMetadata(filePath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal module metadata to YAML: %v", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write module metadata file %s: %v", filePath, err)
	}

	return nil
}

// ToYAML returns the module metadata as YAML bytes
func (m *ModuleMetadata) ToYAML() ([]byte, error) {
	return yaml.Marshal(m)
}

// FromYAML populates the module metadata from YAML bytes
func (m *ModuleMetadata) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, m)
}

// Validate validates the module metadata
func (m *ModuleMetadata) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("module name is required")
	}

	if m.Version == "" {
		return fmt.Errorf("module version is required")
	}

	// Validate version format
	if _, err := ParseVersion(m.Version); err != nil {
		return fmt.Errorf("invalid module version '%s': %v", m.Version, err)
	}

	// Validate dependency version constraints
	for i, dep := range m.ModuleDependencies {
		if dep.Name == "" {
			return fmt.Errorf("dependency %d: name is required", i)
		}

		if dep.Version != "" {
			// Test version constraint by checking against a dummy version
			if _, err := IsVersionCompatible("1.0.0", dep.Version); err != nil {
				return fmt.Errorf("dependency %d (%s): invalid version constraint '%s': %v",
					i, dep.Name, dep.Version, err)
			}
		}
	}

	return nil
}

// GetDependencyNames returns a list of all dependency names
func (m *ModuleMetadata) GetDependencyNames() []string {
	names := make([]string, len(m.ModuleDependencies))
	for i, dep := range m.ModuleDependencies {
		names[i] = dep.Name
	}
	return names
}

// HasDependency checks if the module has a specific dependency
func (m *ModuleMetadata) HasDependency(name string) bool {
	for _, dep := range m.ModuleDependencies {
		if dep.Name == name {
			return true
		}
	}
	return false
}

// GetDependency returns a specific dependency by name
func (m *ModuleMetadata) GetDependency(name string) (*ModuleDependency, bool) {
	for _, dep := range m.ModuleDependencies {
		if dep.Name == name {
			return &dep, true
		}
	}
	return nil, false
}

// AddDependency adds a new module dependency
func (m *ModuleMetadata) AddDependency(dep ModuleDependency) error {
	// Check if dependency already exists
	if m.HasDependency(dep.Name) {
		return fmt.Errorf("dependency '%s' already exists", dep.Name)
	}

	// Validate the dependency
	if dep.Name == "" {
		return fmt.Errorf("dependency name is required")
	}

	if dep.Version != "" {
		// Test version constraint by checking against a dummy version
		if _, err := IsVersionCompatible("1.0.0", dep.Version); err != nil {
			return fmt.Errorf("invalid version constraint '%s': %v", dep.Version, err)
		}
	}

	m.ModuleDependencies = append(m.ModuleDependencies, dep)
	return nil
}

// RemoveDependency removes a module dependency by name
func (m *ModuleMetadata) RemoveDependency(name string) bool {
	for i, dep := range m.ModuleDependencies {
		if dep.Name == name {
			// Remove the dependency
			m.ModuleDependencies = append(m.ModuleDependencies[:i], m.ModuleDependencies[i+1:]...)
			return true
		}
	}
	return false
}

// Clone returns a deep copy of the module metadata
func (m *ModuleMetadata) Clone() *ModuleMetadata {
	clone := &ModuleMetadata{
		Name:        m.Name,
		Version:     m.Version,
		Description: m.Description,
		Author:      m.Author,
		License:     m.License,
		Schema:      m.Schema,
	}

	// Deep copy module dependencies
	if m.ModuleDependencies != nil {
		clone.ModuleDependencies = make([]ModuleDependency, len(m.ModuleDependencies))
		copy(clone.ModuleDependencies, m.ModuleDependencies)
	}

	// Deep copy legacy dependencies
	if m.Dependencies != nil {
		clone.Dependencies = make([]interface{}, len(m.Dependencies))
		copy(clone.Dependencies, m.Dependencies)
	}

	// Deep copy platforms
	if m.Platforms != nil {
		clone.Platforms = make([]string, len(m.Platforms))
		copy(clone.Platforms, m.Platforms)
	}

	// Deep copy interfaces
	if m.Interfaces != nil {
		clone.Interfaces = make([]string, len(m.Interfaces))
		copy(clone.Interfaces, m.Interfaces)
	}

	// Copy nested structures
	if m.Requirements != nil {
		clone.Requirements = &ModuleRequirements{
			MinMemory: m.Requirements.MinMemory,
			MinDisk:   m.Requirements.MinDisk,
		}
		if m.Requirements.OS != nil {
			clone.Requirements.OS = make([]string, len(m.Requirements.OS))
			copy(clone.Requirements.OS, m.Requirements.OS)
		}
		if m.Requirements.Arch != nil {
			clone.Requirements.Arch = make([]string, len(m.Requirements.Arch))
			copy(clone.Requirements.Arch, m.Requirements.Arch)
		}
	}

	if m.Security != nil {
		clone.Security = &ModuleSecurity{
			RequiresRoot: m.Security.RequiresRoot,
		}
		if m.Security.Capabilities != nil {
			clone.Security.Capabilities = make([]string, len(m.Security.Capabilities))
			copy(clone.Security.Capabilities, m.Security.Capabilities)
		}
		if m.Security.Ports != nil {
			clone.Security.Ports = make([]int, len(m.Security.Ports))
			copy(clone.Security.Ports, m.Security.Ports)
		}
	}

	if m.Documentation != nil {
		clone.Documentation = &ModuleDocumentation{
			API:      m.Documentation.API,
			Examples: m.Documentation.Examples,
			README:   m.Documentation.README,
		}
	}

	return clone
}
