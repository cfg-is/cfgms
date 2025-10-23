// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package package_module

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

var (
	// Version format validation
	// Accepts: latest, optional epoch, must start with digit, then alphanumerics, dots, dashes, underscores, plus, and colons
	versionRegex = regexp.MustCompile(`^(latest|([0-9]+:)?[0-9][0-9a-zA-Z_.:+-]*)$`)
)

// PackageManager defines the interface for package management operations
type PackageManager interface {
	// Install installs or updates a package to the specified version
	Install(ctx context.Context, name string, version string) error
	// Remove removes a package
	Remove(ctx context.Context, name string) error
	// GetInstalledVersion returns the currently installed version of a package
	GetInstalledVersion(ctx context.Context, name string) (string, error)
	// ListInstalled returns a map of installed packages and their versions
	ListInstalled(ctx context.Context) (map[string]string, error)
	// Name returns the name of the package manager
	Name() string
	// IsValidManager checks if the given package manager name is valid
	IsValidManager(name string) bool
}

// Config represents the package configuration
type Config struct {
	Name           string   `yaml:"name"`
	State          string   `yaml:"state"`
	Version        string   `yaml:"version"` // "latest" or specific version, treated as MinVersion if update is true
	Update         bool     `yaml:"update"`  // If true, will check for updates every config validation unless maintenance window is specified
	Dependencies   []string `yaml:"dependencies"`
	PackageManager string   `yaml:"package_manager"`
	Maintenance    struct {
		Window   string        `yaml:"window"`   // Optional: Reference to a named maintenance window
		Schedule string        `yaml:"schedule"` // Optional: Inline schedule (cron format)
		Duration time.Duration `yaml:"duration"` // Optional: Duration of the window
		Timezone string        `yaml:"timezone"` // Optional: Timezone for the schedule
	} `yaml:"maintenance,omitempty"` // Optional: Only used if update is true and window/schedule is specified
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *Config) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"name":  c.Name,
		"state": c.State,
	}

	if c.Version != "" {
		result["version"] = c.Version
	}
	if c.Update {
		result["update"] = c.Update
	}
	if len(c.Dependencies) > 0 {
		result["dependencies"] = c.Dependencies
	}
	if c.PackageManager != "" {
		result["package_manager"] = c.PackageManager
	}

	// Only include maintenance if it has values
	if c.Maintenance.Window != "" || c.Maintenance.Schedule != "" {
		maintenance := make(map[string]interface{})
		if c.Maintenance.Window != "" {
			maintenance["window"] = c.Maintenance.Window
		}
		if c.Maintenance.Schedule != "" {
			maintenance["schedule"] = c.Maintenance.Schedule
		}
		if c.Maintenance.Duration != 0 {
			maintenance["duration"] = c.Maintenance.Duration
		}
		if c.Maintenance.Timezone != "" {
			maintenance["timezone"] = c.Maintenance.Timezone
		}
		result["maintenance"] = maintenance
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *Config) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *Config) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *Config) Validate() error {
	return c.validate()
}

// GetManagedFields returns the list of fields this configuration manages
func (c *Config) GetManagedFields() []string {
	fields := []string{"name", "state"}

	if c.Version != "" {
		fields = append(fields, "version")
	}
	if c.Update {
		fields = append(fields, "update")
	}
	if len(c.Dependencies) > 0 {
		fields = append(fields, "dependencies")
	}
	if c.PackageManager != "" {
		fields = append(fields, "package_manager")
	}
	if c.Maintenance.Window != "" || c.Maintenance.Schedule != "" {
		fields = append(fields, "maintenance")
	}

	return fields
}

// validate checks if the configuration is valid
func (c *Config) validate() error {
	// Validate name
	if c.Name == "" {
		return ErrInvalidResourceID
	}
	if err := validatePackageName(c.Name); err != nil {
		return err
	}

	// Validate state
	if c.State != "present" && c.State != "absent" {
		return ErrInvalidState
	}

	// Validate version if present
	if c.State == "present" {
		if c.Version == "" {
			return ErrInvalidVersion
		}
		if !validateVersion(c.Version) {
			return ErrInvalidVersion
		}
	}

	// Validate dependencies
	seenDeps := make(map[string]string)
	for _, dep := range c.Dependencies {
		if err := validatePackageName(dep); err != nil {
			return err
		}
		if dep == c.Name {
			return ErrCircularDependency
		}
		if _, exists := seenDeps[dep]; exists {
			return ErrVersionConflict
		}
		seenDeps[dep] = "latest"
	}

	return nil
}

// validatePackageName validates a package name
func validatePackageName(name string) error {
	if name == "" {
		return ErrInvalidResourceID
	}
	// Package names should not contain slashes or spaces
	if strings.ContainsAny(name, "/ ") {
		return ErrInvalidPackageName
	}
	return nil
}

// validateVersion validates a version string format
func validateVersion(version string) bool {
	if version == "latest" {
		return true
	}

	if version == "" {
		return false
	}

	// Validate version format
	return versionRegex.MatchString(version)
}

// PackageModule implements the Module interface for package management
type PackageModule struct {
	mu             sync.RWMutex
	packageManager PackageManager
	// Embed default logging support for automatic injection capability
	modules.DefaultLoggingSupport
}
