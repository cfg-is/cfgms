// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
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
	Name         string   `yaml:"name"`
	State        string   `yaml:"state"`
	Version      string   `yaml:"version"` // "latest" or specific version, treated as MinVersion if update is true
	Update       bool     `yaml:"update"`  // If true, will check for updates every config validation unless maintenance window is specified
	Dependencies []string `yaml:"dependencies"`
	// PackageManager is the legacy singular provider selector, retained for
	// back-compat. When Providers is empty and PackageManager is set, it is
	// treated as Providers = [PackageManager] (see effectiveProviders).
	PackageManager string `yaml:"package_manager"`
	// Providers is the admin-declared ordered provider allowlist for this
	// resource (e.g. ["winget"], ["apt"]). The module never falls back to a
	// provider outside this list — see resolveProviders/selectManager in
	// providers.go. Empty means "use the @defaults policy, else the platform
	// built-in default."
	Providers   []string `yaml:"providers,omitempty"`
	Maintenance struct {
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
	if len(c.Providers) > 0 {
		result["providers"] = c.Providers
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
	if len(c.Providers) > 0 {
		fields = append(fields, "providers")
	}
	if c.Maintenance.Window != "" || c.Maintenance.Schedule != "" {
		fields = append(fields, "maintenance")
	}

	return fields
}

// effectiveProviders returns the provider allowlist this Config declares:
// Providers if set, else a single-item list derived from the legacy
// PackageManager field for back-compat, else nil (meaning "no
// resource-level preference — fall through to @defaults / platform
// default").
func (c *Config) effectiveProviders() []string {
	if len(c.Providers) > 0 {
		return c.Providers
	}
	if c.PackageManager != "" {
		return []string{c.PackageManager}
	}
	return nil
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
	// Reject slashes, spaces, and leading dashes. Leading dashes would be
	// interpreted as options by root-run package managers (CWE-88).
	if strings.ContainsAny(name, "/ ") || strings.HasPrefix(name, "-") {
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
	mu sync.RWMutex
	// packageManager is a legacy directly-injected manager (NewPackageModule
	// constructor, used by most existing tests). When set, it is used
	// unconditionally for every resource and the provider allowlist
	// machinery below is bypassed entirely.
	packageManager PackageManager
	// resolvedName is set by Configure from config.Name; Get falls back to resourceID when empty.
	resolvedName string
	// resolvedProviders is the raw `providers` list recorded by Configure
	// (NOT back-compat-expanded from package_manager) so Get can echo back
	// exactly what was authored — desired==observed, no false drift.
	resolvedProviders []string
	// resolvedPackageManager is the raw legacy `package_manager` field
	// recorded by Configure, used only for back-compat provider selection
	// (authoredProviders) in Get, never echoed as `providers`.
	resolvedPackageManager string
	// defaultProviders is the host-wide policy set via Set("@defaults", ...).
	// Legitimately shared cross-resource state (guarded by mu), unlike
	// per-resource fields above.
	defaultProviders []string
	// managerCache caches selected PackageManager instances by resolved
	// provider-list key so repeated Get/Set calls don't re-probe.
	managerCache map[string]PackageManager
	// registry is the provider name -> probe/constructor table used for
	// selection. nil means use defaultProviderRegistry (New() sets this
	// explicitly; tests can inject a fake registry).
	registry map[string]providerEntry
	// Embed default logging support for automatic injection capability
	modules.DefaultLoggingSupport
}
