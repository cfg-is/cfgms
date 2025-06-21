package package_module

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	// Version format validation
	// Accepts: latest, optional epoch, must start with digit, then alphanumerics, dots, dashes, underscores, plus, and colons
	versionRegex = regexp.MustCompile(`^(latest|([0-9]+:)?[0-9][0-9a-zA-Z_.:+-]*)$`)
)

// NewPackageModule creates a new package module instance
func NewPackageModule() (*PackageModule, error) {
	return &PackageModule{
		packageManager: NewMockPackageManager(),
	}, nil
}

// Get returns the current state of a package
func (m *PackageModule) Get(ctx context.Context, name string) (string, error) {
	if err := validatePackageName(name); err != nil {
		return "", err
	}

	version, err := m.packageManager.GetInstalledVersion(ctx, name)
	if err != nil {
		// If package is not installed, return absent state
		if strings.Contains(err.Error(), "not installed") {
			return fmt.Sprintf(`
name: %s
state: absent
`, name), nil
		}
		return "", fmt.Errorf("failed to get package version: %w", err)
	}

	// Include package manager information in the response
	return fmt.Sprintf(`
name: %s
state: present
version: "%s"
package_manager: "%s"
`, name, version, m.packageManager.Name()), nil
}

// Set updates the state of a package
func (m *PackageModule) Set(ctx context.Context, name string, config string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := validatePackageName(name); err != nil {
		return err
	}

	cfg, err := parseConfig(config)
	if err != nil {
		return err // Don't wrap this error since parseConfig already returns a specific error
	}

	// Validate that resource ID matches package name
	if cfg.Name != name {
		return ErrResourceIDMismatch
	}

	// Validate package manager if specified
	if cfg.PackageManager != "" {
		if !m.packageManager.IsValidManager(cfg.PackageManager) {
			return ErrInvalidPackageManager
		}
		// Set the package manager if it's valid
		if mock, ok := m.packageManager.(*MockPackageManager); ok {
			mock.SetManager(cfg.PackageManager)
		}
	} else {
		// Set default package manager
		if mock, ok := m.packageManager.(*MockPackageManager); ok {
			mock.SetManager("default")
		}
	}

	if cfg.State == "absent" {
		return m.packageManager.Remove(ctx, name)
	}

	// If update flag is set, use latest version
	if cfg.Update {
		cfg.Version = "latest"
	}

	// Validate version before proceeding
	if !validateVersion(cfg.Version) {
		return ErrInvalidVersion
	}

	// Install dependencies first
	for _, dep := range cfg.Dependencies {
		if err := validatePackageName(dep); err != nil {
			return err
		}

		// Check for circular dependencies
		if dep == name {
			return ErrCircularDependency
		}

		// Install dependency
		err := m.packageManager.Install(ctx, dep, "latest")
		if err != nil {
			return fmt.Errorf("failed to install dependency %s: %w", dep, err)
		}
	}

	return m.packageManager.Install(ctx, name, cfg.Version)
}

// Test checks if a package is in the desired state
func (m *PackageModule) Test(ctx context.Context, name string, config string) (bool, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return false, fmt.Errorf("failed to parse config: %w", err)
	}

	installed, err := m.packageManager.ListInstalled(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to list installed packages: %w", err)
	}

	version, exists := installed[name]
	if cfg.State == "absent" {
		return !exists, nil
	}

	if !exists {
		return false, nil
	}

	if cfg.Version == "latest" {
		return true, nil
	}

	// Use compareVersions to properly compare versions
	comp, err := compareVersions(version, cfg.Version)
	if err != nil {
		return false, fmt.Errorf("failed to compare versions: %w", err)
	}
	return comp == 0, nil
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

// parseConfig parses the package configuration
func parseConfig(config string) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(config), &cfg); err != nil {
		return nil, ErrInvalidConfig
	}

	// Validate package name first
	if cfg.Name == "" {
		return nil, ErrInvalidResourceID
	}
	if err := validatePackageName(cfg.Name); err != nil {
		return nil, err
	}

	// Then validate state
	if cfg.State != "present" && cfg.State != "absent" {
		return nil, ErrInvalidState
	}

	// Finally validate version if present
	if cfg.State == "present" {
		if cfg.Version == "" {
			return nil, ErrInvalidVersion
		}
		if !validateVersion(cfg.Version) {
			return nil, ErrInvalidVersion
		}
	}

	// Validate dependencies
	seenDeps := make(map[string]string)
	for _, dep := range cfg.Dependencies {
		if err := validatePackageName(dep); err != nil {
			return nil, err
		}
		if dep == cfg.Name {
			return nil, ErrCircularDependency
		}
		if _, exists := seenDeps[dep]; exists {
			return nil, ErrVersionConflict
		}
		seenDeps[dep] = "latest"
	}

	return &cfg, nil
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

// compareVersions compares two version strings
func compareVersions(v1, v2 string) (int, error) {
	// Handle special cases
	if v1 == "latest" || v2 == "latest" {
		if v1 == v2 {
			return 0, nil
		}
		if v1 == "latest" {
			return 1, nil
		}
		return -1, nil
	}

	// Remove 'v' prefix if present
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	// Split versions into components
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	// Compare each component
	for i := 0; i < len(v1Parts) || i < len(v2Parts); i++ {
		var num1, num2 int
		if i < len(v1Parts) {
			num1, _ = strconv.Atoi(strings.Split(v1Parts[i], "-")[0])
		}
		if i < len(v2Parts) {
			num2, _ = strconv.Atoi(strings.Split(v2Parts[i], "-")[0])
		}
		if num1 < num2 {
			return -1, nil
		}
		if num1 > num2 {
			return 1, nil
		}
	}

	// If we get here, the versions are equal
	return 0, nil
}
