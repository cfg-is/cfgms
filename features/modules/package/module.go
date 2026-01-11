// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/modules"
)

// New creates a new instance of the Package module
func New() modules.Module {
	return &PackageModule{
		packageManager: NewMockPackageManager(),
	}
}

// NewPackageModule creates a new package module instance
func NewPackageModule() (*PackageModule, error) {
	return &PackageModule{
		packageManager: NewMockPackageManager(),
	}, nil
}

// Get returns the current state of a package
func (m *PackageModule) Get(ctx context.Context, name string) (modules.ConfigState, error) {
	if err := validatePackageName(name); err != nil {
		return nil, err
	}

	version, err := m.packageManager.GetInstalledVersion(ctx, name)
	if err != nil {
		// If package is not installed, return absent state
		if strings.Contains(err.Error(), "not installed") {
			config := &Config{
				Name:  name,
				State: "absent",
			}
			return config, nil
		}
		return nil, fmt.Errorf("failed to get package version: %w", err)
	}

	// Include package manager information in the response
	config := &Config{
		Name:           name,
		State:          "present",
		Version:        version,
		PackageManager: m.packageManager.Name(),
	}
	return config, nil
}

// Set updates the state of a package
func (m *PackageModule) Set(ctx context.Context, name string, config modules.ConfigState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := validatePackageName(name); err != nil {
		return err
	}

	if config == nil {
		return ErrInvalidConfig
	}

	// Convert ConfigState to Config
	configMap := config.AsMap()
	cfg := &Config{}

	if nameVal, ok := configMap["name"].(string); ok {
		cfg.Name = nameVal
	}
	if state, ok := configMap["state"].(string); ok {
		cfg.State = state
	}
	if version, ok := configMap["version"].(string); ok {
		cfg.Version = version
	}
	if update, ok := configMap["update"].(bool); ok {
		cfg.Update = update
	}
	if deps, ok := configMap["dependencies"].([]string); ok {
		cfg.Dependencies = deps
	} else if depsInterface, ok := configMap["dependencies"].([]interface{}); ok {
		// Handle YAML unmarshaling which might give []interface{}
		for _, d := range depsInterface {
			if depStr, ok := d.(string); ok {
				cfg.Dependencies = append(cfg.Dependencies, depStr)
			}
		}
	}
	if pkgMgr, ok := configMap["package_manager"].(string); ok {
		cfg.PackageManager = pkgMgr
	}

	// Validate the configuration
	if err := cfg.validate(); err != nil {
		return err
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
