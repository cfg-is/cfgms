// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"errors"
	"fmt"

	"github.com/cfgis/cfgms/features/modules"
)

// New creates a new instance of the Package module using the platform's real
// package manager. If no supported package manager is found, the returned
// module's Get and Set methods will return the initialization error so the
// steward can surface a clear failure instead of silently providing fake data.
func New() modules.Module {
	mgr, err := NewPackageManager(context.Background())
	if err != nil {
		return &errPackageModule{err: fmt.Errorf("package module init: %w", err)}
	}
	return &PackageModule{packageManager: mgr}
}

// errPackageModule is returned by New when no real package manager is available.
// All operations return the initialization error so callers see a clear failure.
// It embeds DefaultLoggingSupport so the factory can inject loggers regardless of
// whether a package manager was found — needed for logging validation on Windows CI
// runners that lack winget/choco.
type errPackageModule struct {
	modules.DefaultLoggingSupport
	err error
}

var _ modules.Module = (*errPackageModule)(nil)
var _ modules.LoggingInjectable = (*errPackageModule)(nil)

func (m *errPackageModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	return nil, m.err
}

func (m *errPackageModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return m.err
}

// NewPackageModule creates a new package module instance with the provided manager.
func NewPackageModule(mgr PackageManager) (*PackageModule, error) {
	if mgr == nil {
		return nil, ErrInvalidConfig
	}
	return &PackageModule{
		packageManager: mgr,
	}, nil
}

// Configure implements modules.Configurable. The executor calls this before Get
// so the module learns the effective package name (config.Name) ahead of the state read.
func (m *PackageModule) Configure(config modules.ConfigState) error {
	if config == nil {
		return ErrInvalidConfig
	}
	configMap := config.AsMap()
	m.mu.Lock()
	defer m.mu.Unlock()
	if nameVal, ok := configMap["name"].(string); ok {
		m.resolvedName = nameVal
	} else {
		m.resolvedName = ""
	}
	return nil
}

// Get returns the current state of a package.
// It queries by the name stored via Configure (config.Name), falling back to
// resourceID when Configure has not been called or config.Name was empty.
func (m *PackageModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	m.mu.RLock()
	pkgName := m.resolvedName
	m.mu.RUnlock()
	if pkgName == "" {
		pkgName = resourceID
	}

	if err := validatePackageName(pkgName); err != nil {
		return nil, err
	}

	version, err := m.packageManager.GetInstalledVersion(ctx, pkgName)
	if err != nil {
		if errors.Is(err, ErrPackageNotFound) {
			return &Config{Name: pkgName, State: "absent"}, nil
		}
		return nil, fmt.Errorf("failed to get package version: %w", err)
	}

	return &Config{
		Name:           pkgName,
		State:          "present",
		Version:        version,
		PackageManager: m.packageManager.Name(),
	}, nil
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

	// When config.Name is unset, fall back to resourceID so validate() can proceed.
	if cfg.Name == "" {
		cfg.Name = name
	}

	// Validate the configuration
	if err := cfg.validate(); err != nil {
		return err
	}

	// Validate the requested package manager against the active one
	if cfg.PackageManager != "" {
		if !m.packageManager.IsValidManager(cfg.PackageManager) {
			return ErrInvalidPackageManager
		}
	}

	// pkgName is the distribution package name (config.Name), which may differ
	// from the resource identifier (name/resourceID) on apt systems.
	pkgName := cfg.Name

	if cfg.State == "absent" {
		return m.packageManager.Remove(ctx, pkgName)
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
		if dep == pkgName {
			return ErrCircularDependency
		}

		// Install dependency
		err := m.packageManager.Install(ctx, dep, "latest")
		if err != nil {
			return fmt.Errorf("failed to install dependency %s: %w", dep, err)
		}
	}

	return m.packageManager.Install(ctx, pkgName, cfg.Version)
}
