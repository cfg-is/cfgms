// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"errors"
	"fmt"

	"github.com/cfgis/cfgms/features/modules"
)

// New creates a new instance of the Package module. Construction never fails
// and never auto-detects a package manager: selection is deferred to each
// Get/Set call, driven by the resource's declared provider allowlist
// (Config.Providers, or the legacy singular Config.PackageManager), an
// optional host-wide "@defaults" policy resource, or the platform built-in
// default (see resolveProviders/selectManager in providers.go). This lets a
// steward host without any recognized manager still construct the module
// cleanly and report a clear per-resource error only when a resource
// actually needs to converge.
func New() modules.Module {
	return &PackageModule{registry: defaultProviderRegistry}
}

// errPackageModule returns a fixed initialization error from every operation.
// New() no longer constructs this for "no package manager found" — that is
// now a per-resource Get/Set error, not a construction-time failure (see
// New). This type is retained for a genuinely unconstructable module and for
// TestErrPackageModule, which pins the "return init error, not fake data"
// contract. It embeds DefaultLoggingSupport so the factory can inject
// loggers regardless of construction outcome.
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
// so the module learns the effective package name (config.Name) and the
// resource's own provider declarations (config.Providers / legacy
// config.PackageManager) ahead of the state read.
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
	m.resolvedProviders = extractProviders(configMap)
	if pkgMgr, ok := configMap["package_manager"].(string); ok {
		m.resolvedPackageManager = pkgMgr
	} else {
		m.resolvedPackageManager = ""
	}
	return nil
}

// Get returns the current state of a package.
// It queries by the name stored via Configure (config.Name), falling back to
// resourceID when Configure has not been called or config.Name was empty.
//
// The reserved resource name "@defaults" is handled specially: it reports
// the module's host-wide default provider policy instead of a package's
// install state (see Set for how it's configured).
func (m *PackageModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pkgName := m.resolvedName
	if pkgName == "" {
		pkgName = resourceID
	}

	if pkgName == metaDefaultsName {
		return &Config{
			Name:      metaDefaultsName,
			State:     "present",
			Providers: append([]string(nil), m.defaultProviders...),
		}, nil
	}

	if err := validatePackageName(pkgName); err != nil {
		return nil, err
	}

	// rawProviders is echoed back verbatim (not back-compat-expanded) so a
	// resource authored with `providers:` sees no drift; authoredProviders
	// (which DOES apply the package_manager back-compat expansion) is what
	// actually drives manager selection.
	rawProviders := append([]string(nil), m.resolvedProviders...)

	mgr, providerName, err := m.selectOrCachedManager(ctx, m.authoredProviders(), pkgName)
	if err != nil {
		return nil, err
	}

	version, err := mgr.GetInstalledVersion(ctx, pkgName)
	if err != nil {
		if errors.Is(err, ErrPackageNotFound) {
			return &Config{Name: pkgName, State: "absent", Providers: rawProviders}, nil
		}
		return nil, fmt.Errorf("failed to get package version: %w", err)
	}

	return &Config{
		Name:           pkgName,
		State:          "present",
		Version:        version,
		PackageManager: providerName,
		Providers:      rawProviders,
	}, nil
}

// Set updates the state of a package.
//
// The reserved resource name "@defaults" is handled specially: instead of
// installing/removing a package, it configures the module's host-wide
// default provider allowlist (m.defaultProviders), used by resolveProviders
// for any resource that doesn't declare its own providers/package_manager.
// No package operation is attempted and it always reports compliant.
func (m *PackageModule) Set(ctx context.Context, name string, config modules.ConfigState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if name == metaDefaultsName {
		if config == nil {
			return ErrInvalidConfig
		}
		m.defaultProviders = extractProviders(config.AsMap())
		return nil
	}

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
	cfg.Providers = extractProviders(configMap)

	// When config.Name is unset, fall back to resourceID so validate() can proceed.
	if cfg.Name == "" {
		cfg.Name = name
	}

	// Validate the configuration
	if err := cfg.validate(); err != nil {
		return err
	}

	// Legacy path only: when a manager was directly injected (NewPackageModule),
	// validate the requested package_manager against it. Registry-based
	// selection (New()) rejects unknown providers in selectManager below.
	if m.packageManager != nil && cfg.PackageManager != "" {
		if !m.packageManager.IsValidManager(cfg.PackageManager) {
			return ErrInvalidPackageManager
		}
	}

	// pkgName is the distribution package name (config.Name), which may differ
	// from the resource identifier (name/resourceID) on apt systems.
	pkgName := cfg.Name

	mgr, _, err := m.selectOrCachedManager(ctx, cfg.effectiveProviders(), pkgName)
	if err != nil {
		return err
	}

	if cfg.State == "absent" {
		return mgr.Remove(ctx, pkgName)
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
		err := mgr.Install(ctx, dep, "latest")
		if err != nil {
			return fmt.Errorf("failed to install dependency %s: %w", dep, err)
		}
	}

	return mgr.Install(ctx, pkgName, cfg.Version)
}
