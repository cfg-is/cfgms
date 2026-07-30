// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package factory provides module instantiation and lifecycle management for steward.
//
// This package handles dynamic loading of CFGMS modules and manages their lifecycle
// within the steward. It supports built-in modules, plugin-based modules, and
// validates that all modules implement the required ConfigState interface.
//
// The factory uses a registry-based approach where modules are discovered first,
// then loaded on-demand when needed for resource execution. This provides
// efficient memory usage and allows for graceful error handling per configuration.
//
// Basic usage:
//
//	// Create factory with discovered modules
//	registry := discovery.ModuleRegistry{...}
//	errorConfig := config.ErrorHandlingConfig{...}
//	factory := factory.New(registry, errorConfig)
//
//	// Load a module on-demand
//	module, err := factory.LoadModule("directory")
//	if err != nil {
//		log.Printf("Failed to load module: %v", err)
//	}
//
//	// Check loaded modules
//	loadedNames := factory.GetLoadedModules()
//
// Error handling follows the steward's error handling configuration:
//   - continue: Log error and return nil (caller should handle gracefully)
//   - warn: Log warning and return nil
//   - fail: Log error and return error
package factory

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	acme_module "github.com/cfgis/cfgms/features/modules/extended/acme"
	github_runner_module "github.com/cfgis/cfgms/features/modules/extended/github_runner"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	cert_trust_module "github.com/cfgis/cfgms/features/modules/stdlib/cert_trust"
	"github.com/cfgis/cfgms/features/modules/stdlib/file"
	"github.com/cfgis/cfgms/features/modules/stdlib/firewall"
	hostname_module "github.com/cfgis/cfgms/features/modules/stdlib/hostname"
	package_module "github.com/cfgis/cfgms/features/modules/stdlib/package"
	"github.com/cfgis/cfgms/features/modules/stdlib/patch"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	time_module "github.com/cfgis/cfgms/features/modules/stdlib/time"
	user_module "github.com/cfgis/cfgms/features/modules/stdlib/user"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/pkg/logging"
	maintinterfaces "github.com/cfgis/cfgms/pkg/maintenance/interfaces"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// ModuleFactory manages module instantiation and lifecycle for the steward.
//
// The factory provides on-demand loading of modules from the discovery registry,
// caches loaded instances for reuse, handles errors according to the configured
// error handling policy, and implements centralized logging injection.
//
// A ModuleFactory is safe for concurrent use. A single factory is shared by all
// steward call paths (convergence, command handlers, the Tier-2 observe sweep),
// and command handlers run one goroutine per command, so every access to the
// mutable fields below must hold mu. Unsynchronized map access here would be a
// concurrent map read/write — a fatal, unrecoverable process abort.
type ModuleFactory struct {
	// mu guards all mutable factory state: instances, injectionStatus,
	// stewardID, loggerProvider, secretStore and gate. registry and config are
	// immutable after construction and may be read without holding mu.
	mu sync.RWMutex

	// registry contains information about discovered modules
	registry discovery.ModuleRegistry

	// instances caches loaded module instances for reuse. Guarded by mu.
	instances map[string]modules.Module

	// config defines error handling behavior
	config config.ErrorHandlingConfig

	// stewardID identifies the steward this factory belongs to. Guarded by mu.
	stewardID string

	// logger is the factory's own operational logger. Set at construction and
	// never reassigned; logging.Logger implementations are safe for concurrent use.
	logger logging.Logger

	// loggerProvider creates loggers for module injection. Guarded by mu.
	loggerProvider modules.LoggerProvider

	// secretStore is injected into modules that implement SecretStoreInjectable.
	// Guarded by mu.
	secretStore secretsif.SecretStore

	// gate is the maintenance gate injected into the patch module for reboot-window
	// enforcement. When nil, the patch module uses the fail-closed default (nil manager → deny).
	// Guarded by mu.
	gate maintinterfaces.Gate

	// injectionStatus tracks logger injection status for each module. Guarded by mu.
	injectionStatus map[string]modules.LoggerInjectionStatus
}

// New creates a new ModuleFactory instance with the provided registry and error configuration.
//
// The factory will use the registry to locate modules when loading and apply
// the error configuration to determine how to handle loading failures.
func New(registry discovery.ModuleRegistry, errorConfig config.ErrorHandlingConfig, logger logging.Logger) *ModuleFactory {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &ModuleFactory{
		registry:        registry,
		instances:       make(map[string]modules.Module),
		config:          errorConfig,
		stewardID:       "unknown", // Will be set by steward during initialization
		logger:          logger,
		injectionStatus: make(map[string]modules.LoggerInjectionStatus),
	}
}

// NewWithStewardID creates a new ModuleFactory with a specific steward ID and logging capability.
//
// This constructor enables centralized logging from the moment of factory creation.
func NewWithStewardID(registry discovery.ModuleRegistry, errorConfig config.ErrorHandlingConfig, stewardID string, logger logging.Logger) *ModuleFactory {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	factory := &ModuleFactory{
		registry:        registry,
		instances:       make(map[string]modules.Module),
		config:          errorConfig,
		stewardID:       stewardID,
		logger:          logger,
		injectionStatus: make(map[string]modules.LoggerInjectionStatus),
	}

	// Create a logger provider for this steward
	factory.loggerProvider = &StewardLoggerProvider{
		stewardID: stewardID,
	}

	return factory
}

// LoadModule dynamically loads a module from the given path and name.
//
// Module loading follows this priority:
//  1. Return cached instance if already loaded
//  2. Load from registry path if module is discovered
//  3. Fall back to built-in modules if not in registry
//
// This allows built-in modules (file, directory, firewall, etc.) to work
// even when no external modules are discovered on the filesystem.
//
// LoadModule is safe for concurrent use: the whole load is serialized under mu
// so that a cache hit, module construction, dependency injection and the cache
// write are atomic with respect to other callers. Serializing construction also
// guarantees every caller receives the same cached instance for a given name.
func (f *ModuleFactory) LoadModule(moduleName string) (modules.Module, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check if module is already loaded
	if instance, exists := f.instances[moduleName]; exists {
		return instance, nil
	}

	var instance modules.Module
	var err error

	// Design decision: plugin loading (external .so modules) is deferred to the Outpost milestone; all current modules are statically linked built-ins. To add a new module type, implement the modules.Module interface and register it in loadBuiltinModule.
	// Built-in modules are always tried; the registry acts as an allow-list when present.
	instance, err = f.loadBuiltinModule(moduleName)
	if err != nil {
		return nil, fmt.Errorf("module %s not found in registry and not a built-in module", moduleName)
	}

	// Validate the module implements the required interface
	if err := f.ValidateModuleInterface(instance); err != nil {
		return nil, fmt.Errorf("module %s interface validation failed: %w", moduleName, err)
	}

	// Attempt logger injection if supported
	f.attemptLoggerInjection(instance, moduleName)

	// Attempt secret store injection if supported
	f.attemptSecretStoreInjection(instance, moduleName)

	// Cache the instance
	f.instances[moduleName] = instance

	return instance, nil
}

// builtinModuleConstructors maps module names to their zero-argument constructors.
// The "directory" name is retained as an alias for the merged file module so that
// existing cfg files using type: directory continue to work without migration.
// Note: "hyperv" and "patch" are intentionally absent — they are handled separately
// by newHypervModule / newPatchModule (which wire the durable provision store /
// maintenance gate) and early-returned in loadBuiltinModule.
var builtinModuleConstructors = map[string]func() modules.Module{
	"acme":          func() modules.Module { return acme_module.New() },
	"cert_trust":    func() modules.Module { return cert_trust_module.New() },
	"directory":     func() modules.Module { return file.New() }, // merged into file module (type: directory)
	"file":          func() modules.Module { return file.New() },
	"firewall":      func() modules.Module { return firewall.New() },
	"github_runner": func() modules.Module { return github_runner_module.New() },
	"hostname":      func() modules.Module { return hostname_module.New() },
	"package":       func() modules.Module { return package_module.New() },
	"script":        func() modules.Module { return script.New() },
	"time":          func() modules.Module { return time_module.New() },
	"user":          func() modules.Module { return user_module.New() },
}

// loadBuiltinModule creates a new instance of a built-in module.
// The hyperv module is handled specially so a durable provision store can be
// wired via the factory logger (required for the fallback warn path).
// The patch module is handled specially so the maintenance gate can be injected.
//
// Callers must hold f.mu (it reads f.gate and f.stewardID via newPatchModule).
func (f *ModuleFactory) loadBuiltinModule(moduleName string) (modules.Module, error) {
	if moduleName == "hyperv" {
		return f.newHypervModule(), nil
	}
	if moduleName == "patch" {
		return f.newPatchModule(), nil
	}
	ctor, ok := builtinModuleConstructors[moduleName]
	if !ok {
		return nil, fmt.Errorf("unknown built-in module: %s", moduleName)
	}
	return ctor(), nil
}

// newPatchModule constructs the patch module and injects the production
// GateWindowAdapter when a maintenance gate is available. When no gate has been
// set (f.gate == nil), the patch module starts without a window manager; any
// patch config that declares a maintenance.window will then be denied fail-closed.
//
// Callers must hold f.mu (it reads f.gate and f.stewardID).
func (f *ModuleFactory) newPatchModule() modules.Module {
	m := patch.New()
	if f.gate == nil {
		return m
	}
	pm, ok := m.(*patch.PatchModule)
	if !ok {
		f.logger.Warn("patch: cannot inject window manager: unexpected module type")
		return m
	}
	pm.SetWindowManager(patch.NewGateWindowAdapter(f.gate, f.stewardID))
	pm.SetDeviceID(f.stewardID)
	return m
}

// SetMaintenanceGate sets the maintenance gate used by the patch module for
// reboot-window enforcement. Must be called before the first LoadModule("patch")
// for the gate to take effect. Parallels SetSecretStore.
func (f *ModuleFactory) SetMaintenanceGate(gate maintinterfaces.Gate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gate = gate
}

// newHypervModule constructs the hyperv module with a durable provision store.
// If the store cannot be created (e.g. the path is not writable on this boot),
// it falls back to the module's built-in in-memory store — steward startup
// never crashes over a non-critical store init failure.
//
// Callers must hold f.mu (invoked from the LoadModule critical section).
func (f *ModuleFactory) newHypervModule() modules.Module {
	store := f.newHypervProvisionStore()
	if store == nil {
		// Fallback: hyperv.New() defaults to an in-memory provision store.
		// Provisioning is non-durable for this boot (the Warn was already
		// emitted by newHypervProvisionStore).
		return hyperv.New(hyperv.NewDefaultDetector())
	}
	return hyperv.New(hyperv.NewDefaultDetector(), hyperv.WithProvisionStore(store))
}

// newHypervProvisionStore attempts to construct the durable, flatfile-backed
// provision store rooted at defaultHypervProvisionStoreDir(). On success it
// returns the durable store. If construction fails (e.g. the path is not
// writable on this boot) it logs a Warn and returns nil, signalling
// newHypervModule to fall back to the module's in-memory store. Returning nil
// (rather than crashing) keeps steward startup resilient to a non-critical
// store init failure; the tradeoff is that provision records are not durable
// for that boot.
func (f *ModuleFactory) newHypervProvisionStore() hyperv.ProvisionStore {
	root := defaultHypervProvisionStoreDir()
	store, err := hyperv.NewFlatFileProvisionStore(root)
	if err != nil {
		f.logger.Warn("hyperv: durable provision store unavailable; using in-memory fallback for this boot",
			"root", root, "error", err)
		return nil
	}
	return store
}

// defaultHypervProvisionStoreDir returns the platform-specific directory for
// the hyperv module's durable provision store. Mirrors defaultCertStoreDir in
// cmd/steward/main.go (same switch shape, same ProgramData/Library fallbacks).
// CFGMS_HYPERV_PROVISION_STORE_DIR overrides the default for test isolation.
func defaultHypervProvisionStoreDir() string {
	if override := os.Getenv("CFGMS_HYPERV_PROVISION_STORE_DIR"); override != "" {
		return override
	}
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "cfgms", "steward", "hyperv", "provisions")
	case "darwin":
		home, _ := os.UserHomeDir()
		if home == "" {
			home = "/tmp"
		}
		return filepath.Join(home, "Library", "Application Support", "cfgms", "steward", "hyperv", "provisions")
	default:
		return "/var/lib/cfgms/steward/hyperv/provisions"
	}
}

// ValidateModuleInterface ensures the module implements the required Module interface.
func (f *ModuleFactory) ValidateModuleInterface(module interface{}) error {
	if _, ok := module.(modules.Module); !ok {
		return fmt.Errorf("module does not implement Module interface")
	}
	return nil
}

// CreateModuleInstance creates a new instance of the specified module
func (f *ModuleFactory) CreateModuleInstance(moduleName string) (modules.Module, error) {
	// Attempt to load the module
	instance, err := f.LoadModule(moduleName)
	if err != nil {
		// Handle error according to configuration
		switch f.config.ModuleLoadFailure {
		case config.ActionContinue:
			// Log the error but return nil (caller should handle gracefully)
			return nil, nil
		case config.ActionFail:
			return nil, err
		case config.ActionWarn:
			// Log warning and return nil
			return nil, nil
		default:
			return nil, err
		}
	}

	return instance, nil
}

// GetLoadedModules returns a list of currently loaded module names
func (f *ModuleFactory) GetLoadedModules() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	modules := make([]string, 0, len(f.instances))
	for name := range f.instances {
		modules = append(modules, name)
	}
	return modules
}

// RegisterModule adds or replaces a module instance in the cache.
// Subsequent calls to LoadModule or CreateModuleInstance for name will return mod.
// Used in tests to inject real test implementations and in production to pre-wire
// modules that need special construction (e.g. modules with injected dependencies).
func (f *ModuleFactory) RegisterModule(name string, mod modules.Module) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.instances[name] = mod
}

// UnloadModule removes a module instance from the cache
func (f *ModuleFactory) UnloadModule(moduleName string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.instances, moduleName)
}

// UnloadAllModules removes all module instances from the cache
func (f *ModuleFactory) UnloadAllModules() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.instances = make(map[string]modules.Module)
}

// GetModuleInfo returns information about a module from the registry
func (f *ModuleFactory) GetModuleInfo(moduleName string) (discovery.ModuleInfo, bool) {
	info, exists := f.registry[moduleName]
	return info, exists
}

// SetStewardID updates the steward ID for this factory and reinitializes the logger provider
func (f *ModuleFactory) SetStewardID(stewardID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stewardID = stewardID
	f.loggerProvider = &StewardLoggerProvider{
		stewardID: stewardID,
	}
}

// SetSecretStore sets the secret store for module injection.
func (f *ModuleFactory) SetSecretStore(store secretsif.SecretStore) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secretStore = store
}

// attemptSecretStoreInjection tries to inject a secret store into a module if it supports injection.
//
// Callers must hold f.mu (it reads f.secretStore).
func (f *ModuleFactory) attemptSecretStoreInjection(instance modules.Module, moduleName string) {
	injectable, ok := instance.(modules.SecretStoreInjectable)
	if !ok || f.secretStore == nil {
		return
	}

	if err := injectable.SetSecretStore(f.secretStore); err != nil {
		// Log but don't fail - module can operate without secrets
		f.logger.Warn("failed to inject secret store into module", "module", moduleName, "error", err)
	}
}

// attemptLoggerInjection tries to inject a logger into a module if it supports injection.
//
// Callers must hold f.mu (it reads f.stewardID / f.loggerProvider and writes f.injectionStatus).
func (f *ModuleFactory) attemptLoggerInjection(instance modules.Module, moduleName string) {
	// Initialize injection status
	status := modules.LoggerInjectionStatus{
		ModuleName:     moduleName,
		StewardID:      f.stewardID,
		Injected:       false,
		SupportsInject: false,
		LoggerType:     "",
		LastInjected:   0,
		ErrorMessage:   "",
	}

	// Check if module supports logger injection
	injectable, supportsInjection := instance.(modules.LoggingInjectable)
	status.SupportsInject = supportsInjection

	if !supportsInjection {
		// Module doesn't support injection - this is fine, use default behavior
		f.injectionStatus[moduleName] = status
		return
	}

	// Module supports injection, attempt to inject logger
	if f.loggerProvider == nil {
		status.ErrorMessage = "no logger provider available"
		f.injectionStatus[moduleName] = status
		return
	}

	// Create logger for the module
	logger, err := f.loggerProvider.ForModule(moduleName, f.stewardID)
	if err != nil {
		status.ErrorMessage = fmt.Sprintf("failed to create logger: %v", err)
		f.injectionStatus[moduleName] = status
		return
	}

	// Inject the logger
	if err := injectable.SetLogger(logger); err != nil {
		status.ErrorMessage = fmt.Sprintf("failed to inject logger: %v", err)
		f.injectionStatus[moduleName] = status
		return
	}

	// Success!
	status.Injected = true
	status.LoggerType = fmt.Sprintf("%T", logger)
	status.LastInjected = time.Now().Unix()
	f.injectionStatus[moduleName] = status
}

// InjectLogger implements modules.CentralLoggingManager.InjectLogger
func (f *ModuleFactory) InjectLogger(module modules.Module, moduleName string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	injectable, supportsInjection := module.(modules.LoggingInjectable)
	if !supportsInjection {
		return false, nil // Not an error, just doesn't support injection
	}

	if f.loggerProvider == nil {
		return false, fmt.Errorf("no logger provider available")
	}

	logger, err := f.loggerProvider.ForModule(moduleName, f.stewardID)
	if err != nil {
		return false, fmt.Errorf("failed to create logger: %w", err)
	}

	if err := injectable.SetLogger(logger); err != nil {
		return false, fmt.Errorf("failed to inject logger: %w", err)
	}

	// Update injection status
	status := modules.LoggerInjectionStatus{
		ModuleName:     moduleName,
		StewardID:      f.stewardID,
		Injected:       true,
		SupportsInject: true,
		LoggerType:     fmt.Sprintf("%T", logger),
		LastInjected:   time.Now().Unix(),
		ErrorMessage:   "",
	}
	f.injectionStatus[moduleName] = status

	return true, nil
}

// GetModuleLogger implements modules.CentralLoggingManager.GetModuleLogger
func (f *ModuleFactory) GetModuleLogger(module modules.Module) (logging.Logger, bool) {
	injectable, supportsInjection := module.(modules.LoggingInjectable)
	if !supportsInjection {
		return nil, false
	}

	return injectable.GetLogger()
}

// ListModulesWithLoggers implements modules.CentralLoggingManager.ListModulesWithLoggers
func (f *ModuleFactory) ListModulesWithLoggers() map[string]modules.LoggerInjectionStatus {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]modules.LoggerInjectionStatus)
	for name, status := range f.injectionStatus {
		result[name] = status
	}
	return result
}

// StewardLoggerProvider implements modules.LoggerProvider for steward-based logger creation
type StewardLoggerProvider struct {
	stewardID string
}

// ForModule creates a logger for a specific module
func (p *StewardLoggerProvider) ForModule(moduleName, stewardID string) (logging.Logger, error) {
	// Use the global logging provider to create module-specific loggers
	logger := logging.ForModule(moduleName)
	if logger == nil {
		return nil, fmt.Errorf("failed to create logger for module %s", moduleName)
	}

	// Add steward-specific context
	contextLogger := logger.WithField("steward_id", stewardID)
	contextLogger = contextLogger.WithField("component", moduleName)

	return contextLogger, nil
}

// ForComponent creates a logger for a specific component within a module
func (p *StewardLoggerProvider) ForComponent(moduleName, componentName, stewardID string) (logging.Logger, error) {
	// Use the global logging provider to create component-specific loggers
	logger := logging.ForComponent(fmt.Sprintf("%s.%s", moduleName, componentName))
	if logger == nil {
		return nil, fmt.Errorf("failed to create logger for component %s.%s", moduleName, componentName)
	}

	// Add steward-specific context
	contextLogger := logger.WithField("steward_id", stewardID)
	contextLogger = contextLogger.WithField("component", componentName)
	contextLogger = contextLogger.WithField("module", moduleName)

	return contextLogger, nil
}
