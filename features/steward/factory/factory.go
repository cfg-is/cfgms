// SPDX-License-Identifier: Apache-2.0
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
	"reflect"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/directory"
	"github.com/cfgis/cfgms/features/modules/file"
	"github.com/cfgis/cfgms/features/modules/firewall"
	package_module "github.com/cfgis/cfgms/features/modules/package"
	"github.com/cfgis/cfgms/features/modules/patch"
	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// ModuleFactory manages module instantiation and lifecycle for the steward.
//
// The factory provides on-demand loading of modules from the discovery registry,
// caches loaded instances for reuse, handles errors according to the configured
// error handling policy, and implements centralized logging injection.
type ModuleFactory struct {
	// registry contains information about discovered modules
	registry discovery.ModuleRegistry

	// instances caches loaded module instances for reuse
	instances map[string]modules.Module

	// config defines error handling behavior
	config config.ErrorHandlingConfig

	// stewardID identifies the steward this factory belongs to
	stewardID string

	// loggerProvider creates loggers for module injection
	loggerProvider modules.LoggerProvider

	// secretStore is injected into modules that implement SecretStoreInjectable
	secretStore secretsif.SecretStore

	// injectionStatus tracks logger injection status for each module
	injectionStatus map[string]modules.LoggerInjectionStatus
}

// New creates a new ModuleFactory instance with the provided registry and error configuration.
//
// The factory will use the registry to locate modules when loading and apply
// the error configuration to determine how to handle loading failures.
func New(registry discovery.ModuleRegistry, errorConfig config.ErrorHandlingConfig) *ModuleFactory {
	return &ModuleFactory{
		registry:        registry,
		instances:       make(map[string]modules.Module),
		config:          errorConfig,
		stewardID:       "unknown", // Will be set by steward during initialization
		injectionStatus: make(map[string]modules.LoggerInjectionStatus),
	}
}

// NewWithStewardID creates a new ModuleFactory with a specific steward ID and logging capability.
//
// This constructor enables centralized logging from the moment of factory creation.
func NewWithStewardID(registry discovery.ModuleRegistry, errorConfig config.ErrorHandlingConfig, stewardID string) *ModuleFactory {
	factory := &ModuleFactory{
		registry:        registry,
		instances:       make(map[string]modules.Module),
		config:          errorConfig,
		stewardID:       stewardID,
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
func (f *ModuleFactory) LoadModule(moduleName string) (modules.Module, error) {
	// Check if module is already loaded
	if instance, exists := f.instances[moduleName]; exists {
		return instance, nil
	}

	var instance modules.Module
	var err error

	// Try to load from registry first (discovered modules take priority)
	if moduleInfo, exists := f.registry[moduleName]; exists {
		instance, err = f.loadModuleFromPath(moduleName, moduleInfo.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to load module %s from path: %w", moduleName, err)
		}
	} else {
		// Fall back to built-in modules when not in registry
		instance, err = f.loadBuiltinModule(moduleName)
		if err != nil {
			return nil, fmt.Errorf("module %s not found in registry and not a built-in module", moduleName)
		}
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

// loadModuleFromPath loads a Go module from the specified path
func (f *ModuleFactory) loadModuleFromPath(moduleName, modulePath string) (modules.Module, error) {
	// For Go modules, we need to use reflection or plugin system
	// This is a simplified implementation - in a real system you might use:
	// 1. Go plugins (.so files) - requires CGO
	// 2. Built-in module registry with reflection
	// 3. External process communication

	// For now, we'll implement a built-in module registry approach
	return f.loadBuiltinModule(moduleName)
}

// loadBuiltinModule loads modules that are built into the binary
func (f *ModuleFactory) loadBuiltinModule(moduleName string) (modules.Module, error) {
	// This would be expanded to include all built-in modules
	// For now, we'll use a simple registry pattern

	switch moduleName {
	case "directory":
		return directory.New(), nil
	case "file":
		return file.New(), nil
	case "firewall":
		return firewall.New(), nil
	case "package":
		return package_module.New(), nil
	case "patch":
		return patch.New(), nil
	case "script":
		return script.New(), nil
	default:
		return nil, fmt.Errorf("unknown built-in module: %s", moduleName)
	}
}

// loadPluginModule loads a module using Go's plugin system (requires CGO)

// ValidateModuleInterface ensures the module implements the required interface
func (f *ModuleFactory) ValidateModuleInterface(module interface{}) error {
	// Check if it implements the Module interface
	if _, ok := module.(modules.Module); !ok {
		return fmt.Errorf("module does not implement Module interface")
	}

	// Use reflection to verify the interface methods exist with correct signatures
	moduleType := reflect.TypeOf(module)

	// Check Get method
	getMethod, exists := moduleType.MethodByName("Get")
	if !exists {
		return fmt.Errorf("module missing Get method")
	}

	// Validate Get method signature: Get(ctx context.Context, resourceID string) (ConfigState, error)
	if getMethod.Type.NumIn() != 3 { // receiver + 2 parameters
		return fmt.Errorf("Get method has incorrect number of parameters")
	}
	if getMethod.Type.NumOut() != 2 { // ConfigState + error
		return fmt.Errorf("Get method has incorrect number of return values")
	}

	// Check Set method
	setMethod, exists := moduleType.MethodByName("Set")
	if !exists {
		return fmt.Errorf("module missing Set method")
	}

	// Validate Set method signature: Set(ctx context.Context, resourceID string, config ConfigState) error
	if setMethod.Type.NumIn() != 4 { // receiver + 3 parameters
		return fmt.Errorf("Set method has incorrect number of parameters")
	}
	if setMethod.Type.NumOut() != 1 { // error
		return fmt.Errorf("Set method has incorrect number of return values")
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
	modules := make([]string, 0, len(f.instances))
	for name := range f.instances {
		modules = append(modules, name)
	}
	return modules
}

// UnloadModule removes a module instance from the cache
func (f *ModuleFactory) UnloadModule(moduleName string) {
	delete(f.instances, moduleName)
}

// UnloadAllModules removes all module instances from the cache
func (f *ModuleFactory) UnloadAllModules() {
	f.instances = make(map[string]modules.Module)
}

// GetModuleInfo returns information about a module from the registry
func (f *ModuleFactory) GetModuleInfo(moduleName string) (discovery.ModuleInfo, bool) {
	info, exists := f.registry[moduleName]
	return info, exists
}

// SetStewardID updates the steward ID for this factory and reinitializes the logger provider
func (f *ModuleFactory) SetStewardID(stewardID string) {
	f.stewardID = stewardID
	f.loggerProvider = &StewardLoggerProvider{
		stewardID: stewardID,
	}
}

// SetSecretStore sets the secret store for module injection.
func (f *ModuleFactory) SetSecretStore(store secretsif.SecretStore) {
	f.secretStore = store
}

// attemptSecretStoreInjection tries to inject a secret store into a module if it supports injection.
func (f *ModuleFactory) attemptSecretStoreInjection(instance modules.Module, moduleName string) {
	injectable, ok := instance.(modules.SecretStoreInjectable)
	if !ok || f.secretStore == nil {
		return
	}

	if err := injectable.SetSecretStore(f.secretStore); err != nil {
		// Log but don't fail - module can operate without secrets
		fmt.Printf("Warning: Failed to inject secret store into module %s: %v\n", moduleName, err)
	}
}

// attemptLoggerInjection tries to inject a logger into a module if it supports injection
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
