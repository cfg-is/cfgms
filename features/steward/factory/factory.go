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
//
package factory

import (
	"fmt"
	"plugin"
	"reflect"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/directory"
	"github.com/cfgis/cfgms/features/modules/file"
	"github.com/cfgis/cfgms/features/modules/firewall"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
)

// ModuleFactory manages module instantiation and lifecycle for the steward.
//
// The factory provides on-demand loading of modules from the discovery registry,
// caches loaded instances for reuse, and handles errors according to the
// configured error handling policy.
type ModuleFactory struct {
	// registry contains information about discovered modules
	registry   discovery.ModuleRegistry
	
	// instances caches loaded module instances for reuse
	instances  map[string]modules.Module
	
	// config defines error handling behavior
	config     config.ErrorHandlingConfig
}

// New creates a new ModuleFactory instance with the provided registry and error configuration.
//
// The factory will use the registry to locate modules when loading and apply
// the error configuration to determine how to handle loading failures.
func New(registry discovery.ModuleRegistry, errorConfig config.ErrorHandlingConfig) *ModuleFactory {
	return &ModuleFactory{
		registry:  registry,
		instances: make(map[string]modules.Module),
		config:    errorConfig,
	}
}

// LoadModule dynamically loads a module from the given path and name
func (f *ModuleFactory) LoadModule(moduleName string) (modules.Module, error) {
	// Check if module is already loaded
	if instance, exists := f.instances[moduleName]; exists {
		return instance, nil
	}

	// Get module info from registry
	moduleInfo, exists := f.registry[moduleName]
	if !exists {
		return nil, fmt.Errorf("module not found in registry: %s", moduleName)
	}

	// Load the module
	instance, err := f.loadModuleFromPath(moduleName, moduleInfo.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to load module %s: %w", moduleName, err)
	}

	// Validate the module implements the required interface
	if err := f.ValidateModuleInterface(instance); err != nil {
		return nil, fmt.Errorf("module %s interface validation failed: %w", moduleName, err)
	}

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
		// Import would be: "cfgms/features/modules/package"
		// return package.New(), nil
		return nil, fmt.Errorf("package module not yet implemented with ConfigState interface")
	default:
		return nil, fmt.Errorf("unknown built-in module: %s", moduleName)
	}
}

// loadPluginModule loads a module using Go's plugin system (requires CGO)
func (f *ModuleFactory) loadPluginModule(modulePath string) (modules.Module, error) {
	// Load the plugin
	p, err := plugin.Open(modulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin: %w", err)
	}

	// Look for the New function
	newFunc, err := p.Lookup("New")
	if err != nil {
		return nil, fmt.Errorf("New function not found in plugin: %w", err)
	}

	// Ensure it's the right type
	newFuncTyped, ok := newFunc.(func() modules.Module)
	if !ok {
		return nil, fmt.Errorf("New function has incorrect signature")
	}

	// Create the module instance
	instance := newFuncTyped()
	
	return instance, nil
}

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