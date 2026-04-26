// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package modules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/steward/discovery"
)

// ModuleLoader defines the interface for loading modules
type ModuleLoader interface {
	LoadModule(moduleName string) (Module, error)
	UnloadModule(moduleName string)
	UnloadAllModules()
	ValidateModuleInterface(module interface{}) error
	GetModuleInfo(moduleName string) (discovery.ModuleInfo, bool)
}

// LifecycleAwareModuleFactory extends module loading with lifecycle management capabilities
// It integrates with the ModuleLifecycleManager to provide coordinated module lifecycle operations
type LifecycleAwareModuleFactory struct {
	// loader is the underlying module loader for loading modules
	loader ModuleLoader

	// lifecycleManager manages module lifecycles
	lifecycleManager *ModuleLifecycleManager

	// registry provides module registry capabilities
	registry *ModuleRegistry

	// discoveryRegistry provides module discovery capabilities
	discoveryRegistry discovery.ModuleRegistry

	// config contains lifecycle configuration defaults
	config ModuleConfig

	// mu protects concurrent access
	mu sync.RWMutex
}

// NewLifecycleAwareModuleFactory creates a new lifecycle-aware module factory
func NewLifecycleAwareModuleFactory(
	discoveryRegistry discovery.ModuleRegistry,
	moduleRegistry *ModuleRegistry,
	loader ModuleLoader,
) *LifecycleAwareModuleFactory {

	// Create lifecycle manager
	lifecycleManager := NewModuleLifecycleManager(moduleRegistry)

	return &LifecycleAwareModuleFactory{
		loader:            loader,
		lifecycleManager:  lifecycleManager,
		registry:          moduleRegistry,
		discoveryRegistry: discoveryRegistry,
		config:            DefaultModuleConfig(),
	}
}

// Start starts the lifecycle-aware factory and begins lifecycle management
func (laf *LifecycleAwareModuleFactory) Start() error {
	laf.mu.Lock()
	defer laf.mu.Unlock()

	return laf.lifecycleManager.Start()
}

// Stop stops the lifecycle-aware factory and shuts down all modules
func (laf *LifecycleAwareModuleFactory) Stop() error {
	laf.mu.Lock()
	defer laf.mu.Unlock()

	// Stop all modules first
	if err := laf.lifecycleManager.StopAllModules(); err != nil {
		return fmt.Errorf("failed to stop modules: %v", err)
	}

	// Stop the lifecycle manager
	return laf.lifecycleManager.Stop()
}

// LoadModule loads a module and registers it with the lifecycle manager
func (laf *LifecycleAwareModuleFactory) LoadModule(moduleName string) (Module, error) {
	laf.mu.Lock()
	defer laf.mu.Unlock()

	// Check if module is already managed by lifecycle manager
	if instance, err := laf.lifecycleManager.GetModuleInstance(moduleName); err == nil {
		return instance.Module, nil
	}

	// Load module using loader
	module, err := laf.loader.LoadModule(moduleName)
	if err != nil {
		return nil, fmt.Errorf("failed to load module '%s': %v", moduleName, err)
	}

	// Get module metadata from registry
	metadata, err := laf.registry.GetModuleMetadata(moduleName)
	if err != nil {
		// If no metadata in registry, create minimal metadata
		metadata = &ModuleMetadata{
			Name:    moduleName,
			Version: "1.0.0", // Default version
		}
	}

	// Register with lifecycle manager
	instance, err := laf.lifecycleManager.RegisterModule(metadata, module, laf.config)
	if err != nil {
		return nil, fmt.Errorf("failed to register module '%s' with lifecycle manager: %v", moduleName, err)
	}

	// Load the module (initialize it)
	if err := laf.lifecycleManager.LoadModule(moduleName); err != nil {
		// Unregister on failure
		if unregErr := laf.lifecycleManager.UnregisterModule(moduleName); unregErr != nil {
			// Log the unregister error but don't change the return error
			fmt.Printf("Warning: failed to unregister module '%s' after load failure: %v\n", moduleName, unregErr)
		}
		return nil, fmt.Errorf("failed to initialize module '%s': %v", moduleName, err)
	}

	return instance.Module, nil
}

// LoadModuleWithConfig loads a module with custom lifecycle configuration
func (laf *LifecycleAwareModuleFactory) LoadModuleWithConfig(moduleName string, config ModuleConfig) (Module, error) {
	laf.mu.Lock()
	defer laf.mu.Unlock()

	// Check if module is already managed
	if instance, err := laf.lifecycleManager.GetModuleInstance(moduleName); err == nil {
		return instance.Module, nil
	}

	// Load module using loader
	module, err := laf.loader.LoadModule(moduleName)
	if err != nil {
		return nil, fmt.Errorf("failed to load module '%s': %v", moduleName, err)
	}

	// Get module metadata from registry
	metadata, err := laf.registry.GetModuleMetadata(moduleName)
	if err != nil {
		// If no metadata in registry, create minimal metadata
		metadata = &ModuleMetadata{
			Name:    moduleName,
			Version: "1.0.0", // Default version
		}
	}

	// Register with lifecycle manager using custom config
	instance, err := laf.lifecycleManager.RegisterModule(metadata, module, config)
	if err != nil {
		return nil, fmt.Errorf("failed to register module '%s' with lifecycle manager: %v", moduleName, err)
	}

	// Load the module (initialize it)
	if err := laf.lifecycleManager.LoadModule(moduleName); err != nil {
		// Unregister on failure
		if unregErr := laf.lifecycleManager.UnregisterModule(moduleName); unregErr != nil {
			// Log the unregister error but don't change the return error
			fmt.Printf("Warning: failed to unregister module '%s' after load failure: %v\n", moduleName, unregErr)
		}
		return nil, fmt.Errorf("failed to initialize module '%s': %v", moduleName, err)
	}

	return instance.Module, nil
}

// StartModule starts a specific module
func (laf *LifecycleAwareModuleFactory) StartModule(moduleName string) error {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	return laf.lifecycleManager.StartModule(moduleName)
}

// StopModule stops a specific module
func (laf *LifecycleAwareModuleFactory) StopModule(moduleName string) error {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	return laf.lifecycleManager.StopModule(moduleName)
}

// StartAllModules starts all registered modules in dependency order
func (laf *LifecycleAwareModuleFactory) StartAllModules() error {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	return laf.lifecycleManager.StartAllModules()
}

// GetModule returns a module instance, loading it if necessary
func (laf *LifecycleAwareModuleFactory) GetModule(moduleName string) (Module, error) {
	// Check if module is already loaded
	if instance, err := laf.lifecycleManager.GetModuleInstance(moduleName); err == nil {
		return instance.Module, nil
	}

	// Load the module
	return laf.LoadModule(moduleName)
}

// GetModuleInstance returns the full module instance with lifecycle information
func (laf *LifecycleAwareModuleFactory) GetModuleInstance(moduleName string) (*ModuleInstance, error) {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	return laf.lifecycleManager.GetModuleInstance(moduleName)
}

// ListModules returns a list of all registered modules
func (laf *LifecycleAwareModuleFactory) ListModules() []string {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	instances := laf.lifecycleManager.ListModuleInstances()
	modules := make([]string, 0, len(instances))
	for name := range instances {
		modules = append(modules, name)
	}
	return modules
}

// GetModuleState returns the lifecycle state of a module
func (laf *LifecycleAwareModuleFactory) GetModuleState(moduleName string) (ModuleState, error) {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	instance, err := laf.lifecycleManager.GetModuleInstance(moduleName)
	if err != nil {
		return ModuleStateUnknown, err
	}

	return instance.GetState(), nil
}

// GetModuleHealth returns the health status of a module
func (laf *LifecycleAwareModuleFactory) GetModuleHealth(moduleName string) (HealthStatus, error) {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	return laf.lifecycleManager.GetModuleHealth(moduleName)
}

// GetSystemHealth returns the overall system health status
func (laf *LifecycleAwareModuleFactory) GetSystemHealth() SystemHealthStatus {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	return laf.lifecycleManager.GetSystemHealth()
}

// AddEventListener adds a lifecycle event listener
func (laf *LifecycleAwareModuleFactory) AddEventListener(listener LifecycleEventListener) {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	laf.lifecycleManager.AddEventListener(listener)
}

// RemoveEventListener removes a lifecycle event listener
func (laf *LifecycleAwareModuleFactory) RemoveEventListener(listener LifecycleEventListener) {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	laf.lifecycleManager.RemoveEventListener(listener)
}

// SetHealthCheckInterval sets the health check interval
func (laf *LifecycleAwareModuleFactory) SetHealthCheckInterval(interval time.Duration) {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	laf.lifecycleManager.SetHealthCheckInterval(interval)
}

// SetDefaultConfig sets the default lifecycle configuration for new modules
func (laf *LifecycleAwareModuleFactory) SetDefaultConfig(config ModuleConfig) {
	laf.mu.Lock()
	defer laf.mu.Unlock()

	laf.config = config
}

// GetDefaultConfig returns the default lifecycle configuration
func (laf *LifecycleAwareModuleFactory) GetDefaultConfig() ModuleConfig {
	laf.mu.RLock()
	defer laf.mu.RUnlock()

	return laf.config
}

// UnloadModule removes a module from both the factory and lifecycle manager
func (laf *LifecycleAwareModuleFactory) UnloadModule(moduleName string) error {
	laf.mu.Lock()
	defer laf.mu.Unlock()

	// Unregister from lifecycle manager
	if err := laf.lifecycleManager.UnregisterModule(moduleName); err != nil {
		return fmt.Errorf("failed to unregister module '%s' from lifecycle manager: %v", moduleName, err)
	}

	// Unload from loader
	laf.loader.UnloadModule(moduleName)

	return nil
}

// ValidateModuleInterface validates that a module implements the required interface
func (laf *LifecycleAwareModuleFactory) ValidateModuleInterface(module interface{}) error {
	return laf.loader.ValidateModuleInterface(module)
}

// Shutdown performs a complete shutdown of the factory and all modules
func (laf *LifecycleAwareModuleFactory) Shutdown(ctx context.Context) error {
	laf.mu.Lock()
	defer laf.mu.Unlock()

	// Stop all modules gracefully
	if err := laf.lifecycleManager.StopAllModules(); err != nil {
		return fmt.Errorf("failed to stop modules during shutdown: %v", err)
	}

	// Stop the lifecycle manager
	if err := laf.lifecycleManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop lifecycle manager: %v", err)
	}

	// Unload all modules from loader
	laf.loader.UnloadAllModules()

	return nil
}
