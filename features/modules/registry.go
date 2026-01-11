// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package modules

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// ModuleRegistry manages the collection of available modules and their dependencies
type ModuleRegistry struct {
	// mu protects concurrent access to the registry
	mu sync.RWMutex

	// modules maps module names to their metadata
	modules map[string]*ModuleMetadata

	// instances maps module names to their actual Module implementations
	instances map[string]Module

	// dependencyGraph manages module dependencies
	dependencyGraph *DependencyGraph

	// loadOrder contains the topologically sorted module loading order
	loadOrder []string

	// initialized tracks if the registry has been initialized
	initialized bool
}

// NewModuleRegistry creates a new module registry
func NewModuleRegistry() *ModuleRegistry {
	return &ModuleRegistry{
		modules:         make(map[string]*ModuleMetadata),
		instances:       make(map[string]Module),
		dependencyGraph: NewDependencyGraph(),
		loadOrder:       make([]string, 0),
		initialized:     false,
	}
}

// RegisterModule registers a module with its metadata and implementation
func (r *ModuleRegistry) RegisterModule(metadata *ModuleMetadata, instance Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if metadata == nil {
		return fmt.Errorf("module metadata cannot be nil")
	}

	if instance == nil {
		return fmt.Errorf("module instance cannot be nil")
	}

	// Validate metadata
	if err := metadata.Validate(); err != nil {
		return fmt.Errorf("invalid module metadata for '%s': %v", metadata.Name, err)
	}

	// Check for conflicts
	if existing, exists := r.modules[metadata.Name]; exists {
		if existing.Version != metadata.Version {
			return fmt.Errorf("module version conflict: '%s' already registered with version '%s', cannot register version '%s'",
				metadata.Name, existing.Version, metadata.Version)
		}
		return fmt.Errorf("module '%s' is already registered", metadata.Name)
	}

	// Store module metadata and instance
	r.modules[metadata.Name] = metadata
	r.instances[metadata.Name] = instance

	// Add to dependency graph
	if err := r.dependencyGraph.AddModule(metadata); err != nil {
		// Rollback registration
		delete(r.modules, metadata.Name)
		delete(r.instances, metadata.Name)
		return fmt.Errorf("failed to add module '%s' to dependency graph: %v", metadata.Name, err)
	}

	// Mark as uninitialized since we added a new module
	r.initialized = false

	return nil
}

// UnregisterModule removes a module from the registry
func (r *ModuleRegistry) UnregisterModule(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if module exists
	if _, exists := r.modules[name]; !exists {
		return fmt.Errorf("module '%s' is not registered", name)
	}

	// Rebuild dependency graph to get current state
	tempGraph := NewDependencyGraph()
	for _, metadata := range r.modules {
		if metadata.Name != name { // Skip the module we're about to remove
			if err := tempGraph.AddModule(metadata); err != nil {
				return fmt.Errorf("failed to rebuild dependency graph: %w", err)
			}
		}
	}

	// Check if any other modules depend on this one
	dependents := tempGraph.GetDependents(name)
	if len(dependents) > 0 {
		return fmt.Errorf("cannot unregister module '%s': it is required by %s",
			name, strings.Join(dependents, ", "))
	}

	// Remove from registry
	delete(r.modules, name)
	delete(r.instances, name)

	// Mark as uninitialized since we need to rebuild the dependency graph
	r.initialized = false

	return nil
}

// GetModule returns a module instance by name
func (r *ModuleRegistry) GetModule(name string) (Module, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	instance, exists := r.instances[name]
	if !exists {
		return nil, fmt.Errorf("module '%s' is not registered", name)
	}

	return instance, nil
}

// GetModuleMetadata returns module metadata by name
func (r *ModuleRegistry) GetModuleMetadata(name string) (*ModuleMetadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	metadata, exists := r.modules[name]
	if !exists {
		return nil, fmt.Errorf("module '%s' is not registered", name)
	}

	// Return a clone to prevent external modification
	return metadata.Clone(), nil
}

// ListModules returns a list of all registered module names
func (r *ModuleRegistry) ListModules() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.modules))
	for name := range r.modules {
		names = append(names, name)
	}

	return names
}

// Initialize validates dependencies and calculates the loading order
func (r *ModuleRegistry) Initialize() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.initialized {
		return nil // Already initialized
	}

	// Rebuild dependency graph from scratch
	r.dependencyGraph = NewDependencyGraph()

	// Add all modules to the dependency graph
	for _, metadata := range r.modules {
		if err := r.dependencyGraph.AddModule(metadata); err != nil {
			return fmt.Errorf("failed to build dependency graph: %v", err)
		}
	}

	// Validate all dependencies
	errors := r.dependencyGraph.ValidateAllDependencies()
	if len(errors) > 0 {
		var errorMessages []string
		for _, err := range errors {
			errorMessages = append(errorMessages, err.Error())
		}
		return fmt.Errorf("dependency validation failed:\n%s", strings.Join(errorMessages, "\n"))
	}

	// Calculate topological sort for loading order
	order, err := r.dependencyGraph.TopologicalSort()
	if err != nil {
		return fmt.Errorf("failed to calculate module loading order: %v", err)
	}

	r.loadOrder = order
	r.initialized = true

	return nil
}

// GetLoadingOrder returns the topologically sorted loading order
func (r *ModuleRegistry) GetLoadingOrder() ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.initialized {
		return nil, fmt.Errorf("registry is not initialized - call Initialize() first")
	}

	// Return a copy to prevent external modification
	order := make([]string, len(r.loadOrder))
	copy(order, r.loadOrder)

	return order, nil
}

// GetDependencies returns the direct dependencies of a module
func (r *ModuleRegistry) GetDependencies(moduleName string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, exists := r.modules[moduleName]; !exists {
		return nil, fmt.Errorf("module '%s' is not registered", moduleName)
	}

	return r.dependencyGraph.GetDependencies(moduleName), nil
}

// GetDependents returns the modules that depend on the given module
func (r *ModuleRegistry) GetDependents(moduleName string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, exists := r.modules[moduleName]; !exists {
		return nil, fmt.Errorf("module '%s' is not registered", moduleName)
	}

	return r.dependencyGraph.GetDependents(moduleName), nil
}

// ValidateModuleDependencies validates that all dependencies for a specific module are satisfied
func (r *ModuleRegistry) ValidateModuleDependencies(moduleName string) []DependencyError {
	r.mu.RLock()
	defer r.mu.RUnlock()

	metadata, exists := r.modules[moduleName]
	if !exists {
		return []DependencyError{{
			Type:    DependencyErrorMissing,
			Module:  moduleName,
			Message: fmt.Sprintf("module '%s' is not registered", moduleName),
		}}
	}

	var errors []DependencyError
	for _, dep := range metadata.ModuleDependencies {
		if err := r.dependencyGraph.ValidateDependency(moduleName, dep); err != nil {
			errors = append(errors, *err)
		}
	}

	return errors
}

// DetectConflicts detects version conflicts and circular dependencies
func (r *ModuleRegistry) DetectConflicts() ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var conflicts []string

	// Check for circular dependencies
	if hasCycles, cycle := r.dependencyGraph.HasCycles(); hasCycles {
		conflicts = append(conflicts, fmt.Sprintf("Circular dependency detected: %s", strings.Join(cycle, " -> ")))
	}

	// Check for dependency validation errors
	errors := r.dependencyGraph.ValidateAllDependencies()
	for _, err := range errors {
		conflicts = append(conflicts, err.Error())
	}

	return conflicts, nil
}

// LoadModulesFromDirectory scans a directory for module.yaml files and loads them
// This is a utility method for bulk loading modules
func (r *ModuleRegistry) LoadModulesFromDirectory(directory string) ([]string, []error) {
	var loadedModules []string
	var errors []error

	// Find all module.yaml files
	pattern := filepath.Join(directory, "*", "module.yaml")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		errors = append(errors, fmt.Errorf("failed to scan directory '%s': %v", directory, err))
		return loadedModules, errors
	}

	// Load each module metadata
	for _, metadataFile := range matches {
		metadata, err := LoadModuleMetadata(metadataFile)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to load module metadata from '%s': %v", metadataFile, err))
			continue
		}

		// Note: We only load the metadata here. The actual Module implementation
		// needs to be registered separately using RegisterModule()
		// This method is primarily for validation and dependency analysis

		if err := r.dependencyGraph.AddModule(metadata); err != nil {
			errors = append(errors, fmt.Errorf("failed to add module '%s' to dependency graph: %v", metadata.Name, err))
			continue
		}

		r.modules[metadata.Name] = metadata
		loadedModules = append(loadedModules, metadata.Name)
	}

	return loadedModules, errors
}

// GetRegistryStatus returns a summary of the registry state
func (r *ModuleRegistry) GetRegistryStatus() RegistryStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	conflicts, _ := r.DetectConflicts()

	return RegistryStatus{
		TotalModules: len(r.modules),
		Initialized:  r.initialized,
		HasConflicts: len(conflicts) > 0,
		Conflicts:    conflicts,
		LoadOrder:    append([]string(nil), r.loadOrder...), // Copy slice
	}
}

// RegistryStatus represents the current state of the module registry
type RegistryStatus struct {
	TotalModules int      `json:"total_modules"`
	Initialized  bool     `json:"initialized"`
	HasConflicts bool     `json:"has_conflicts"`
	Conflicts    []string `json:"conflicts,omitempty"`
	LoadOrder    []string `json:"load_order,omitempty"`
}

// String returns a human-readable representation of the registry status
func (s RegistryStatus) String() string {
	status := fmt.Sprintf("Registry Status: %d modules", s.TotalModules)

	if s.Initialized {
		status += " (initialized)"
	} else {
		status += " (not initialized)"
	}

	if s.HasConflicts {
		status += fmt.Sprintf(" - %d conflicts detected", len(s.Conflicts))
	}

	return status
}
