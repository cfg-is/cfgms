// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package modules

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ModuleLifecycleManager manages the lifecycle of all modules in the system
type ModuleLifecycleManager struct {
	// registry is the module registry for dependency management
	registry *ModuleRegistry

	// instances tracks all loaded module instances
	instances map[string]*ModuleInstance

	// eventListeners are registered event listeners
	eventListeners []LifecycleEventListener

	// healthCheckInterval is the interval for periodic health checks
	healthCheckInterval time.Duration

	// healthCheckTicker is the ticker for health checks
	healthCheckTicker *time.Ticker

	// ctx is the context for background operations
	ctx context.Context

	// cancel cancels background operations
	cancel context.CancelFunc

	// mu protects concurrent access
	mu sync.RWMutex

	// running indicates if the manager is running
	running bool
}

// NewModuleLifecycleManager creates a new module lifecycle manager
func NewModuleLifecycleManager(registry *ModuleRegistry) *ModuleLifecycleManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &ModuleLifecycleManager{
		registry:            registry,
		instances:           make(map[string]*ModuleInstance),
		eventListeners:      make([]LifecycleEventListener, 0),
		healthCheckInterval: 60 * time.Second, // Default: 1 minute
		ctx:                 ctx,
		cancel:              cancel,
		running:             false,
	}
}

// Start starts the lifecycle manager and begins health monitoring
func (mlm *ModuleLifecycleManager) Start() error {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	if mlm.running {
		return fmt.Errorf("lifecycle manager is already running")
	}

	// Start health check monitoring
	mlm.healthCheckTicker = time.NewTicker(mlm.healthCheckInterval)
	go mlm.healthCheckLoop(mlm.healthCheckTicker)

	mlm.running = true

	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeInfo,
		Module:    "LifecycleManager",
		Message:   "Module lifecycle manager started",
		Timestamp: time.Now(),
	})

	return nil
}

// Stop stops the lifecycle manager and cancels all background operations
func (mlm *ModuleLifecycleManager) Stop() error {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	if !mlm.running {
		return nil // Already stopped
	}

	// Stop health monitoring - the ticker will be stopped by the healthCheckLoop goroutine
	mlm.healthCheckTicker = nil

	// Cancel background operations
	mlm.cancel()

	mlm.running = false

	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeInfo,
		Module:    "LifecycleManager",
		Message:   "Module lifecycle manager stopped",
		Timestamp: time.Now(),
	})

	return nil
}

// RegisterModule registers a module with the lifecycle manager
func (mlm *ModuleLifecycleManager) RegisterModule(metadata *ModuleMetadata, module Module, config ModuleConfig) (*ModuleInstance, error) {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	if _, exists := mlm.instances[metadata.Name]; exists {
		return nil, fmt.Errorf("module '%s' is already registered", metadata.Name)
	}

	// Determine if module implements lifecycle interface
	var lifecycle ModuleLifecycle
	if lc, ok := module.(ModuleLifecycle); ok {
		lifecycle = lc
	} else {
		lifecycle = NewDefaultLifecycleImplementation(module)
	}

	// Create module instance
	instance := &ModuleInstance{
		Metadata:        metadata,
		Module:          module,
		Lifecycle:       lifecycle,
		State:           ModuleStateDiscovered,
		Config:          config,
		LoadedAt:        time.Now(),
		LastStateChange: time.Now(),
		Health:          lifecycle.Health(), // Get initial health from lifecycle
	}

	mlm.instances[metadata.Name] = instance

	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeInfo,
		Module:    metadata.Name,
		State:     ModuleStateDiscovered,
		Message:   "Module registered with lifecycle manager",
		Timestamp: time.Now(),
	})

	return instance, nil
}

// UnregisterModule unregisters a module from the lifecycle manager
func (mlm *ModuleLifecycleManager) UnregisterModule(moduleName string) error {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	instance, exists := mlm.instances[moduleName]
	if !exists {
		return fmt.Errorf("module '%s' is not registered", moduleName)
	}

	// Ensure module is stopped before unregistering
	if !instance.GetState().IsTerminalState() {
		if err := mlm.stopModuleUnsafe(instance); err != nil {
			return fmt.Errorf("failed to stop module '%s' before unregistering: %v", moduleName, err)
		}
	}

	delete(mlm.instances, moduleName)

	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeInfo,
		Module:    moduleName,
		Message:   "Module unregistered from lifecycle manager",
		Timestamp: time.Now(),
	})

	return nil
}

// LoadModule loads a module and transitions it to Ready state
func (mlm *ModuleLifecycleManager) LoadModule(moduleName string) error {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	instance, exists := mlm.instances[moduleName]
	if !exists {
		return fmt.Errorf("module '%s' is not registered", moduleName)
	}

	if instance.GetState() != ModuleStateDiscovered {
		return fmt.Errorf("module '%s' is not in discovered state (current: %s)", moduleName, instance.GetState().String())
	}

	return mlm.loadModuleUnsafe(instance)
}

// StartModule starts a module and transitions it to Running state
func (mlm *ModuleLifecycleManager) StartModule(moduleName string) error {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	instance, exists := mlm.instances[moduleName]
	if !exists {
		return fmt.Errorf("module '%s' is not registered", moduleName)
	}

	// Load module if not already loaded
	if instance.GetState() == ModuleStateDiscovered {
		if err := mlm.loadModuleUnsafe(instance); err != nil {
			return err
		}
	}

	if instance.GetState() != ModuleStateReady {
		return fmt.Errorf("module '%s' is not ready for startup (current: %s)", moduleName, instance.GetState().String())
	}

	return mlm.startModuleUnsafe(instance)
}

// StopModule stops a module and transitions it to Stopped state
func (mlm *ModuleLifecycleManager) StopModule(moduleName string) error {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	instance, exists := mlm.instances[moduleName]
	if !exists {
		return fmt.Errorf("module '%s' is not registered", moduleName)
	}

	return mlm.stopModuleUnsafe(instance)
}

// StartAllModules starts all registered modules in dependency order
func (mlm *ModuleLifecycleManager) StartAllModules() error {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	// Get loading order from registry
	if err := mlm.registry.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize registry: %v", err)
	}

	loadOrder, err := mlm.registry.GetLoadingOrder()
	if err != nil {
		return fmt.Errorf("failed to get loading order: %v", err)
	}

	// Start modules in dependency order
	for _, moduleName := range loadOrder {
		instance, exists := mlm.instances[moduleName]
		if !exists {
			continue // Module not registered with lifecycle manager
		}

		// Load if necessary
		if instance.GetState() == ModuleStateDiscovered {
			if err := mlm.loadModuleUnsafe(instance); err != nil {
				return fmt.Errorf("failed to load module '%s': %v", moduleName, err)
			}
		}

		// Start if ready
		if instance.GetState() == ModuleStateReady {
			if err := mlm.startModuleUnsafe(instance); err != nil {
				return fmt.Errorf("failed to start module '%s': %v", moduleName, err)
			}
		}
	}

	return nil
}

// StopAllModules stops all registered modules in reverse dependency order
func (mlm *ModuleLifecycleManager) StopAllModules() error {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	// Get loading order from registry and reverse it
	if err := mlm.registry.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize registry: %v", err)
	}

	loadOrder, err := mlm.registry.GetLoadingOrder()
	if err != nil {
		return fmt.Errorf("failed to get loading order: %v", err)
	}

	// Stop modules in reverse dependency order
	for i := len(loadOrder) - 1; i >= 0; i-- {
		moduleName := loadOrder[i]
		instance, exists := mlm.instances[moduleName]
		if !exists {
			continue // Module not registered with lifecycle manager
		}

		if err := mlm.stopModuleUnsafe(instance); err != nil {
			// Log error but continue stopping other modules
			mlm.publishEvent(LifecycleEvent{
				Type:      EventTypeError,
				Module:    moduleName,
				Message:   "Failed to stop module during shutdown",
				Error:     err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	return nil
}

// GetModuleInstance returns the module instance for the given module name
func (mlm *ModuleLifecycleManager) GetModuleInstance(moduleName string) (*ModuleInstance, error) {
	mlm.mu.RLock()
	defer mlm.mu.RUnlock()

	instance, exists := mlm.instances[moduleName]
	if !exists {
		return nil, fmt.Errorf("module '%s' is not registered", moduleName)
	}

	return instance, nil
}

// ListModuleInstances returns all registered module instances
func (mlm *ModuleLifecycleManager) ListModuleInstances() map[string]*ModuleInstance {
	mlm.mu.RLock()
	defer mlm.mu.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]*ModuleInstance)
	for name, instance := range mlm.instances {
		result[name] = instance
	}

	return result
}

// GetModuleHealth returns the health status of a module
func (mlm *ModuleLifecycleManager) GetModuleHealth(moduleName string) (HealthStatus, error) {
	mlm.mu.RLock()
	defer mlm.mu.RUnlock()

	instance, exists := mlm.instances[moduleName]
	if !exists {
		return HealthStatus{}, fmt.Errorf("module '%s' is not registered", moduleName)
	}

	return instance.GetHealth(), nil
}

// GetSystemHealth returns the overall system health status
func (mlm *ModuleLifecycleManager) GetSystemHealth() SystemHealthStatus {
	mlm.mu.RLock()
	defer mlm.mu.RUnlock()

	status := SystemHealthStatus{
		OverallStatus: HealthStateHealthy,
		Modules:       make(map[string]ModuleHealthSummary),
		Timestamp:     time.Now(),
	}

	healthyCount := 0
	warningCount := 0
	unhealthyCount := 0
	criticalCount := 0

	for name, instance := range mlm.instances {
		health := instance.GetHealth()
		errorCount, lastError := instance.GetErrorInfo()

		summary := ModuleHealthSummary{
			State:      instance.GetState(),
			Health:     health,
			ErrorCount: errorCount,
		}

		if lastError != nil {
			summary.LastError = lastError.Error()
		}

		status.Modules[name] = summary

		// Count health states
		switch health.Status {
		case HealthStateHealthy:
			healthyCount++
		case HealthStateWarning:
			warningCount++
		case HealthStateUnhealthy:
			unhealthyCount++
		case HealthStateCritical:
			criticalCount++
		}
	}

	// Determine overall status
	if criticalCount > 0 {
		status.OverallStatus = HealthStateCritical
	} else if unhealthyCount > 0 {
		status.OverallStatus = HealthStateUnhealthy
	} else if warningCount > 0 {
		status.OverallStatus = HealthStateWarning
	}

	status.HealthyModules = healthyCount
	status.WarningModules = warningCount
	status.UnhealthyModules = unhealthyCount
	status.CriticalModules = criticalCount
	status.TotalModules = len(mlm.instances)

	return status
}

// AddEventListener adds a lifecycle event listener
func (mlm *ModuleLifecycleManager) AddEventListener(listener LifecycleEventListener) {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()
	mlm.eventListeners = append(mlm.eventListeners, listener)
}

// RemoveEventListener removes a lifecycle event listener
func (mlm *ModuleLifecycleManager) RemoveEventListener(listener LifecycleEventListener) {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	targetID := listener.GetID()
	for i, l := range mlm.eventListeners {
		if l.GetID() == targetID {
			mlm.eventListeners = append(mlm.eventListeners[:i], mlm.eventListeners[i+1:]...)
			break
		}
	}
}

// SetHealthCheckInterval sets the health check interval
func (mlm *ModuleLifecycleManager) SetHealthCheckInterval(interval time.Duration) {
	mlm.mu.Lock()
	defer mlm.mu.Unlock()

	mlm.healthCheckInterval = interval

	// Restart health check ticker if running
	if mlm.running && mlm.healthCheckTicker != nil {
		mlm.healthCheckTicker.Stop()
		mlm.healthCheckTicker = time.NewTicker(interval)
	}
}

// loadModuleUnsafe loads a module without locking (caller must hold lock)
func (mlm *ModuleLifecycleManager) loadModuleUnsafe(instance *ModuleInstance) error {
	moduleName := instance.Metadata.Name

	// Transition to loading state
	instance.SetState(ModuleStateLoading)
	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeStateChange,
		Module:    moduleName,
		State:     ModuleStateLoading,
		Timestamp: time.Now(),
	})

	// Create context with timeout for initialization
	ctx, cancel := context.WithTimeout(mlm.ctx, instance.Config.InitializationTimeout)
	defer cancel()

	// Transition to initializing state
	instance.SetState(ModuleStateInitializing)
	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeStateChange,
		Module:    moduleName,
		State:     ModuleStateInitializing,
		Timestamp: time.Now(),
	})

	// Initialize the module
	if err := instance.Lifecycle.Initialize(ctx, instance.Config); err != nil {
		instance.SetState(ModuleStateError)
		instance.IncrementErrorCount(err)

		lifecycleErr := NewLifecycleOperationError(moduleName, "initialize", ModuleStateInitializing, err)
		mlm.publishEvent(LifecycleEvent{
			Type:      EventTypeError,
			Module:    moduleName,
			State:     ModuleStateError,
			Error:     lifecycleErr.Error(),
			Timestamp: time.Now(),
		})

		return lifecycleErr
	}

	// Transition to ready state
	instance.SetState(ModuleStateReady)
	instance.SetHealth(instance.Lifecycle.Health())

	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeStateChange,
		Module:    moduleName,
		State:     ModuleStateReady,
		Timestamp: time.Now(),
	})

	return nil
}

// startModuleUnsafe starts a module without locking (caller must hold lock)
func (mlm *ModuleLifecycleManager) startModuleUnsafe(instance *ModuleInstance) error {
	moduleName := instance.Metadata.Name

	// Transition to starting state
	instance.SetState(ModuleStateStarting)
	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeStateChange,
		Module:    moduleName,
		State:     ModuleStateStarting,
		Timestamp: time.Now(),
	})

	// Create context with timeout for startup
	ctx, cancel := context.WithTimeout(mlm.ctx, instance.Config.StartupTimeout)
	defer cancel()

	// Start the module
	if err := instance.Lifecycle.Start(ctx); err != nil {
		instance.SetState(ModuleStateError)
		instance.IncrementErrorCount(err)

		lifecycleErr := NewLifecycleOperationError(moduleName, "start", ModuleStateStarting, err)
		mlm.publishEvent(LifecycleEvent{
			Type:      EventTypeError,
			Module:    moduleName,
			State:     ModuleStateError,
			Error:     lifecycleErr.Error(),
			Timestamp: time.Now(),
		})

		return lifecycleErr
	}

	// Transition to running state
	instance.SetState(ModuleStateRunning)
	instance.SetHealth(instance.Lifecycle.Health())

	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeStateChange,
		Module:    moduleName,
		State:     ModuleStateRunning,
		Timestamp: time.Now(),
	})

	return nil
}

// stopModuleUnsafe stops a module without locking (caller must hold lock)
func (mlm *ModuleLifecycleManager) stopModuleUnsafe(instance *ModuleInstance) error {
	moduleName := instance.Metadata.Name

	// Skip if already stopped or failed
	if instance.GetState().IsTerminalState() {
		return nil
	}

	// Transition to stopping state
	instance.SetState(ModuleStateStopping)
	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeStateChange,
		Module:    moduleName,
		State:     ModuleStateStopping,
		Timestamp: time.Now(),
	})

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(mlm.ctx, instance.Config.ShutdownTimeout)
	defer cancel()

	// Stop the module
	if err := instance.Lifecycle.Stop(ctx); err != nil {
		instance.SetState(ModuleStateError)
		instance.IncrementErrorCount(err)

		lifecycleErr := NewLifecycleOperationError(moduleName, "stop", ModuleStateStopping, err)
		mlm.publishEvent(LifecycleEvent{
			Type:      EventTypeError,
			Module:    moduleName,
			State:     ModuleStateError,
			Error:     lifecycleErr.Error(),
			Timestamp: time.Now(),
		})

		return lifecycleErr
	}

	// Shutdown the module
	if err := instance.Lifecycle.Shutdown(ctx); err != nil {
		instance.SetState(ModuleStateError)
		instance.IncrementErrorCount(err)

		lifecycleErr := NewLifecycleOperationError(moduleName, "shutdown", ModuleStateStopping, err)
		mlm.publishEvent(LifecycleEvent{
			Type:      EventTypeError,
			Module:    moduleName,
			State:     ModuleStateError,
			Error:     lifecycleErr.Error(),
			Timestamp: time.Now(),
		})

		return lifecycleErr
	}

	// Transition to stopped state
	instance.SetState(ModuleStateStopped)

	mlm.publishEvent(LifecycleEvent{
		Type:      EventTypeStateChange,
		Module:    moduleName,
		State:     ModuleStateStopped,
		Timestamp: time.Now(),
	})

	return nil
}

// publishEvent publishes a lifecycle event to all listeners
func (mlm *ModuleLifecycleManager) publishEvent(event LifecycleEvent) {
	// Note: caller should hold appropriate lock
	for _, listener := range mlm.eventListeners {
		// Call listener in goroutine to avoid blocking
		go func(l LifecycleEventListener, e LifecycleEvent) {
			defer func() {
				if r := recover(); r != nil {
					// Log panic but don't crash the system
					fmt.Printf("Panic in lifecycle event listener: %v\n", r)
				}
			}()
			l.OnLifecycleEvent(e)
		}(listener, event)
	}
}

// healthCheckLoop performs periodic health checks on all modules
func (mlm *ModuleLifecycleManager) healthCheckLoop(ticker *time.Ticker) {
	defer ticker.Stop()

	for {
		select {
		case <-mlm.ctx.Done():
			return
		case <-ticker.C:
			mlm.performHealthChecks()
		}
	}
}

// performHealthChecks checks the health of all running modules
func (mlm *ModuleLifecycleManager) performHealthChecks() {
	mlm.mu.RLock()
	instances := make([]*ModuleInstance, 0, len(mlm.instances))
	for _, instance := range mlm.instances {
		instances = append(instances, instance)
	}
	mlm.mu.RUnlock()

	for _, instance := range instances {
		if instance.GetState() == ModuleStateRunning {
			previousHealth := instance.GetHealth()
			currentHealth := instance.Lifecycle.Health()

			instance.SetHealth(currentHealth)

			// Publish health change event if status changed
			if previousHealth.Status != currentHealth.Status {
				mlm.publishEvent(LifecycleEvent{
					Type:      EventTypeHealthChange,
					Module:    instance.Metadata.Name,
					State:     instance.GetState(),
					Health:    &currentHealth,
					Timestamp: time.Now(),
				})
			}
		}
	}
}

// SystemHealthStatus represents the overall health status of the system
type SystemHealthStatus struct {
	OverallStatus    HealthState                    `json:"overall_status"`
	TotalModules     int                            `json:"total_modules"`
	HealthyModules   int                            `json:"healthy_modules"`
	WarningModules   int                            `json:"warning_modules"`
	UnhealthyModules int                            `json:"unhealthy_modules"`
	CriticalModules  int                            `json:"critical_modules"`
	Modules          map[string]ModuleHealthSummary `json:"modules"`
	Timestamp        time.Time                      `json:"timestamp"`
}

// ModuleHealthSummary represents a summary of a module's health status
type ModuleHealthSummary struct {
	State      ModuleState  `json:"state"`
	Health     HealthStatus `json:"health"`
	ErrorCount int          `json:"error_count"`
	LastError  string       `json:"last_error,omitempty"`
}
