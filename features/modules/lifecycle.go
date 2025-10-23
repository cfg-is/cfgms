// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package modules

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ModuleState represents the current state of a module in its lifecycle
type ModuleState int

const (
	ModuleStateUnknown      ModuleState = iota
	ModuleStateDiscovered               // Module has been discovered but not loaded
	ModuleStateLoading                  // Module is being loaded
	ModuleStateInitializing             // Module is being initialized
	ModuleStateReady                    // Module is ready but not started
	ModuleStateStarting                 // Module is starting up
	ModuleStateRunning                  // Module is running normally
	ModuleStateStopping                 // Module is shutting down
	ModuleStateStopped                  // Module has been stopped
	ModuleStateError                    // Module encountered an error
	ModuleStateFailed                   // Module has failed and cannot recover
)

// String returns a human-readable representation of the module state
func (ms ModuleState) String() string {
	switch ms {
	case ModuleStateDiscovered:
		return "Discovered"
	case ModuleStateLoading:
		return "Loading"
	case ModuleStateInitializing:
		return "Initializing"
	case ModuleStateReady:
		return "Ready"
	case ModuleStateStarting:
		return "Starting"
	case ModuleStateRunning:
		return "Running"
	case ModuleStateStopping:
		return "Stopping"
	case ModuleStateStopped:
		return "Stopped"
	case ModuleStateError:
		return "Error"
	case ModuleStateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// IsTerminalState returns true if the state represents a final state
func (ms ModuleState) IsTerminalState() bool {
	return ms == ModuleStateStopped || ms == ModuleStateFailed
}

// IsErrorState returns true if the state represents an error condition
func (ms ModuleState) IsErrorState() bool {
	return ms == ModuleStateError || ms == ModuleStateFailed
}

// HealthStatus represents the health status of a module
type HealthStatus struct {
	Status    HealthState       `json:"status"`
	Message   string            `json:"message,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// HealthState represents the health state of a module
type HealthState int

const (
	HealthStateUnknown   HealthState = iota
	HealthStateHealthy               // Module is healthy and functioning normally
	HealthStateWarning               // Module has warnings but is still functioning
	HealthStateUnhealthy             // Module is unhealthy but may recover
	HealthStateCritical              // Module is in critical state and needs intervention
)

// String returns a human-readable representation of the health state
func (hs HealthState) String() string {
	switch hs {
	case HealthStateHealthy:
		return "Healthy"
	case HealthStateWarning:
		return "Warning"
	case HealthStateUnhealthy:
		return "Unhealthy"
	case HealthStateCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// ModuleConfig represents configuration for module lifecycle operations
type ModuleConfig struct {
	// InitializationTimeout is the maximum time allowed for initialization
	InitializationTimeout time.Duration `json:"initialization_timeout,omitempty"`

	// StartupTimeout is the maximum time allowed for startup
	StartupTimeout time.Duration `json:"startup_timeout,omitempty"`

	// ShutdownTimeout is the maximum time allowed for shutdown
	ShutdownTimeout time.Duration `json:"shutdown_timeout,omitempty"`

	// HealthCheckInterval is the interval for periodic health checks
	HealthCheckInterval time.Duration `json:"health_check_interval,omitempty"`

	// MaxRetries is the maximum number of retry attempts for failed operations
	MaxRetries int `json:"max_retries,omitempty"`

	// RetryDelay is the delay between retry attempts
	RetryDelay time.Duration `json:"retry_delay,omitempty"`

	// Settings contains module-specific configuration
	Settings map[string]interface{} `json:"settings,omitempty"`
}

// DefaultModuleConfig returns a configuration with sensible defaults
func DefaultModuleConfig() ModuleConfig {
	return ModuleConfig{
		InitializationTimeout: 30 * time.Second,
		StartupTimeout:        30 * time.Second,
		ShutdownTimeout:       30 * time.Second,
		HealthCheckInterval:   60 * time.Second,
		MaxRetries:            3,
		RetryDelay:            5 * time.Second,
		Settings:              make(map[string]interface{}),
	}
}

// ModuleLifecycle defines the lifecycle interface that modules can optionally implement
// Modules not implementing this interface will use default lifecycle behavior
type ModuleLifecycle interface {
	// Initialize prepares the module for operation with the given configuration
	Initialize(ctx context.Context, config ModuleConfig) error

	// Start begins module operations
	Start(ctx context.Context) error

	// Stop gracefully shuts down module operations
	Stop(ctx context.Context) error

	// Shutdown performs final cleanup and resource deallocation
	Shutdown(ctx context.Context) error

	// Health returns the current health status of the module
	Health() HealthStatus
}

// ModuleInstance represents a loaded module with its lifecycle state
type ModuleInstance struct {
	// Metadata contains the module's metadata
	Metadata *ModuleMetadata

	// Module is the actual module implementation
	Module Module

	// Lifecycle is the optional lifecycle implementation
	Lifecycle ModuleLifecycle

	// State tracks the current lifecycle state
	State ModuleState

	// Health tracks the current health status
	Health HealthStatus

	// Config contains the lifecycle configuration
	Config ModuleConfig

	// LoadedAt is when the module was loaded
	LoadedAt time.Time

	// LastStateChange is when the state last changed
	LastStateChange time.Time

	// ErrorCount tracks the number of errors encountered
	ErrorCount int

	// LastError contains the most recent error
	LastError error

	// mu protects concurrent access to the instance
	mu sync.RWMutex
}

// GetState returns the current state of the module instance
func (mi *ModuleInstance) GetState() ModuleState {
	mi.mu.RLock()
	defer mi.mu.RUnlock()
	return mi.State
}

// SetState sets the state of the module instance
func (mi *ModuleInstance) SetState(state ModuleState) {
	mi.mu.Lock()
	defer mi.mu.Unlock()

	if mi.State != state {
		mi.State = state
		mi.LastStateChange = time.Now()
	}
}

// GetHealth returns the current health status
func (mi *ModuleInstance) GetHealth() HealthStatus {
	mi.mu.RLock()
	defer mi.mu.RUnlock()
	return mi.Health
}

// SetHealth sets the health status
func (mi *ModuleInstance) SetHealth(health HealthStatus) {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	mi.Health = health
}

// IncrementErrorCount increments the error counter and updates last error
func (mi *ModuleInstance) IncrementErrorCount(err error) {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	mi.ErrorCount++
	mi.LastError = err
}

// GetErrorInfo returns error count and last error
func (mi *ModuleInstance) GetErrorInfo() (int, error) {
	mi.mu.RLock()
	defer mi.mu.RUnlock()
	return mi.ErrorCount, mi.LastError
}

// LifecycleEvent represents an event in the module lifecycle
type LifecycleEvent struct {
	Type      LifecycleEventType `json:"type"`
	Module    string             `json:"module"`
	State     ModuleState        `json:"state"`
	Health    *HealthStatus      `json:"health,omitempty"`
	Message   string             `json:"message,omitempty"`
	Error     string             `json:"error,omitempty"`
	Timestamp time.Time          `json:"timestamp"`
}

// LifecycleEventType represents the type of lifecycle event
type LifecycleEventType int

const (
	EventTypeStateChange LifecycleEventType = iota
	EventTypeHealthChange
	EventTypeError
	EventTypeWarning
	EventTypeInfo
)

// String returns a human-readable representation of the event type
func (let LifecycleEventType) String() string {
	switch let {
	case EventTypeStateChange:
		return "StateChange"
	case EventTypeHealthChange:
		return "HealthChange"
	case EventTypeError:
		return "Error"
	case EventTypeWarning:
		return "Warning"
	case EventTypeInfo:
		return "Info"
	default:
		return "Unknown"
	}
}

// LifecycleEventListener defines the interface for listening to lifecycle events
type LifecycleEventListener interface {
	OnLifecycleEvent(event LifecycleEvent)
	GetID() string // Unique identifier for the listener
}

// LifecycleEventHandler is a wrapper for function-based event handlers
type LifecycleEventHandler struct {
	id      string
	handler func(event LifecycleEvent)
}

// NewLifecycleEventHandler creates a new lifecycle event handler
func NewLifecycleEventHandler(id string, handler func(event LifecycleEvent)) *LifecycleEventHandler {
	return &LifecycleEventHandler{
		id:      id,
		handler: handler,
	}
}

// OnLifecycleEvent implements LifecycleEventListener
func (h *LifecycleEventHandler) OnLifecycleEvent(event LifecycleEvent) {
	h.handler(event)
}

// GetID implements LifecycleEventListener
func (h *LifecycleEventHandler) GetID() string {
	return h.id
}

// DefaultLifecycleImplementation provides default implementations for modules
// that don't implement the ModuleLifecycle interface
type DefaultLifecycleImplementation struct {
	module Module
	health HealthStatus
	mu     sync.RWMutex
}

// NewDefaultLifecycleImplementation creates a default lifecycle implementation
func NewDefaultLifecycleImplementation(module Module) *DefaultLifecycleImplementation {
	return &DefaultLifecycleImplementation{
		module: module,
		health: HealthStatus{
			Status:    HealthStateHealthy,
			Message:   "Module is operational",
			Timestamp: time.Now(),
		},
	}
}

// Initialize performs default initialization (no-op)
func (dli *DefaultLifecycleImplementation) Initialize(ctx context.Context, config ModuleConfig) error {
	dli.mu.Lock()
	defer dli.mu.Unlock()

	dli.health = HealthStatus{
		Status:    HealthStateHealthy,
		Message:   "Module initialized successfully",
		Timestamp: time.Now(),
	}

	return nil
}

// Start performs default start operation (no-op)
func (dli *DefaultLifecycleImplementation) Start(ctx context.Context) error {
	dli.mu.Lock()
	defer dli.mu.Unlock()

	dli.health = HealthStatus{
		Status:    HealthStateHealthy,
		Message:   "Module started successfully",
		Timestamp: time.Now(),
	}

	return nil
}

// Stop performs default stop operation (no-op)
func (dli *DefaultLifecycleImplementation) Stop(ctx context.Context) error {
	dli.mu.Lock()
	defer dli.mu.Unlock()

	dli.health = HealthStatus{
		Status:    HealthStateHealthy,
		Message:   "Module stopped successfully",
		Timestamp: time.Now(),
	}

	return nil
}

// Shutdown performs default shutdown operation (no-op)
func (dli *DefaultLifecycleImplementation) Shutdown(ctx context.Context) error {
	dli.mu.Lock()
	defer dli.mu.Unlock()

	dli.health = HealthStatus{
		Status:    HealthStateHealthy,
		Message:   "Module shutdown successfully",
		Timestamp: time.Now(),
	}

	return nil
}

// Health returns the current health status
func (dli *DefaultLifecycleImplementation) Health() HealthStatus {
	dli.mu.RLock()
	defer dli.mu.RUnlock()
	return dli.health
}

// LifecycleOperationError represents an error that occurred during a lifecycle operation
type LifecycleOperationError struct {
	Module    string
	Operation string
	State     ModuleState
	Cause     error
	Timestamp time.Time
}

// Error implements the error interface
func (loe *LifecycleOperationError) Error() string {
	return fmt.Sprintf("lifecycle operation '%s' failed for module '%s' in state '%s': %v",
		loe.Operation, loe.Module, loe.State.String(), loe.Cause)
}

// Unwrap returns the underlying cause
func (loe *LifecycleOperationError) Unwrap() error {
	return loe.Cause
}

// NewLifecycleOperationError creates a new lifecycle operation error
func NewLifecycleOperationError(module, operation string, state ModuleState, cause error) *LifecycleOperationError {
	return &LifecycleOperationError{
		Module:    module,
		Operation: operation,
		State:     state,
		Cause:     cause,
		Timestamp: time.Now(),
	}
}
