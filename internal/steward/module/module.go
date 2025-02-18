package module

import (
	"context"
	"time"
)

// ModuleState represents the current state of a module
type ModuleState int

const (
	// StateUnknown indicates the module state cannot be determined
	StateUnknown ModuleState = iota
	// StateInitialized indicates the module has been initialized but not started
	StateInitialized
	// StateRunning indicates the module is actively running
	StateRunning
	// StateStopped indicates the module has been stopped
	StateStopped
	// StateError indicates the module has encountered an error
	StateError
)

// Module defines the interface that all agent modules must implement
type Module interface {
	// Initialize prepares the module for use
	Initialize(ctx context.Context) error

	// Start begins the module's operation
	Start(ctx context.Context) error

	// Stop gracefully shuts down the module
	Stop(ctx context.Context) error

	// Status returns the current module state and any error condition
	Status() (ModuleState, error)

	// Health performs a health check of the module
	Health(ctx context.Context) error

	// Name returns the module's name
	Name() string

	// Version returns the module's version
	Version() string
}

// BaseModule provides common functionality for modules
type BaseModule struct {
	name    string
	version string
	state   ModuleState
	started time.Time
}

// NewBaseModule creates a new BaseModule instance
func NewBaseModule(name, version string) *BaseModule {
	return &BaseModule{
		name:    name,
		version: version,
		state:   StateUnknown,
	}
}

// Name returns the module's name
func (b *BaseModule) Name() string {
	return b.name
}

// Version returns the module's version
func (b *BaseModule) Version() string {
	return b.version
}

// Status returns the current module state
func (b *BaseModule) Status() (ModuleState, error) {
	return b.state, nil
}

// SetState updates the module's state
func (b *BaseModule) SetState(state ModuleState) {
	b.state = state
}

// StartTime returns when the module was started
func (b *BaseModule) StartTime() time.Time {
	return b.started
}

// Health performs a basic health check
func (b *BaseModule) Health(ctx context.Context) error {
	if b.state == StateError {
		return ErrModuleUnhealthy
	}
	return nil
}

// ModuleConfig defines the basic configuration structure for modules
type ModuleConfig struct {
	// Name is the unique identifier for the module
	Name string `json:"name" yaml:"name"`

	// Version is the semantic version of the module
	Version string `json:"version" yaml:"version"`

	// Enabled determines if the module should be started
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Config holds module-specific configuration
	Config map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
}
