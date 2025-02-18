package module

import (
	"context"
)

// EventType represents the type of module event
type EventType int

const (
	// EventStateChange indicates a change in module state
	EventStateChange EventType = iota
	// EventError indicates an error occurred
	EventError
	// EventWarning indicates a warning condition
	EventWarning
	// EventInfo indicates an informational event
	EventInfo
)

// Module defines the interface that all CFGMS modules must implement
type Module interface {
	// Get returns the current configuration state
	Get(ctx context.Context) (interface{}, error)

	// Set applies the given configuration
	Set(ctx context.Context, config interface{}) (bool, error)

	// Test validates if current state matches desired state
	Test(ctx context.Context) (bool, error)

	// Monitor for real-time state changes
	// Returns a channel that will receive module state change events
	// The channel will be closed when monitoring stops or context is cancelled
	Monitor(ctx context.Context) (<-chan Event, error)
}

// Event represents a module state change event
type Event struct {
	Type  EventType
	Data  interface{}
	Error error
}

// RegisterOptions contains options for registering a module
type RegisterOptions struct {
	// Name is the unique identifier for the module
	Name string
	// Version is the semantic version of the module
	Version string
	// Dependencies lists other modules this module depends on
	Dependencies []string
}

// ModuleInfo contains metadata about a registered module
type ModuleInfo struct {
	Name         string
	Version      string
	Dependencies []string
	Status       ModuleStatus
}

// ModuleStatus represents the current status of a module
type ModuleStatus int

const (
	// ModuleStatusUnknown indicates the module status cannot be determined
	ModuleStatusUnknown ModuleStatus = iota
	// ModuleStatusActive indicates the module is running normally
	ModuleStatusActive
	// ModuleStatusError indicates the module has encountered an error
	ModuleStatusError
	// ModuleStatusDisabled indicates the module has been disabled
	ModuleStatusDisabled
)

// String returns the string representation of ModuleStatus
func (s ModuleStatus) String() string {
	switch s {
	case ModuleStatusActive:
		return "Active"
	case ModuleStatusError:
		return "Error"
	case ModuleStatusDisabled:
		return "Disabled"
	default:
		return "Unknown"
	}
}
