package modules

import (
	"context"
)

// Module defines the core interface that all modules must implement
type Module interface {
	// Get returns the current configuration of a resource
	Get(ctx context.Context, resourceID string) (ConfigState, error)

	// Set updates the resource configuration to match the desired state
	Set(ctx context.Context, resourceID string, config ConfigState) error
}

// ConfigState defines the interface that all module configuration states must implement
type ConfigState interface {
	// AsMap returns the configuration as a map for efficient field-by-field comparison
	AsMap() map[string]interface{}

	// ToYAML serializes the configuration to YAML for export/storage
	ToYAML() ([]byte, error)

	// FromYAML deserializes YAML data into the configuration
	FromYAML([]byte) error

	// Validate ensures the configuration is valid
	Validate() error

	// GetManagedFields returns the list of fields this configuration manages
	GetManagedFields() []string
}

// Monitor interface for modules that support real-time monitoring (optional)
type Monitor interface {
	// Monitor watches for changes to a resource and triggers events
	Monitor(ctx context.Context, resourceID string, config ConfigState) error

	// Changes returns a channel for receiving change notifications
	Changes() <-chan ChangeEvent

	// Close stops monitoring and releases resources
	Close() error
}

// ChangeEvent represents a configuration change event
type ChangeEvent struct {
	ResourceID string
	Timestamp  int64
	ChangeType ChangeType
	Details    ConfigState
}

// ChangeType represents the type of change that occurred
type ChangeType int

const (
	ChangeTypeCreated ChangeType = iota
	ChangeTypeModified
	ChangeTypeDeleted
	ChangeTypePermissions
)
