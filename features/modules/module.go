package modules

import (
	"context"
)

// Module defines the core interface that all modules must implement
type Module interface {
	// Get returns the current configuration of a resource
	Get(ctx context.Context, resourceID string) (string, error)

	// Set updates the resource configuration
	Set(ctx context.Context, resourceID string, configData string) error

	// Test validates if the current configuration matches the desired state
	Test(ctx context.Context, resourceID string, configData string) (bool, error)
}
