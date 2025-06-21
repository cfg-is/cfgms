package file

import (
	"context"
	"os"
)

// FileConfig represents the configuration for a file resource
type FileConfig struct {
	Content     string
	Permissions os.FileMode
	Owner       string
	Group       string
}

// Module defines the public interface for the file module
type Module interface {
	// Get returns the current content of the file
	Get(ctx context.Context, resourceID string) (FileConfig, error)

	// Set updates the file content and attributes
	Set(ctx context.Context, resourceID string, config FileConfig) error

	// Test checks if the file content and attributes match the desired state
	Test(ctx context.Context, resourceID string, config FileConfig) (bool, error)
}
