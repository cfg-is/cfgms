// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package controller

import "context"

// Module defines the interface that all modules must implement
type Module interface {
	// Name returns the name of the module
	Name() string

	// Get returns the current state of the resource as YAML configuration
	Get(ctx context.Context, resourceID string) (string, error)

	// Set applies the desired state to the resource
	Set(ctx context.Context, resourceID string, configData string) error

	// Test validates if the current state matches the desired state
	Test(ctx context.Context, resourceID string, configData string) (bool, error)
}
