// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package controller

import (
	"context"
)

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

// Controller manages the core CFGMS functionality
type Controller struct {
	// Configuration for the controller
	config *Config

	// Module registry
	modules map[string]Module

	// Shutdown management
	shutdown chan struct{}
}

// Config holds the controller configuration
type Config struct {
	// Path to TLS certificates
	CertPath string

	// Controller listen address
	ListenAddr string

	// Data directory
	DataDir string
}

// New creates a new Controller instance
func New(cfg *Config) (*Controller, error) {
	if cfg == nil {
		cfg = &Config{} // Use defaults
	}

	return &Controller{
		config:   cfg,
		modules:  make(map[string]Module),
		shutdown: make(chan struct{}),
	}, nil
}

// Start initializes and starts the controller
func (c *Controller) Start(ctx context.Context) error {
	// Placeholder for future implementation
	return nil
}

// Stop gracefully shuts down the controller
func (c *Controller) Stop(ctx context.Context) error {
	close(c.shutdown)
	return nil
}
