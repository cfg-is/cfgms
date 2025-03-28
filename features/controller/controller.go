package controller

import (
	"context"
	"sync"

	"cfgms/features/controller/config"
	"cfgms/pkg/logging"
)

// Interface defines the core controller functionality
type Interface interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	RegisterModule(module Module) error
	GetModule(name string) (Module, error)
}

// Controller manages the core CFGMS functionality
type Controller struct {
	mu sync.RWMutex

	// Configuration for the controller
	config *config.Config

	// Logger for the controller
	logger logging.Logger

	// Module registry
	modules map[string]Module

	// Shutdown management
	shutdown chan struct{}
}

// New creates a new Controller instance
func New(cfg *config.Config, logger logging.Logger) (*Controller, error) {
	if cfg == nil {
		cfg = config.DefaultConfig() // Use defaults
	}

	return &Controller{
		config:   cfg,
		logger:   logger,
		modules:  make(map[string]Module),
		shutdown: make(chan struct{}),
	}, nil
}

// Start initializes and starts the controller
func (c *Controller) Start(ctx context.Context) error {
	c.logger.Info("Starting controller")

	// TODO: Initialize core services
	// - Set up mTLS server
	// - Initialize module system
	// - Start health monitoring

	c.logger.Info("Controller started successfully")
	return nil
}

// Stop gracefully shuts down the controller
func (c *Controller) Stop(ctx context.Context) error {
	c.logger.Info("Stopping controller")
	close(c.shutdown)

	// TODO: Implement graceful shutdown

	c.logger.Info("Controller stopped successfully")
	return nil
}

// RegisterModule registers a module with the controller
func (c *Controller) RegisterModule(module Module) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	name := module.Name()
	if _, exists := c.modules[name]; exists {
		return ErrModuleExists
	}

	c.modules[name] = module
	c.logger.Info("Registered module", "name", name)
	return nil
}

// GetModule returns a module by name
func (c *Controller) GetModule(name string) (Module, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	module, exists := c.modules[name]
	if !exists {
		return nil, ErrModuleNotFound
	}

	return module, nil
}
