package controller

import (
	"context"
	"sync"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/server"
	"github.com/cfgis/cfgms/pkg/logging"
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

	// gRPC server for steward communication
	server *server.Server

	// Shutdown management
	shutdown chan struct{}
	running  bool
}

// New creates a new Controller instance
func New(cfg *config.Config, logger logging.Logger) (*Controller, error) {
	if cfg == nil {
		cfg = config.DefaultConfig() // Use defaults
	}

	// Create the gRPC server
	srv, err := server.New(cfg, logger)
	if err != nil {
		return nil, err
	}

	return &Controller{
		config:   cfg,
		logger:   logger,
		modules:  make(map[string]Module),
		server:   srv,
		shutdown: make(chan struct{}),
	}, nil
}

// Start initializes and starts the controller
func (c *Controller) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return ErrAlreadyRunning
	}

	c.logger.Info("Starting controller")

	// Start the gRPC server
	if err := c.server.Start(); err != nil {
		c.logger.Error("Failed to start gRPC server", "error", err)
		return err
	}

	c.running = true
	c.logger.Info("Controller started successfully")
	return nil
}

// Stop gracefully shuts down the controller
func (c *Controller) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return ErrNotRunning
	}

	c.logger.Info("Stopping controller")

	// Stop the gRPC server
	if err := c.server.Stop(); err != nil {
		c.logger.Error("Failed to stop gRPC server", "error", err)
		return err
	}

	close(c.shutdown)
	c.running = false
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
