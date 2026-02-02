// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package controller

import (
	"context"
	"sync"

	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/directory"
	"github.com/cfgis/cfgms/features/controller/server"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"

	// Import logging providers for auto-registration
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/timescale"
)

// Interface defines the core controller functionality
type Interface interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	RegisterModule(module Module) error
	GetModuleTyped(name string) (Module, error)
	GetDirectoryService() directory.Service
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

	// REST API server for external HTTP access
	apiServer *api.Server

	// Directory service for unified directory operations
	directoryService directory.Service

	// Shutdown management
	shutdown chan struct{}
	running  bool
}

// New creates a new Controller instance
func New(cfg *config.Config, logger logging.Logger) (*Controller, error) {
	if cfg == nil {
		cfg = config.DefaultConfig() // Use defaults
	}

	// Initialize global logging provider system if configured
	if cfg.Logging != nil {
		loggingConfig := cfg.Logging.ToLoggingManagerConfig()
		if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
			// Log warning but continue with fallback logging
			logger.Warn("Failed to initialize global logging provider, using fallback", "error", err, "provider", cfg.Logging.Provider)
		} else {
			logger.Info("Initialized global logging provider", "provider", cfg.Logging.Provider)
		}

		// Initialize global logger factory for module injection
		logging.InitializeGlobalLoggerFactory(loggingConfig.ServiceName, loggingConfig.Component)
	} else {
		// Initialize with defaults if no logging config provided
		logging.InitializeGlobalLoggerFactory("cfgms-controller", "controller")
	}

	// Create the gRPC server
	srv, err := server.New(cfg, logger)
	if err != nil {
		return nil, err
	}

	// Create the REST API server
	apiSrv, err := api.New(
		cfg,
		logger,
		srv.GetControllerService(),
		srv.GetConfigurationService(),
		srv.GetCertificateProvisioningService(),
		srv.GetRBACService(),
		srv.GetCertificateManager(),
		srv.GetTenantManager(),
		srv.GetRBACManager(),
		nil,                             // systemMonitor - will be integrated in Phase 5
		nil,                             // platformMonitor - will be integrated in this story completion
		nil,                             // tracer - will be integrated in Phase 5
		srv.GetHAManager(),              // HA manager
		srv.GetRegistrationTokenStore(), // registrationTokenStore - now wired for MQTT+QUIC mode
	)
	if err != nil {
		return nil, err
	}

	// Create the directory service
	dirService := directory.NewDirectoryService(logger)

	controller := &Controller{
		config:           cfg,
		logger:           logger,
		modules:          make(map[string]Module),
		server:           srv,
		apiServer:        apiSrv,
		directoryService: dirService,
		shutdown:         make(chan struct{}),
	}

	// Set up module registry integration
	dirService.SetModuleRegistry(controller)

	return controller, nil
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

	// Start the REST API server
	if err := c.apiServer.Start(); err != nil {
		c.logger.Error("Failed to start REST API server", "error", err)
		// Don't fail completely if REST API fails to start
		c.logger.Warn("Controller running without REST API server")
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

	// Stop the REST API server
	if err := c.apiServer.Stop(); err != nil {
		c.logger.Error("Failed to stop REST API server", "error", err)
		// Continue stopping other services
	}

	// Stop the gRPC server
	if err := c.server.Stop(); err != nil {
		c.logger.Error("Failed to stop gRPC server", "error", err)
		return err
	}

	// Cleanup global logging provider
	if manager := logging.GetGlobalLoggingManager(); manager != nil {
		if err := manager.Close(); err != nil {
			c.logger.Error("Failed to close global logging manager", "error", err)
			// Continue with cleanup, don't fail
		} else {
			c.logger.Info("Global logging manager closed successfully")
		}
	}

	// Close shutdown channel only if not already closed
	select {
	case <-c.shutdown:
		// Already closed
	default:
		close(c.shutdown)
	}
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

// GetConfigurationService returns the configuration service instance
func (c *Controller) GetConfigurationService() *service.ConfigurationService {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.server.GetConfigurationService()
}

// GetListenAddr returns the actual listen address after binding
func (c *Controller) GetListenAddr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.server.GetListenAddr()
}

// GetDirectoryService returns the directory service instance
func (c *Controller) GetDirectoryService() directory.Service {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.directoryService
}

// GetCertificateManager returns the certificate manager instance
// Used by tests to access certificates generated by the controller
func (c *Controller) GetCertificateManager() *cert.Manager {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.server == nil {
		return nil
	}
	return c.server.GetCertificateManager()
}

// GetRegistrationTokenStore returns the registration token store instance
// Story #294 Phase 2: E2E framework needs access to create registration tokens
func (c *Controller) GetRegistrationTokenStore() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.server.GetRegistrationTokenStore()
}

// ModuleRegistry implementation for directory service integration

// ListModules returns all available modules
func (c *Controller) ListModules() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var modules []string
	for name := range c.modules {
		modules = append(modules, name)
	}
	return modules
}

// GetModule returns a module by name (for ModuleRegistry interface)
func (c *Controller) GetModule(name string) (interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	module, exists := c.modules[name]
	if !exists {
		return nil, ErrModuleNotFound
	}

	return module, nil
}

// GetModuleTyped returns a module by name with proper typing
func (c *Controller) GetModuleTyped(name string) (Module, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	module, exists := c.modules[name]
	if !exists {
		return nil, ErrModuleNotFound
	}

	return module, nil
}

// ExecuteModuleOperation executes an operation on a module
func (c *Controller) ExecuteModuleOperation(ctx context.Context, moduleName, operation string, params map[string]interface{}) (interface{}, error) {
	module, err := c.GetModule(moduleName)
	if err != nil {
		return nil, err
	}

	// This would be implemented based on the specific module interface
	// For now, return a generic interface
	c.logger.Info("Executing module operation", "module", moduleName, "operation", operation)
	return module, nil
}
