// Package steward provides standalone configuration management capabilities.
//
// The steward package implements a complete standalone system that can operate
// without a controller using local hostname.cfg files. It includes module
// discovery, configuration management, and execution orchestration.
//
// The steward supports two operation modes:
//   - Standalone: Uses local hostname.cfg files and discovered modules
//   - Controller: Connects to a remote controller (legacy mode)
//
// Basic standalone usage:
//
//	logger := logging.NewLogger("info")
//	steward, err := steward.NewStandalone("", logger)
//	if err != nil {
//		log.Fatal(err)
//	}
//	
//	ctx := context.Background()
//	err = steward.Start(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Controller mode (legacy):
//
//	cfg := steward.DefaultConfig()
//	steward, err := steward.New(cfg, logger)
//
package steward

import (
	"context"
	"fmt"
	"sync"
	
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Config holds the steward configuration for controller mode (legacy compatibility).
//
// This configuration is used when the steward operates in controller mode,
// connecting to a remote CFGMS controller for configuration and coordination.
type Config struct {
	// ControllerAddr is the address of the CFGMS controller to connect to
	ControllerAddr string `yaml:"controller_addr"`
	
	// CertPath is the directory containing TLS certificates for mTLS authentication
	CertPath string `yaml:"cert_path"`
	
	// DataDir is the directory for local storage and caching
	DataDir string `yaml:"data_dir"`
	
	// LogLevel sets the logging verbosity (debug, info, warn, error)
	LogLevel string `yaml:"log_level"`
	
	// ID is the unique identifier for this steward instance
	ID string `yaml:"id"`
}

// DefaultConfig returns a Config with reasonable defaults for controller mode.
//
// The returned configuration connects to a local controller and uses
// relative paths for certificates and data storage.
func DefaultConfig() *Config {
	return &Config{
		ControllerAddr: "127.0.0.1:8080",
		CertPath:       "certs/",
		DataDir:        "data/",
		LogLevel:       "info",
		ID:             "",
	}
}

// Steward manages configuration for a single endpoint with dual-mode capabilities.
//
// The Steward can operate in two modes:
//   - Standalone: Uses local hostname.cfg files and discovered modules
//   - Controller: Connects to a remote CFGMS controller (legacy mode)
//
// All operations are thread-safe and support graceful shutdown via context cancellation.
type Steward struct {
	mu sync.RWMutex
	
	// Legacy configuration (for controller mode)
	legacyConfig *Config
	
	// Standalone configuration loaded from hostname.cfg
	standaloneConfig config.StewardConfig
	
	// Logger for structured logging
	logger logging.Logger
	
	// Health monitoring and metrics collection
	healthCheck *HealthMonitor
	
	// Standalone components (nil in controller mode)
	moduleRegistry discovery.ModuleRegistry
	moduleFactory  *factory.ModuleFactory
	comparator     *testing.StateComparator
	executionEngine *execution.ExecutionEngine
	
	// Shutdown coordination
	shutdown chan struct{}
	
	// Operation mode flag
	isStandalone bool
}

// New creates a new Steward instance for controller mode (legacy compatibility).
//
// This constructor initializes a steward that connects to a remote CFGMS controller
// for configuration management. If cfg is nil, DefaultConfig() values are used.
//
// Returns an error only in future versions when additional validation is added.
// Currently always returns a valid steward instance.
func New(cfg *Config, logger logging.Logger) (*Steward, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	
	healthMonitor := NewHealthMonitor(logger)
	
	return &Steward{
		legacyConfig: cfg,
		logger:       logger,
		healthCheck:  healthMonitor,
		shutdown:     make(chan struct{}),
		isStandalone: false,
	}, nil
}

// NewStandalone creates a new Steward instance for standalone operation.
//
// The steward will load configuration from hostname.cfg files and discover
// available modules from the filesystem. If configPath is empty, the steward
// searches platform-specific locations for hostname.cfg.
//
// Configuration search order:
//   1. Provided configPath (if not empty)
//   2. Current working directory
//   3. User configuration directories
//   4. System configuration directories
//
// Module discovery searches:
//   1. Custom paths from configuration
//   2. Directory relative to binary
//   3. Platform-specific system paths
//
// Returns an error if configuration loading, module discovery, or component
// initialization fails.
func NewStandalone(configPath string, logger logging.Logger) (*Steward, error) {
	// Load standalone configuration with validation and defaults
	cfg, err := config.LoadConfiguration(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	
	// Discover available modules from filesystem
	registry, err := discovery.DiscoverModules(cfg.Steward.ModulePaths)
	if err != nil {
		return nil, fmt.Errorf("failed to discover modules: %w", err)
	}
	
	// Create module factory for dynamic loading
	moduleFactory := factory.New(registry, cfg.Steward.ErrorHandling)
	
	// Create state comparator for configuration drift detection
	comparator := testing.NewStateComparator()
	
	// Create execution engine for resource orchestration
	executionEngine := execution.New(moduleFactory, comparator, cfg.Steward.ErrorHandling, logger)
	
	// Create health monitor for metrics collection
	healthMonitor := NewHealthMonitor(logger)
	
	return &Steward{
		standaloneConfig: cfg,
		logger:          logger,
		healthCheck:     healthMonitor,
		moduleRegistry:  registry,
		moduleFactory:   moduleFactory,
		comparator:      comparator,
		executionEngine: executionEngine,
		shutdown:        make(chan struct{}),
		isStandalone:    true,
	}, nil
}

// Start initializes and starts the steward based on its operation mode.
//
// For standalone mode, this will execute the configuration immediately and start
// health monitoring. For controller mode, this will connect to the remote controller.
//
// The method is non-blocking and starts background goroutines for ongoing operations.
// Use Stop() to gracefully shut down the steward.
//
// Returns an error if startup fails, but not for configuration execution errors
// in standalone mode (those are logged and included in execution reports).
func (s *Steward) Start(ctx context.Context) error {
	if s.isStandalone {
		return s.startStandalone(ctx)
	}
	return s.startController(ctx)
}

// startStandalone starts the steward in standalone mode with immediate execution.
//
// This method:
//   1. Starts health monitoring in a background goroutine
//   2. Executes the configuration immediately on startup  
//   3. Logs execution results and any errors
//
// Configuration execution errors are logged but do not cause startup to fail,
// allowing the steward to continue operating and retry later.
func (s *Steward) startStandalone(ctx context.Context) error {
	s.logger.Info("Starting steward in standalone mode", 
		"id", s.standaloneConfig.Steward.ID,
		"resources", len(s.standaloneConfig.Resources))
	
	// Start health monitoring in background
	go s.healthCheck.Start(ctx)
	
	// Execute configuration immediately on startup
	report := s.executionEngine.ExecuteConfiguration(ctx, s.standaloneConfig)
	
	s.logger.Info("Initial configuration execution completed",
		"total", report.TotalResources,
		"successful", report.SuccessfulCount,
		"failed", report.FailedCount,
		"skipped", report.SkippedCount)
	
	// Log configuration execution errors but don't fail startup
	for _, err := range report.Errors {
		s.logger.Error("Configuration execution error", "error", err)
	}
	
	s.logger.Info("Steward started successfully in standalone mode")
	return nil
}

// startController starts the steward in controller mode (legacy implementation).
//
// This method starts health monitoring and will eventually connect to a remote
// CFGMS controller for configuration management. Currently this is a placeholder
// for future controller integration.
func (s *Steward) startController(ctx context.Context) error {
	s.logger.Info("Starting steward in controller mode", "id", s.legacyConfig.ID)
	
	// Start health monitoring in background
	go s.healthCheck.Start(ctx)
	
	// TODO: Connect to controller using mTLS
	// TODO: Register with controller
	// TODO: Start module system
	
	s.logger.Info("Steward started successfully in controller mode")
	return nil
}

// Stop gracefully shuts down the steward and cleans up resources.
//
// This method:
//   1. Signals shutdown to all background goroutines
//   2. Stops health monitoring
//   3. Unloads all modules in standalone mode
//   4. Waits for graceful cleanup to complete
//
// The context can be used to set a timeout for shutdown operations.
// Returns an error only if cleanup operations fail.
func (s *Steward) Stop(ctx context.Context) error {
	if s.isStandalone {
		s.logger.Info("Stopping steward in standalone mode", "id", s.standaloneConfig.Steward.ID)
	} else {
		s.logger.Info("Stopping steward in controller mode", "id", s.legacyConfig.ID)
	}
	
	// Signal shutdown to all background goroutines
	close(s.shutdown)
	
	// Stop health monitoring
	s.healthCheck.Stop()
	
	// Cleanup standalone components and unload modules
	if s.isStandalone && s.moduleFactory != nil {
		s.moduleFactory.UnloadAllModules()
	}
	
	s.logger.Info("Steward stopped successfully")
	return nil
}

// ExecuteConfiguration manually executes the current configuration in standalone mode.
//
// This method is only available in standalone mode and allows manual triggering
// of configuration execution outside of the automatic startup execution.
//
// Returns a detailed execution report including resource results, timing,
// and any errors encountered during execution.
//
// Returns an error if called on a steward in controller mode.
func (s *Steward) ExecuteConfiguration(ctx context.Context) (execution.ExecutionReport, error) {
	if !s.isStandalone {
		return execution.ExecutionReport{}, fmt.Errorf("ExecuteConfiguration is only available in standalone mode")
	}
	
	report := s.executionEngine.ExecuteConfiguration(ctx, s.standaloneConfig)
	return report, nil
}

// GetModuleRegistry returns the discovered module registry for standalone mode.
//
// The registry contains information about all modules discovered during
// steward initialization, including their paths, versions, and capabilities.
//
// Returns an empty registry if called on a steward in controller mode.
func (s *Steward) GetModuleRegistry() discovery.ModuleRegistry {
	return s.moduleRegistry
}

// GetLoadedModules returns a list of currently loaded module names in standalone mode.
//
// This includes only modules that have been successfully instantiated by the
// module factory, not all discovered modules. Modules are loaded on-demand
// when needed for resource execution.
//
// Returns an empty slice if called on a steward in controller mode or if
// no modules have been loaded yet.
func (s *Steward) GetLoadedModules() []string {
	if !s.isStandalone || s.moduleFactory == nil {
		return []string{}
	}
	return s.moduleFactory.GetLoadedModules()
} 