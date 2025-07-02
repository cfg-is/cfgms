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

// Config holds the steward configuration (legacy compatibility)
type Config struct {
	// Controller connection details
	ControllerAddr string `yaml:"controller_addr"`
	
	// Path to TLS certificates
	CertPath string `yaml:"cert_path"`
	
	// Data directory for local storage
	DataDir string `yaml:"data_dir"`
	
	// Log level
	LogLevel string `yaml:"log_level"`
	
	// Steward identifier
	ID string `yaml:"id"`
}

// DefaultConfig returns a Config with reasonable defaults (legacy compatibility)
func DefaultConfig() *Config {
	return &Config{
		ControllerAddr: "127.0.0.1:8080",
		CertPath:       "certs/",
		DataDir:        "data/",
		LogLevel:       "info",
		ID:             "",
	}
}

// Steward manages a single endpoint with standalone capabilities
type Steward struct {
	mu sync.RWMutex
	
	// Legacy configuration (for controller mode)
	legacyConfig *Config
	
	// Standalone configuration
	standaloneConfig config.StewardConfig
	
	// Logger
	logger logging.Logger
	
	// Health monitoring
	healthCheck *HealthMonitor
	
	// Standalone components
	moduleRegistry discovery.ModuleRegistry
	moduleFactory  *factory.ModuleFactory
	comparator     *testing.StateComparator
	executionEngine *execution.ExecutionEngine
	
	// Shutdown management
	shutdown chan struct{}
	
	// Operation mode
	isStandalone bool
}

// New creates a new Steward instance (legacy constructor for controller mode)
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

// NewStandalone creates a new Steward instance for standalone operation
func NewStandalone(configPath string, logger logging.Logger) (*Steward, error) {
	// Load standalone configuration
	cfg, err := config.LoadConfiguration(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	
	// Discover available modules
	registry, err := discovery.DiscoverModules(cfg.Steward.ModulePaths)
	if err != nil {
		return nil, fmt.Errorf("failed to discover modules: %w", err)
	}
	
	// Create module factory
	moduleFactory := factory.New(registry, cfg.Steward.ErrorHandling)
	
	// Create state comparator
	comparator := testing.NewStateComparator()
	
	// Create execution engine
	executionEngine := execution.New(moduleFactory, comparator, cfg.Steward.ErrorHandling, logger)
	
	// Create health monitor
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

// Start initializes and starts the steward
func (s *Steward) Start(ctx context.Context) error {
	if s.isStandalone {
		return s.startStandalone(ctx)
	}
	return s.startController(ctx)
}

// startStandalone starts the steward in standalone mode
func (s *Steward) startStandalone(ctx context.Context) error {
	s.logger.Info("Starting steward in standalone mode", 
		"id", s.standaloneConfig.Steward.ID,
		"resources", len(s.standaloneConfig.Resources))
	
	// Start health monitoring
	go s.healthCheck.Start(ctx)
	
	// Execute configuration once on startup
	report := s.executionEngine.ExecuteConfiguration(ctx, s.standaloneConfig)
	
	s.logger.Info("Initial configuration execution completed",
		"total", report.TotalResources,
		"successful", report.SuccessfulCount,
		"failed", report.FailedCount,
		"skipped", report.SkippedCount)
	
	// Log any errors
	for _, err := range report.Errors {
		s.logger.Error("Configuration execution error", "error", err)
	}
	
	s.logger.Info("Steward started successfully in standalone mode")
	return nil
}

// startController starts the steward in controller mode (legacy)
func (s *Steward) startController(ctx context.Context) error {
	s.logger.Info("Starting steward in controller mode", "id", s.legacyConfig.ID)
	
	// Start health monitoring
	go s.healthCheck.Start(ctx)
	
	// TODO: Connect to controller using mTLS
	// TODO: Register with controller
	// TODO: Start module system
	
	s.logger.Info("Steward started successfully in controller mode")
	return nil
}

// Stop gracefully shuts down the steward
func (s *Steward) Stop(ctx context.Context) error {
	if s.isStandalone {
		s.logger.Info("Stopping steward in standalone mode", "id", s.standaloneConfig.Steward.ID)
	} else {
		s.logger.Info("Stopping steward in controller mode", "id", s.legacyConfig.ID)
	}
	
	close(s.shutdown)
	
	// Stop health monitoring
	s.healthCheck.Stop()
	
	// Cleanup standalone components
	if s.isStandalone && s.moduleFactory != nil {
		s.moduleFactory.UnloadAllModules()
	}
	
	s.logger.Info("Steward stopped successfully")
	return nil
}

// ExecuteConfiguration executes the current configuration (standalone mode only)
func (s *Steward) ExecuteConfiguration(ctx context.Context) (execution.ExecutionReport, error) {
	if !s.isStandalone {
		return execution.ExecutionReport{}, fmt.Errorf("ExecuteConfiguration is only available in standalone mode")
	}
	
	report := s.executionEngine.ExecuteConfiguration(ctx, s.standaloneConfig)
	return report, nil
}

// GetModuleRegistry returns the module registry (standalone mode only)
func (s *Steward) GetModuleRegistry() discovery.ModuleRegistry {
	return s.moduleRegistry
}

// GetLoadedModules returns a list of currently loaded modules (standalone mode only)
func (s *Steward) GetLoadedModules() []string {
	if !s.isStandalone || s.moduleFactory == nil {
		return []string{}
	}
	return s.moduleFactory.GetLoadedModules()
} 