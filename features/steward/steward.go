package steward

import (
	"context"
	"sync"
	
	"cfgms/pkg/logging"
)

// Config holds the steward configuration
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

// DefaultConfig returns a Config with reasonable defaults
func DefaultConfig() *Config {
	return &Config{
		ControllerAddr: "127.0.0.1:8080",
		CertPath:       "certs/",
		DataDir:        "data/",
		LogLevel:       "info",
		ID:             "",
	}
}

// Steward manages a single endpoint
type Steward struct {
	mu sync.RWMutex
	
	// Configuration
	config *Config
	
	// Logger
	logger logging.Logger
	
	// Health monitoring
	healthCheck *HealthMonitor
	
	// Shutdown management
	shutdown chan struct{}
}

// New creates a new Steward instance
func New(cfg *Config, logger logging.Logger) (*Steward, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	
	healthMonitor := NewHealthMonitor(logger)
	
	return &Steward{
		config:      cfg,
		logger:      logger,
		healthCheck: healthMonitor,
		shutdown:    make(chan struct{}),
	}, nil
}

// Start initializes and starts the steward
func (s *Steward) Start(ctx context.Context) error {
	s.logger.Info("Starting steward", "id", s.config.ID)
	
	// Start health monitoring
	go s.healthCheck.Start(ctx)
	
	// TODO: Connect to controller using mTLS
	// TODO: Register with controller
	// TODO: Start module system
	
	s.logger.Info("Steward started successfully")
	return nil
}

// Stop gracefully shuts down the steward
func (s *Steward) Stop(ctx context.Context) error {
	s.logger.Info("Stopping steward", "id", s.config.ID)
	close(s.shutdown)
	
	// Stop health monitoring
	s.healthCheck.Stop()
	
	// TODO: Implement graceful shutdown
	// TODO: Disconnect from controller
	
	s.logger.Info("Steward stopped successfully")
	return nil
} 