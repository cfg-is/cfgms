package server

import (
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Server represents the gRPC server component of the controller
type Server struct {
	cfg    *config.Config
	logger logging.Logger
}

// New creates a new server instance
func New(cfg *config.Config, logger logging.Logger) (*Server, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	
	return &Server{
		cfg:    cfg,
		logger: logger,
	}, nil
}

// Start initializes and starts the gRPC server
func (s *Server) Start() error {
	// TODO: Set up and start mTLS gRPC server
	// TODO: Register services with gRPC server
	
	s.logger.Info("Controller server started", "address", s.cfg.ListenAddr)
	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	s.logger.Info("Shutting down controller server")
	// TODO: Implement graceful shutdown of gRPC server
	return nil
} 