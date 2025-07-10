package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Server represents the gRPC server component of the controller
type Server struct {
	mu                sync.RWMutex
	cfg               *config.Config
	logger            logging.Logger
	grpcServer        *grpc.Server
	controllerService *service.ControllerService
	configService     *service.ConfigurationService
}

// New creates a new server instance
func New(cfg *config.Config, logger logging.Logger) (*Server, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	
	// Create the controller service
	controllerService := service.NewControllerService(logger)
	
	// Create the configuration service
	configService := service.NewConfigurationService(logger, controllerService)
	
	return &Server{
		cfg:               cfg,
		logger:            logger,
		controllerService: controllerService,
		configService:     configService,
	}, nil
}

// Start initializes and starts the gRPC server
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Create listener
	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.ListenAddr, err)
	}
	
	// Update config with actual bound address (important for :0 ports)
	s.cfg.ListenAddr = listener.Addr().String()
	
	// Configure TLS (if certificates are available)
	var opts []grpc.ServerOption
	certFile := s.cfg.CertPath + "/server.crt"
	keyFile := s.cfg.CertPath + "/server.key"
	
	// Check if certificate files exist
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				s.logger.Warn("Failed to load TLS certificates, starting without TLS", "error", err)
			} else {
				creds := credentials.NewTLS(&tls.Config{
					Certificates: []tls.Certificate{cert},
				})
				opts = append(opts, grpc.Creds(creds))
				s.logger.Info("TLS enabled for gRPC server")
			}
		}
	}
	
	// Create gRPC server
	s.grpcServer = grpc.NewServer(opts...)
	
	// Register services
	controller.RegisterControllerServer(s.grpcServer, s.controllerService)
	controller.RegisterConfigurationServiceServer(s.grpcServer, s.configService)
	
	// Start serving in a goroutine
	go func() {
		s.mu.RLock()
		server := s.grpcServer
		s.mu.RUnlock()
		
		if server != nil {
			if err := server.Serve(listener); err != nil {
				s.logger.Error("gRPC server failed", "error", err)
			}
		}
	}()
	
	s.logger.Info("Controller server started", "address", s.cfg.ListenAddr)
	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.logger.Info("Shutting down controller server")
	
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	
	return nil
}

// GetConfigurationService returns the configuration service instance
func (s *Server) GetConfigurationService() *service.ConfigurationService {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configService
}

// GetListenAddr returns the actual listen address after binding
func (s *Server) GetListenAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ListenAddr
} 