package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/ha"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	tenantmemory "github.com/cfgis/cfgms/features/tenant/memory"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// Server represents the gRPC server component of the controller
type Server struct {
	mu                      sync.RWMutex
	cfg                     *config.Config
	logger                  logging.Logger
	grpcServer              *grpc.Server
	controllerService       *service.ControllerService
	configService           *service.ConfigurationService
	rbacService             *service.RBACService
	certProvisioningService *service.CertificateProvisioningService
	certManager             *cert.Manager
	tenantManager           *tenant.Manager
	rbacManager             *rbac.Manager
	auditManager            *audit.Manager
	haManager               *ha.Manager
}

// New creates a new server instance
func New(cfg *config.Config, logger logging.Logger) (*Server, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	// Initialize global storage provider system - REQUIRED for all deployments
	if cfg.Storage == nil {
		return nil, fmt.Errorf("storage configuration is required for CFGMS operation - configure storage.provider as 'git' (minimum) or 'database' (production). See docs/examples/controller-storage-config.yaml for examples")
	}

	logger.Info("Initializing global storage provider", "provider", cfg.Storage.Provider)
	
	// Create storage manager with pluggable provider - no fallbacks allowed
	storageManager, err := interfaces.CreateAllStoresFromConfig(cfg.Storage.Provider, cfg.Storage.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage provider '%s': %w. Verify storage configuration and ensure storage backend is accessible", cfg.Storage.Provider, err)
	}

	// Initialize RBAC system with pluggable storage only
	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	
	// Initialize unified audit system with pluggable storage only
	auditManager := audit.NewManager(storageManager.GetAuditStore(), "controller")
	
	logger.Info("RBAC and Audit systems initialized with pluggable storage", "provider", cfg.Storage.Provider)

	// Initialize default permissions and roles
	if err := rbacManager.Initialize(context.Background()); err != nil {
		logger.Warn("Failed to initialize RBAC configuration", "error", err)
	}

	// Initialize tenant management (currently uses memory store)
	tenantStore := tenantmemory.NewStore()
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	// Create the controller service
	controllerService := service.NewControllerService(logger)

	// Create the configuration service
	configService := service.NewConfigurationService(logger, controllerService)

	// Create the RBAC service
	rbacService := service.NewRBACService(rbacManager)

	// Initialize certificate manager if enabled
	var certManager *cert.Manager
	var certProvisioningService *service.CertificateProvisioningService
	if cfg.Certificate != nil && cfg.Certificate.EnableCertManagement {
		var err error
		certManager, err = initializeCertificateManager(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize certificate manager: %w", err)
		}

		// Create certificate provisioning service
		certProvisioningService = service.NewCertificateProvisioningService(certManager, logger)
		if cfg.Certificate.ClientCertValidityDays > 0 {
			certProvisioningService.SetCertificateDefaults(
				cfg.Certificate.ClientCertValidityDays,
				cfg.Certificate.Server.Organization,
			)
		}
	}

	// Initialize HA manager
	haManager, err := initializeHAManager(cfg, logger, storageManager)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HA manager: %w", err)
	}

	return &Server{
		cfg:                     cfg,
		logger:                  logger,
		controllerService:       controllerService,
		configService:           configService,
		rbacService:             rbacService,
		certProvisioningService: certProvisioningService,
		certManager:             certManager,
		tenantManager:           tenantManager,
		rbacManager:             rbacManager,
		auditManager:            auditManager,
		haManager:               haManager,
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

	// Configure TLS with certificate management
	var opts []grpc.ServerOption
	tlsConfig, err := s.setupTLS()
	if err != nil {
		s.logger.Warn("Failed to setup TLS, starting without TLS", "error", err)
	} else if tlsConfig != nil {
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.Creds(creds))
		s.logger.Info("TLS enabled for gRPC server with certificate management")
	}

	// Create gRPC server
	s.grpcServer = grpc.NewServer(opts...)

	// Register services
	controller.RegisterControllerServer(s.grpcServer, s.controllerService)
	controller.RegisterConfigurationServiceServer(s.grpcServer, s.configService)
	controller.RegisterRBACServiceServer(s.grpcServer, s.rbacService)

	// Start HA manager
	if s.haManager != nil {
		if err := s.haManager.Start(context.Background()); err != nil {
			return fmt.Errorf("failed to start HA manager: %w", err)
		}
	}

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

	s.logger.Info("Controller server started",
		"address", s.cfg.ListenAddr,
		"ha_mode", s.haManager.GetDeploymentMode().String(),
		"is_leader", s.haManager.IsLeader())
	
	// Record system startup audit event
	if s.auditManager != nil {
		ctx := context.Background()
		event := audit.SystemEvent("system", "controller_start", fmt.Sprintf("Controller server started on %s", s.cfg.ListenAddr))
		if err := s.auditManager.RecordEvent(ctx, event); err != nil {
			s.logger.Warn("Failed to record startup audit event", "error", err)
		}
	}
	
	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("Shutting down controller server")

	// Stop HA manager first
	if s.haManager != nil {
		if err := s.haManager.Stop(context.Background()); err != nil {
			s.logger.Warn("Failed to stop HA manager", "error", err)
		}
	}

	// Record system shutdown audit event
	if s.auditManager != nil {
		ctx := context.Background()
		event := audit.SystemEvent("system", "controller_stop", "Controller server shutting down")
		if err := s.auditManager.RecordEvent(ctx, event); err != nil {
			s.logger.Warn("Failed to record shutdown audit event", "error", err)
		}
	}

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

// GetCertificateManager returns the certificate manager instance
func (s *Server) GetCertificateManager() *cert.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certManager
}

// GetCertificateProvisioningService returns the certificate provisioning service instance
func (s *Server) GetCertificateProvisioningService() *service.CertificateProvisioningService {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certProvisioningService
}

// GetControllerService returns the controller service instance
func (s *Server) GetControllerService() *service.ControllerService {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.controllerService
}

// GetRBACService returns the RBAC service instance
func (s *Server) GetRBACService() *service.RBACService {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rbacService
}

// GetTenantManager returns the tenant manager instance
func (s *Server) GetTenantManager() *tenant.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tenantManager
}

// GetRBACManager returns the RBAC manager instance
func (s *Server) GetRBACManager() *rbac.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rbacManager
}

// GetHAManager returns the HA manager instance
func (s *Server) GetHAManager() *ha.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.haManager
}

// initializeCertificateManager initializes the certificate manager based on configuration
func initializeCertificateManager(cfg *config.Config, logger logging.Logger) (*cert.Manager, error) {
	// Check if CA exists or needs to be created
	caExists := false
	if _, err := os.Stat(filepath.Join(cfg.Certificate.CAPath, "ca.crt")); err == nil {
		if _, err := os.Stat(filepath.Join(cfg.Certificate.CAPath, "ca.key")); err == nil {
			caExists = true
		}
	}

	var manager *cert.Manager
	var err error

	if caExists {
		// Load existing CA
		manager, err = cert.NewManager(&cert.ManagerConfig{
			StoragePath:          cfg.CertPath,
			LoadExistingCA:       true,
			EnableAutoRenewal:    cfg.Certificate.EnableAutoRenewal,
			RenewalThresholdDays: cfg.Certificate.RenewalThresholdDays,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to load existing CA: %w", err)
		}
		logger.Info("Loaded existing Certificate Authority")
	} else {
		// Create new CA
		caConfig := &cert.CAConfig{
			Organization: cfg.Certificate.Server.Organization,
			Country:      "US", // Default
			ValidityDays: 3650, // 10 years for CA
			StoragePath:  cfg.Certificate.CAPath,
		}

		manager, err = cert.NewManager(&cert.ManagerConfig{
			StoragePath:          cfg.CertPath,
			CAConfig:             caConfig,
			LoadExistingCA:       false,
			EnableAutoRenewal:    cfg.Certificate.EnableAutoRenewal,
			RenewalThresholdDays: cfg.Certificate.RenewalThresholdDays,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create new CA: %w", err)
		}
		logger.Info("Created new Certificate Authority")
	}

	return manager, nil
}

// setupTLS configures TLS for the gRPC server using certificate management
func (s *Server) setupTLS() (*tls.Config, error) {
	// If certificate management is disabled, try legacy certificate loading
	if s.certManager == nil {
		return s.setupLegacyTLS()
	}

	// Get or generate server certificate
	serverCert, err := s.ensureServerCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to ensure server certificate: %w", err)
	}

	// Load the certificate and key
	cert, err := tls.X509KeyPair(serverCert.CertificatePEM, serverCert.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Get CA certificate for client verification
	caCertPEM, err := s.certManager.GetCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}

	// Create CA certificate pool
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Configure mTLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}

// setupLegacyTLS configures TLS using legacy certificate files
func (s *Server) setupLegacyTLS() (*tls.Config, error) {
	certFile := filepath.Join(s.cfg.CertPath, "server.crt")
	keyFile := filepath.Join(s.cfg.CertPath, "server.key")

	// Check if certificate files exist
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return nil, nil // No TLS
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return nil, nil // No TLS
	}

	// Load certificate
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load legacy certificates: %w", err)
	}

	// Basic TLS configuration for legacy mode
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}

// ensureServerCertificate gets or generates a server certificate
func (s *Server) ensureServerCertificate() (*cert.Certificate, error) {
	// Look for existing server certificate by common name
	certificates, err := s.certManager.GetCertificateByCommonName(s.cfg.Certificate.Server.CommonName)
	if err != nil {
		return nil, fmt.Errorf("failed to search for existing certificates: %w", err)
	}

	// Check if we have a valid certificate
	for _, certInfo := range certificates {
		if certInfo.Type == cert.CertificateTypeServer && certInfo.IsValid && !certInfo.NeedsRenewal {
			// Load the full certificate
			fullCert, err := s.certManager.GetCertificate(certInfo.SerialNumber)
			if err != nil {
				s.logger.Warn("Failed to load existing certificate, will generate new one",
					"serial", certInfo.SerialNumber, "error", err)
				continue
			}

			s.logger.Info("Using existing server certificate",
				"common_name", certInfo.CommonName,
				"serial", certInfo.SerialNumber,
				"expires", certInfo.ExpiresAt.Format("2006-01-02"))
			return fullCert, nil
		}
	}

	// Generate new server certificate
	if !s.cfg.Certificate.AutoGenerate {
		return nil, fmt.Errorf("no valid server certificate found and auto-generation is disabled")
	}

	s.logger.Info("Generating new server certificate", "common_name", s.cfg.Certificate.Server.CommonName)

	serverConfig := &cert.ServerCertConfig{
		CommonName:   s.cfg.Certificate.Server.CommonName,
		DNSNames:     s.cfg.Certificate.Server.DNSNames,
		IPAddresses:  s.cfg.Certificate.Server.IPAddresses,
		Organization: s.cfg.Certificate.Server.Organization,
		ValidityDays: s.cfg.Certificate.ServerCertValidityDays,
	}

	serverCert, err := s.certManager.GenerateServerCertificate(serverConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	s.logger.Info("Generated new server certificate",
		"common_name", serverCert.CommonName,
		"serial", serverCert.SerialNumber,
		"expires", serverCert.ExpiresAt.Format("2006-01-02"))

	return serverCert, nil
}

// initializeHAManager initializes the HA manager based on configuration
func initializeHAManager(cfg *config.Config, logger logging.Logger, storageManager *interfaces.StorageManager) (*ha.Manager, error) {
	// Convert config to HA config
	haConfig, err := convertToHAConfig(cfg.HA)
	if err != nil {
		return nil, fmt.Errorf("failed to convert HA configuration: %w", err)
	}

	// Create HA manager
	haManager, err := ha.NewManager(haConfig, logger, storageManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create HA manager: %w", err)
	}

	logger.Info("HA Manager initialized",
		"mode", haConfig.GetModeString(),
		"node_id", haConfig.Node.ID)

	return haManager, nil
}

// convertToHAConfig converts controller config HA section to HA package config
func convertToHAConfig(configHA *config.HAConfig) (*ha.Config, error) {
	if configHA == nil {
		return ha.DefaultConfig(), nil
	}

	haConfig := ha.DefaultConfig()

	// Parse deployment mode
	switch configHA.Mode {
	case "single":
		haConfig.Mode = ha.SingleServerMode
	case "blue-green":
		haConfig.Mode = ha.BlueGreenMode
	case "cluster":
		haConfig.Mode = ha.ClusterMode
	default:
		return nil, fmt.Errorf("invalid HA mode: %s", configHA.Mode)
	}

	// Convert node configuration
	if configHA.Node != nil {
		haConfig.Node.ID = configHA.Node.ID
		haConfig.Node.Name = configHA.Node.Name
		haConfig.Node.ExternalAddress = configHA.Node.ExternalAddress
		haConfig.Node.InternalAddress = configHA.Node.InternalAddress
		haConfig.Node.Capabilities = configHA.Node.Capabilities
		haConfig.Node.Metadata = configHA.Node.Metadata
	}

	// Convert cluster configuration
	if configHA.Cluster != nil {
		haConfig.Cluster.ExpectedSize = configHA.Cluster.ExpectedSize
		haConfig.Cluster.MinQuorum = configHA.Cluster.MinQuorum

		if configHA.Cluster.ElectionTimeout != "" {
			if timeout, err := time.ParseDuration(configHA.Cluster.ElectionTimeout); err == nil {
				haConfig.Cluster.ElectionTimeout = timeout
			}
		}

		if configHA.Cluster.HeartbeatInterval != "" {
			if interval, err := time.ParseDuration(configHA.Cluster.HeartbeatInterval); err == nil {
				haConfig.Cluster.HeartbeatInterval = interval
			}
		}

		// Convert discovery configuration
		if configHA.Cluster.Discovery != nil {
			haConfig.Cluster.Discovery.Method = configHA.Cluster.Discovery.Method
			haConfig.Cluster.Discovery.Config = configHA.Cluster.Discovery.Config

			if configHA.Cluster.Discovery.Interval != "" {
				if interval, err := time.ParseDuration(configHA.Cluster.Discovery.Interval); err == nil {
					haConfig.Cluster.Discovery.Interval = interval
				}
			}

			if configHA.Cluster.Discovery.NodeTimeout != "" {
				if timeout, err := time.ParseDuration(configHA.Cluster.Discovery.NodeTimeout); err == nil {
					haConfig.Cluster.Discovery.NodeTimeout = timeout
				}
			}
		}

		// Convert session sync configuration
		if configHA.Cluster.SessionSync != nil {
			haConfig.Cluster.SessionSync.Enabled = configHA.Cluster.SessionSync.Enabled
			haConfig.Cluster.SessionSync.MaxStateSize = configHA.Cluster.SessionSync.MaxStateSize

			if configHA.Cluster.SessionSync.SyncInterval != "" {
				if interval, err := time.ParseDuration(configHA.Cluster.SessionSync.SyncInterval); err == nil {
					haConfig.Cluster.SessionSync.SyncInterval = interval
				}
			}

			if configHA.Cluster.SessionSync.StateTimeout != "" {
				if timeout, err := time.ParseDuration(configHA.Cluster.SessionSync.StateTimeout); err == nil {
					haConfig.Cluster.SessionSync.StateTimeout = timeout
				}
			}
		}
	}

	// Convert health check configuration
	if configHA.HealthCheck != nil {
		haConfig.HealthCheck.FailureThreshold = configHA.HealthCheck.FailureThreshold
		haConfig.HealthCheck.SuccessThreshold = configHA.HealthCheck.SuccessThreshold
		haConfig.HealthCheck.EnableInternal = configHA.HealthCheck.EnableInternal
		haConfig.HealthCheck.EnableExternal = configHA.HealthCheck.EnableExternal

		if configHA.HealthCheck.Interval != "" {
			if interval, err := time.ParseDuration(configHA.HealthCheck.Interval); err == nil {
				haConfig.HealthCheck.Interval = interval
			}
		}

		if configHA.HealthCheck.Timeout != "" {
			if timeout, err := time.ParseDuration(configHA.HealthCheck.Timeout); err == nil {
				haConfig.HealthCheck.Timeout = timeout
			}
		}
	}

	// Convert failover configuration
	if configHA.Failover != nil {
		haConfig.Failover.Enabled = configHA.Failover.Enabled
		haConfig.Failover.MaxSessionMigration = configHA.Failover.MaxSessionMigration

		if configHA.Failover.Timeout != "" {
			if timeout, err := time.ParseDuration(configHA.Failover.Timeout); err == nil {
				haConfig.Failover.Timeout = timeout
			}
		}

		if configHA.Failover.MaxDuration != "" {
			if duration, err := time.ParseDuration(configHA.Failover.MaxDuration); err == nil {
				haConfig.Failover.MaxDuration = duration
			}
		}

		if configHA.Failover.GracePeriod != "" {
			if period, err := time.ParseDuration(configHA.Failover.GracePeriod); err == nil {
				haConfig.Failover.GracePeriod = period
			}
		}
	}

	// Convert load balancing configuration
	if configHA.LoadBalancing != nil {
		switch configHA.LoadBalancing.Strategy {
		case "round-robin":
			haConfig.LoadBalancing.Strategy = ha.RoundRobinStrategy
		case "least-connections":
			haConfig.LoadBalancing.Strategy = ha.LeastConnectionsStrategy
		case "health-based":
			haConfig.LoadBalancing.Strategy = ha.HealthBasedStrategy
		}

		if configHA.LoadBalancing.HealthBased != nil {
			haConfig.LoadBalancing.HealthBased.MinHealthScore = configHA.LoadBalancing.HealthBased.MinHealthScore
			haConfig.LoadBalancing.HealthBased.HealthWeightFactor = configHA.LoadBalancing.HealthBased.HealthWeightFactor
		}

		if configHA.LoadBalancing.ConnectionBased != nil {
			haConfig.LoadBalancing.ConnectionBased.MaxConnectionsPerNode = configHA.LoadBalancing.ConnectionBased.MaxConnectionsPerNode
			haConfig.LoadBalancing.ConnectionBased.ConnectionThreshold = configHA.LoadBalancing.ConnectionBased.ConnectionThreshold
		}
	}

	// Convert split-brain configuration
	if configHA.SplitBrain != nil {
		haConfig.SplitBrain.Enabled = configHA.SplitBrain.Enabled
		haConfig.SplitBrain.ResolutionStrategy = configHA.SplitBrain.ResolutionStrategy

		if configHA.SplitBrain.DetectionInterval != "" {
			if interval, err := time.ParseDuration(configHA.SplitBrain.DetectionInterval); err == nil {
				haConfig.SplitBrain.DetectionInterval = interval
			}
		}

		if configHA.SplitBrain.QuorumInterval != "" {
			if interval, err := time.ParseDuration(configHA.SplitBrain.QuorumInterval); err == nil {
				haConfig.SplitBrain.QuorumInterval = interval
			}
		}
	}

	return haConfig, nil
}
