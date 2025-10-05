package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/ha"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	tenantmemory "github.com/cfgis/cfgms/features/tenant/memory"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
	_ "github.com/cfgis/cfgms/pkg/mqtt/providers/mochi" // Register mochi-mqtt provider
	mqttTypes "github.com/cfgis/cfgms/pkg/mqtt/types"
	quicServer "github.com/cfgis/cfgms/pkg/quic/server"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// Server represents the gRPC server component of the controller
type Server struct {
	mu                      sync.RWMutex
	cfg                     *config.Config
	logger                  logging.Logger
	grpcServer              *grpc.Server
	httpServer              *api.Server
	controllerService       *service.ControllerService
	configService           *service.ConfigurationService
	rbacService             *service.RBACService
	certProvisioningService *service.CertificateProvisioningService
	certManager             *cert.Manager
	tenantManager           *tenant.Manager
	rbacManager             *rbac.Manager
	auditManager            *audit.Manager
	haManager               *ha.Manager
	mqttBroker              mqttInterfaces.Broker
	heartbeatService        *heartbeat.Service
	commandPublisher        *commands.Publisher
	quicServer              *quicServer.Server
}

// New creates a new server instance
func New(cfg *config.Config, logger logging.Logger) (*Server, error) {
	log.Println("DEBUG server.New(): Function entry")
	logger.Info("DEBUG: Entered server.New() function")
	log.Println("DEBUG server.New(): About to check cfg nil")
	if cfg == nil {
		log.Println("DEBUG server.New(): Config is nil")
		logger.Info("DEBUG: Config is nil, returning error")
		return nil, ErrNilConfig
	}
	log.Println("DEBUG server.New(): Config validation passed")
	logger.Info("DEBUG: Config validation passed, starting server initialization...")
	log.Println("DEBUG server.New(): About to start storage initialization")
	logger.Info("Config validated, proceeding with storage initialization...")

	// Initialize global storage provider system - REQUIRED for all deployments
	log.Println("DEBUG server.New(): Checking cfg.Storage for nil")
	if cfg.Storage == nil {
		log.Println("DEBUG server.New(): cfg.Storage is nil, returning error")
		return nil, fmt.Errorf("storage configuration is required for CFGMS operation - configure storage.provider as 'git' (minimum) or 'database' (production). See docs/examples/controller-storage-config.yaml for examples")
	}
	log.Println("DEBUG server.New(): cfg.Storage is not nil, provider:", cfg.Storage.Provider)

	logger.Info("Initializing global storage provider", "provider", cfg.Storage.Provider)
	log.Println("DEBUG server.New(): About to call CreateAllStoresFromConfig with provider:", cfg.Storage.Provider)
	
	// Create storage manager with pluggable provider - no fallbacks allowed
	logger.Info("DEBUG: About to call interfaces.CreateAllStoresFromConfig...", "provider", cfg.Storage.Provider)
	log.Println("DEBUG server.New(): Calling CreateAllStoresFromConfig now...")
	storageManager, err := interfaces.CreateAllStoresFromConfig(cfg.Storage.Provider, cfg.Storage.Config)
	log.Println("DEBUG server.New(): CreateAllStoresFromConfig call completed")
	if err != nil {
		log.Println("DEBUG server.New(): CreateAllStoresFromConfig returned error:", err)
		return nil, fmt.Errorf("failed to initialize storage provider '%s': %w. Verify storage configuration and ensure storage backend is accessible", cfg.Storage.Provider, err)
	}
	log.Println("DEBUG server.New(): Storage manager created successfully, proceeding to RBAC initialization")
	logger.Info("DEBUG: Storage manager created successfully - CreateAllStoresFromConfig completed")

	// Initialize RBAC system with pluggable storage only
	logger.Info("Creating RBAC manager with storage...")
	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	logger.Info("RBAC manager created")

	// Initialize unified audit system with pluggable storage only
	logger.Info("Creating audit manager...")
	auditManager := audit.NewManager(storageManager.GetAuditStore(), "controller")
	logger.Info("Audit manager created")

	logger.Info("RBAC and Audit systems initialized with pluggable storage", "provider", cfg.Storage.Provider)

	// Initialize default permissions and roles
	logger.Info("Starting RBAC initialization...")
	if err := rbacManager.Initialize(context.Background()); err != nil {
		logger.Warn("Failed to initialize RBAC configuration", "error", err)
	}
	logger.Info("RBAC initialization completed")

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
	logger.Info("Initializing HA manager...")
	haManager, err := initializeHAManager(cfg, logger, storageManager)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HA manager: %w", err)
	}
	logger.Info("HA manager initialized successfully")

	// Initialize MQTT broker if enabled
	var mqttBroker mqttInterfaces.Broker
	var heartbeatService *heartbeat.Service
	var commandPublisher *commands.Publisher
	if cfg.MQTT != nil && cfg.MQTT.Enabled {
		logger.Info("Initializing MQTT broker...")
		mqttBroker, err = initializeMQTTBroker(cfg, logger, certManager)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize MQTT broker: %w", err)
		}
		logger.Info("MQTT broker initialized successfully")

		// Initialize heartbeat monitoring service
		logger.Info("Initializing heartbeat monitoring service...")
		heartbeatService, err = heartbeat.New(&heartbeat.Config{
			Broker:           mqttBroker,
			HeartbeatTimeout: 15 * time.Second, // Story #198 requirement
			CheckInterval:    5 * time.Second,
			OnStatusChange: func(stewardID string, healthy bool, status heartbeat.StewardStatus) {
				if healthy {
					logger.Info("Steward heartbeat recovered", "steward_id", stewardID)
				} else {
					logger.Warn("Steward heartbeat failed", "steward_id", stewardID, "status", status.Status)
				}
			},
			Logger: logger,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize heartbeat service: %w", err)
		}
		logger.Info("Heartbeat monitoring service initialized successfully")

		// Initialize command publisher (Story #198)
		logger.Info("Initializing command publisher...")
		commandPublisher, err = commands.New(&commands.Config{
			Broker: mqttBroker,
			Logger: logger,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize command publisher: %w", err)
		}
		logger.Info("Command publisher initialized successfully")
	}

	// Initialize QUIC server if enabled (Story #198)
	var quicSrv *quicServer.Server
	if cfg.QUIC != nil && cfg.QUIC.Enabled {
		logger.Info("Initializing QUIC server...")
		quicSrv, err = initializeQUICServer(cfg, logger, certManager, configService, controllerService)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize QUIC server: %w", err)
		}
		logger.Info("QUIC server initialized successfully")
	}

	// Initialize HTTP API server with minimal monitoring for now
	// TODO: Properly initialize monitoring components when needed
	httpServer, err := api.New(
		cfg,
		logger,
		controllerService,
		configService,
		certProvisioningService,
		rbacService,
		certManager,
		tenantManager,
		rbacManager,
		nil, // systemMonitor
		nil, // platformMonitor
		nil, // tracer
		haManager,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP API server: %w", err)
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
		mqttBroker:              mqttBroker,
		heartbeatService:        heartbeatService,
		commandPublisher:        commandPublisher,
		quicServer:              quicSrv,
		httpServer:              httpServer,
	}, nil
}

// Start initializes and starts the gRPC server
func (s *Server) Start() error {
	log.Println("DEBUG server.Start(): Function entry")
	s.logger.Info("DEBUG: Entered server.Start() function")
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Println("DEBUG server.Start(): About to create listener")
	// Create listener
	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		log.Println("DEBUG server.Start(): Failed to create listener")
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.ListenAddr, err)
	}
	log.Println("DEBUG server.Start(): Listener created successfully")

	// Update config with actual bound address (important for :0 ports)
	s.cfg.ListenAddr = listener.Addr().String()

	log.Println("DEBUG server.Start(): About to configure TLS")
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
	log.Println("DEBUG server.Start(): TLS configuration completed")

	log.Println("DEBUG server.Start(): About to create gRPC server")
	// Create gRPC server
	s.grpcServer = grpc.NewServer(opts...)
	log.Println("DEBUG server.Start(): gRPC server created")

	log.Println("DEBUG server.Start(): About to register services")
	// Register services
	controller.RegisterControllerServer(s.grpcServer, s.controllerService)
	controller.RegisterConfigurationServiceServer(s.grpcServer, s.configService)
	controller.RegisterRBACServiceServer(s.grpcServer, s.rbacService)
	log.Println("DEBUG server.Start(): Services registered")

	log.Println("DEBUG server.Start(): About to start HA manager")
	// Start HA manager with timeout
	if s.haManager != nil {
		s.logger.Info("Starting HA manager...")

		// Create a context with timeout to prevent infinite hang
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		log.Println("DEBUG server.Start(): About to call haManager.Start() with 30s timeout")
		if err := s.haManager.Start(ctx); err != nil {
			log.Println("DEBUG server.Start(): HA manager failed to start:", err)
			return fmt.Errorf("failed to start HA manager: %w", err)
		}
		s.logger.Info("HA manager started successfully")
		log.Println("DEBUG server.Start(): HA manager started successfully")
	} else {
		log.Println("DEBUG server.Start(): HA manager is nil, skipping")
	}

	// Start MQTT broker if configured
	if s.mqttBroker != nil {
		s.logger.Info("Starting MQTT broker...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.mqttBroker.Start(ctx); err != nil {
			return fmt.Errorf("failed to start MQTT broker: %w", err)
		}
		s.logger.Info("MQTT broker started successfully",
			"listen_addr", s.mqttBroker.GetListenAddress(),
			"provider", s.mqttBroker.Name())

		// Start heartbeat monitoring service
		if s.heartbeatService != nil {
			s.logger.Info("Starting heartbeat monitoring service...")
			if err := s.heartbeatService.Start(ctx); err != nil {
				return fmt.Errorf("failed to start heartbeat service: %w", err)
			}
			s.logger.Info("Heartbeat monitoring service started successfully")
		}

		// Start command publisher (Story #198)
		if s.commandPublisher != nil {
			s.logger.Info("Starting command publisher...")
			if err := s.commandPublisher.Start(ctx); err != nil {
				return fmt.Errorf("failed to start command publisher: %w", err)
			}
			s.logger.Info("Command publisher started successfully")
		}

		// Subscribe to DNA updates from stewards (Story #198)
		dnaUpdateTopic := "cfgms/steward/+/dna"
		if err := s.mqttBroker.Subscribe(ctx, dnaUpdateTopic, 1, s.handleDNAUpdate); err != nil {
			return fmt.Errorf("failed to subscribe to DNA updates: %w", err)
		}
		s.logger.Info("Subscribed to DNA updates", "topic", dnaUpdateTopic)
	}

	// Start QUIC server (Story #198)
	if s.quicServer != nil {
		s.logger.Info("Starting QUIC server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.quicServer.Start(ctx); err != nil {
			return fmt.Errorf("failed to start QUIC server: %w", err)
		}
		s.logger.Info("QUIC server started successfully",
			"listen_addr", s.cfg.QUIC.ListenAddr)
	}

	// Start HTTP API server
	if s.httpServer != nil {
		go func() {
			if err := s.httpServer.Start(); err != nil {
				s.logger.Error("HTTP API server failed", "error", err)
			}
		}()
		s.logger.Info("HTTP API server started")
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

	// Stop QUIC server (Story #198)
	if s.quicServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.quicServer.Stop(ctx); err != nil {
			s.logger.Warn("Failed to stop QUIC server", "error", err)
		}
	}

	// Stop command publisher
	if s.commandPublisher != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.commandPublisher.Stop(ctx); err != nil {
			s.logger.Warn("Failed to stop command publisher", "error", err)
		}
	}

	// Stop heartbeat service
	if s.heartbeatService != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.heartbeatService.Stop(ctx); err != nil {
			s.logger.Warn("Failed to stop heartbeat service", "error", err)
		}
	}

	// Stop MQTT broker
	if s.mqttBroker != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.mqttBroker.Stop(ctx); err != nil {
			s.logger.Warn("Failed to stop MQTT broker", "error", err)
		}
	}

	// Stop HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Stop(); err != nil {
			s.logger.Warn("Failed to stop HTTP server", "error", err)
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
	// Load HA config directly from environment variables (bypassing controller config)
	haConfig := ha.DefaultConfig()
	log.Printf("DEBUG: NodeID Trace - Before LoadFromEnvironment: node_id=%s, node_id_empty=%t", haConfig.Node.ID, haConfig.Node.ID == "")

	if err := haConfig.LoadFromEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to load HA configuration from environment: %w", err)
	}

	log.Printf("DEBUG: NodeID Trace - After LoadFromEnvironment: node_id=%s, node_id_empty=%t", haConfig.Node.ID, haConfig.Node.ID == "")

	// Create HA manager
	log.Printf("DEBUG: NodeID Trace - Before NewManager: node_id=%s, node_id_empty=%t", haConfig.Node.ID, haConfig.Node.ID == "")

	haManager, err := ha.NewManager(haConfig, logger, storageManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create HA manager: %w", err)
	}

	log.Printf("DEBUG: NodeID Trace - After NewManager (HA Manager initialized): mode=%s, node_id=%s, node_id_empty=%t, manager_node_id=%s, manager_node_id_empty=%t", haConfig.GetModeString(), haConfig.Node.ID, haConfig.Node.ID == "", haManager.GetLocalNode().ID, haManager.GetLocalNode().ID == "")

	return haManager, nil
}

func initializeMQTTBroker(cfg *config.Config, logger logging.Logger, certManager *cert.Manager) (mqttInterfaces.Broker, error) {
	// Get mochi-mqtt broker from registry
	broker := mqttInterfaces.GetBroker("mochi")
	if broker == nil {
		return nil, fmt.Errorf("mochi-mqtt broker not registered")
	}

	// Build MQTT broker configuration
	mqttConfig := map[string]interface{}{
		"listen_addr":             cfg.MQTT.ListenAddr,
		"enable_tls":              cfg.MQTT.EnableTLS,
		"require_client_cert":     cfg.MQTT.RequireClientCert,
		"max_clients":             cfg.MQTT.MaxClients,
		"max_message_size":        float64(cfg.MQTT.MaxMessageSize),
		"session_expiry_interval": cfg.MQTT.SessionExpiryInterval,
	}

	// Configure TLS certificates
	if cfg.MQTT.EnableTLS {
		var serverCertPath, serverKeyPath, caPath string

		if cfg.MQTT.UseCertManager && certManager != nil {
			// Use certificate manager certificates
			serverCertPath = filepath.Join(cfg.Certificate.CAPath, "server", "server.crt")
			serverKeyPath = filepath.Join(cfg.Certificate.CAPath, "server", "server.key")
			caPath = filepath.Join(cfg.Certificate.CAPath, "ca.crt")

			// Check if certificates exist, if not try to generate them (for testing)
			if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
				logger.Info("MQTT certificates not found, generating test certificates for development/testing")
				if err := ensureMQTTTestCertificates(cfg.Certificate.CAPath); err != nil {
					return nil, fmt.Errorf("failed to generate test certificates: %w", err)
				}
			}

			logger.Info("MQTT broker using certificate manager certificates",
				"cert_path", serverCertPath,
				"ca_path", caPath)
		} else if cfg.MQTT.TLSCertPath != "" && cfg.MQTT.TLSKeyPath != "" {
			// Use manually configured certificate paths
			serverCertPath = cfg.MQTT.TLSCertPath
			serverKeyPath = cfg.MQTT.TLSKeyPath
			caPath = cfg.MQTT.TLSCAPath

			logger.Info("MQTT broker using configured certificates",
				"cert_path", cfg.MQTT.TLSCertPath,
				"ca_path", cfg.MQTT.TLSCAPath)
		} else {
			return nil, fmt.Errorf("TLS enabled but no certificates configured")
		}

		mqttConfig["tls_cert_path"] = serverCertPath
		mqttConfig["tls_key_path"] = serverKeyPath
		if caPath != "" {
			mqttConfig["tls_ca_path"] = caPath
		}
	}

	// Initialize broker with configuration
	if err := broker.Initialize(mqttConfig); err != nil {
		return nil, fmt.Errorf("failed to initialize MQTT broker: %w", err)
	}

	// Check if broker is available (has required certificates, etc.)
	available, err := broker.Available()
	if !available {
		return nil, fmt.Errorf("MQTT broker not available: %w", err)
	}

	logger.Info("MQTT broker initialized and ready",
		"provider", broker.Name(),
		"listen_addr", cfg.MQTT.ListenAddr,
		"tls_enabled", cfg.MQTT.EnableTLS,
		"mtls_enabled", cfg.MQTT.RequireClientCert)

	return broker, nil
}

// ensureMQTTTestCertificates generates test certificates for MQTT broker if they don't exist.
// This follows the same pattern as our other test certificate generation.
func ensureMQTTTestCertificates(caPath string) error {
	// Create directory structure
	serverDir := filepath.Join(caPath, "server")
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		return fmt.Errorf("failed to create server cert directory: %w", err)
	}
	if err := os.MkdirAll(caPath, 0755); err != nil {
		return fmt.Errorf("failed to create CA directory: %w", err)
	}

	// Generate CA certificate
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"CFGMS MQTT CA"},
			CommonName:   "CFGMS MQTT CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Save CA certificate
	caCertFile, err := os.Create(filepath.Join(caPath, "ca.crt"))
	if err != nil {
		return fmt.Errorf("failed to create CA cert file: %w", err)
	}
	if err := pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
		caCertFile.Close()
		return fmt.Errorf("failed to encode CA certificate: %w", err)
	}
	caCertFile.Close()

	// Generate server certificate
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"CFGMS MQTT Server"},
			CommonName:   "cfgms-mqtt-server",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(0, 0, 0, 0)},
		DNSNames:    []string{"localhost", "cfgms-mqtt-server"},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Save server certificate
	serverCertFile, err := os.Create(filepath.Join(serverDir, "server.crt"))
	if err != nil {
		return fmt.Errorf("failed to create server cert file: %w", err)
	}
	if err := pem.Encode(serverCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}); err != nil {
		serverCertFile.Close()
		return fmt.Errorf("failed to encode server certificate: %w", err)
	}
	serverCertFile.Close()

	// Save server key
	serverKeyFile, err := os.Create(filepath.Join(serverDir, "server.key"))
	if err != nil {
		return fmt.Errorf("failed to create server key file: %w", err)
	}
	if err := pem.Encode(serverKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}); err != nil {
		serverKeyFile.Close()
		return fmt.Errorf("failed to encode server key: %w", err)
	}
	serverKeyFile.Close()

	return nil
}

func initializeQUICServer(cfg *config.Config, logger logging.Logger, certManager *cert.Manager, configService *service.ConfigurationService, controllerService *service.ControllerService) (*quicServer.Server, error) {
	// Build TLS config for QUIC
	var tlsConfig *tls.Config

	if cfg.QUIC.UseCertManager && certManager != nil {
		// Use certificate manager certificates (same as MQTT)
		serverCertPath := filepath.Join(cfg.Certificate.CAPath, "server", "server.crt")
		serverKeyPath := filepath.Join(cfg.Certificate.CAPath, "server", "server.key")
		caPath := filepath.Join(cfg.Certificate.CAPath, "ca.crt")

		// Check if certificates exist
		if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
			logger.Info("QUIC certificates not found, using MQTT certificates")
			// MQTT cert generation already happened, so these should exist
			if err := ensureMQTTTestCertificates(cfg.Certificate.CAPath); err != nil {
				return nil, fmt.Errorf("failed to ensure certificates: %w", err)
			}
		}

		// Load certificate
		cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load QUIC certificate: %w", err)
		}

		// Load CA certificate for client verification
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caCertPool,
			MinVersion:   tls.VersionTLS13, // QUIC requires TLS 1.3
			NextProtos:   []string{"cfgms-quic"}, // Application protocol
		}

		logger.Info("QUIC server using certificate manager certificates",
			"cert_path", serverCertPath,
			"ca_path", caPath)
	} else if cfg.QUIC.TLSCertPath != "" && cfg.QUIC.TLSKeyPath != "" {
		// Use manually configured certificate paths
		cert, err := tls.LoadX509KeyPair(cfg.QUIC.TLSCertPath, cfg.QUIC.TLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load QUIC certificate: %w", err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"cfgms-quic"},
		}

		logger.Info("QUIC server using configured certificates",
			"cert_path", cfg.QUIC.TLSCertPath)
	} else {
		return nil, fmt.Errorf("QUIC enabled but no certificates configured")
	}

	// Create QUIC server
	sessionTimeout := time.Duration(cfg.QUIC.SessionTimeout) * time.Second
	quicSrv, err := quicServer.New(&quicServer.Config{
		ListenAddr:     cfg.QUIC.ListenAddr,
		TLSConfig:      tlsConfig,
		SessionTimeout: sessionTimeout,
		Logger:         logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create QUIC server: %w", err)
	}

	// Register stream handlers
	// Stream 1: Configuration sync
	quicSrv.RegisterStreamHandler(1, func(ctx context.Context, session *quicServer.Session, stream *quic.Stream) error {
		return handleConfigSyncStream(ctx, session, stream, configService, logger)
	})

	// Stream 2: DNA sync
	quicSrv.RegisterStreamHandler(2, func(ctx context.Context, session *quicServer.Session, stream *quic.Stream) error {
		return handleDNASyncStream(ctx, session, stream, controllerService, logger)
	})

	logger.Info("QUIC server initialized",
		"listen_addr", cfg.QUIC.ListenAddr,
		"session_timeout", sessionTimeout,
		"tls_version", "TLS 1.3")

	return quicSrv, nil
}

// handleConfigSyncStream handles configuration sync requests on stream 1.
func handleConfigSyncStream(ctx context.Context, session *quicServer.Session, stream *quic.Stream, configService *service.ConfigurationService, logger logging.Logger) error {
	logger.Info("Handling config sync request",
		"session_id", session.ID,
		"steward_id", session.StewardID)

	// Read steward ID from stream
	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read steward ID: %w", err)
	}

	stewardID := string(buf[:n])
	// Remove newline if present
	if len(stewardID) > 0 && stewardID[len(stewardID)-1] == '\n' {
		stewardID = stewardID[:len(stewardID)-1]
	}

	logger.Info("Config sync request received",
		"steward_id", stewardID,
		"session_id", session.ID)

	// Fetch configuration from ConfigurationService
	configReq := &controller.ConfigRequest{
		StewardId: stewardID,
	}

	configResp, err := configService.GetConfiguration(ctx, configReq)
	if err != nil {
		logger.Error("Failed to get configuration",
			"steward_id", stewardID,
			"error", err)
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Check if configuration was found
	if configResp.Status.Code != common.Status_OK {
		logger.Warn("Configuration not available",
			"steward_id", stewardID,
			"status", configResp.Status.Code,
			"message", configResp.Status.Message)

		// Send error response
		errorMsg := fmt.Sprintf("ERROR: %s\n", configResp.Status.Message)
		if _, err := stream.Write([]byte(errorMsg)); err != nil {
			return fmt.Errorf("failed to write error response: %w", err)
		}
		return nil
	}

	// Marshal configuration to JSON
	configData, err := json.Marshal(configResp.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Send configuration data
	if _, err := stream.Write(configData); err != nil {
		return fmt.Errorf("failed to write config response: %w", err)
	}

	logger.Info("Config sync response sent",
		"steward_id", stewardID,
		"bytes_sent", len(configData))

	return nil
}

// handleDNASyncStream handles DNA sync requests on stream 2.
func handleDNASyncStream(ctx context.Context, session *quicServer.Session, stream *quic.Stream, controllerService *service.ControllerService, logger logging.Logger) error {
	logger.Info("Handling DNA sync request",
		"session_id", session.ID,
		"steward_id", session.StewardID)

	// Read steward ID from stream
	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read steward ID: %w", err)
	}

	stewardID := string(buf[:n])
	// Remove newline if present
	if len(stewardID) > 0 && stewardID[len(stewardID)-1] == '\n' {
		stewardID = stewardID[:len(stewardID)-1]
	}

	logger.Info("DNA sync request received",
		"steward_id", stewardID,
		"session_id", session.ID)

	// Fetch DNA from ControllerService
	dnaReq := &controller.StewardRequest{
		StewardId: stewardID,
	}

	dna, err := controllerService.GetStewardDNA(ctx, dnaReq)
	if err != nil {
		logger.Error("Failed to get DNA",
			"steward_id", stewardID,
			"error", err)

		// Send error response
		errorMsg := fmt.Sprintf("ERROR: %s\n", err.Error())
		if _, writeErr := stream.Write([]byte(errorMsg)); writeErr != nil {
			return fmt.Errorf("failed to write error response: %w", writeErr)
		}
		return nil
	}

	// Marshal DNA to JSON
	dnaData, err := json.Marshal(dna)
	if err != nil {
		return fmt.Errorf("failed to marshal DNA: %w", err)
	}

	// Send DNA data
	if _, err := stream.Write(dnaData); err != nil {
		return fmt.Errorf("failed to write DNA response: %w", err)
	}

	logger.Info("DNA sync response sent",
		"steward_id", stewardID,
		"bytes_sent", len(dnaData))

	return nil
}


// handleDNAUpdate processes DNA update messages from stewards via MQTT.
func (s *Server) handleDNAUpdate(topic string, payload []byte, qos byte, retained bool) error {
	var dnaUpdate mqttTypes.DNAUpdate
	if err := json.Unmarshal(payload, &dnaUpdate); err != nil {
		s.logger.Error("Failed to parse DNA update", "error", err)
		return fmt.Errorf("failed to parse DNA update: %w", err)
	}

	s.logger.Info("Received DNA update via MQTT",
		"steward_id", dnaUpdate.StewardID,
		"attributes_count", len(dnaUpdate.DNA),
		"config_hash", dnaUpdate.ConfigHash)

	// Convert to protobuf DNA format
	dna := &common.DNA{
		Id:              dnaUpdate.StewardID,
		Attributes:      dnaUpdate.DNA,
		ConfigHash:      dnaUpdate.ConfigHash,
		SyncFingerprint: dnaUpdate.SyncFingerprint,
		LastUpdated:     timestamppb.New(dnaUpdate.Timestamp),
	}

	// Update DNA in controller service
	ctx := context.Background()
	status, err := s.controllerService.SyncDNA(ctx, dna)
	if err != nil {
		s.logger.Error("Failed to sync DNA",
			"steward_id", dnaUpdate.StewardID,
			"error", err)
		return fmt.Errorf("failed to sync DNA: %w", err)
	}

	if status.Code != common.Status_OK {
		s.logger.Warn("DNA sync returned non-OK status",
			"steward_id", dnaUpdate.StewardID,
			"status_code", status.Code,
			"message", status.Message)
	} else {
		s.logger.Info("DNA synced successfully via MQTT",
			"steward_id", dnaUpdate.StewardID)
	}

	return nil
}

