// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/types/known/timestamppb"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/commercial/ha"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	controllerQuic "github.com/cfgis/cfgms/features/controller/quic"
	"github.com/cfgis/cfgms/features/controller/registration"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
	_ "github.com/cfgis/cfgms/pkg/mqtt/providers/mochi" // Register mochi-mqtt provider
	mqttTypes "github.com/cfgis/cfgms/pkg/mqtt/types"
	quicServer "github.com/cfgis/cfgms/pkg/quic/server"
	quicSession "github.com/cfgis/cfgms/pkg/quic/session"
	pkgRegistration "github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// Server represents the controller server component (MQTT+QUIC based)
type Server struct {
	mu                      sync.RWMutex
	cfg                     *config.Config
	logger                  logging.Logger
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
	registrationHandler     *registration.Handler
	registrationTokenStore  pkgRegistration.Store
	quicServer              *quicServer.Server
	quicSessionManager      *quicSession.Manager
}

// New creates a new server instance
func New(cfg *config.Config, logger logging.Logger) (*Server, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	logger.Info("Config validated, proceeding with storage initialization...")

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
	auditStore := storageManager.GetAuditStore()
	clientTenantStore := storageManager.GetClientTenantStore()
	rbacStore := storageManager.GetRBACStore()

	logger.Info("Creating RBAC manager with storage...")
	rbacManager := rbac.NewManagerWithStorage(
		auditStore,
		clientTenantStore,
		rbacStore,
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

	// Initialize tenant management with durable storage
	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
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
	var registrationHandler *registration.Handler
	var regStore pkgRegistration.Store
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

		// Initialize registration handler (Story #198, updated Story #263)
		logger.Info("Initializing registration handler...")
		// Registration token storage - now uses durable storage from storage manager
		// Story #263: Migrated from in-memory to pluggable durable storage (git/database)
		regTokenStore := storageManager.GetRegistrationTokenStore()
		if err := regTokenStore.Initialize(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to initialize registration token store: %w", err)
		}
		regStore = pkgRegistration.NewStorageAdapter(regTokenStore)

		// For Docker testing: Create pre-configured test tokens
		// These tokens are used by integration tests in test/integration/mqtt_quic/
		now := time.Now()
		expiredTime := now.Add(-1 * time.Hour)
		testTokens := []*pkgRegistration.Token{
			{
				Token:         "cfgms_reg_dockertest_standalone",
				TenantID:      "test-tenant",
				ControllerURL: "tcp://controller-standalone:1883",
				Group:         "test-group",
				CreatedAt:     now,
				ExpiresAt:     nil,   // Never expires for testing
				SingleUse:     false, // Can be reused for testing
				Revoked:       false,
			},
			{
				Token:         "cfgms_reg_integration_reusable",
				TenantID:      "test-tenant-integration",
				ControllerURL: "tcp://localhost:1886",
				Group:         "production",
				CreatedAt:     now,
				ExpiresAt:     nil,   // Never expires for testing
				SingleUse:     false, // Can be reused for integration tests
				Revoked:       false,
			},
			{
				Token:         "cfgms_reg_integration_expired",
				TenantID:      "test-tenant-integration",
				ControllerURL: "tcp://localhost:1886",
				Group:         "production",
				CreatedAt:     now.Add(-2 * time.Hour),
				ExpiresAt:     &expiredTime, // Expired 1 hour ago
				SingleUse:     true,
				Revoked:       false,
			},
			{
				Token:         "cfgms_reg_integration_revoked",
				TenantID:      "test-tenant-integration",
				ControllerURL: "tcp://localhost:1886",
				Group:         "production",
				CreatedAt:     now,
				ExpiresAt:     nil,
				SingleUse:     true,
				Revoked:       true, // Revoked token
				RevokedAt:     &now,
			},
			{
				Token:         "cfgms_reg_integration_singleuse",
				TenantID:      "test-tenant-integration",
				ControllerURL: "tcp://localhost:1886",
				Group:         "production",
				CreatedAt:     now,
				ExpiresAt:     nil,
				SingleUse:     true, // Single-use token
				Revoked:       false,
			},
		}

		for _, testToken := range testTokens {
			if err := regStore.SaveToken(context.Background(), testToken); err != nil {
				logger.Warn("Failed to create test token for Docker testing", "error", err, "token", testToken.Token)
			} else {
				logger.Info("Created test registration token for Docker testing", "token", testToken.Token, "tenant", testToken.TenantID)
			}
		}

		regValidator := pkgRegistration.NewValidator(regStore)
		registrationHandler, err = registration.New(&registration.Config{
			Broker:    mqttBroker,
			Validator: regValidator,
			Logger:    logger,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize registration handler: %w", err)
		}
		logger.Info("Registration handler initialized successfully")
	}

	// Initialize QUIC server if enabled (Story #198)
	var quicSrv *quicServer.Server
	var quicSessionMgr *quicSession.Manager
	if cfg.QUIC != nil && cfg.QUIC.Enabled {
		logger.Info("Initializing QUIC server...")
		quicSrv, quicSessionMgr, err = initializeQUICServer(cfg, logger, certManager, configService, controllerService)
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
		regStore, // registrationTokenStore
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
		registrationHandler:     registrationHandler,
		registrationTokenStore:  regStore,
		quicServer:              quicSrv,
		quicSessionManager:      quicSessionMgr,
		httpServer:              httpServer,
	}, nil
}

// Start initializes and starts the controller server (MQTT+QUIC mode)
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Start HA manager with timeout
	if s.haManager != nil {
		s.logger.Info("Starting HA manager...")

		// Create a context with timeout to prevent infinite hang
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.haManager.Start(ctx); err != nil {
			return fmt.Errorf("failed to start HA manager: %w", err)
		}
		s.logger.Info("HA manager started successfully")
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

		// Start registration handler (Story #198)
		if s.registrationHandler != nil {
			s.logger.Info("Starting registration handler...")
			if err := s.registrationHandler.Start(ctx); err != nil {
				return fmt.Errorf("failed to start registration handler: %w", err)
			}
			s.logger.Info("Registration handler started successfully")
		}

		// Subscribe to DNA updates from stewards (Story #198)
		dnaUpdateTopic := "cfgms/steward/+/dna"
		if err := s.mqttBroker.Subscribe(ctx, dnaUpdateTopic, 1, s.handleDNAUpdate); err != nil {
			return fmt.Errorf("failed to subscribe to DNA updates: %w", err)
		}
		s.logger.Info("Subscribed to DNA updates", "topic", dnaUpdateTopic)

		// Subscribe to configuration status reports from stewards (Story #198)
		configStatusTopic := "cfgms/steward/+/config-status"
		if err := s.mqttBroker.Subscribe(ctx, configStatusTopic, 1, s.handleConfigStatusReport); err != nil {
			return fmt.Errorf("failed to subscribe to config status reports: %w", err)
		}
		s.logger.Info("Subscribed to config status reports", "topic", configStatusTopic)

		// Subscribe to configuration validation requests from stewards (Story #198)
		validationRequestTopic := "cfgms/steward/+/validate-request"
		if err := s.mqttBroker.Subscribe(ctx, validationRequestTopic, 1, s.handleValidationRequest); err != nil {
			return fmt.Errorf("failed to subscribe to validation requests: %w", err)
		}
		s.logger.Info("Subscribed to validation requests", "topic", validationRequestTopic)
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

	s.logger.Info("Controller server started (MQTT+QUIC mode)",
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

	// Stop registration handler
	if s.registrationHandler != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.registrationHandler.Stop(ctx); err != nil {
			s.logger.Warn("Failed to stop registration handler", "error", err)
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

// TriggerQUICConnection initiates a QUIC connection to a steward.
// This generates a session ID and sends a connect_quic command via MQTT.
func (s *Server) TriggerQUICConnection(ctx context.Context, stewardID string) (string, error) {
	if s.quicSessionManager == nil {
		return "", fmt.Errorf("QUIC session manager not available")
	}
	if s.commandPublisher == nil {
		return "", fmt.Errorf("command publisher not available")
	}
	if s.cfg.QUIC == nil || !s.cfg.QUIC.Enabled {
		return "", fmt.Errorf("QUIC is not enabled")
	}

	// Generate session ID for this QUIC connection
	session, err := s.quicSessionManager.GenerateSession(stewardID)
	if err != nil {
		return "", fmt.Errorf("failed to generate QUIC session: %w", err)
	}

	s.logger.Info("Generated QUIC session",
		"steward_id", stewardID,
		"session_id", session.SessionID,
		"expires_at", session.ExpiresAt)

	// Send connect_quic command to steward via MQTT
	commandID, err := s.commandPublisher.TriggerQUICConnection(
		ctx,
		stewardID,
		s.cfg.QUIC.ListenAddr,
		session.SessionID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to send connect_quic command: %w", err)
	}

	s.logger.Info("Triggered QUIC connection for steward",
		"steward_id", stewardID,
		"session_id", session.SessionID,
		"command_id", commandID,
		"quic_address", s.cfg.QUIC.ListenAddr)

	return commandID, nil
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

// initializeHAManager initializes the HA manager based on configuration
func initializeHAManager(cfg *config.Config, logger logging.Logger, storageManager *interfaces.StorageManager) (*ha.Manager, error) {
	// Load HA config directly from environment variables (bypassing controller config)
	haConfig := ha.DefaultConfig()

	if err := haConfig.LoadFromEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to load HA configuration from environment: %w", err)
	}

	// Create HA manager
	haManager, err := ha.NewManager(haConfig, logger, storageManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create HA manager: %w", err)
	}

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

			// Check if certificates exist, if not generate them using certManager
			if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
				logger.Info("MQTT certificates not found, generating using certificate manager")
				if err := ensureMQTTCertificatesFromManager(cfg.Certificate.CAPath, certManager, logger); err != nil {
					return nil, fmt.Errorf("failed to generate MQTT certificates: %w", err)
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

// ensureMQTTCertificatesFromManager generates MQTT server certificates using the certificate manager.
// This ensures MQTT uses the same CA as the HTTP/REST API, enabling proper mTLS with unified certificate chain.
func ensureMQTTCertificatesFromManager(caPath string, certManager *cert.Manager, logger logging.Logger) error {
	// Create directory structure
	serverDir := filepath.Join(caPath, "server")
	if err := os.MkdirAll(serverDir, 0750); err != nil { // Restrict to owner+group only
		return fmt.Errorf("failed to create server cert directory: %w", err)
	}

	// Generate MQTT server certificate using certManager (same CA as HTTP)
	serverCert, err := certManager.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "cfgms-mqtt-server",
		Organization: "CFGMS",
		DNSNames:     []string{"localhost", "cfgms-mqtt-server", "controller-standalone"},
		IPAddresses:  []string{"127.0.0.1", "0.0.0.0"},
		ValidityDays: 365,
	})
	if err != nil {
		return fmt.Errorf("failed to generate MQTT server certificate: %w", err)
	}

	// Save server certificate
	serverCertPath := filepath.Join(serverDir, "server.crt")
	if err := os.WriteFile(serverCertPath, serverCert.CertificatePEM, 0600); err != nil { // Restrict to owner only
		return fmt.Errorf("failed to write server certificate: %w", err)
	}

	// Save server key
	serverKeyPath := filepath.Join(serverDir, "server.key")
	if err := os.WriteFile(serverKeyPath, serverCert.PrivateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write server key: %w", err)
	}

	// Export CA certificate to caPath for MQTT broker
	caCert, err := certManager.GetCACertificate()
	if err != nil {
		return fmt.Errorf("failed to get CA certificate: %w", err)
	}

	caPath = filepath.Join(caPath, "ca.crt")
	if err := os.WriteFile(caPath, caCert, 0600); err != nil { // Restrict to owner only
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	logger.Info("Generated MQTT certificates using unified certificate manager",
		"server_cert", serverCertPath,
		"ca_cert", caPath)

	return nil
}

func initializeQUICServer(cfg *config.Config, logger logging.Logger, certManager *cert.Manager, configService *service.ConfigurationService, controllerService *service.ControllerService) (*quicServer.Server, *quicSession.Manager, error) {
	// Build TLS config for QUIC
	var tlsConfig *tls.Config
	var serverCertPEMForSigner, serverKeyPEMForSigner []byte

	if cfg.QUIC.UseCertManager && certManager != nil {
		// Use certificate manager certificates (same as MQTT)
		serverCertPath := filepath.Join(cfg.Certificate.CAPath, "server", "server.crt")
		serverKeyPath := filepath.Join(cfg.Certificate.CAPath, "server", "server.key")
		caPath := filepath.Join(cfg.Certificate.CAPath, "ca.crt")

		// Check if certificates exist
		if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
			logger.Info("QUIC certificates not found, using MQTT certificates")
			// MQTT cert generation already happened, so these should exist
			if err := ensureMQTTCertificatesFromManager(cfg.Certificate.CAPath, certManager, logger); err != nil {
				return nil, nil, fmt.Errorf("failed to ensure certificates: %w", err)
			}
		}

		// Load certificate and key from disk
		// #nosec G304 - Certificate paths are controlled via configuration
		serverCertPEM, err := os.ReadFile(serverCertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read server certificate: %w", err)
		}
		// #nosec G304 - Certificate paths are controlled via configuration
		serverKeyPEM, err := os.ReadFile(serverKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read server key: %w", err)
		}

		// Get CA certificate from cert manager
		caCertPEM, err := certManager.GetCACertificate()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get CA certificate: %w", err)
		}

		// Create TLS config using pkg/cert helper
		tlsConfig, err = cert.CreateServerTLSConfig(serverCertPEM, serverKeyPEM, caCertPEM, tls.VersionTLS13)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create QUIC TLS config: %w", err)
		}

		// QUIC-specific configuration
		tlsConfig.NextProtos = []string{"cfgms-quic"}

		logger.Info("QUIC server using certificate manager certificates",
			"cert_path", serverCertPath,
			"ca_path", caPath)
		// Store for signer creation
		serverCertPEMForSigner = serverCertPEM
		serverKeyPEMForSigner = serverKeyPEM
	} else if cfg.QUIC.TLSCertPath != "" && cfg.QUIC.TLSKeyPath != "" {
		// Use manually configured certificate paths
		// #nosec G304 - Certificate paths are controlled via configuration
		serverCertPEM, err := os.ReadFile(cfg.QUIC.TLSCertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read QUIC certificate: %w", err)
		}
		// #nosec G304 - Certificate paths are controlled via configuration
		serverKeyPEM, err := os.ReadFile(cfg.QUIC.TLSKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read QUIC key: %w", err)
		}

		// Create basic TLS config using pkg/cert helper (no client auth for manual certs)
		tlsConfig, err = cert.CreateBasicTLSConfig(serverCertPEM, serverKeyPEM, tls.VersionTLS13)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create QUIC TLS config: %w", err)
		}

		// QUIC-specific configuration
		tlsConfig.NextProtos = []string{"cfgms-quic"}

		logger.Info("QUIC server using configured certificates",
			"cert_path", cfg.QUIC.TLSCertPath)

		// Store for signer creation
		serverCertPEMForSigner = serverCertPEM
		serverKeyPEMForSigner = serverKeyPEM
	} else {
		return nil, nil, fmt.Errorf("QUIC enabled but no certificates configured")
	}

	// Create configuration signer using server certificate
	var configSigner signature.Signer
	if len(serverKeyPEMForSigner) > 0 {
		signer, err := signature.NewSigner(&signature.SignerConfig{
			PrivateKeyPEM:  serverKeyPEMForSigner,
			CertificatePEM: serverCertPEMForSigner,
		})
		if err != nil {
			logger.Warn("Failed to create configuration signer, configs will be unsigned",
				"error", err)
		} else {
			configSigner = signer
			logger.Info("Configuration signer initialized",
				"algorithm", signer.Algorithm(),
				"key_fingerprint", signer.KeyFingerprint())
		}
	}

	// Create QUIC session manager
	quicSessionMgr := quicSession.NewManager(&quicSession.Config{
		SessionTTL:      30 * time.Second, // Short-lived sessions
		CleanupInterval: 1 * time.Minute,
	})

	// Create QUIC server
	sessionTimeout := time.Duration(cfg.QUIC.SessionTimeout) * time.Second
	quicSrv, err := quicServer.New(&quicServer.Config{
		ListenAddr:     cfg.QUIC.ListenAddr,
		TLSConfig:      tlsConfig,
		SessionTimeout: sessionTimeout,
		SessionManager: quicSessionMgr,
		Logger:         logger,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create QUIC server: %w", err)
	}

	// Register stream handlers
	// Stream 1: Configuration sync
	configHandler := controllerQuic.NewConfigHandler(configService, logger, configSigner)
	quicSrv.RegisterStreamHandler(controllerQuic.ConfigSyncStreamID, configHandler.Handle)

	// Stream 2: DNA sync
	quicSrv.RegisterStreamHandler(2, func(ctx context.Context, session *quicServer.Session, stream *quic.Stream) error {
		return handleDNASyncStream(ctx, session, stream, controllerService, logger)
	})

	logger.Info("QUIC server initialized",
		"listen_addr", cfg.QUIC.ListenAddr,
		"session_timeout", sessionTimeout,
		"tls_version", "TLS 1.3")

	return quicSrv, quicSessionMgr, nil
}

// handleConfigSyncStream handles configuration sync requests on stream 1.
//
//nolint:unused // Reserved for future use
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

// handleConfigStatusReport processes configuration status reports from stewards via MQTT.
func (s *Server) handleConfigStatusReport(topic string, payload []byte, qos byte, retained bool) error {
	var report mqttTypes.ConfigStatusReport
	if err := json.Unmarshal(payload, &report); err != nil {
		s.logger.Error("Failed to parse config status report", "error", err)
		return fmt.Errorf("failed to parse config status report: %w", err)
	}

	s.logger.Info("Received configuration status report via MQTT",
		"steward_id", report.StewardID,
		"config_version", report.ConfigVersion,
		"overall_status", report.Status,
		"modules_count", len(report.Modules))

	// Log detailed module status
	for moduleName, moduleStatus := range report.Modules {
		s.logger.Info("Module status",
			"steward_id", report.StewardID,
			"module", moduleName,
			"status", moduleStatus.Status,
			"message", moduleStatus.Message)
	}

	// TODO: Store status report in database/audit log for MSP admin visibility
	// This would integrate with the configuration service to track module execution history

	return nil
}

// handleValidationRequest processes configuration validation requests from stewards via MQTT.
func (s *Server) handleValidationRequest(topic string, payload []byte, qos byte, retained bool) error {
	var request mqttTypes.ValidationRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		s.logger.Error("Failed to parse validation request", "error", err)
		return fmt.Errorf("failed to parse validation request: %w", err)
	}

	s.logger.Info("Received validation request via MQTT",
		"steward_id", request.StewardID,
		"request_id", request.RequestID,
		"version", request.Version)

	// Parse configuration
	var stewardConfig stewardconfig.StewardConfig
	if err := json.Unmarshal(request.Config, &stewardConfig); err != nil {
		// Send validation error response
		response := mqttTypes.ValidationResponse{
			RequestID: request.RequestID,
			Valid:     false,
			Errors:    []string{fmt.Sprintf("Invalid configuration format: %v", err)},
			Timestamp: time.Now(),
		}
		_ = s.sendValidationResponse(request.StewardID, request.RequestID, response)
		return nil
	}

	// Validate using the steward config validation (simpler than full framework for now)
	var errors []string
	if err := stewardconfig.ValidateConfiguration(stewardConfig); err != nil {
		errors = append(errors, err.Error())
	}

	// TODO: Use comprehensive validation framework like ValidateConfig does
	// This would require access to s.configService.validator

	// Create response
	response := mqttTypes.ValidationResponse{
		RequestID: request.RequestID,
		Valid:     len(errors) == 0,
		Errors:    errors,
		Timestamp: time.Now(),
	}

	// Send response
	if err := s.sendValidationResponse(request.StewardID, request.RequestID, response); err != nil {
		s.logger.Error("Failed to send validation response",
			"steward_id", request.StewardID,
			"request_id", request.RequestID,
			"error", err)
		return err
	}

	s.logger.Info("Sent validation response",
		"steward_id", request.StewardID,
		"request_id", request.RequestID,
		"valid", response.Valid,
		"errors_count", len(response.Errors))

	return nil
}

// sendValidationResponse sends a validation response to a steward.
func (s *Server) sendValidationResponse(stewardID string, requestID string, response mqttTypes.ValidationResponse) error {
	payload, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal validation response: %w", err)
	}

	ctx := context.Background()
	responseTopic := fmt.Sprintf("cfgms/steward/%s/validate-response/%s", stewardID, requestID)
	if err := s.mqttBroker.Publish(ctx, responseTopic, payload, 1, false); err != nil {
		return fmt.Errorf("failed to publish validation response: %w", err)
	}

	return nil
}
