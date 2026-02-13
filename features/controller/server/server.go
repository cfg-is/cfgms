// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"google.golang.org/protobuf/types/known/timestamppb"

	common "github.com/cfgis/cfgms/api/proto/common"
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
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	_ "github.com/cfgis/cfgms/pkg/dataplane/providers/quic" // Register QUIC data plane provider
	dataplaneTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
	_ "github.com/cfgis/cfgms/pkg/mqtt/providers/mochi" // Register mochi-mqtt provider
	mqttTypes "github.com/cfgis/cfgms/pkg/mqtt/types"
	quicServer "github.com/cfgis/cfgms/pkg/quic/server"
	pkgRegistration "github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// BUILD_VERSION_CHECK is a compile-time constant to verify code version in Docker
const BUILD_VERSION_CHECK = "story-362-config-signing-enabled"

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
	dataPlaneProvider       dataplaneInterfaces.DataPlaneProvider
	configHandler           *controllerQuic.ConfigHandler
	signerCertSerial        string // Serial number of server cert used for config signing (Story #378)
}

// New creates a new server instance
func New(cfg *config.Config, logger logging.Logger) (*Server, error) {
	fmt.Printf("[DEBUG] server.New() called\n")
	if cfg == nil {
		return nil, ErrNilConfig
	}

	fmt.Printf("[DEBUG] server.New() - cfg validated\n")
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

	// Initialize data plane provider if enabled (Story #362)
	var dataPlane dataplaneInterfaces.DataPlaneProvider
	fmt.Printf("[DEBUG] New(): Checking QUIC config: nil=%v enabled=%v\n", cfg.QUIC == nil, cfg.QUIC != nil && cfg.QUIC.Enabled)
	if cfg.QUIC != nil && cfg.QUIC.Enabled {
		fmt.Printf("[DEBUG] New(): Data plane enabled, initializing provider...\n")
		logger.Info("Initializing data plane provider...")
		dataPlane, err = initializeDataPlaneProvider(cfg, logger, certManager, configService)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize data plane provider: %w", err)
		}
		logger.Info("Data plane provider initialized successfully",
			"provider", dataPlane.Name())
	}

	// Initialize config handler for data plane configuration sync (Story #362)
	var configHandler *controllerQuic.ConfigHandler
	var signerCertSerial string // Story #378: Track cert serial for registration handler
	if dataPlane != nil {
		fmt.Printf("[DEBUG] Initializing config handler with signer support...\n")
		// Create signer from server certificate for config signing (Story #315)
		var signer signature.Signer
		if certManager != nil {
			fmt.Printf("[DEBUG] certManager available, fetching server certificates...\n")
			serverCerts, err := certManager.GetCertificatesByType(cert.CertificateTypeServer)
			fmt.Printf("[DEBUG] GetCertificatesByType returned: err=%v numCerts=%d\n", err, len(serverCerts))
			if err == nil && len(serverCerts) > 0 {
				// Export server certificate with private key
				signerCertSerial = serverCerts[0].SerialNumber
				fmt.Printf("[DEBUG] Exporting server cert with serial=%s\n", signerCertSerial)
				certPEM, keyPEM, err := certManager.ExportCertificate(signerCertSerial, true)
				fmt.Printf("[DEBUG] ExportCertificate returned: err=%v certLen=%d keyLen=%d\n", err, len(certPEM), len(keyPEM))
				if err == nil && len(certPEM) > 0 && len(keyPEM) > 0 {
					// Create signer from server certificate
					fmt.Printf("[DEBUG] Creating signer from server certificate...\n")
					signer, err = signature.NewSigner(&signature.SignerConfig{
						PrivateKeyPEM:  keyPEM,
						CertificatePEM: certPEM,
					})
					if err != nil {
						fmt.Printf("[DEBUG] Failed to create signer: %v\n", err)
						logger.Warn("Failed to create config signer", "error", err)
					} else {
						// CRITICAL (Story #378): Serial stored and will be passed to registration handler
						// Registration MUST use the SAME cert serial to ensure signature verification works
						fmt.Printf("[DEBUG] Signer created successfully: algorithm=%s fingerprint=%s serial=%s\n",
							signer.Algorithm(), signer.KeyFingerprint(), signerCertSerial)
						logger.Info("Config signer initialized successfully",
							"algorithm", signer.Algorithm(),
							"fingerprint", signer.KeyFingerprint(),
							"cert_serial", signerCertSerial)
					}
				} else {
					fmt.Printf("[DEBUG] Skipping signer creation: missing cert or key\n")
				}
			} else {
				fmt.Printf("[DEBUG] No server certificates found or error occurred\n")
			}
		} else {
			fmt.Printf("[DEBUG] certManager is nil, cannot create signer\n")
		}

		// Create config handler with signer (signs configs if signer available)
		fmt.Printf("[DEBUG] Creating config handler with signer=%v\n", signer != nil)
		configHandler = controllerQuic.NewConfigHandler(configService, logger, signer)
		fmt.Printf("[DEBUG] Config handler created successfully\n")
		logger.Debug("Config handler initialized for data plane", "signing_enabled", signer != nil)
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
		regStore,         // registrationTokenStore
		signerCertSerial, // Story #378: signer cert serial for registration
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP API server: %w", err)
	}

	logger.Info("HTTP API server initialized successfully")

	srv := &Server{
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
		dataPlaneProvider:       dataPlane,
		configHandler:           configHandler,
		httpServer:              httpServer,
		signerCertSerial:        signerCertSerial, // Story #378: For registration handler
	}

	// Wire up QUIC trigger function to API server (if data plane is enabled)
	if dataPlane != nil {
		httpServer.SetQUICTriggerFunc(srv.TriggerQUICConnection)
		logger.Info("QUIC trigger function wired to HTTP API server")
	}

	return srv, nil
}

// Start initializes and starts the controller server (MQTT+QUIC mode)
func (s *Server) Start() error {
	fmt.Printf("[DEBUG] Controller Server Start() method called\n")
	s.mu.Lock()
	defer s.mu.Unlock()

	// Start HA manager with timeout
	fmt.Printf("[DEBUG] Controller checking HA manager: %v\n", s.haManager != nil)
	if s.haManager != nil {
		fmt.Printf("[DEBUG] Controller starting HA manager\n")
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

	// Start data plane provider (Story #362)
	fmt.Printf("[DEBUG] BUILD VERSION: %s\n", BUILD_VERSION_CHECK)
	s.logger.Info("Controller build version", "version", BUILD_VERSION_CHECK)
	fmt.Printf("[DEBUG] Controller checking if dataPlaneProvider is nil: %v\n", s.dataPlaneProvider == nil)
	if s.dataPlaneProvider != nil {
		fmt.Printf("[DEBUG] Controller starting data plane provider...\n")
		s.logger.Info("Starting data plane provider...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		fmt.Printf("[DEBUG] Controller calling dataPlaneProvider.Start()\n")
		if err := s.dataPlaneProvider.Start(ctx); err != nil {
			fmt.Printf("[DEBUG] Controller dataPlaneProvider.Start() returned error: %v\n", err)
			return fmt.Errorf("failed to start data plane provider: %w", err)
		}
		fmt.Printf("[DEBUG] Controller dataPlaneProvider.Start() succeeded\n")
		s.logger.Info("Data plane provider started successfully",
			"provider", s.dataPlaneProvider.Name(),
			"listen_addr", s.cfg.QUIC.ListenAddr)

		// Register config handler with QUIC provider (bridge until session acceptance is implemented)
		if err := s.registerConfigHandlerBridge(); err != nil {
			s.logger.Warn("Failed to register config handler bridge", "error", err)
			// Non-fatal - continues startup but config sync won't work
		}

		// TODO(Story #362): Session acceptance not yet fully implemented
		// The provider pattern requires adding session queueing to pkg/quic/server
		// For now, QUIC server continues to use its internal connection handling
		// This will be completed in a follow-up enhancement
		// go s.acceptDataPlaneSessions(context.Background())
	} else {
		fmt.Printf("[DEBUG] Controller dataPlaneProvider is nil, skipping data plane startup\n")
	}

	// Start HTTP API server
	fmt.Printf("[DEBUG] Controller checking if httpServer is nil: %v\n", s.httpServer == nil)
	if s.httpServer != nil {
		fmt.Printf("[DEBUG] Controller starting HTTP server...\n")
		logger := s.logger // Capture logger for goroutine
		go func() {
			fmt.Printf("[DEBUG] Controller httpServer.Start() goroutine started\n")
			logger.Info("[DEBUG_LOGGER] HTTP goroutine started")
			fmt.Printf("[DEBUG] About to call httpServer.Start()...\n")
			logger.Info("[DEBUG_LOGGER] About to call httpServer.Start()")
			err := s.httpServer.Start()
			logger.Info("[DEBUG_LOGGER] httpServer.Start() call completed", "error", err)
			if err != nil {
				fmt.Printf("[DEBUG] Controller httpServer.Start() returned error: %v\n", err)
				logger.Error("HTTP API server failed", "error", err)
			} else {
				fmt.Printf("[DEBUG] Controller httpServer.Start() returned successfully\n")
			}
		}()
		s.logger.Info("HTTP API server started")
	} else {
		fmt.Printf("[DEBUG] Controller httpServer is nil, skipping HTTP startup\n")
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

	// Stop data plane provider (Story #362)
	if s.dataPlaneProvider != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.dataPlaneProvider.Stop(ctx); err != nil {
			s.logger.Warn("Failed to stop data plane provider", "error", err)
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
// This sends a connect_quic command via MQTT to trigger the steward to connect.
func (s *Server) TriggerQUICConnection(ctx context.Context, stewardID string) (string, error) {
	if s.dataPlaneProvider == nil {
		return "", fmt.Errorf("data plane provider not available")
	}
	if s.commandPublisher == nil {
		return "", fmt.Errorf("command publisher not available")
	}
	if s.cfg.QUIC == nil || !s.cfg.QUIC.Enabled {
		return "", fmt.Errorf("QUIC is not enabled")
	}

	// Generate session ID for this QUIC connection
	// Note: With the new provider pattern, session management is internal
	// We'll use a simple UUID for the session ID
	sessionID := fmt.Sprintf("session-%s-%d", stewardID, time.Now().Unix())

	s.logger.Info("Triggering QUIC connection",
		"steward_id", stewardID,
		"session_id", sessionID)

	// Construct external QUIC address for steward connection
	// If listen address is 0.0.0.0:port, replace with external hostname
	quicAddress := s.cfg.QUIC.ListenAddr
	if strings.HasPrefix(quicAddress, "0.0.0.0:") {
		externalHostname := os.Getenv("CFGMS_EXTERNAL_HOSTNAME")
		if externalHostname == "" {
			externalHostname = "localhost"
		}
		port := strings.TrimPrefix(quicAddress, "0.0.0.0:")
		quicAddress = externalHostname + ":" + port
	}

	// Send connect_quic command to steward via MQTT
	commandID, err := s.commandPublisher.TriggerQUICConnection(
		ctx,
		stewardID,
		quicAddress,
		sessionID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to send connect_quic command: %w", err)
	}

	s.logger.Info("Triggered QUIC connection for steward",
		"steward_id", stewardID,
		"session_id", sessionID,
		"command_id", commandID,
		"quic_address", quicAddress)

	return commandID, nil
}

// GetCertificateManager returns the certificate manager instance
func (s *Server) GetCertificateManager() *cert.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certManager
}

// GetSignerCertSerial returns the signer certificate serial (Story #378)
func (s *Server) GetSignerCertSerial() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.signerCertSerial
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

// GetRegistrationTokenStore returns the registration token store
func (s *Server) GetRegistrationTokenStore() pkgRegistration.Store {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.registrationTokenStore
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
		// Load existing CA (reboot/restart scenario)
		manager, err = cert.NewManager(&cert.ManagerConfig{
			StoragePath:          cfg.CertPath,
			LoadExistingCA:       true,
			EnableAutoRenewal:    cfg.Certificate.EnableCertManagement, // Enable renewal when cert management is enabled
			RenewalThresholdDays: cfg.Certificate.RenewalThresholdDays,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to load existing CA: %w", err)
		}
		logger.Info("Loaded existing Certificate Authority")
	} else {
		// Create new CA (first deployment scenario)
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
			EnableAutoRenewal:    cfg.Certificate.EnableCertManagement, // Enable renewal when cert management is enabled
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

	// Configure ACL handler for multi-tenant topic isolation (Story #313)
	// Enforces that stewards can only access topics under their own namespace:
	// cfgms/steward/{clientID}/#
	broker.SetACLHandler(stewardACLHandler)
	logger.Info("MQTT broker ACL handler configured for multi-tenant isolation")

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

// buildQUICTLSConfig creates TLS configuration for QUIC data plane
func buildQUICTLSConfig(cfg *config.Config, certManager *cert.Manager, logger logging.Logger) (*tls.Config, error) {
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
			if err := ensureMQTTCertificatesFromManager(cfg.Certificate.CAPath, certManager, logger); err != nil {
				return nil, fmt.Errorf("failed to ensure certificates: %w", err)
			}
		}

		// Load certificate and key from disk
		// #nosec G304 - Certificate paths are controlled via configuration
		serverCertPEM, err := os.ReadFile(serverCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read server certificate: %w", err)
		}
		// #nosec G304 - Certificate paths are controlled via configuration
		serverKeyPEM, err := os.ReadFile(serverKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read server key: %w", err)
		}

		// Get CA certificate from cert manager
		caCertPEM, err := certManager.GetCACertificate()
		if err != nil {
			return nil, fmt.Errorf("failed to get CA certificate: %w", err)
		}

		// Create TLS config using pkg/cert helper
		tlsConfig, err = cert.CreateServerTLSConfig(serverCertPEM, serverKeyPEM, caCertPEM, tls.VersionTLS13)
		if err != nil {
			return nil, fmt.Errorf("failed to create QUIC TLS config: %w", err)
		}

		// QUIC-specific configuration
		tlsConfig.NextProtos = []string{"cfgms-quic"}

		logger.Info("Data plane using certificate manager certificates",
			"cert_path", serverCertPath,
			"ca_path", caPath)
	} else if cfg.QUIC.TLSCertPath != "" && cfg.QUIC.TLSKeyPath != "" {
		// Use manually configured certificate paths
		// #nosec G304 - Certificate paths are controlled via configuration
		serverCertPEM, err := os.ReadFile(cfg.QUIC.TLSCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read QUIC certificate: %w", err)
		}
		// #nosec G304 - Certificate paths are controlled via configuration
		serverKeyPEM, err := os.ReadFile(cfg.QUIC.TLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read QUIC key: %w", err)
		}

		// Create basic TLS config using pkg/cert helper (no client auth for manual certs)
		tlsConfig, err = cert.CreateBasicTLSConfig(serverCertPEM, serverKeyPEM, tls.VersionTLS13)
		if err != nil {
			return nil, fmt.Errorf("failed to create QUIC TLS config: %w", err)
		}

		// QUIC-specific configuration
		tlsConfig.NextProtos = []string{"cfgms-quic"}

		logger.Info("Data plane using configured certificates",
			"cert_path", cfg.QUIC.TLSCertPath)
	} else {
		return nil, fmt.Errorf("QUIC enabled but no certificates configured")
	}

	return tlsConfig, nil
}

// initializeDataPlaneProvider initializes the data plane provider (Story #362)
func initializeDataPlaneProvider(cfg *config.Config, logger logging.Logger, certManager *cert.Manager, configService *service.ConfigurationService) (dataplaneInterfaces.DataPlaneProvider, error) {
	// Build TLS configuration for QUIC
	tlsConfig, err := buildQUICTLSConfig(cfg, certManager, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	// Get QUIC provider from registry
	provider := dataplaneInterfaces.GetProvider("quic")
	if provider == nil {
		return nil, fmt.Errorf("QUIC data plane provider not registered")
	}

	// Build provider configuration
	providerConfig := map[string]interface{}{
		"mode":        "server",
		"listen_addr": cfg.QUIC.ListenAddr,
		"tls_config":  tlsConfig,
		"logger":      logger,
	}

	// Initialize provider
	if err := provider.Initialize(context.Background(), providerConfig); err != nil {
		return nil, fmt.Errorf("failed to initialize data plane provider: %w", err)
	}

	logger.Info("Data plane provider initialized",
		"provider", provider.Name(),
		"listen_addr", cfg.QUIC.ListenAddr)

	return provider, nil
}

// registerConfigHandlerBridge registers the config handler with the underlying QUIC server.
// This is a bridge solution while session acceptance is being completed (Story #362).
// It allows config sync to work by routing QUIC stream ID 4 to the config handler.
func (s *Server) registerConfigHandlerBridge() error {
	fmt.Printf("[DEBUG] registerConfigHandlerBridge() called\n")
	s.logger.Info("Attempting to register config handler bridge")

	if s.configHandler == nil {
		fmt.Printf("[DEBUG] config handler is nil\n")
		return fmt.Errorf("config handler not initialized")
	}
	fmt.Printf("[DEBUG] config handler is initialized\n")

	// Type assert to QUIC provider to access RegisterStreamHandler
	// Interface must match exact signature from pkg/dataplane/providers/quic/provider.go
	type quicProvider interface {
		RegisterStreamHandler(streamID int64, handler quicServer.StreamHandler) error
	}

	fmt.Printf("[DEBUG] Attempting type assertion to quicProvider, provider type=%T\n", s.dataPlaneProvider)
	provider, ok := s.dataPlaneProvider.(quicProvider)
	if !ok {
		// Not a QUIC provider, skip registration
		fmt.Printf("[DEBUG] Type assertion FAILED - not a QUIC provider\n")
		s.logger.Warn("Data plane provider does not support stream handler registration", "provider_type", fmt.Sprintf("%T", s.dataPlaneProvider))
		return fmt.Errorf("provider type %T does not implement RegisterStreamHandler", s.dataPlaneProvider)
	}
	fmt.Printf("[DEBUG] Type assertion SUCCESS - is a QUIC provider\n")

	// Create bridge handler that adapts old QUIC server signature to new config handler
	bridgeHandler := func(ctx context.Context, sess *quicServer.Session, strm *quic.Stream) error {
		fmt.Printf("[DEBUG] BRIDGE HANDLER INVOKED: session=%s stream=%d\n", sess.ID, (*strm).StreamID())
		s.logger.Info("Bridge handler invoked", "session_id", sess.ID, "stream_id", (*strm).StreamID())

		// Wrap old QUIC session as DataPlaneSession
		session := &quicSessionBridge{raw: sess}
		fmt.Printf("[DEBUG] Created session bridge: id=%s peer_id=%s\n", session.ID(), session.PeerID())

		// Wrap old QUIC stream as Stream
		stream := &quicStreamBridge{raw: strm}
		fmt.Printf("[DEBUG] Created stream bridge: id=%d type=%v\n", stream.ID(), stream.Type())

		// Call config handler with wrapped interfaces
		fmt.Printf("[DEBUG] Calling config handler...\n")
		err := s.configHandler.Handle(ctx, session, stream)
		fmt.Printf("[DEBUG] Config handler returned: err=%v\n", err)
		return err
	}

	// Register handler for config sync stream (stream ID 4)
	const configSyncStreamID = 4
	fmt.Printf("[DEBUG] Calling RegisterStreamHandler for stream_id=%d\n", configSyncStreamID)
	if err := provider.RegisterStreamHandler(configSyncStreamID, bridgeHandler); err != nil {
		fmt.Printf("[DEBUG] RegisterStreamHandler FAILED: %v\n", err)
		return fmt.Errorf("failed to register config handler: %w", err)
	}

	fmt.Printf("[DEBUG] RegisterStreamHandler SUCCESS\n")
	s.logger.Info("Config handler registered with QUIC provider", "stream_id", configSyncStreamID)
	return nil
}

// acceptDataPlaneSessions accepts incoming data plane connections and handles them (Story #362)
//
//nolint:unused // Will be enabled after session acceptance is fully implemented
func (s *Server) acceptDataPlaneSessions(ctx context.Context) {
	s.logger.Info("Started data plane session acceptance loop")

	for {
		// Accept connection with context
		session, err := s.dataPlaneProvider.AcceptConnection(ctx)
		if err != nil {
			// Check if context was canceled (shutdown)
			if ctx.Err() != nil {
				s.logger.Info("Data plane session acceptance stopped (context canceled)")
				return
			}
			s.logger.Error("Failed to accept data plane connection", "error", err)
			continue
		}

		s.logger.Info("Accepted data plane connection",
			"session_id", session.ID(),
			"peer_id", session.PeerID(),
			"remote_addr", session.RemoteAddr())

		// Handle session in separate goroutine
		go s.handleDataPlaneSession(ctx, session)
	}
}

// handleDataPlaneSession handles a data plane session (Story #362)
//
//nolint:unused // Will be enabled after session acceptance is fully implemented
func (s *Server) handleDataPlaneSession(ctx context.Context, session dataplaneInterfaces.DataPlaneSession) {
	defer func() {
		if err := session.Close(ctx); err != nil {
			s.logger.Warn("Error closing data plane session",
				"session_id", session.ID(),
				"error", err)
		}
	}()

	s.logger.Info("Handling data plane session",
		"session_id", session.ID(),
		"peer_id", session.PeerID())

	// Accept and handle streams in this session
	for {
		stream, streamType, err := session.AcceptStream(ctx)
		if err != nil {
			// Check if session is closed or context canceled
			if ctx.Err() != nil || session.IsClosed() {
				s.logger.Debug("Data plane session closed",
					"session_id", session.ID())
				return
			}
			s.logger.Error("Failed to accept stream",
				"session_id", session.ID(),
				"error", err)
			return
		}

		s.logger.Debug("Accepted stream",
			"session_id", session.ID(),
			"stream_id", stream.ID(),
			"stream_type", streamType)

		// Route stream based on type
		switch streamType {
		case dataplaneTypes.StreamConfig:
			// Handle configuration sync request
			s.logger.Info("Handling config sync stream",
				"session_id", session.ID(),
				"stream_id", stream.ID())

			// Call config handler (Story #362)
			if s.configHandler != nil {
				if err := s.configHandler.Handle(ctx, session, stream); err != nil {
					s.logger.Error("Config handler failed",
						"session_id", session.ID(),
						"stream_id", stream.ID(),
						"error", err)
				}
			} else {
				s.logger.Warn("Config handler not initialized, closing stream",
					"session_id", session.ID())
				if err := stream.Close(); err != nil {
					s.logger.Warn("Error closing config stream", "error", err)
				}
			}

		case dataplaneTypes.StreamDNA:
			// Handle DNA sync request
			s.logger.Info("Handling DNA sync stream",
				"session_id", session.ID(),
				"stream_id", stream.ID())
			// TODO: Implement DNA handler with new provider pattern
			// For now, close the stream
			if err := stream.Close(); err != nil {
				s.logger.Warn("Error closing DNA stream", "error", err)
			}

		default:
			s.logger.Warn("Unknown stream type",
				"session_id", session.ID(),
				"stream_id", stream.ID(),
				"stream_type", streamType)
			if err := stream.Close(); err != nil {
				s.logger.Warn("Error closing unknown stream", "error", err)
			}
		}
	}
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

// Bridge types to adapt old QUIC server types to new provider interfaces
// These are temporary until full session acceptance is implemented (Story #362)

type quicSessionBridge struct {
	raw *quicServer.Session
}

func (s *quicSessionBridge) ID() string {
	if s.raw != nil {
		return s.raw.ID
	}
	return "unknown"
}

func (s *quicSessionBridge) PeerID() string {
	if s.raw != nil {
		return s.raw.StewardID
	}
	return "unknown"
}

func (s *quicSessionBridge) SendConfig(ctx context.Context, config *dataplaneTypes.ConfigTransfer) error {
	return fmt.Errorf("SendConfig not implemented in bridge")
}

func (s *quicSessionBridge) ReceiveConfig(ctx context.Context) (*dataplaneTypes.ConfigTransfer, error) {
	return nil, fmt.Errorf("ReceiveConfig not implemented in bridge")
}

func (s *quicSessionBridge) SendDNA(ctx context.Context, dna *dataplaneTypes.DNATransfer) error {
	return fmt.Errorf("SendDNA not implemented in bridge")
}

func (s *quicSessionBridge) ReceiveDNA(ctx context.Context) (*dataplaneTypes.DNATransfer, error) {
	return nil, fmt.Errorf("ReceiveDNA not implemented in bridge")
}

func (s *quicSessionBridge) SendBulk(ctx context.Context, bulk *dataplaneTypes.BulkTransfer) error {
	return fmt.Errorf("SendBulk not implemented in bridge")
}

func (s *quicSessionBridge) ReceiveBulk(ctx context.Context) (*dataplaneTypes.BulkTransfer, error) {
	return nil, fmt.Errorf("ReceiveBulk not implemented in bridge")
}

func (s *quicSessionBridge) OpenStream(ctx context.Context, streamType dataplaneTypes.StreamType) (dataplaneInterfaces.Stream, error) {
	return nil, fmt.Errorf("OpenStream not implemented in bridge")
}

func (s *quicSessionBridge) AcceptStream(ctx context.Context) (dataplaneInterfaces.Stream, dataplaneTypes.StreamType, error) {
	return nil, "", fmt.Errorf("AcceptStream not implemented in bridge")
}

func (s *quicSessionBridge) Close(ctx context.Context) error {
	return nil // Session cleanup handled by QUIC server
}

func (s *quicSessionBridge) IsClosed() bool {
	return false
}

func (s *quicSessionBridge) LocalAddr() string {
	return ""
}

func (s *quicSessionBridge) RemoteAddr() string {
	if s.raw != nil && s.raw.Connection != nil {
		return (*s.raw.Connection).RemoteAddr().String()
	}
	return "unknown"
}

type quicStreamBridge struct {
	raw *quic.Stream
}

func (s *quicStreamBridge) Read(p []byte) (int, error) {
	if s.raw != nil {
		return (*s.raw).Read(p)
	}
	return 0, fmt.Errorf("invalid stream type")
}

func (s *quicStreamBridge) Write(p []byte) (int, error) {
	if s.raw != nil {
		return (*s.raw).Write(p)
	}
	return 0, fmt.Errorf("invalid stream type")
}

func (s *quicStreamBridge) Close() error {
	if s.raw != nil {
		return (*s.raw).Close()
	}
	return nil
}

func (s *quicStreamBridge) ID() uint64 {
	if s.raw != nil {
		return uint64((*s.raw).StreamID())
	}
	return 0
}

func (s *quicStreamBridge) Type() dataplaneTypes.StreamType {
	// For the bridge, we know this is a config stream (stream ID 4)
	// A more robust implementation would detect based on stream ID
	return dataplaneTypes.StreamConfig
}

func (s *quicStreamBridge) SetDeadline(ctx context.Context) error {
	// Extract deadline from context if present
	deadline, ok := ctx.Deadline()
	if !ok {
		// No deadline set in context
		return nil
	}

	if s.raw != nil {
		return (*s.raw).SetDeadline(deadline)
	}
	return fmt.Errorf("invalid stream type")
}
