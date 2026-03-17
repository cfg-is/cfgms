// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"crypto/tls"
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
	configgit "github.com/cfgis/cfgms/features/config/git"
	gitStorage "github.com/cfgis/cfgms/features/config/git/storage"
	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	"github.com/cfgis/cfgms/features/controller/initialization"
	controllerQuic "github.com/cfgis/cfgms/features/controller/quic"
	"github.com/cfgis/cfgms/features/controller/registration"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	reportapi "github.com/cfgis/cfgms/features/reports/api"
	reportscache "github.com/cfgis/cfgms/features/reports/cache"
	reportsengine "github.com/cfgis/cfgms/features/reports/engine"
	reportsexporters "github.com/cfgis/cfgms/features/reports/exporters"
	reportsprovider "github.com/cfgis/cfgms/features/reports/provider"
	reportstemplates "github.com/cfgis/cfgms/features/reports/templates"
	dnadrift "github.com/cfgis/cfgms/features/steward/dna/drift"
	dnaStorage "github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	_ "github.com/cfgis/cfgms/pkg/controlplane/providers/mqtt" // Register MQTT control plane provider
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	_ "github.com/cfgis/cfgms/pkg/dataplane/providers/quic" // Register QUIC data plane provider
	dataplaneTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
	_ "github.com/cfgis/cfgms/pkg/mqtt/providers/mochi" // Register mochi-mqtt provider
	quicServer "github.com/cfgis/cfgms/pkg/quic/server" //nolint:staticcheck // SA1019: Controller infrastructure bootstrap
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
	configService           *service.ConfigurationServiceV2
	rbacService             *service.RBACService
	certProvisioningService *service.CertificateProvisioningService
	certManager             *cert.Manager
	tenantManager           *tenant.Manager
	rbacManager             *rbac.Manager
	auditManager            *audit.Manager
	haManager               *ha.Manager
	mqttBroker              mqttInterfaces.Broker
	controlPlane            controlplaneInterfaces.ControlPlaneProvider // Story #363
	heartbeatService        *heartbeat.Service
	commandPublisher        *commands.Publisher
	registrationHandler     *registration.Handler
	registrationTokenStore  pkgRegistration.Store
	dataPlaneProvider       dataplaneInterfaces.DataPlaneProvider
	configHandler           *controllerQuic.ConfigHandler
	signerCertSerial        string // Serial number of server cert used for config signing (Story #378)
	healthCollector         *health.Collector
	alertManager            *health.DefaultAlertManager
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

	// Create the configuration service (V2: durable storage via StorageManager)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)

	// Create the RBAC service
	rbacService := service.NewRBACService(rbacManager)

	// Initialize certificate manager if enabled
	var certManager *cert.Manager
	var certProvisioningService *service.CertificateProvisioningService
	if cfg.Certificate != nil && cfg.Certificate.EnableCertManagement {
		// Init guard: controller must be initialized before normal startup
		caPath := cfg.Certificate.CAPath
		if !initialization.IsInitialized(caPath) {
			if initialization.CAFilesExist(caPath) {
				// Legacy: existing CA files but no marker — auto-create marker for backward compat
				logger.Info("Legacy CA detected without init marker, creating marker for backward compatibility", "ca_path", caPath)
				if err := initialization.CreateLegacyMarker(caPath); err != nil {
					return nil, fmt.Errorf("failed to create legacy init marker: %w", err)
				}
			} else {
				// Not initialized — refuse to start
				return nil, ErrNotInitialized
			}
		}

		var err error
		certManager, err = loadExistingCertificateManager(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate manager: %w", err)
		}

		// Story #377: Boot migration for separated certificate architecture
		if cfg.Certificate.IsSeparatedArchitecture() {
			logger.Info("Certificate architecture: separated — ensuring purpose-specific certificates")
			internalCfg := &cert.ServerCertConfig{
				CommonName:   "cfgms-internal",
				DNSNames:     []string{"localhost", "cfgms-internal", "controller-standalone"},
				IPAddresses:  []string{"127.0.0.1", "0.0.0.0"},
				ValidityDays: 365,
			}
			if cfg.Certificate.Internal != nil {
				if cfg.Certificate.Internal.CommonName != "" {
					internalCfg.CommonName = cfg.Certificate.Internal.CommonName
				}
				if len(cfg.Certificate.Internal.DNSNames) > 0 {
					internalCfg.DNSNames = cfg.Certificate.Internal.DNSNames
				}
				if len(cfg.Certificate.Internal.IPAddresses) > 0 {
					internalCfg.IPAddresses = cfg.Certificate.Internal.IPAddresses
				}
			}
			if cfg.Certificate.InternalCertValidityDays > 0 {
				internalCfg.ValidityDays = cfg.Certificate.InternalCertValidityDays
			}

			signingCfg := &cert.SigningCertConfig{
				CommonName:   "cfgms-config-signer",
				ValidityDays: 1095,
				KeySize:      4096,
			}
			if cfg.Certificate.Signing != nil {
				if cfg.Certificate.Signing.CommonName != "" {
					signingCfg.CommonName = cfg.Certificate.Signing.CommonName
				}
				if cfg.Certificate.Signing.Organization != "" {
					signingCfg.Organization = cfg.Certificate.Signing.Organization
				}
			}
			if cfg.Certificate.SigningCertValidityDays > 0 {
				signingCfg.ValidityDays = cfg.Certificate.SigningCertValidityDays
			}

			if err := certManager.EnsureSeparatedCertificates(internalCfg, signingCfg); err != nil {
				return nil, fmt.Errorf("failed to ensure separated certificates: %w", err)
			}
			logger.Info("Separated certificates ensured (internal mTLS + config signing)")
		} else {
			logger.Info("Certificate architecture: unified (default)")
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
	var controlPlane controlplaneInterfaces.ControlPlaneProvider
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

		// Initialize control plane provider in server mode (Story #363)
		logger.Info("Initializing control plane provider...")
		controlPlane = controlplaneInterfaces.GetProvider("mqtt")
		if controlPlane == nil {
			return nil, fmt.Errorf("MQTT control plane provider not registered")
		}
		if err := controlPlane.Initialize(context.Background(), map[string]interface{}{
			"mode":   "server",
			"broker": mqttBroker,
		}); err != nil {
			return nil, fmt.Errorf("failed to initialize control plane provider: %w", err)
		}
		logger.Info("Control plane provider initialized successfully", "provider", controlPlane.Name())

		// Initialize heartbeat monitoring service
		logger.Info("Initializing heartbeat monitoring service...")
		heartbeatService, err = heartbeat.New(&heartbeat.Config{
			ControlPlane:     controlPlane,
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

		// Initialize command publisher (Story #198, Story #363)
		logger.Info("Initializing command publisher...")
		commandPublisher, err = commands.New(&commands.Config{
			ControlPlane: controlPlane,
			Logger:       logger,
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
				Token:         "dockertest_standalone",
				TenantID:      "test-tenant",
				ControllerURL: "tcp://controller-standalone:1883",
				Group:         "test-group",
				CreatedAt:     now,
				ExpiresAt:     nil,   // Never expires for testing
				SingleUse:     false, // Can be reused for testing
				Revoked:       false,
			},
			{
				Token:         "integration_reusable",
				TenantID:      "test-tenant-integration",
				ControllerURL: "tcp://localhost:1886",
				Group:         "production",
				CreatedAt:     now,
				ExpiresAt:     nil,   // Never expires for testing
				SingleUse:     false, // Can be reused for integration tests
				Revoked:       false,
			},
			{
				Token:         "integration_expired",
				TenantID:      "test-tenant-integration",
				ControllerURL: "tcp://localhost:1886",
				Group:         "production",
				CreatedAt:     now.Add(-2 * time.Hour),
				ExpiresAt:     &expiredTime, // Expired 1 hour ago
				SingleUse:     true,
				Revoked:       false,
			},
			{
				Token:         "integration_revoked",
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
				Token:         "integration_singleuse",
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
	if cfg.QUIC != nil && cfg.QUIC.Enabled {
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
		// Create signer from certificate for config signing (Story #315, #377)
		// In separated mode: use CertificateTypeConfigSigning (dedicated signing cert)
		// In unified mode: use CertificateTypeServer (backward compatible)
		var signer signature.Signer
		if certManager != nil {
			signerCertType := cert.CertificateTypeServer
			if cfg.Certificate != nil && cfg.Certificate.IsSeparatedArchitecture() {
				signerCertType = cert.CertificateTypeConfigSigning
			}

			signerCerts, err := certManager.GetCertificatesByType(signerCertType)
			if err == nil && len(signerCerts) > 0 {
				signerCertSerial = signerCerts[0].SerialNumber
				certPEM, keyPEM, err := certManager.ExportCertificate(signerCertSerial, true)
				if err == nil && len(certPEM) > 0 && len(keyPEM) > 0 {
					signer, err = signature.NewSigner(&signature.SignerConfig{
						PrivateKeyPEM:  keyPEM,
						CertificatePEM: certPEM,
					})
					if err != nil {
						logger.Warn("Failed to create config signer", "error", err)
					} else {
						logger.Info("Config signer initialized successfully",
							"algorithm", signer.Algorithm(),
							"fingerprint", signer.KeyFingerprint(),
							"cert_serial", signerCertSerial,
							"cert_type", signerCertType.String())
					}
				}
			}
		}

		// Create config handler with signer (signs configs if signer available)
		configHandler = controllerQuic.NewConfigHandler(configService, logger, signer)
		logger.Debug("Config handler initialized for data plane", "signing_enabled", signer != nil)
	}

	// Initialize health collectors (Story #417)
	var healthCollector *health.Collector
	var healthAlertManager *health.DefaultAlertManager
	{
		// MQTT collector — only created when broker is configured
		var mqttCollector health.MQTTCollector
		if mqttBroker != nil {
			mqttCollector = health.NewDefaultMQTTCollector(NewMochiBrokerStatsAdapter(mqttBroker))
		}

		// Storage stats — provider name only, latency instrumentation is follow-up
		storageStats := NewBasicStorageStats(cfg.Storage.Provider)
		storageCollector := health.NewDefaultStorageCollector(storageStats)

		// Application stats — no-op until workflow engine exists
		appCollector := health.NewDefaultApplicationCollector(&NoOpApplicationQueueStats{})

		// System stats (CPU, memory, goroutines)
		systemCollector, sysErr := health.NewDefaultSystemCollector()
		if sysErr != nil {
			logger.Warn("Failed to initialize system collector", "error", sysErr)
		}

		healthCollector = health.NewCollector(mqttCollector, storageCollector, appCollector, systemCollector)
		healthAlertManager = health.NewAlertManager(health.DefaultThresholds(), health.SMTPConfig{})
		logger.Info("Health collectors initialized (Story #417)")
	}

	// Initialize HTTP API server
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
		healthCollector,  // Story #417: CFGMS health monitoring
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
		controlPlane:            controlPlane, // Story #363
		heartbeatService:        heartbeatService,
		commandPublisher:        commandPublisher,
		registrationHandler:     registrationHandler,
		registrationTokenStore:  regStore,
		dataPlaneProvider:       dataPlane,
		configHandler:           configHandler,
		httpServer:              httpServer,
		signerCertSerial:        signerCertSerial, // Story #378: For registration handler
		healthCollector:         healthCollector,
		alertManager:            healthAlertManager,
	}

	// Wire up QUIC trigger function to API server (if data plane is enabled)
	if dataPlane != nil {
		httpServer.SetQUICTriggerFunc(srv.TriggerQUICConnection)
		logger.Info("QUIC trigger function wired to HTTP API server")
	}

	// Story #416: Wire rollback manager into API server
	rollbackManager := initializeRollbackManager(storageManager, logger)
	httpServer.SetRollbackManager(rollbackManager)
	logger.Info("Rollback manager wired to HTTP API server")

	// Story #416: Wire reports engine into API server
	reportsHandler := initializeReportsHandler(cfg, logger)
	if reportsHandler != nil {
		httpServer.SetReportsHandler(reportsHandler)
		logger.Info("Reports engine wired to HTTP API server")
	}

	return srv, nil
}

// noOpModuleRegistry is a minimal ModuleRegistry for controller wiring.
// Returns safe defaults when no external module registry is configured.
type noOpModuleRegistry struct{}

func (r *noOpModuleRegistry) GetModuleVersion(_ context.Context, _ string) (string, error) {
	return "latest", nil
}

func (r *noOpModuleRegistry) GetModuleDependencies(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (r *noOpModuleRegistry) IsModuleCompatible(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}

// initializeRollbackManager creates and wires the rollback manager.
func initializeRollbackManager(storageManager *interfaces.StorageManager, logger logging.Logger) rollback.RollbackManager {
	// Use durable storage for rollback operations
	rollbackStore := rollback.NewStorageRollbackStore(storageManager.GetConfigStore())

	// Create validator with no-op module registry (full module registry requires separate story)
	rollbackValidator := rollback.NewRollbackValidator(&noOpModuleRegistry{}, nil)

	// Create notifier using standard logger
	rollbackNotifier := rollback.NewDefaultRollbackNotifier(nil)

	// Create local git store for commit history access
	localGitStore := gitStorage.NewLocalRepositoryStore("", "")

	// Create git manager for rollback point discovery (nil provider = local-only mode)
	gitManager := configgit.NewGitManager(nil, localGitStore, configgit.GitManagerConfig{
		DefaultBranch: "main",
		AutoSync:      false,
	})

	manager := rollback.NewRollbackManager(gitManager, rollbackValidator, rollbackStore, rollbackNotifier)
	logger.Info("Rollback manager initialized")
	return manager
}

// initializeReportsHandler creates the reports API handler with its dependencies.
func initializeReportsHandler(cfg *config.Config, logger logging.Logger) *reportapi.Handler {
	// Initialize DNA storage with SQLite backend in a dedicated directory
	dnaStorageConfig := dnaStorage.DefaultConfig()
	dnaStorageConfig.DataDir = filepath.Join(cfg.DataDir, "dna-reports")

	dnaStorageManager, err := dnaStorage.NewManager(dnaStorageConfig, logger)
	if err != nil {
		logger.Warn("Failed to initialize DNA storage for reports engine", "error", err)
		return nil
	}

	// Initialize drift detector with default configuration
	driftDetector, err := dnadrift.NewDetector(nil, logger)
	if err != nil {
		logger.Warn("Failed to initialize drift detector for reports engine", "error", err)
		return nil
	}

	// Build the reports engine from its components
	dataProvider := reportsprovider.New(dnaStorageManager, driftDetector, logger)
	templateProcessor := reportstemplates.New(logger)
	exporter := reportsexporters.New(logger)
	reportsCache := reportscache.NewMemoryCache()
	reportEngine := reportsengine.New(dataProvider, templateProcessor, exporter, reportsCache, logger)

	logger.Info("Reports engine initialized")
	return reportapi.New(reportEngine, exporter, logger)
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

		// Start control plane provider (Story #363)
		if s.controlPlane != nil {
			s.logger.Info("Starting control plane provider...")
			if err := s.controlPlane.Start(ctx); err != nil {
				return fmt.Errorf("failed to start control plane provider: %w", err)
			}
			s.logger.Info("Control plane provider started successfully")

			// Subscribe to events from stewards via ControlPlaneProvider (Story #363)
			// DNA updates, config status reports, and validation requests are received as events
			// using new topic pattern: cfgms/events/+ instead of cfgms/steward/+/{type}
			if err := s.controlPlane.SubscribeEvents(ctx, nil, s.handleEventFromProvider); err != nil {
				return fmt.Errorf("failed to subscribe to events: %w", err)
			}
			s.logger.Info("Subscribed to steward events via control plane provider")
		}
	}

	// Start data plane provider (Story #362)
	s.logger.Info("Controller build version", "version", BUILD_VERSION_CHECK)
	if s.dataPlaneProvider != nil {
		s.logger.Info("Starting data plane provider...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.dataPlaneProvider.Start(ctx); err != nil {
			return fmt.Errorf("failed to start data plane provider: %w", err)
		}
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
	}

	// Start health collector and alert manager (Story #417)
	if s.healthCollector != nil {
		if err := s.healthCollector.Start(context.Background(), 30*time.Second); err != nil {
			s.logger.Warn("Failed to start health collector", "error", err)
		} else {
			s.logger.Info("Health collector started", "interval", "30s")
		}
	}
	if s.alertManager != nil {
		if err := s.alertManager.Start(context.Background()); err != nil {
			s.logger.Warn("Failed to start alert manager", "error", err)
		} else {
			s.logger.Info("Alert manager started")
		}
	}

	// Start HTTP API server
	if s.httpServer != nil {
		logger := s.logger // Capture logger for goroutine
		go func() {
			if err := s.httpServer.Start(); err != nil {
				logger.Error("HTTP API server failed", "error", err)
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

	// Stop health collector and alert manager (Story #417)
	if s.healthCollector != nil {
		if err := s.healthCollector.Stop(); err != nil {
			s.logger.Warn("Failed to stop health collector", "error", err)
		}
	}
	if s.alertManager != nil {
		if err := s.alertManager.Stop(); err != nil {
			s.logger.Warn("Failed to stop alert manager", "error", err)
		}
	}

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

	// Stop control plane provider (Story #363)
	if s.controlPlane != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.controlPlane.Stop(ctx); err != nil {
			s.logger.Warn("Failed to stop control plane provider", "error", err)
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
func (s *Server) GetConfigurationService() *service.ConfigurationServiceV2 {
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

// loadExistingCertificateManager loads the certificate manager from an existing CA.
// Unlike the old initializeCertificateManager, this never creates a new CA — that
// responsibility belongs to `controller --init` (initialization.Run).
func loadExistingCertificateManager(cfg *config.Config, logger logging.Logger) (*cert.Manager, error) {
	certPath := cfg.CertPath
	if certPath == "" {
		certPath = cfg.Certificate.CAPath
	}

	manager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:          certPath,
		LoadExistingCA:       true,
		EnableAutoRenewal:    cfg.Certificate.EnableCertManagement,
		RenewalThresholdDays: cfg.Certificate.RenewalThresholdDays,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load existing CA from %s: %w", cfg.Certificate.CAPath, err)
	}
	logger.Info("Loaded existing Certificate Authority", "ca_path", cfg.Certificate.CAPath)

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
				separated := cfg.Certificate != nil && cfg.Certificate.IsSeparatedArchitecture()
				if err := ensureMQTTCertificatesFromManagerWithArch(cfg.Certificate.CAPath, certManager, logger, separated); err != nil {
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

// ensureMQTTCertificatesFromManagerWithArch generates MQTT server certificates using the certificate manager.
// This ensures MQTT uses the same CA as the HTTP/REST API, enabling proper mTLS with unified certificate chain.
// Story #377: In separated mode, uses CertificateTypeInternalServer; in unified mode, uses CertificateTypeServer.
func ensureMQTTCertificatesFromManagerWithArch(caPath string, certManager *cert.Manager, logger logging.Logger, separated bool) error {
	// Create directory structure
	serverDir := filepath.Join(caPath, "server")
	if err := os.MkdirAll(serverDir, 0750); err != nil { // Restrict to owner+group only
		return fmt.Errorf("failed to create server cert directory: %w", err)
	}

	certCfg := &cert.ServerCertConfig{
		CommonName:   "cfgms-mqtt-server",
		Organization: "CFGMS",
		DNSNames:     []string{"localhost", "cfgms-mqtt-server", "controller-standalone"},
		IPAddresses:  []string{"127.0.0.1", "0.0.0.0"},
		ValidityDays: 365,
	}

	// Generate certificate using appropriate type based on architecture
	var serverCert *cert.Certificate
	var err error
	if separated {
		serverCert, err = certManager.GenerateInternalServerCertificate(certCfg)
	} else {
		serverCert, err = certManager.GenerateServerCertificate(certCfg)
	}
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
			separated := cfg.Certificate != nil && cfg.Certificate.IsSeparatedArchitecture()
			if err := ensureMQTTCertificatesFromManagerWithArch(cfg.Certificate.CAPath, certManager, logger, separated); err != nil {
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
func initializeDataPlaneProvider(cfg *config.Config, logger logging.Logger, certManager *cert.Manager, configService *service.ConfigurationServiceV2) (dataplaneInterfaces.DataPlaneProvider, error) {
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
	s.logger.Info("Attempting to register config handler bridge")

	if s.configHandler == nil {
		return fmt.Errorf("config handler not initialized")
	}

	// Type assert to QUIC provider to access RegisterStreamHandler
	// Interface must match exact signature from pkg/dataplane/providers/quic/provider.go
	type quicProvider interface {
		RegisterStreamHandler(streamID int64, handler quicServer.StreamHandler) error
	}

	provider, ok := s.dataPlaneProvider.(quicProvider)
	if !ok {
		// Not a QUIC provider, skip registration
		s.logger.Warn("Data plane provider does not support stream handler registration", "provider_type", fmt.Sprintf("%T", s.dataPlaneProvider))
		return fmt.Errorf("provider type %T does not implement RegisterStreamHandler", s.dataPlaneProvider)
	}

	// Create bridge handler that adapts old QUIC server signature to new config handler
	bridgeHandler := func(ctx context.Context, sess *quicServer.Session, strm *quic.Stream) error {
		s.logger.Info("Bridge handler invoked", "session_id", sess.ID, "stream_id", (*strm).StreamID())

		// Wrap old QUIC session as DataPlaneSession
		session := &quicSessionBridge{raw: sess}

		// Wrap old QUIC stream as Stream
		stream := &quicStreamBridge{raw: strm}

		// Call config handler with wrapped interfaces
		return s.configHandler.Handle(ctx, session, stream)
	}

	// Register handler for config sync stream (stream ID 4)
	const configSyncStreamID = 4
	if err := provider.RegisterStreamHandler(configSyncStreamID, bridgeHandler); err != nil {
		return fmt.Errorf("failed to register config handler: %w", err)
	}

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

// handleEventFromProvider processes events from stewards via the ControlPlaneProvider.
// Story #363: Unified event handler replaces separate DNA/config-status/validation handlers.
// Events are received on the new topic pattern: cfgms/events/{steward_id}
func (s *Server) handleEventFromProvider(ctx context.Context, event *controlplaneTypes.Event) error {
	switch event.Type {
	case controlplaneTypes.EventDNAChanged:
		return s.handleDNAEvent(ctx, event)
	case controlplaneTypes.EventConfigApplied:
		return s.handleConfigAppliedEvent(ctx, event)
	default:
		// Log unhandled event types for debugging
		s.logger.Debug("Received event from steward",
			"steward_id", event.StewardID,
			"event_type", event.Type,
			"event_id", event.ID)
	}
	return nil
}

// handleDNAEvent processes DNA change events from stewards.
// Story #363: Replaces handleDNAUpdate which used direct MQTT subscription.
func (s *Server) handleDNAEvent(ctx context.Context, event *controlplaneTypes.Event) error {
	s.logger.Info("Received DNA change event",
		"steward_id", event.StewardID,
		"event_id", event.ID)

	// Extract DNA data from event details
	dna := &common.DNA{
		Id:          event.StewardID,
		LastUpdated: timestamppb.New(event.Timestamp),
	}

	// Extract attributes from event details
	if details := event.Details; details != nil {
		if attrs, ok := details["dna"].(map[string]interface{}); ok {
			dna.Attributes = make(map[string]string, len(attrs))
			for k, v := range attrs {
				dna.Attributes[k] = fmt.Sprintf("%v", v)
			}
		}
		if hash, ok := details["config_hash"].(string); ok {
			dna.ConfigHash = hash
		}
		if fp, ok := details["sync_fingerprint"].(string); ok {
			dna.SyncFingerprint = fp
		}
	}

	// Update DNA in controller service
	status, err := s.controllerService.SyncDNA(ctx, dna)
	if err != nil {
		s.logger.Error("Failed to sync DNA",
			"steward_id", event.StewardID,
			"error", err)
		return fmt.Errorf("failed to sync DNA: %w", err)
	}

	if status.Code != common.Status_OK {
		s.logger.Warn("DNA sync returned non-OK status",
			"steward_id", event.StewardID,
			"status_code", status.Code,
			"message", status.Message)
	} else {
		s.logger.Info("DNA synced successfully",
			"steward_id", event.StewardID)
	}

	return nil
}

// handleConfigAppliedEvent processes configuration applied events from stewards.
// Story #363: Replaces handleConfigStatusReport which used direct MQTT subscription.
func (s *Server) handleConfigAppliedEvent(ctx context.Context, event *controlplaneTypes.Event) error {
	s.logger.Info("Received config applied event",
		"steward_id", event.StewardID,
		"event_id", event.ID)

	// Extract config status details from event
	if details := event.Details; details != nil {
		configVersion, _ := details["config_version"].(string)
		overallStatus, _ := details["status"].(string)

		s.logger.Info("Configuration status report",
			"steward_id", event.StewardID,
			"config_version", configVersion,
			"overall_status", overallStatus)

		// Log module details if present
		if modules, ok := details["modules"].(map[string]interface{}); ok {
			for moduleName, moduleData := range modules {
				if moduleMap, ok := moduleData.(map[string]interface{}); ok {
					moduleStatus, _ := moduleMap["status"].(string)
					moduleMessage, _ := moduleMap["message"].(string)
					s.logger.Info("Module status",
						"steward_id", event.StewardID,
						"module", moduleName,
						"status", moduleStatus,
						"message", moduleMessage)
				}
			}
		}
	}

	// TODO: Store status report in database/audit log for MSP admin visibility

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
