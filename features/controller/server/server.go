// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"database/sql"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"google.golang.org/grpc"
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
	"github.com/cfgis/cfgms/features/controller/dispatcher"
	dnaStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/features/controller/push"
	controllerRegistration "github.com/cfgis/cfgms/features/controller/registration"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	"github.com/cfgis/cfgms/features/controller/service"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	scriptmodule "github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/features/rbac"
	reportapi "github.com/cfgis/cfgms/features/reports/api"
	reportscache "github.com/cfgis/cfgms/features/reports/cache"
	reportsengine "github.com/cfgis/cfgms/features/reports/engine"
	reportsexporters "github.com/cfgis/cfgms/features/reports/exporters"
	reportsprovider "github.com/cfgis/cfgms/features/reports/provider"
	reportstemplates "github.com/cfgis/cfgms/features/reports/templates"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	dnadrift "github.com/cfgis/cfgms/features/steward/dna/drift"
	stewardfactory "github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/workflow"
	workflowtrigger "github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc" // gRPC control plane provider
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	dataplaneGRPC "github.com/cfgis/cfgms/pkg/dataplane/providers/grpc" // Register gRPC data plane provider; exported for ServerOptions
	"github.com/cfgis/cfgms/pkg/gitsync"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgRegistration "github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile" // register flatfile provider for OSS composite manager
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"   // register sqlite provider for OSS composite manager
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"gopkg.in/yaml.v3"
)

// buildVersionCheck is a compile-time constant to verify code version in Docker
const buildVersionCheck = "story-362-config-signing-enabled"

// Server represents the controller server component (gRPC-over-QUIC based)
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
	controlPlane            controlplaneInterfaces.ControlPlaneProvider // Story #363 / #514
	connRegistry            registry.Registry                           // Issue #1572: shared steward connection registry (CP provider + API server)
	heartbeatService        *heartbeat.Service
	commandPublisher        *commands.Publisher
	registrationTokenStore  pkgRegistration.Store
	dataPlaneProvider       dataplaneInterfaces.DataPlaneProvider
	configHandler           *controllerTransport.ConfigHandler
	grpcServer              *grpc.Server            // Shared gRPC server for CP+DP (Story #515)
	quicListener            *quictransport.Listener // Shared QUIC listener (Story #515)
	signerCertSerial        string                  // Serial number of server cert used for config signing (Story #378)
	healthCollector         *health.Collector
	alertManager            *health.DefaultAlertManager
	dnaStorageManager       *dnaStorage.Manager                 // Reports engine DNA storage (must be closed on Stop)
	triggerManager          *workflowtrigger.TriggerManagerImpl // Issue #414: Workflow trigger manager
	gitSyncer               *gitsync.Syncer                     // Issue #666: git-sync write-through component
	webhookHandler          *gitsync.WebhookHandler             // Issue #681: drain in-flight webhook syncs on shutdown
	storageManager          *interfaces.StorageManager          // Main storage manager (must be closed on Stop to release SQLite handles)
	manualReviewHook        *api.ManualReviewApprovalHook       // Issue #1599: manual-review approval hook (nil if not in use)
	executionQueue          *scriptmodule.ExecutionQueue        // Issue #1672: persistent queue for script executions
	jobDispatcher           *dispatcher.Dispatcher              // Issue #1672: job dispatcher for script executions
	runManager              *controllerrun.Manager              // Issue #1673: run/job tracking (must be closed on Stop to release SQLite handle)
}

// New creates a new server instance
func New(cfg *config.Config, logger logging.Logger) (*Server, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	logger.Info("Config validated, proceeding with storage initialization...")

	// Initialize global storage provider system - REQUIRED for all deployments
	if cfg.Storage == nil {
		return nil, fmt.Errorf("storage configuration is required for CFGMS operation - configure storage.flatfile_root and storage.sqlite_path (OSS composite). See docs/examples/minimum-storage-config.cfg for examples")
	}

	// Create storage manager — OSS composite (flatfile+SQLite) or database single-provider.
	// The git provider is removed (Issue #664) and is rejected here with a migration hint.
	var storageManager *interfaces.StorageManager
	if cfg.Storage.FlatfileRoot != "" {
		logger.Info("Initializing OSS composite storage backend...",
			"flatfile_root", cfg.Storage.FlatfileRoot,
			"sqlite_path", cfg.Storage.SQLitePath)
		var ossErr error
		storageManager, ossErr = interfaces.CreateOSSStorageManager(cfg.Storage.FlatfileRoot, cfg.Storage.SQLitePath)
		if ossErr != nil {
			return nil, fmt.Errorf("failed to initialize OSS composite storage: %w", ossErr)
		}
		logger.Info("OSS composite storage backend initialized")
	} else if cfg.Storage.Provider == "database" {
		logger.Info("Initializing database storage provider (commercial single-provider mode)")
		var dbErr error
		// Database provider deliberately uses the legacy single-provider helper: commercial
		// deployments run all stores through one PostgreSQL backend, which CreateAllStoresFromConfig
		// is explicitly retained to support (see pkg/storage/interfaces/provider.go).
		//nolint:staticcheck // SA1019 — retained for database single-provider mode
		storageManager, dbErr = interfaces.CreateAllStoresFromConfig("database", cfg.Storage.Config)
		if dbErr != nil {
			return nil, fmt.Errorf("failed to initialize database storage provider: %w. Verify storage.config contains valid database connection parameters", dbErr)
		}
	} else {
		return nil, fmt.Errorf("storage.flatfile_root is required for OSS composite storage, or storage.provider must be 'database' for commercial single-provider mode. The 'git' storage provider has been removed — run 'cfg storage migrate --from git --to flatfile' to migrate existing data")
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
	auditManager, auditErr := audit.NewManager(storageManager.GetAuditStore(), "controller")
	if auditErr != nil {
		return nil, fmt.Errorf("failed to initialize audit manager: %w", auditErr)
	}
	logger.Info("Audit manager created")

	logger.Info("RBAC and Audit systems initialized with pluggable storage", "provider", cfg.Storage.Provider)

	// Initialize default permissions and roles
	logger.Info("Starting RBAC initialization...")
	if err := rbacManager.Initialize(context.Background()); err != nil {
		logger.Warn("Failed to initialize RBAC configuration", "error", err)
	}
	logger.Info("RBAC initialization completed")

	// Initialize tenant management with durable storage
	tenantManager := tenant.NewManager(storageManager.GetTenantStore(), rbacManager)

	// DNA storage — durable steward DNA + fleet registry. Shared by the
	// controller service (warm-loading the steward registry after a restart)
	// and the reports engine. (Issue #1572)
	dnaStorageConfig := dnaStorage.DefaultConfig()
	dnaStorageConfig.DataDir = filepath.Join(cfg.DataDir, "dna-reports")
	dnaStorageManager, dnaErr := dnaStorage.NewManager(dnaStorageConfig, logger)
	if dnaErr != nil {
		logger.Warn("Failed to initialize DNA storage; steward registry will not survive a controller restart", "error", dnaErr)
	}

	// Create the controller service. With durable DNA storage its in-memory
	// steward registry is warm-loaded from a previous run on startup, so a
	// controller restart does not lose track of connected stewards. (Issue #1572)
	var controllerService *service.ControllerService
	if dnaStorageManager != nil {
		controllerService = service.NewControllerServiceWithStorage(logger, dnaStorageManager)
		if loadErr := controllerService.LoadFromStorage(context.Background()); loadErr != nil {
			logger.Warn("Failed to warm-load steward registry from DNA storage", "error", loadErr)
		}
	} else {
		controllerService = service.NewControllerService(logger)
	}

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
	haManager, err := initializeHAManager(logger, storageManager)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HA manager: %w", err)
	}
	logger.Info("HA manager initialized successfully")

	// Initialize registration token store for HTTP-based registration (Story #263)
	var regStore pkgRegistration.Store
	{
		regTokenStore := storageManager.GetRegistrationTokenStore()
		if err := regTokenStore.Initialize(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to initialize registration token store: %w", err)
		}
		regStore = pkgRegistration.NewStorageAdapter(regTokenStore)

		// Seed test tokens only when explicitly requested via environment variable.
		// Never runs in production — must be set deliberately in test environments.
		if os.Getenv("CFGMS_SEED_TEST_TOKENS") == "1" {
			now := time.Now()
			expiredTime := now.Add(-1 * time.Hour)
			testTokens := []*pkgRegistration.Token{
				{
					Token:         "dockertest_standalone", //nolint:gosec // test-only seeding, env-gated
					TenantID:      "test-tenant",
					ControllerURL: "tcp://controller-standalone:1883",
					Group:         "test-group",
					CreatedAt:     now,
					ExpiresAt:     nil,
					Revoked:       false,
				},
				{
					Token:         "integration_reusable", //nolint:gosec // test-only seeding, env-gated
					TenantID:      "test-tenant-integration",
					ControllerURL: "tcp://localhost:1886",
					Group:         "production",
					CreatedAt:     now,
					ExpiresAt:     nil,
					Revoked:       false,
				},
				{
					Token:         "integration_expired", //nolint:gosec // test-only seeding, env-gated
					TenantID:      "test-tenant-integration",
					ControllerURL: "tcp://localhost:1886",
					Group:         "production",
					CreatedAt:     now.Add(-2 * time.Hour),
					ExpiresAt:     &expiredTime,
					Revoked:       false,
				},
				{
					Token:         "integration_revoked", //nolint:gosec // test-only seeding, env-gated
					TenantID:      "test-tenant-integration",
					ControllerURL: "tcp://localhost:1886",
					Group:         "production",
					CreatedAt:     now,
					ExpiresAt:     nil,
					Revoked:       true,
					RevokedAt:     &now,
				},
				{
					Token:         "dockertest_fleet", //nolint:gosec // test-only seeding, env-gated
					TenantID:      "test-tenant-fleet",
					ControllerURL: "fleet-controller:4433",
					Group:         "test-group",
					CreatedAt:     now,
					ExpiresAt:     nil,
					Revoked:       false,
				},
			}

			for _, testToken := range testTokens {
				if err := regStore.SaveToken(context.Background(), testToken); err != nil {
					logger.Warn("Failed to seed test token", "error", err, "token", testToken.Token)
				} else {
					logger.Info("Seeded test registration token", "token", testToken.Token, "tenant", testToken.TenantID)
				}
			}
		}
	}

	// Initialize shared gRPC-over-QUIC transport (Story #515)
	var controlPlane controlplaneInterfaces.ControlPlaneProvider
	// connRegistry tracks active steward ControlChannel connections. It is
	// created once here and shared between the CP provider (which registers
	// connections) and the HTTP API server (which reads connection_state for
	// GET /api/v1/stewards/{id}). Without this wiring the API server has no
	// registry and always reports stewards as disconnected (Issue #1572).
	var connRegistry registry.Registry
	var heartbeatService *heartbeat.Service
	var commandPublisher *commands.Publisher
	var executionQueue *scriptmodule.ExecutionQueue
	var jobDispatcher *dispatcher.Dispatcher
	// hoistedSigner and hoistedSignerCertSerial are set inside the transport block and
	// re-used by the data plane config handler so both consumers share the same key.
	var hoistedSigner signature.Signer
	var hoistedSignerCertSerial string
	if cfg.Transport != nil && certManager != nil {
		logger.Info("Initializing gRPC control plane provider...", "addr", cfg.Transport.ListenAddr)

		grpcTLSConfig, err := buildGRPCControlPlaneTLSConfig(cfg, certManager, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to build transport TLS config: %w", err)
		}

		// Initialize CP provider (shared gRPC server created fresh in Start)
		connRegistry = registry.NewRegistry()
		controlPlane = grpcCP.New(grpcCP.ModeServer)
		if err := controlPlane.Initialize(context.Background(), map[string]interface{}{
			"mode":       "server",
			"addr":       cfg.Transport.ListenAddr,
			"tls_config": grpcTLSConfig,
			"registry":   connRegistry,
		}); err != nil {
			return nil, fmt.Errorf("failed to initialize gRPC control plane provider: %w", err)
		}
		logger.Info("gRPC control plane provider initialized", "provider", controlPlane.Name(), "addr", cfg.Transport.ListenAddr)

		// Story #919: Hoist signer construction so the command publisher, config
		// handler, and job dispatcher all share the same signer instance.
		// Constructed here — before any publisher or dispatcher — so every
		// controller-issued command carries a consistent signature.
		//
		// In separated mode: use CertificateTypeConfigSigning (dedicated signing cert)
		// In unified mode: use CertificateTypeServer (backward compatible)
		if certManager != nil {
			signerCertType := cert.CertificateTypeServer
			if cfg.Certificate != nil && cfg.Certificate.IsSeparatedArchitecture() {
				signerCertType = cert.CertificateTypeConfigSigning
			}
			signerCerts, scErr := certManager.GetCertificatesByType(signerCertType)
			if scErr == nil && len(signerCerts) > 0 {
				hoistedSignerCertSerial = signerCerts[0].SerialNumber
				certPEM, keyPEM, exportErr := certManager.ExportCertificate(hoistedSignerCertSerial, true)
				if exportErr == nil && len(certPEM) > 0 && len(keyPEM) > 0 {
					var signerErr error
					hoistedSigner, signerErr = signature.NewSigner(&signature.SignerConfig{
						PrivateKeyPEM:  keyPEM,
						CertificatePEM: certPEM,
					})
					if signerErr != nil {
						logger.Warn("Failed to create config signer", "error", signerErr)
					} else {
						logger.Info("Config signer initialized successfully",
							"algorithm", hoistedSigner.Algorithm(),
							"fingerprint", hoistedSigner.KeyFingerprint(),
							"cert_serial", hoistedSignerCertSerial,
							"cert_type", signerCertType.String())
					}
				}
			}
		}

		// Initialize execution queue and job dispatcher (Issue #1672).
		// The dispatcher drains the execution queue on every steward heartbeat and
		// on a 30-second polling loop. The heartbeat service wires dispatcher.OnHeartbeat
		// via OnHeartbeatReceived so that the queue is drained within one heartbeat
		// cycle even before the next polling tick.
		logger.Info("Initializing execution queue and job dispatcher...")
		monitor := scriptmodule.NewExecutionMonitor()
		keyManager := scriptmodule.NewEphemeralKeyManager()
		executionQueue = scriptmodule.NewExecutionQueue(
			monitor,
			keyManager,
			0,              // maxAge — defaults to 24 h
			cfg.ListenAddr, // controllerURL for ephemeral-key callbacks
			nil,            // store — defaults to InMemoryQueueStore
			nil,            // scriptRepo — resolved at dispatch time when wired separately
			0,              // dispatchTimeout — defaults to 1 h
		)
		var dispatcherErr error
		jobDispatcher, dispatcherErr = dispatcher.New(&dispatcher.Config{
			Queue:        executionQueue,
			ControlPlane: controlPlane,
			Signer:       hoistedSigner, // share the same signer as commandPublisher
			Logger:       logger,
		})
		if dispatcherErr != nil {
			return nil, fmt.Errorf("failed to initialize job dispatcher: %w", dispatcherErr)
		}
		logger.Info("Execution queue and job dispatcher initialized")

		// Wire the IP-trust evaluator into the heartbeat service when the
		// IP-trust store is available (Issue #1694). The database provider
		// supplies an IPTrustStore; the OSS composite (flatfile+SQLite) returns
		// nil, in which case the evaluator is skipped.
		var heartbeatTrustEvaluator heartbeat.TrustEvaluator
		if ipTrustStore := storageManager.GetIPTrustStore(); ipTrustStore != nil {
			stewardStore := storageManager.GetStewardStore()
			ipTrustThreshold := cfg.Registration.GetIPTrustThreshold()
			evaluator := controllerRegistration.NewIPTrustEvaluator(controllerRegistration.IPTrustEvaluatorConfig{
				Store:     ipTrustStore,
				Threshold: ipTrustThreshold,
				Logger:    logger,
			})
			heartbeatTrustEvaluator = newStewardIPTrustAdapter(evaluator, stewardStore, logger)
			logger.Info("IP-trust evaluator wired into heartbeat service",
				"threshold", ipTrustThreshold)
		}

		// Initialize heartbeat monitoring service
		logger.Info("Initializing heartbeat monitoring service...")
		heartbeatService, err = heartbeat.New(&heartbeat.Config{
			ControlPlane:     controlPlane,
			HeartbeatTimeout: 15 * time.Second,
			CheckInterval:    5 * time.Second,
			OnStatusChange: func(stewardID string, healthy bool, status heartbeat.StewardStatus) {
				if healthy {
					logger.Info("Steward heartbeat recovered", "steward_id", stewardID)
				} else {
					logger.Warn("Steward heartbeat failed", "steward_id", stewardID, "status", status.Status)
				}
			},
			OnHeartbeatReceived: jobDispatcher.OnHeartbeat,
			TrustEvaluator:      heartbeatTrustEvaluator,
			Logger:              logger,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize heartbeat service: %w", err)
		}
		logger.Info("Heartbeat monitoring service initialized successfully")

		// Initialize command publisher (Story #198, Story #363, Story #514, Story #919)
		logger.Info("Initializing command publisher...")
		commandPublisher, err = commands.New(&commands.Config{
			ControlPlane: controlPlane,
			Signer:       hoistedSigner,
			Logger:       logger,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize command publisher: %w", err)
		}
		logger.Info("Command publisher initialized successfully", "signing_enabled", hoistedSigner != nil)
	} else {
		logger.Warn("Transport config not set — gRPC control plane disabled")
	}

	// Initialize gRPC data plane provider (Story #515)
	// The shared gRPC server is passed during Start().
	var dataPlane dataplaneInterfaces.DataPlaneProvider
	if controlPlane != nil {
		logger.Info("Initializing gRPC data plane provider...")
		dataPlane = dataplaneInterfaces.GetProvider("grpc")
		if dataPlane == nil {
			return nil, fmt.Errorf("gRPC data plane provider not registered")
		}
		// Initialize in server mode; the shared gRPC server will be wired during Start
		if err := dataPlane.Initialize(context.Background(), map[string]interface{}{
			"mode":        "server",
			"grpc_server": grpc.NewServer(), // Design decision: this initial gRPC server is replaced by the real server in Start(); this field satisfies initialization requirements before the server lifecycle begins.
		}); err != nil {
			return nil, fmt.Errorf("failed to initialize gRPC data plane provider: %w", err)
		}
		logger.Info("gRPC data plane provider initialized", "provider", dataPlane.Name())
	}

	// Initialize config handler for data plane configuration sync (Story #362)
	// Re-uses the hoisted signer so both config and command signing use the same key.
	var configHandler *controllerTransport.ConfigHandler
	var signerCertSerial string // Story #378: Track cert serial for registration handler
	if dataPlane != nil {
		// Use the signer hoisted above (nil when certManager absent or export failed).
		signerCertSerial = hoistedSignerCertSerial
		configHandler = controllerTransport.NewConfigHandler(configService, logger, hoistedSigner)
		logger.Debug("Config handler initialized for data plane", "signing_enabled", hoistedSigner != nil)
	}

	// Initialize health collectors (Story #417, #517)
	var healthCollector *health.Collector
	var healthAlertManager *health.DefaultAlertManager
	{
		// Transport collector reads from the gRPC control plane provider (Issue #517).
		// Remains nil when no controlPlane is initialized (e.g., Transport config absent).
		var transportCollector health.TransportCollector
		if controlPlane != nil {
			transportCollector = health.NewDefaultTransportCollector(NewGRPCTransportStatsAdapter(controlPlane))
		}

		// Storage stats — provider name only, latency instrumentation is follow-up
		storageStats := NewUnimplementedStorageStats(cfg.Storage.Provider)
		storageCollector := health.NewDefaultStorageCollector(storageStats)

		// Application stats — uses no-op queue stats; workflow engine health
		// is surfaced via the /api/v1/health endpoint (Issue #414)
		appCollector := health.NewDefaultApplicationCollector(&NoOpApplicationQueueStats{})

		// System stats (CPU, memory, goroutines)
		systemCollector, sysErr := health.NewDefaultSystemCollector()
		if sysErr != nil {
			logger.Warn("Failed to initialize system collector", "error", sysErr)
		}

		healthCollector = health.NewCollector(transportCollector, storageCollector, appCollector, systemCollector)
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
		haManager,
		regStore,                      // registrationTokenStore
		signerCertSerial,              // Story #378: signer cert serial for registration
		healthCollector,               // Story #417: CFGMS health monitoring
		auditManager,                  // Issue #775: registration audit events
		commandPublisher,              // Issue #1319: fan-out config push to active stewards
		storageManager.GetPushStore(), // Issue #1320: durable push-state for HA failover
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP API server: %w", err)
	}

	logger.Info("HTTP API server initialized successfully")

	// Wire the shared connection registry into the API server so
	// GET /api/v1/stewards/{id} reports the live connection_state (Issue #1572).
	if connRegistry != nil {
		httpServer.SetRegistry(connRegistry)
	}

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
		controlPlane:            controlPlane, // Story #363 / #514
		connRegistry:            connRegistry, // Issue #1572: shared with CP provider re-init in Start()
		heartbeatService:        heartbeatService,
		commandPublisher:        commandPublisher,
		registrationTokenStore:  regStore,
		dataPlaneProvider:       dataPlane,
		configHandler:           configHandler,
		httpServer:              httpServer,
		signerCertSerial:        signerCertSerial, // Story #378: For registration handler
		healthCollector:         healthCollector,
		alertManager:            healthAlertManager,
		storageManager:          storageManager,
		executionQueue:          executionQueue, // Issue #1672
		jobDispatcher:           jobDispatcher,  // Issue #1672
	}

	// Issue #1673: Wire run/job/execution model into API server.
	// The run store opens a dedicated connection to the same SQLite database.
	if runManager := initializeRunManager(context.Background(), cfg, executionQueue, logger); runManager != nil {
		srv.runManager = runManager
		httpServer.SetRunManager(runManager, executionQueue)
		// Wire the run manager as the dispatcher's completion sink so steward
		// completion events advance run/job status to terminal (Issue #1673).
		if jobDispatcher != nil {
			jobDispatcher.SetRunCompletionSink(runManager)
		}
		logger.Info("Run manager wired to HTTP API server and job dispatcher")
	}

	// Story #416: Wire rollback manager into API server
	rollbackManager := initializeRollbackManager(storageManager, logger, rbacManager)
	httpServer.SetRollbackManager(rollbackManager)
	configService.SetRollbackManager(rollbackManager)
	logger.Info("Rollback manager wired to HTTP API server and gRPC config service")

	// Story #416: Wire reports engine into API server over the shared DNA
	// storage manager. The controller server owns the manager's lifecycle
	// (closed on Stop).
	srv.dnaStorageManager = dnaStorageManager
	reportsHandler := initializeReportsHandler(dnaStorageManager, logger)
	if reportsHandler != nil {
		httpServer.SetReportsHandler(reportsHandler)
		logger.Info("Reports engine wired to HTTP API server")
	}

	// Issue #414: Wire workflow engine and trigger manager into API server
	workflowHandler, triggerMgr := initializeWorkflowHandler(storageManager, logger)
	if workflowHandler != nil {
		httpServer.SetWorkflowHandler(workflowHandler)
		srv.triggerManager = triggerMgr
		logger.Info("Workflow engine wired to HTTP API server")

		// Issue #1527: Seed the built-in registration approval workflow before wiring the hook.
		seedBuiltinRegistrationWorkflow(cfg, storageManager.GetConfigStore(), logger)

		// Issue #1599: When approval_mode = "manual-review", use ManualReviewApprovalHook
		// which persists requests to PendingRegistrationStore for CLI approve/deny (#1522-B).
		// Otherwise fall back to the workflow-engine hook (Issue #422).
		if cfg.Registration != nil && cfg.Registration.ApprovalMode == "manual-review" {
			pendingStore := storageManager.GetPendingRegistrationStore()
			if pendingStore != nil {
				hook := api.NewManualReviewApprovalHook(pendingStore, 24*time.Hour, logger)
				httpServer.SetApprovalHook(hook)
				srv.manualReviewHook = hook
				logger.Info("Manual-review registration approval hook wired (Issue #1599)")
			} else {
				logger.Warn("approval_mode=manual-review requested but PendingRegistrationStore unavailable, falling back to workflow hook")
				approvalHook := workflowHandler.NewRegistrationApprovalHook(logger)
				httpServer.SetApprovalHook(approvalHook)
				logger.Info("Registration approval hook wired (Issue #422)")
			}
		} else {
			// Issue #422: Wire registration approval hook backed by the workflow engine.
			// Operators configure the "steward-registration-approval" workflow to customise policy.
			approvalHook := workflowHandler.NewRegistrationApprovalHook(logger)
			httpServer.SetApprovalHook(approvalHook)
			logger.Info("Registration approval hook wired (Issue #422)")
		}
	}

	// Issue #666: Wire git-sync component when a data directory is configured.
	// The syncer writes through to the controller's config store.
	if cfg.DataDir != "" {
		gitSyncer, webhookHandler := initializeGitSync(cfg.DataDir, storageManager.GetConfigStore(), logger)
		if gitSyncer != nil {
			srv.gitSyncer = gitSyncer
			srv.webhookHandler = webhookHandler // Issue #681: retain for shutdown drain
			if err := gitSyncer.Start(context.Background()); err != nil {
				logger.Warn("git-sync: failed to start syncer", "error", err)
			} else {
				logger.Info("git-sync: syncer started", "data_dir", cfg.DataDir)
			}
			if webhookHandler != nil {
				httpServer.SetGitSyncWebhookHandler(webhookHandler)
			}
		}
	}

	return srv, nil
}

// initializeGitSync creates a git-sync Syncer and webhook handler using the
// given config root and config store. Returns nil, nil when the binding store
// cannot be created.
func initializeGitSync(
	dataDir string,
	configStore cfgconfig.ConfigStore,
	logger logging.Logger,
) (*gitsync.Syncer, *gitsync.WebhookHandler) {
	workDir := filepath.Join(dataDir, ".gitsync", "repos")
	bindingStore, err := gitsync.NewBindingStore(dataDir)
	if err != nil {
		logger.Warn("git-sync: failed to create binding store, git-sync disabled", "error", err)
		return nil, nil
	}
	syncer, err := gitsync.NewSyncer(configStore, bindingStore, workDir, logger)
	if err != nil {
		logger.Warn("git-sync: failed to create syncer, git-sync disabled", "error", err)
		return nil, nil
	}
	webhookHandler := gitsync.NewWebhookHandler(syncer, bindingStore, logger)
	return syncer, webhookHandler
}

// builtinWorkflowTenantID is the tenant scope used when seeding built-in registration
// approval workflows. "root" is the standard root tenant in CFGMS multi-tenant deployments.
// Registrations using tokens with TenantID "root" will find the built-in workflow.
// Sub-tenants requiring the manual-review policy must deploy their own per-tenant workflow.
const builtinWorkflowTenantID = "root"

// seedBuiltinRegistrationWorkflow seeds the appropriate built-in registration approval
// workflow into the config store under the root tenant scope based on
// cfg.Registration.Workflow (Issue #1527).
//
// If the workflow field is empty and a custom "steward-registration-approval" workflow
// already exists in the root scope, seeding is skipped to preserve operator-authored workflows.
func seedBuiltinRegistrationWorkflow(cfg *config.Config, configStore cfgconfig.ConfigStore, logger logging.Logger) {
	ctx := context.Background()

	// Root-tenant workflow store.
	store := workflow.NewWorkflowStore(configStore, builtinWorkflowTenantID)

	workflowChoice := "auto-approve"
	if cfg.Registration != nil && cfg.Registration.Workflow != "" {
		workflowChoice = cfg.Registration.Workflow
	} else {
		// No explicit workflow configured: skip seeding if a custom workflow already exists.
		if _, err := store.GetLatestWorkflow(ctx, "steward-registration-approval"); err == nil {
			logger.Info("Custom registration approval workflow found, skipping built-in seeding (Issue #1527)")
			return
		}
	}

	var rawYAML []byte
	switch workflowChoice {
	case "auto-approve":
		rawYAML = controllerRegistration.AutoApproveYAML
	case "manual-review":
		rawYAML = controllerRegistration.ManualReviewYAML
	default:
		// Sanitize workflowChoice: it flows from user-supplied config into the log,
		// which CodeQL's go/log-injection query flags. Per CLAUDE.md convention.
		logger.Warn("Unknown registration.workflow value, defaulting to auto-approve (Issue #1527)",
			"workflow", logging.SanitizeLogValue(workflowChoice))
		rawYAML = controllerRegistration.AutoApproveYAML
	}

	var vw workflow.VersionedWorkflow
	if err := yaml.Unmarshal(rawYAML, &vw); err != nil {
		logger.Warn("Failed to parse built-in registration workflow YAML (Issue #1527)", "error", err)
		return
	}

	if err := store.StoreWorkflow(ctx, &vw); err != nil {
		logger.Warn("Failed to seed built-in registration workflow (Issue #1527)", "error", err)
		return
	}

	// Sanitize workflowChoice (user-supplied config) — closes go/log-injection.
	logger.Info("Built-in registration approval workflow seeded (Issue #1527)", "workflow", logging.SanitizeLogValue(workflowChoice))
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
func initializeRollbackManager(storageManager *interfaces.StorageManager, logger logging.Logger, rbacManager rbac.RBACManager) rollback.RollbackManager {
	// Use durable storage for rollback operations
	rollbackStore := rollback.NewStorageRollbackStore(storageManager.GetConfigStore())

	// Create validator with no-op module registry (full module registry requires separate story)
	rollbackValidator := rollback.NewRollbackValidator(&noOpModuleRegistry{}, nil, rbacManager)

	// Create notifier using standard logger
	rollbackNotifier := rollback.NewDefaultRollbackNotifier(logger)

	// Create local git store for commit history access
	localGitStore := gitStorage.NewLocalRepositoryStore("", "")

	// Create git manager for rollback point discovery (nil provider = local-only mode)
	gitManager := configgit.NewGitManager(nil, localGitStore, configgit.GitManagerConfig{
		DefaultBranch: "main",
		AutoSync:      false,
	}, logger)

	manager := rollback.NewRollbackManager(gitManager, rollbackValidator, rollbackStore, rollbackNotifier)
	logger.Info("Rollback manager initialized")
	return manager
}

// initializeReportsHandler creates the reports API handler over the shared DNA
// storage manager. Returns nil when DNA storage is unavailable (reports engine
// disabled) — the manager's lifecycle is owned by the caller. (Issue #1572)
func initializeReportsHandler(dnaStorageManager *dnaStorage.Manager, logger logging.Logger) *reportapi.Handler {
	if dnaStorageManager == nil {
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

// initializeWorkflowHandler creates the workflow engine, trigger manager, and API handler.
// Returns nil, nil on failure so the controller starts without workflow support rather than failing.
func initializeWorkflowHandler(storageManager *interfaces.StorageManager, logger logging.Logger) (*api.WorkflowHandler, *workflowtrigger.TriggerManagerImpl) {
	// Create a minimal module factory for the workflow engine.
	// The controller does not load steward modules directly; the factory is
	// required by the engine constructor but not exercised during REST API use.
	moduleFactory := stewardfactory.New(
		discovery.ModuleRegistry{},
		stewardconfig.ErrorHandlingConfig{},
		logger,
	)

	workflowEngine := workflow.NewEngine(moduleFactory, logger, nil)

	configStore := storageManager.GetConfigStore()

	// workflowEngineAdapter bridges workflow.Engine to trigger.WorkflowTrigger.
	// Triggers resolve workflows by name from the default tenant store.
	adapter := &workflowEngineAdapter{
		engine:      workflowEngine,
		configStore: configStore,
	}

	storageProvider, err := interfaces.GetStorageProvider("flatfile")
	if err != nil {
		logger.Warn("Failed to get flatfile storage provider for trigger manager", "error", err)
		return nil, nil
	}
	triggerMgr := workflowtrigger.NewControllerTriggerManager(storageProvider, adapter)

	handler := api.NewWorkflowHandler(workflowEngine, configStore, triggerMgr, logger)

	logger.Info("Workflow engine and trigger manager initialized (Issue #414)")
	return handler, triggerMgr
}

// workflowEngineAdapter implements trigger.WorkflowTrigger by delegating to the workflow engine.
type workflowEngineAdapter struct {
	engine      *workflow.Engine
	configStore cfgconfig.ConfigStore
}

func (a *workflowEngineAdapter) TriggerWorkflow(ctx context.Context, trig *workflowtrigger.Trigger, data map[string]interface{}) (*workflow.WorkflowExecution, error) {
	// Resolve workflow from storage using a system-level (empty) tenant scope.
	store := workflow.NewWorkflowStore(a.configStore, trig.TenantID)
	vw, err := store.GetLatestWorkflow(ctx, trig.WorkflowName)
	if err != nil {
		return nil, fmt.Errorf("workflow %q not found for trigger %q: %w", trig.WorkflowName, trig.ID, err)
	}

	// Merge trigger default variables with runtime data
	vars := make(map[string]interface{})
	for k, v := range trig.Variables {
		vars[k] = v
	}
	for k, v := range data {
		vars[k] = v
	}

	exec, err := a.engine.ExecuteWorkflow(ctx, vw.Workflow, vars)
	if err != nil {
		return nil, fmt.Errorf("failed to start workflow %q: %w", trig.WorkflowName, err)
	}

	return exec, nil
}

func (a *workflowEngineAdapter) ValidateTrigger(_ context.Context, trig *workflowtrigger.Trigger) error {
	if trig.WorkflowName == "" {
		return fmt.Errorf("trigger %q must specify a workflow_name", trig.ID)
	}
	return nil
}

// Start initializes and starts the controller server (gRPC-over-QUIC mode)
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

	// Start shared gRPC-over-QUIC transport and wire composite handler (Story #515)
	s.logger.Info("Controller build version", "version", buildVersionCheck)
	if s.controlPlane != nil {
		// Build TLS config for the QUIC listener
		grpcTLSConfig, err := buildGRPCControlPlaneTLSConfig(s.cfg, s.certManager, s.logger)
		if err != nil {
			return fmt.Errorf("failed to build transport TLS config: %w", err)
		}

		// Create fresh shared gRPC server + QUIC listener per Start() cycle.
		// grpc.Server is not reusable after Stop(), so we create a new one each time.
		s.grpcServer = grpc.NewServer(
			append([]grpc.ServerOption{grpc.Creds(quictransport.TransportCredentials())}, dataplaneGRPC.ServerOptions()...)...,
		)
		ql, err := quictransport.Listen(s.cfg.Transport.ListenAddr, grpcTLSConfig, nil)
		if err != nil {
			return fmt.Errorf("failed to start shared QUIC listener: %w", err)
		}
		s.quicListener = ql

		// Re-initialize CP provider with the fresh gRPC server
		// Re-initializing creates a fresh registry unless the shared one is
		// passed back in — keep the same instance the API server holds so
		// connection_state stays accurate across the Start() re-init (Issue #1572).
		if err := s.controlPlane.Initialize(context.Background(), map[string]interface{}{
			"mode":        "server",
			"addr":        s.cfg.Transport.ListenAddr,
			"tls_config":  grpcTLSConfig,
			"grpc_server": s.grpcServer,
			"registry":    s.connRegistry,
		}); err != nil {
			return fmt.Errorf("failed to re-initialize CP provider with shared server: %w", err)
		}

		// Start CP and DP providers (they create their handlers but don't register/listen)
		if err := s.controlPlane.Start(context.Background()); err != nil {
			return fmt.Errorf("failed to start control plane provider: %w", err)
		}
		s.logger.Info("Control plane provider started")

		if s.dataPlaneProvider != nil {
			// Re-initialize DP with the fresh gRPC server
			if err := s.dataPlaneProvider.Initialize(context.Background(), map[string]interface{}{
				"mode":        "server",
				"grpc_server": s.grpcServer,
			}); err != nil {
				return fmt.Errorf("failed to re-initialize DP provider with shared server: %w", err)
			}
			if err := s.dataPlaneProvider.Start(context.Background()); err != nil {
				return fmt.Errorf("failed to start data plane provider: %w", err)
			}
			s.logger.Info("Data plane provider started", "provider", s.dataPlaneProvider.Name())
		}

		// Build and register composite handler
		cpProvider, ok := s.controlPlane.(*grpcCP.Provider)
		if !ok {
			return fmt.Errorf("control plane provider is not *grpcCP.Provider (got %T)", s.controlPlane)
		}
		cpHandler := cpProvider.ServerHandler()
		if cpHandler == nil {
			return fmt.Errorf("CP provider ServerHandler() returned nil")
		}

		tenantQueue := controllerTransport.NewTenantQueue()
		dnaHandler := controllerTransport.NewDNAHandler(s.logger, tenantQueue)
		bulkHandler := controllerTransport.NewBulkHandler(s.logger, tenantQueue)
		composite := newCompositeTransportServer(cpHandler, dnaHandler, bulkHandler, s.configHandler, s.logger)
		transportpb.RegisterStewardTransportServer(s.grpcServer, composite)

		// Start serving on the shared QUIC listener
		go func() {
			if err := s.grpcServer.Serve(s.quicListener); err != nil {
				s.logger.Error("Shared gRPC server stopped", "error", err)
			}
		}()
		s.logger.Info("Shared gRPC-over-QUIC transport started",
			"addr", s.quicListener.Addr().String())

		// Subscribe to events from stewards via ControlPlaneProvider
		if err := s.controlPlane.SubscribeEvents(context.Background(), nil, s.handleEventFromProvider); err != nil {
			return fmt.Errorf("failed to subscribe to events: %w", err)
		}
		s.logger.Info("Subscribed to steward events via gRPC control plane provider")

		// Start heartbeat monitoring service
		if s.heartbeatService != nil {
			if err := s.heartbeatService.Start(context.Background()); err != nil {
				return fmt.Errorf("failed to start heartbeat service: %w", err)
			}
			s.logger.Info("Heartbeat monitoring service started")
		}

		// Start command publisher
		if s.commandPublisher != nil {
			if err := s.commandPublisher.Start(context.Background()); err != nil {
				return fmt.Errorf("failed to start command publisher: %w", err)
			}
			s.logger.Info("Command publisher started")
		}

		// Start job dispatcher (Issue #1672)
		if s.jobDispatcher != nil {
			if err := s.jobDispatcher.Start(context.Background()); err != nil {
				return fmt.Errorf("failed to start job dispatcher: %w", err)
			}
			s.logger.Info("Job dispatcher started")
		}
	}

	// Start workflow trigger manager (Issue #414)
	if s.triggerManager != nil {
		if err := s.triggerManager.Start(context.Background()); err != nil {
			s.logger.Warn("Failed to start trigger manager", "error", err)
		} else {
			s.logger.Info("Workflow trigger manager started")
		}
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

	s.logger.Info("Controller server started (gRPC-over-QUIC transport mode)",
		"ha_mode", s.haManager.GetDeploymentMode().String(),
		"is_leader", s.haManager.IsLeader())

	// Issue #1320: On startup, if this node is the leader, replay any push
	// operations that were interrupted before a previous leader could complete
	// delivery. Nil haManager means OSS single-node mode, which is always leader.
	if (s.haManager == nil || s.haManager.IsLeader()) && s.commandPublisher != nil {
		go s.resumePendingPushes(context.Background())
	}

	// Record system startup audit event
	if s.auditManager != nil {
		ctx := context.Background()
		// TODO(#751): controller identity as a real tenant — replace audit.SystemTenantID with proper identity.
		event := audit.SystemEvent(audit.SystemTenantID, "controller_start", fmt.Sprintf("Controller server started on %s", s.cfg.ListenAddr))
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

	// Stop manual-review approval hook background goroutine (Issue #1599)
	if s.manualReviewHook != nil {
		s.manualReviewHook.Stop()
	}

	// Stop workflow trigger manager (Issue #414)
	if s.triggerManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.triggerManager.Stop(ctx); err != nil {
			s.logger.Warn("Failed to stop trigger manager", "error", err)
		}
	}

	// Stop HA manager first
	if s.haManager != nil {
		if err := s.haManager.Stop(context.Background()); err != nil {
			s.logger.Warn("Failed to stop HA manager", "error", err)
		}
	}

	// Record system shutdown audit event, then drain the audit write queue and
	// stop the background drain goroutine. Stop must run BEFORE the underlying
	// storage manager is closed so pending entries can still reach disk.
	// Issue #764: audit writes are now asynchronous via an internal queue —
	// Stop provides the shutdown guarantee that previously relied on synchronous
	// store calls.
	if s.auditManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		// TODO(#751): controller identity as a real tenant — replace audit.SystemTenantID with proper identity.
		event := audit.SystemEvent(audit.SystemTenantID, "controller_stop", "Controller server shutting down")
		if err := s.auditManager.RecordEvent(ctx, event); err != nil {
			s.logger.Warn("Failed to record shutdown audit event", "error", err)
		}
		if err := s.auditManager.Stop(ctx); err != nil {
			s.logger.Warn("Failed to stop audit manager", "error", err)
		}
		cancel()
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

	// Stop shared gRPC server and QUIC listener (Story #515)
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	if s.quicListener != nil {
		_ = s.quicListener.Close()
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

	// Stop job dispatcher and execution queue (Issue #1672)
	if s.jobDispatcher != nil {
		s.jobDispatcher.Stop()
	}
	if s.executionQueue != nil {
		s.executionQueue.Stop()
	}

	// Close DNA storage manager (releases SQLite DB file handles)
	if s.dnaStorageManager != nil {
		if err := s.dnaStorageManager.Close(); err != nil {
			s.logger.Warn("Failed to close DNA storage manager", "error", err)
		}
	}

	// Close run manager — releases the dedicated SQLite connection so temp-directory
	// cleanup succeeds on Windows (Issue #1673).
	if s.runManager != nil {
		if err := s.runManager.Close(); err != nil {
			s.logger.Warn("Failed to close run manager", "error", err)
		}
	}

	// Drain in-flight webhook-triggered syncs before closing storage (Issue #681).
	// WaitForPendingSyncs must run before storageManager.Close() because webhook
	// sync goroutines write to the config store.
	if s.webhookHandler != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.webhookHandler.WaitForPendingSyncs(ctx)
	}

	// Stop git-sync syncer — cancels polling goroutines (Issue #666).
	// Must also run before storageManager.Close().
	if s.gitSyncer != nil {
		s.gitSyncer.Stop()
		s.logger.Info("git-sync syncer stopped")
	}

	// Close main storage manager — releases flatfile + SQLite store handles so
	// temp-directory cleanup succeeds on Windows. Must run after managers that
	// use the stores have stopped.
	if s.storageManager != nil {
		if err := s.storageManager.Close(); err != nil {
			s.logger.Warn("Failed to close storage manager", "error", err)
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

// resumePendingPushes is called on leader startup to re-deliver any push
// operations that were recorded as in_progress before the previous leader
// stopped. It unmarshals the stored StewardConfiguration blob and calls
// push.Fanout for each pending record, updating the final status on completion.
func (s *Server) resumePendingPushes(ctx context.Context) {
	if s.storageManager == nil || s.commandPublisher == nil {
		return
	}
	pushStore := s.storageManager.GetPushStore()
	if pushStore == nil {
		return
	}
	records, err := pushStore.GetPendingPushes(ctx)
	if err != nil {
		s.logger.Error("Failed to load pending pushes for leader resume", "error", err)
		return
	}
	if len(records) == 0 {
		return
	}
	s.logger.Info("Resuming pending push operations after leader election", "count", len(records))
	for _, record := range records {
		var cfg push.StewardConfiguration
		if err := json.Unmarshal(record.Data, &cfg); err != nil {
			s.logger.Error("Failed to unmarshal push data for resume; marking failed",
				"push_id", record.ID, "error", err)
			if updateErr := pushStore.UpdatePushStatus(ctx, record.ID, business.PushStatusFailed); updateErr != nil {
				s.logger.Warn("Failed to mark push as failed after unmarshal error",
					"push_id", record.ID, "error", updateErr)
			}
			continue
		}
		stewards := s.controllerService.GetAllStewards()
		result := push.Fanout(ctx, &cfg, stewards, s.commandPublisher, s.logger)
		s.logger.Info("Resumed push fan-out complete",
			"push_id", record.ID,
			"succeeded", len(result.Succeeded),
			"failed", len(result.Failed))
		finalStatus := business.PushStatusCompleted
		if len(result.Failed) > 0 && len(result.Succeeded) == 0 {
			finalStatus = business.PushStatusFailed
		}
		if updateErr := pushStore.UpdatePushStatus(ctx, record.ID, finalStatus); updateErr != nil {
			s.logger.Warn("Failed to update push record status after resume",
				"push_id", record.ID, "error", updateErr)
		}
	}
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

// GetConfigStore returns the controller's config store (Issue #1527: used to verify built-in workflow seeding in tests).
func (s *Server) GetConfigStore() cfgconfig.ConfigStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.storageManager.GetConfigStore()
}

// GetHTTPListenAddr returns the HTTP API server's listen address after binding.
func (s *Server) GetHTTPListenAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.httpServer != nil {
		return s.httpServer.GetListenAddr()
	}
	return ""
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

// initializeHAManager initializes the HA manager using ha.DefaultConfig().
func initializeHAManager(logger logging.Logger, storageManager *interfaces.StorageManager) (*ha.Manager, error) {
	haManager, err := ha.NewManager(ha.DefaultConfig(), logger, storageManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create HA manager: %w", err)
	}
	return haManager, nil
}

// grpcControlPlaneServerSANs returns the DNS names and IP addresses to embed in
// the generated gRPC control-plane server certificate.
//
// It starts from the transport defaults (localhost / loopback) and merges in
// any operator-configured server SANs (certificate.server.dns_names and
// certificate.server.ip_addresses) plus CFGMS_EXTERNAL_HOSTNAME. Without this,
// a steward dialing the controller by its external hostname fails mTLS
// verification because the generated certificate omits that name. The
// CFGMS_EXTERNAL_HOSTNAME value is classified as an IP SAN when it parses as an
// IP literal and as a DNS SAN otherwise. Duplicates are removed and ordering is
// deterministic.
func grpcControlPlaneServerSANs(cfg *config.Config) (dnsNames, ipAddresses []string) {
	dnsNames = []string{"localhost", "cfgms-grpc-server", "controller-standalone"}
	ipAddresses = []string{"127.0.0.1", "0.0.0.0"}

	if cfg != nil && cfg.Certificate != nil && cfg.Certificate.Server != nil {
		dnsNames = append(dnsNames, cfg.Certificate.Server.DNSNames...)
		ipAddresses = append(ipAddresses, cfg.Certificate.Server.IPAddresses...)
	}

	if hostname := strings.TrimSpace(os.Getenv("CFGMS_EXTERNAL_HOSTNAME")); hostname != "" {
		if net.ParseIP(hostname) != nil {
			ipAddresses = append(ipAddresses, hostname)
		} else {
			dnsNames = append(dnsNames, hostname)
		}
	}

	return dedupeSANs(dnsNames), dedupeSANs(ipAddresses)
}

// dedupeSANs returns the input slice with empty strings dropped and duplicates
// removed, preserving first-seen order.
func dedupeSANs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// buildGRPCControlPlaneTLSConfig creates TLS configuration for the gRPC control plane provider.
//
// Uses the certificate manager to load or generate the server certificate and CA, then creates
// a mTLS config with the ALPN identifier required by the gRPC-over-QUIC transport layer.
// In separated architecture mode, uses CertificateTypeInternalServer for mTLS separation.
// Generates a server certificate on first boot if none exists.
func buildGRPCControlPlaneTLSConfig(cfg *config.Config, certManager *cert.Manager, logger logging.Logger) (*tls.Config, error) {
	separated := cfg.Certificate != nil && cfg.Certificate.IsSeparatedArchitecture()
	certType := cert.CertificateTypeServer
	if separated {
		certType = cert.CertificateTypeInternalServer
	}

	var serverCertPEM, serverKeyPEM []byte

	// Try to load existing certificate; generate one on first boot if none exists
	serverCerts, err := certManager.GetCertificatesByType(certType)
	if err != nil || len(serverCerts) == 0 {
		if separated {
			// Also check base server type as fallback in separated mode
			serverCerts, err = certManager.GetCertificatesByType(cert.CertificateTypeServer)
		}
	}

	if err != nil || len(serverCerts) == 0 {
		// First boot: generate server certificate for gRPC control plane.
		// SANs merge the transport defaults with any operator-configured server
		// SANs and CFGMS_EXTERNAL_HOSTNAME so a steward connecting by the
		// controller's external hostname can verify the certificate.
		logger.Info("Generating gRPC control plane server certificate")
		dnsNames, ipAddresses := grpcControlPlaneServerSANs(cfg)
		certCfg := &cert.ServerCertConfig{
			CommonName:   "cfgms-grpc-server",
			Organization: "CFGMS",
			DNSNames:     dnsNames,
			IPAddresses:  ipAddresses,
			ValidityDays: 365,
		}
		var generatedCert *cert.Certificate
		if separated {
			generatedCert, err = certManager.GenerateInternalServerCertificate(certCfg)
		} else {
			generatedCert, err = certManager.GenerateServerCertificate(certCfg)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to generate gRPC control plane server certificate: %w", err)
		}
		serverCertPEM = generatedCert.CertificatePEM
		serverKeyPEM = generatedCert.PrivateKeyPEM
		logger.Info("gRPC control plane server certificate generated", "serial", generatedCert.SerialNumber)
	} else {
		// Load existing certificate
		serial := serverCerts[0].SerialNumber
		serverCertPEM, serverKeyPEM, err = certManager.ExportCertificate(serial, true)
		if err != nil {
			return nil, fmt.Errorf("failed to export gRPC control plane server certificate: %w", err)
		}
		logger.Info("gRPC control plane using existing server certificate", "serial", serial)
	}

	caCertPEM, err := certManager.GetCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate for gRPC control plane: %w", err)
	}

	// Build mTLS server config using pkg/cert helper
	tlsConfig, err := cert.CreateServerTLSConfig(serverCertPEM, serverKeyPEM, caCertPEM, tls.VersionTLS13)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC control plane TLS config: %w", err)
	}

	// Set gRPC-over-QUIC ALPN (distinguishes control plane from data plane on same port)
	tlsConfig.NextProtos = []string{quictransport.ALPNProtocol}

	logger.Info("gRPC control plane TLS config created", "alpn", quictransport.ALPNProtocol)
	return tlsConfig, nil
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
// Story #363: Replaces handleDNAUpdate which used direct topic subscription.
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
// Story #363: Replaces handleConfigStatusReport which used direct topic subscription.
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

// GetTransportListenAddr returns the actual QUIC transport listen address after binding.
// Unlike GetListenAddr (which returns the configured address), this returns the OS-assigned
// address when port 0 is configured, making it safe for dynamic-port integration tests.
func (s *Server) GetTransportListenAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.quicListener != nil {
		return s.quicListener.Addr().String()
	}
	return s.cfg.Transport.ListenAddr
}

// initializeRunManager opens a dedicated SQLite connection for the run store,
// initializes the schema, and returns a run.Manager. Returns nil on failure so
// the controller starts without run support rather than failing.
func initializeRunManager(
	ctx context.Context,
	cfg *config.Config,
	executionQueue *scriptmodule.ExecutionQueue,
	logger logging.Logger,
) *controllerrun.Manager {
	if cfg.Storage == nil || cfg.Storage.SQLitePath == "" {
		logger.Warn("Run manager: SQLite path not configured, run API disabled")
		return nil
	}

	dsn := cfg.Storage.SQLitePath
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		logger.Warn("Run manager: failed to open SQLite", "error", err)
		return nil
	}
	// busy_timeout prevents SQLITE_BUSY errors when the main connection is writing.
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		logger.Warn("Run manager: failed to set busy_timeout", "error", err)
		_ = db.Close()
		return nil
	}

	store := controllerrun.NewRunStoreSQL(db)
	if err := store.Init(ctx); err != nil {
		logger.Warn("Run manager: failed to initialize schema", "error", err)
		_ = db.Close()
		return nil
	}

	logger.Info("Run manager initialized", "sqlite_path", cfg.Storage.SQLitePath)
	return controllerrun.NewManager(store, executionQueue)
}
