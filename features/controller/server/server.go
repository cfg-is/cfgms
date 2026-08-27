// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	common "github.com/cfgis/cfgms/api/proto/common"

	configgit "github.com/cfgis/cfgms/features/config/git"
	gitStorage "github.com/cfgis/cfgms/features/config/git/storage"
	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/features/controller/clusterregistry"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/dispatcher"
	controllerFleet "github.com/cfgis/cfgms/features/controller/fleet"
	dnaStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	"github.com/cfgis/cfgms/features/controller/initialization"
	modulecache "github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/controller/modules/resolution"
	"github.com/cfgis/cfgms/features/controller/push"
	controllerRegistration "github.com/cfgis/cfgms/features/controller/registration"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/controller/tagstore"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	hypervcompletion "github.com/cfgis/cfgms/features/modules/hyperv/completion"
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/rbac"
	reportapi "github.com/cfgis/cfgms/features/reports/api"
	reportscache "github.com/cfgis/cfgms/features/reports/cache"
	reportsengine "github.com/cfgis/cfgms/features/reports/engine"
	reportsexporters "github.com/cfgis/cfgms/features/reports/exporters"
	reportinterfaces "github.com/cfgis/cfgms/features/reports/interfaces"
	reportsprovider "github.com/cfgis/cfgms/features/reports/provider"
	reportstemplates "github.com/cfgis/cfgms/features/reports/templates"
	stewardosquery "github.com/cfgis/cfgms/features/steward/osquery"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/features/workflow"
	workflownodes "github.com/cfgis/cfgms/features/workflow/nodes"
	workflowruntime "github.com/cfgis/cfgms/features/workflow/runtime"
	workflowtrigger "github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc" // gRPC control plane provider
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	dataplaneGRPC "github.com/cfgis/cfgms/pkg/dataplane/providers/grpc" // Register gRPC data plane provider; exported for ServerOptions
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egdatabase "github.com/cfgis/cfgms/pkg/entitygraph/providers/database"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	egconfigstorewriter "github.com/cfgis/cfgms/pkg/entitygraph/writers/configstore"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
	fleetSelector "github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/gitsync"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgRegistration "github.com/cfgis/cfgms/pkg/registration"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/blobstore/filesystem" // register filesystem blob provider (Issue #1702)
	_ "github.com/cfgis/cfgms/pkg/storage/providers/blobstore/s3"         // register S3 blob provider for cluster mode (Issue #2118)
	dbprovider "github.com/cfgis/cfgms/pkg/storage/providers/database"    // Postgres-backed stores; used by initializeSessionStore in cluster mode (Issue #2775)
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"             // register flatfile provider for OSS composite manager
	memoryprovider "github.com/cfgis/cfgms/pkg/storage/providers/memory"  // in-memory fallback stores (Issue #1948, #2296)
	sqliteprovider "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"  // register sqlite provider; provides SQLiteUpgradeStore (Issue #2464)
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"gopkg.in/yaml.v3"
)

// buildVersionCheck is a compile-time constant to verify code version in Docker
const buildVersionCheck = "story-362-config-signing-enabled"

// ObserveManifestProvider is the interface through which the controller server
// accesses module manifests for the Tier-2 observe-module resolution step
// (Issue #3104, ADR-024 Amendment 1 §3). It wraps the module cache in production
// and an in-memory stub in tests. Nil = feature disabled.
type ObserveManifestProvider interface {
	// ListObservableManifests returns all approved module manifests that declare
	// at least one observe_when predicate or have always_pull set, making them
	// eligible for Tier-2 dispatch.
	ListObservableManifests() ([]*modules.ModuleMetadata, error)
}

// moduleManifestAdapter adapts *modulecache.ModuleCache as
// ObserveManifestProvider. Only approved bundles are returned; manifests with no
// observe_when predicates and always_pull unset are silently filtered out.
type moduleManifestAdapter struct {
	cache *modulecache.ModuleCache
}

var _ ObserveManifestProvider = (*moduleManifestAdapter)(nil)

func (p *moduleManifestAdapter) ListObservableManifests() ([]*modules.ModuleMetadata, error) {
	entries, err := p.cache.List()
	if err != nil {
		return nil, fmt.Errorf("list module cache: %w", err)
	}
	var result []*modules.ModuleMetadata
	for _, entry := range entries {
		if entry.Status != modulecache.ApprovalStatusApproved {
			continue
		}
		b, getErr := p.cache.Get(entry.Addr)
		if getErr != nil {
			continue
		}
		if b.Manifest != nil && (len(b.Manifest.ObserveWhen) > 0 || b.Manifest.AlwaysPull) {
			result = append(result, b.Manifest)
		}
	}
	return result, nil
}

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
	logStreamHandler        *controllerTransport.LogStreamHandler // Issue #2140: LogStream ingestion handler
	grpcServer              *grpc.Server                          // Shared gRPC server for CP+DP (Story #515)
	quicListener            *quictransport.Listener               // Shared QUIC listener (Story #515)
	signerCertSerial        string                                // Serial number of server cert used for config signing (Story #378)
	healthCollector         *health.Collector
	alertManager            *health.DefaultAlertManager
	dnaStorageManager       *dnaStorage.Manager                      // Reports engine DNA storage (must be closed on Stop)
	triggerManager          *workflowtrigger.TriggerManagerImpl      // Issue #414: Workflow trigger manager
	gitSyncer               *gitsync.Syncer                          // Issue #666: git-sync write-through component
	webhookHandler          *gitsync.WebhookHandler                  // Issue #681: drain in-flight webhook syncs on shutdown
	storageManager          *interfaces.StorageManager               // Main storage manager (must be closed on Stop to release SQLite handles)
	manualReviewHook        *api.ManualReviewApprovalHook            // Issue #1599: manual-review approval hook (nil if not in use)
	executionQueue          *scriptmodule.ExecutionQueue             // Issue #1672: persistent queue for script executions
	jobDispatcher           *dispatcher.Dispatcher                   // Issue #1672: job dispatcher for script executions
	runManager              *controllerrun.Manager                   // Issue #1673: run/job tracking (must be closed on Stop to release SQLite handle)
	upgradeStore            business.UpgradeStore                    // Issue #2464: durable upgrade store (must be closed on Stop to release SQLite handle)
	tagStore                *tagstore.Store                          // Issue #2542: durable tag store (must be closed on Stop to release SQLite handle)
	sessionStore            session.Store                            // Issue #2774: durable session token store (must be closed on Stop to release SQLite handle)
	ipTrustExpiryJob        *controllerRegistration.IPTrustExpiryJob // Issue #1697: 30-day dark-window expiry
	pendingExpiryJob        *controllerRegistration.PendingExpiryJob // Issue #1697: 5-day pending-registration expiry
	stewardEventManager     *logging.LoggingManager                  // Issue #2139: dedicated sink for ingested steward events
	observeManifestProvider ObserveManifestProvider                  // Issue #3104: nil = Tier-2 disabled
	terminalSessionMgr      terminal.SessionManager                  // Issue #2761: must be stopped on Stop to finalize session recordings
	egProvider              egServerProvider                         // Issue #3253: entity graph provider (must be closed on Stop to release DB handle)
	egClusterMembership     dnasync.ClusterMembership                // Issue #3376: gates cluster authority; nil denies every claim
}

// egServerProvider is the combined interface the controller server needs for
// the entity graph provider: the full EntityGraphProvider contract (so the
// provider can be passed directly to SetEntityGraphProvider and
// SetEntityGraphWriteProvider without an intermediate assertion) plus Close()
// for lifecycle management. Both SQLiteEntityGraphProvider and
// DatabaseEntityGraphProvider satisfy this interface (Issue #3253).
type egServerProvider interface {
	eginterfaces.EntityGraphProvider
	Close() error
}

// resolveDNADataRoot returns an ABSOLUTE directory under which the durable DNA
// store (dna-reports/dna.db) is placed. The result MUST be independent of the
// process working directory: two controllers of the same deployment may be
// launched from different CWDs — most importantly the systemd unit
// (WorkingDirectory=/) versus a blue/green candidate spawned by
// `cfg controller upgrade run` (inheriting the operator's CWD). If the DNA path
// were CWD-relative, the candidate would open a DIFFERENT, empty dna.db, warm-
// load zero stewards, and the steward admin registry (cfg list/status/exec)
// would be blind to the whole fleet after a cutover. (Issue #2010)
//
// Resolution:
//   - A rooted cfg.DataDir is honored as-is (config.IsRootedPath, not filepath.IsAbs —
//     a controller.cfg is a reviewed, hand-authored artefact that ships a POSIX
//     data_dir right next to cert_path and is parsed on every platform the controller
//     builds for; filepath.IsAbs answers for the running platform only and would
//     silently discard a POSIX-rooted DataDir on Windows, Issue #3460).
//   - An empty OR relative cfg.DataDir is replaced by a root derived from the
//     configured durable storage paths (SQLitePath dir, then FlatfileRoot dir),
//     which are absolute in any real deployment, co-locating the DNA store with
//     the controller's other durable state.
//   - As a last resort (no storage paths configured, e.g. minimal tests) the
//     value is anchored to an absolute path via filepath.Abs so it is at least
//     deterministic within the process. Note this last-resort anchor is the
//     process CWD at startup, so true cross-CWD consistency in an all-defaults
//     deployment still relies on absolute storage paths being configured (every
//     real deployment, e.g. ctrl-01, sets absolute Storage.SQLitePath).
func resolveDNADataRoot(cfg *config.Config) string {
	root := cfg.DataDir
	if root == "" || !config.IsRootedPath(root) {
		if cfg.Storage != nil {
			switch {
			case cfg.Storage.SQLitePath != "":
				root = filepath.Dir(cfg.Storage.SQLitePath)
			case cfg.Storage.FlatfileRoot != "":
				root = filepath.Dir(cfg.Storage.FlatfileRoot)
			}
		}
	}
	if !config.IsRootedPath(root) {
		if abs, err := filepath.Abs(root); err == nil {
			root = abs
		}
	}
	return root
}

// resolveInstallerBlobRoot returns the configured installer artifact root, or
// derives it from the resolved deployment storage paths. BlobStorage.Root must
// remain empty in DefaultConfig so a YAML data_dir/storage override cannot
// inherit the stale relative "data/installers" default from before unmarshal.
func resolveInstallerBlobRoot(cfg *config.Config) string {
	if cfg.BlobStorage.Root != "" {
		return cfg.BlobStorage.Root
	}
	if cfg.Storage != nil {
		if cfg.Storage.FlatfileRoot != "" {
			return filepath.Join(filepath.Dir(cfg.Storage.FlatfileRoot), "installers")
		}
		if cfg.Storage.SQLitePath != "" {
			return filepath.Join(filepath.Dir(cfg.Storage.SQLitePath), "installers")
		}
	}
	if cfg.DataDir != "" {
		return filepath.Join(cfg.DataDir, "installers")
	}
	return ""
}

// makeHeartbeatStatusChangeCallback builds the OnStatusChange closure wired into
// the heartbeat.Service. When a steward's liveness state changes, the callback
// persists the new status to the durable StewardStore so that cfg steward list
// and GET /api/v1/stewards reflect the change without a restart (Issue #2463).
func makeHeartbeatStatusChangeCallback(store business.StewardStore, logger logging.Logger) heartbeat.StatusChangeCallback {
	return func(sid string, healthy bool, status heartbeat.StewardStatus) {
		if healthy {
			logger.Info("Steward heartbeat recovered", "steward_id", logging.SanitizeLogValue(sid))
			if store == nil {
				return
			}
			rec, getErr := store.GetSteward(context.Background(), sid)
			if getErr != nil {
				logger.Warn("Heartbeat recovery: failed to read current durable status",
					"steward_id", logging.SanitizeLogValue(sid), "error", getErr)
				return
			}
			// Only promote to Active when currently Registered or Lost; never
			// overwrite Deregistered, Archived, Dormant, or Revoked (Issue #2463).
			if rec.Status == business.StewardStatusRegistered || rec.Status == business.StewardStatusLost {
				if updErr := store.UpdateStewardStatus(context.Background(), sid, business.StewardStatusActive); updErr != nil {
					logger.Warn("Heartbeat recovery: failed to persist active status",
						"steward_id", logging.SanitizeLogValue(sid), "error", updErr)
				}
			}
		} else {
			logger.Warn("Steward heartbeat failed", "steward_id", logging.SanitizeLogValue(sid), "status", status.Status)
			if store == nil {
				return
			}
			if updErr := store.UpdateStewardStatus(context.Background(), sid, business.StewardStatusLost); updErr != nil {
				logger.Warn("Heartbeat lost: failed to persist lost status",
					"steward_id", logging.SanitizeLogValue(sid), "error", updErr)
			}
		}
	}
}

// New creates a new server instance
func New(cfg *config.Config, logger logging.Logger) (*Server, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	if err := cfg.ValidateExecutionSecurity(); err != nil {
		return nil, fmt.Errorf("execution security validation failed: %w", err)
	}

	// Validate transport config early: refuse to start if 0.0.0.0 bind has no external address.
	if cfg.Transport != nil && strings.HasPrefix(cfg.Transport.ListenAddr, "0.0.0.0") {
		externalAddr := cfg.Transport.ExternalAddress
		if externalAddr == "" {
			externalAddr = os.Getenv("CFGMS_EXTERNAL_HOSTNAME")
		}
		if externalAddr == "" {
			return nil, fmt.Errorf("transport.listen_addr binds 0.0.0.0 but no external address is configured; set transport.external_address in controller.cfg or CFGMS_EXTERNAL_HOSTNAME env var")
		}
	}

	logger.Info("Config validated, proceeding with storage initialization...")

	// Initialize global storage provider system - REQUIRED for all deployments
	if cfg.Storage == nil {
		return nil, fmt.Errorf("storage configuration is required for CFGMS operation - configure storage.flatfile_root and storage.sqlite_path (OSS composite). See docs/examples/minimum-storage-config.cfg for examples")
	}

	// Create storage manager — cluster mode (Postgres), OSS composite (flatfile+SQLite),
	// or legacy database single-provider. The git provider is removed (Issue #664).
	var storageManager *interfaces.StorageManager
	if cfg.HA.IsClusterMode() {
		// Cluster mode: all business stores backed by shared Postgres so every node
		// serving the same fleet uses the same state (Issue #2119).
		pgDSN := ""
		sessionHMACKey := ""
		if cfg.Storage.Cluster != nil {
			pgDSN = cfg.Storage.Cluster.PostgresDSN
			sessionHMACKey = cfg.Storage.Cluster.SessionHMACKey
		}
		var s3Config map[string]interface{}
		if cfg.Storage.Cluster != nil {
			s3Config = cfg.Storage.Cluster.S3
		}
		logger.Info("Cluster mode: initializing Postgres business store backend...",
			"ha_mode", cfg.HA.Mode)
		var clusterErr error
		storageManager, clusterErr = interfaces.CreateClusterStorageManager(pgDSN, sessionHMACKey, s3Config)
		if clusterErr != nil {
			return nil, fmt.Errorf("failed to initialize cluster storage: %w", clusterErr)
		}
		logger.Info("Cluster storage backend initialized")
		if backendErr := assertClusterBackendsReady(cfg, storageManager); backendErr != nil {
			return nil, backendErr
		}
	} else if cfg.Storage.FlatfileRoot != "" {
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

	// From here on New holds open SQLite/Postgres handles. Every remaining failure
	// returns without a Server, so nothing would ever call Stop to release them —
	// the handles would leak for the process's life. On Windows that also pins the
	// database files, so a caller cannot delete the data directory of a controller
	// that refused to start. Each store below registers itself here as soon as it
	// is opened, mirroring what Stop releases.
	constructed := false
	var openedStores []func() error
	defer func() {
		if constructed {
			return
		}
		// Reverse order, so a store closes before anything it was layered onto.
		for i := len(openedStores) - 1; i >= 0; i-- {
			if closeErr := openedStores[i](); closeErr != nil {
				logger.Warn("Failed to release storage after controller initialization failed",
					"error", closeErr)
			}
		}
	}()
	openedStores = append(openedStores, storageManager.Close)

	// Validate that the constructed StorageManager supplies every store required by
	// the enabled subsystems. A missing required store fails closed here — at startup,
	// before anything tries to use the store — rather than silently producing a nil
	// that causes a 503 at request time (issue #3400 regression guard).
	// Registration (#3491) and push (#3492) are wired; workflow-trigger (#3493)
	// is now wired too — all three subsystems from epic #3406 declare their
	// required stores below.
	activeReqs := collectActiveStorageRequirements(cfg)
	if reqErr := interfaces.ValidateStorageRequirements(storageManager, activeReqs); reqErr != nil {
		return nil, reqErr
	}

	// Collect declared-optional capabilities that are absent in this deployment.
	// Computed once at composition (Issue #3409): the capability set is fixed at
	// startup and served verbatim by GET /api/v1/ha/status — no per-request recompute.
	absentCaps := interfaces.CollectAbsentOptionalCapabilities(storageManager, activeReqs, storageProviderName(cfg))
	if len(absentCaps) > 0 {
		for _, cap := range absentCaps {
			logger.Warn("Optional storage capability absent — deployment running in degraded mode",
				"capability", cap.Capability,
				"subsystem", cap.Subsystem,
				"provider", cap.Provider,
				"consequence", cap.Consequence,
			)
		}
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
	auditSecrets, auditSecretsErr := api.NewSecretStore(cfg)
	if auditSecretsErr != nil {
		return nil, fmt.Errorf("failed to initialize durable audit signing key store: %w", auditSecretsErr)
	}
	auditManager, auditErr := audit.NewManager(
		storageManager.GetAuditStore(),
		"controller",
		audit.WithSecretsStore(auditSecrets),
	)
	closeAuditSecretsErr := auditSecrets.Close()
	if auditErr != nil {
		return nil, fmt.Errorf("failed to initialize audit manager: %w", auditErr)
	}
	if closeAuditSecretsErr != nil {
		return nil, fmt.Errorf("failed to close audit signing key store after initialization: %w", closeAuditSecretsErr)
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
	tenantManager := tenant.NewManager(storageManager.GetTenantStore(), rbacManager).
		WithAuditManager(auditManager)

	// Detect HA cluster mode from cfg.HA (populated by LoadWithPath from ha.mode YAML
	// key and CFGMS_HA_MODE env var). This is the single source of truth for mode
	// selection; the separate haEarlyCfg.LoadFromEnvironment() path is no longer needed
	// because LoadWithPath already applies env-var overrides to cfg.HA (Issue #2119).
	isClusterMode := cfg.HA.IsClusterMode()

	// DNA storage — durable steward DNA + fleet registry. Shared by the
	// controller service (warm-loading the steward registry after a restart)
	// and the reports engine. (Issue #1572)
	//
	// Single-node: SQLite at an absolute, CWD-independent path (see resolveDNADataRoot
	// and Issue #2010). Cluster: PostgreSQL-backed DatabaseBackend shared by all nodes
	// (connection string from CFGMS_DNA_DATABASE_URL); resolveDNADataRoot is not
	// called in cluster mode (Issue #2118).
	dnaStorageConfig := dnaStorage.DefaultConfig()
	if isClusterMode {
		dnaStorageConfig.Backend = dnaStorage.BackendDatabase
		// DatabaseURL left empty: NewDatabaseBackend reads CFGMS_DNA_DATABASE_URL
		// or individual CFGMS_DNA_DB_* env vars.
		logger.Info("Cluster mode: using PostgreSQL DNA backend (CFGMS_DNA_DATABASE_URL)")
	} else {
		dnaStorageConfig.DataDir = filepath.Join(resolveDNADataRoot(cfg), "dna-reports")
	}
	dnaStorageManager, dnaErr := dnaStorage.NewManager(dnaStorageConfig, logger)
	if dnaErr != nil {
		logger.Warn("Failed to initialize DNA storage; steward registry will not survive a controller restart", "error", dnaErr)
	}
	if dnaStorageManager != nil {
		openedStores = append(openedStores, dnaStorageManager.Close)
	}

	// Create the controller service. With durable DNA storage its in-memory
	// steward registry is warm-loaded from a previous run on startup, so a
	// controller restart does not lose track of connected stewards. (Issue #1572)
	var controllerService *service.ControllerService
	if dnaStorageManager != nil {
		controllerService = service.NewControllerServiceWithStorage(logger, dnaStorageManager)
	} else {
		controllerService = service.NewControllerService(logger)
	}
	// Issue #3403: Wire the StewardStore before LoadFromStorage so the warm-load
	// can enumerate enrolled-but-never-connected stewards from the fleet registry
	// in addition to connected stewards tracked in DNA storage.
	if ss := storageManager.GetStewardStore(); ss != nil {
		controllerService.SetStewardStore(ss)
	}
	// LoadFromStorage is a no-op when neither DNA storage nor StewardStore is
	// configured (controller_service.go:130). Call it unconditionally so a
	// deployment without DNA storage still warms the registry from StewardStore.
	if err := controllerService.LoadFromStorage(context.Background()); err != nil {
		// Do not log the raw error: storage-driver errors embed the DSN (and
		// therefore the DB password) in their message text. Log the fixed sentinel
		// only; the storage layer already logs the underlying cause at its boundary.
		logger.Warn("Failed to warm-load steward registry from DNA storage or fleet store")
	}

	// Wire deployment ring config into controller service (Issue #2271).
	if err := cfg.ValidateDeploymentRings(); err != nil {
		return nil, fmt.Errorf("invalid deployment_rings config: %w", err)
	}
	controllerService.SetRingConfig(cfg.EffectiveRings())

	// Issue #2542: Wire durable SQLite-backed tag store. Nil when SQLite is not
	// configured (tags API degrades gracefully; SetTagStore is a no-op on nil).
	tagStoreInstance := initializeTagStore(context.Background(), cfg, logger)
	if tagStoreInstance != nil {
		openedStores = append(openedStores, tagStoreInstance.Close)
		controllerService.SetTagStore(tagStoreInstance)
	}

	// Issue #3253: Construct the entity graph provider, tracking the same
	// storage backend as the rest of the controller. The provider is registered
	// in openedStores immediately so a mid-New failure releases its handle.
	egProvider, egErr := initializeEntityGraphProvider(cfg, logger)
	if egErr != nil {
		return nil, fmt.Errorf("failed to initialize entity graph provider: %w", egErr)
	}
	openedStores = append(openedStores, egProvider.Close)

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
		if cfg.SecurityProfile == config.SecurityProfilePublicBeta {
			if err := validatePublicBetaControllerRoots(certManager, time.Now()); err != nil {
				return nil, fmt.Errorf("public-beta signing roots are invalid: %w", err)
			}
		}

		// Reject legacy unified-mode config and block on legacy cert types in store
		if err := cfg.Certificate.ValidateCertificateArchitecture(); err != nil {
			return nil, err
		}
		if err := certManager.CheckForLegacyCertificates(); err != nil {
			return nil, err
		}

		// Ensure purpose-specific certificates exist (idempotent first-boot generation).
		// initialization.TransportCertSANs merges transport defaults, operator-configured
		// SANs (server + internal blocks), and CFGMS_EXTERNAL_HOSTNAME so stewards can
		// verify the cert by external hostname. Shared with initialization.Run so that
		// --init mints the cert with the same SAN set this startup path would generate.
		logger.Info("Ensuring separated certificates (internal mTLS + config signing)...")
		dnsNames, ipAddresses := initialization.TransportCertSANs(cfg)
		internalCfg := &cert.ServerCertConfig{
			CommonName:   "cfgms-internal",
			DNSNames:     dnsNames,
			IPAddresses:  ipAddresses,
			ValidityDays: 365,
		}
		if cfg.Certificate.Internal != nil && cfg.Certificate.Internal.CommonName != "" {
			internalCfg.CommonName = cfg.Certificate.Internal.CommonName
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

		// Create certificate provisioning service
		certProvisioningService = service.NewCertificateProvisioningService(certManager, logger)
		if cfg.Certificate.ClientCertValidityDays > 0 {
			certProvisioningService.SetCertificateDefaults(
				cfg.Certificate.ClientCertValidityDays,
				cfg.Certificate.Server.Organization,
			)
		}
	}

	// Initialize HA manager. The Raft WAL lives alongside other per-node durable
	// state, matching the module-cache / workflow-runtime pattern.
	logger.Info("Initializing HA manager...")
	raftLogDir := filepath.Join(resolveDNADataRoot(cfg), "raft-log")
	haManager, err := initializeHAManager(cfg, logger, storageManager, certManager, raftLogDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HA manager: %w", err)
	}
	logger.Info("HA manager initialized successfully")

	// Initialize registration token store for HTTP-based registration (Story #263)
	var regStore pkgRegistration.Store
	regTokenStore := storageManager.GetRegistrationTokenStore()
	{
		if regTokenStore == nil {
			return nil, fmt.Errorf("registration token store is required")
		}
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
				{
					Token:         "dockertest_fleet_child_a", //nolint:gosec // test-only seeding, env-gated
					TenantID:      "fleet-root/fleet-child-a",
					ControllerURL: "fleet-controller:4433",
					Group:         "test-group",
					CreatedAt:     now,
					ExpiresAt:     nil,
					Revoked:       false,
				},
				{
					Token:         "dockertest_fleet_child_b", //nolint:gosec // test-only seeding, env-gated
					TenantID:      "fleet-root/fleet-child-b",
					ControllerURL: "fleet-controller:4433",
					Group:         "test-group",
					CreatedAt:     now,
					ExpiresAt:     nil,
					Revoked:       false,
				},
			}

			for _, testToken := range testTokens {
				redactedToken := logging.RedactedID(testToken.Token)
				if err := regStore.SaveToken(context.Background(), testToken); err != nil {
					logger.Warn("Failed to seed test token", "error", err, "token", redactedToken)
				} else {
					logger.Info("Seeded test registration token", "token", redactedToken, "tenant", testToken.TenantID)
				}
			}

			// Seed fleet cascade tenant hierarchy and MSP-level parent policy (Issue #1723).
			// Creates fleet-root → fleet-child-a/fleet-child-b so the InheritanceResolver
			// can walk the ancestor chain and cascade the parent policy to both child tenants.
			seedFleetCascadeTestData(context.Background(), storageManager, logger)
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
	// hoistedSigner is the static signing cert captured at boot. It is kept for
	// the config handler's nil-certManager fallback path. The command publisher and
	// dispatcher use commandSigner (a DynamicSigner) instead (Issue #1844).
	// hoistedSignerCertSerial is reported by the registration handler (Story #378).
	var hoistedSigner signature.Signer
	var hoistedSignerCertSerial string
	// signingRotationSvc is hoisted so it can be wired to both the gRPC on-connect hook
	// and the HTTP API rotate endpoint (Issue #1816).
	var signingRotationSvc *service.SigningRotationService
	if cfg.Transport != nil && certManager != nil {
		logger.Info("Initializing gRPC control plane provider...", "addr", cfg.Transport.ListenAddr)

		grpcTLSConfig, err := buildGRPCControlPlaneTLSConfig(cfg, certManager, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to build transport TLS config: %w", err)
		}

		// Initialize CP provider (shared gRPC server created fresh in Start).
		// Issue #1817: Create the signing rotation service before the provider so
		// we can inject it as the on-connect hook. The publisher is wired after
		// commandPublisher is constructed below (breaks the init cycle).
		connRegistry = registry.NewRegistry()
		stewardStore := storageManager.GetStewardStore()
		if stewardStore == nil {
			return nil, fmt.Errorf("steward approval store is required when transport is enabled")
		}
		approvalChecker := grpcCP.NewStewardStoreApprovalChecker(stewardStore)
		// Issue #2008: compose the admin-registry upsert hook alongside the
		// signing-rotation hook so every authenticated (re)connect repopulates
		// ControllerService.s.stewards (which backs cfg steward list/status/exec).
		// A cert-reuse reconnect never re-runs HTTP registration, so without this
		// the registry stays empty for a reconnecting steward until a restart.
		registryConnectHook := service.NewStewardRegistryConnectHook(controllerService, logger)
		// Issue #2050: completion reconciler — flips finalizing→ready when the
		// newly-registered steward's CN matches the CorrelationID in the provision
		// record, and sweeps timed-out non-terminal records to failed. A no-op
		// memProvisionStore is used when the hyperv feature is not configured so
		// the controller boots cleanly without any hyperv-specific configuration.
		completionReconciler := hypervcompletion.New(hyperv.NewMemProvisionStore(), logger)
		if certManager != nil {
			signingRotationSvc = service.NewSigningRotationService(certManager, logger)
			composite := service.NewCompositeOnConnectHook(logger, signingRotationSvc, registryConnectHook, completionReconciler)
			controlPlane = grpcCP.New(
				grpcCP.ModeServer,
				grpcCP.WithOnConnectHook(composite),
				grpcCP.WithApprovalChecker(approvalChecker),
			)
		} else {
			composite := service.NewCompositeOnConnectHook(logger, registryConnectHook, completionReconciler)
			controlPlane = grpcCP.New(
				grpcCP.ModeServer,
				grpcCP.WithOnConnectHook(composite),
				grpcCP.WithApprovalChecker(approvalChecker),
			)
		}
		if err := controlPlane.Initialize(context.Background(), map[string]interface{}{
			"mode":                     "server",
			"addr":                     cfg.Transport.ListenAddr,
			"tls_config":               grpcTLSConfig,
			"registry":                 connRegistry,
			"logger":                   logger,
			"max_connections":          cfg.Transport.MaxConnections,
			"registration_token_store": regTokenStore,
			"require_security_stores":  true,
		}); err != nil {
			return nil, fmt.Errorf("failed to initialize gRPC control plane provider: %w", err)
		}
		logger.Info("gRPC control plane provider initialized", "provider", controlPlane.Name(), "addr", cfg.Transport.ListenAddr)

		// Story #919: Hoist signer construction so the command publisher, config
		// handler, and job dispatcher all share the same signer instance.
		// Constructed here — before any publisher or dispatcher — so every
		// controller-issued command carries a consistent signature.
		//
		// The signer MUST use a dedicated, persisted config-signing certificate
		// (CertificateTypeConfigSigning) in every architecture mode. A steward
		// caches the controller's signing certificate at registration (and
		// restores it from disk on a cert-reuse reconnect) and rejects any
		// command or config signed by a different key. The gRPC server
		// certificate must never be used as the signer: listing certs by type
		// returns every Server-typed cert newest-first, and the controller owns
		// more than one (gRPC transport + HTTP API), so that selection is not
		// stable across restarts. EnsureSigningCertificate is idempotent — it
		// generates the signing cert once and reuses it on every later boot.
		if certManager != nil {
			if ensureErr := certManager.EnsureSigningCertificate(nil); ensureErr != nil {
				if cfg.SecurityProfile == config.SecurityProfilePublicBeta {
					return nil, fmt.Errorf("public-beta signing certificate initialization failed: %w", ensureErr)
				}
				logger.Warn("Failed to ensure config signing certificate", "error", ensureErr)
			}
			signerCert, scErr := certManager.GetCurrentCertForPurpose(cert.PurposeSigning)
			if scErr == nil {
				hoistedSignerCertSerial = signerCert.SerialNumber
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
							"cert_type", cert.CertificateTypeConfigSigning.String())
					}
				}
			} else if cfg.SecurityProfile == config.SecurityProfilePublicBeta {
				return nil, fmt.Errorf("public-beta signing certificate is unavailable: %w", scErr)
			}
		}
		if cfg.SecurityProfile == config.SecurityProfilePublicBeta && hoistedSigner == nil {
			return nil, fmt.Errorf("public-beta startup requires a valid loaded command-signing certificate and private key")
		}

		// Issue #1844: Command publisher and dispatcher use a DynamicSigner that
		// resolves the current signing cert at each sign call rather than a signer
		// pinned to the boot cert. After a signing-cert rotation where the boot cert
		// is retired from a steward's trusted set, boot-signed commands fail
		// verification on the steward side — the same failure the config signer had
		// before Issue #1816. The DynamicSigner re-resolves the live signing serial
		// per sign and rebuilds the underlying signer only when that serial changes
		// (once per rotation, not once per command).
		//
		// push_signing_cert safety: this command must be signed with a cert the
		// target steward already trusts. During the overlap window both old and new
		// certs are trusted by the steward, so a DynamicSigner resolving the current
		// (newly rotated) cert is safe as long as the steward is within the overlap
		// window. After overlap expires, a steward that missed push_signing_cert
		// needs re-enrollment (Issue #1845).
		var commandSigner signature.Signer
		if certManager != nil {
			cm := certManager
			commandSigner = signature.NewDynamicSigner(func() (string, func() (signature.SigningKeyExport, error), error) {
				current, err := cm.GetCurrentCertForPurpose(cert.PurposeSigning)
				if err != nil {
					return "", nil, err
				}
				serial := current.SerialNumber
				return serial, func() (signature.SigningKeyExport, error) {
					certPEM, keyPEM, exportErr := cm.ExportCertificate(serial, true)
					if exportErr != nil {
						return signature.SigningKeyExport{}, exportErr
					}
					return signature.SigningKeyExport{CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}, nil
				}, nil
			})
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
			Queue:              executionQueue,
			ControlPlane:       controlPlane,
			Signer:             commandSigner,
			RequireSignedAdhoc: cfg.Execution.RequireSignedAdhoc,
			Logger:             logger,
		})
		if dispatcherErr != nil {
			return nil, fmt.Errorf("failed to initialize job dispatcher: %w", dispatcherErr)
		}
		logger.Info("Execution queue and job dispatcher initialized")

		// Wire the IP-trust evaluator into the heartbeat service when the
		// IP-trust store is available (Issue #1694). Both the database provider
		// and the OSS composite (flatfile+SQLite, Issue #1900) supply an
		// IPTrustStore; the evaluator is skipped only when no store is wired.
		hbStewardStore := storageManager.GetStewardStore()
		var heartbeatTrustEvaluator heartbeat.TrustEvaluator
		if ipTrustStore := storageManager.GetIPTrustStore(); ipTrustStore != nil {
			ipTrustThreshold := cfg.Registration.GetIPTrustThreshold()
			evaluator := controllerRegistration.NewIPTrustEvaluator(controllerRegistration.IPTrustEvaluatorConfig{
				Store:     ipTrustStore,
				Threshold: ipTrustThreshold,
				Logger:    logger,
			})
			heartbeatTrustEvaluator = newStewardIPTrustAdapter(evaluator, hbStewardStore, logger)
			logger.Info("IP-trust evaluator wired into heartbeat service",
				"threshold", ipTrustThreshold)
		}

		// Initialize heartbeat monitoring service
		logger.Info("Initializing heartbeat monitoring service...")
		heartbeatService, err = heartbeat.New(&heartbeat.Config{
			ControlPlane:        controlPlane,
			HeartbeatTimeout:    15 * time.Second,
			CheckInterval:       5 * time.Second,
			OnStatusChange:      makeHeartbeatStatusChangeCallback(hbStewardStore, logger),
			OnHeartbeatReceived: jobDispatcher.OnHeartbeat,
			TrustEvaluator:      heartbeatTrustEvaluator,
			Logger:              logger,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize heartbeat service: %w", err)
		}
		logger.Info("Heartbeat monitoring service initialized successfully")

		// Issue #1986: bridge control-plane heartbeats into the steward registry
		// the API serves. heartbeat.Service tracks liveness in its own in-memory
		// map but never updates ControllerService, so GET /api/v1/stewards/{id}
		// would report a last_seen frozen at registration time and a status stuck
		// at "registered" even while the steward heartbeats. Register a second
		// heartbeat handler that advances the registry via RecordHeartbeat.
		//
		// The same handler carries Layer-3 instrumentation: it records the
		// controller-side receipt cadence per steward and warns when a gap exceeds
		// the expected steward interval, so intermittent heartbeat loss is
		// observable without changing log levels.
		if controllerService != nil {
			var heartbeatGapTracker sync.Map // stewardID -> time.Time (last receipt)
			const heartbeatGapWarnThreshold = 45 * time.Second
			if subErr := controlPlane.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *controlplaneTypes.Heartbeat) error {
				if hb == nil {
					return nil
				}
				recorded := controllerService.RecordHeartbeat(hb.StewardID, hb.Version, hb.Timestamp)

				now := time.Now()
				if prev, ok := heartbeatGapTracker.Load(hb.StewardID); ok {
					gap := now.Sub(prev.(time.Time))
					if gap > heartbeatGapWarnThreshold {
						logger.Warn("Steward heartbeat receipt gap exceeded expected interval (Issue #1986 Layer 3)",
							"steward_id", logging.SanitizeLogValue(hb.StewardID),
							"gap", gap.Round(time.Millisecond),
							"recorded", recorded)
					} else {
						logger.Debug("heartbeat received",
							"steward_id", logging.SanitizeLogValue(hb.StewardID),
							"gap", gap.Round(time.Millisecond),
							"recorded", recorded)
					}
				} else {
					logger.Debug("heartbeat received (first)",
						"steward_id", logging.SanitizeLogValue(hb.StewardID),
						"recorded", recorded)
				}
				heartbeatGapTracker.Store(hb.StewardID, now)
				return nil
			}); subErr != nil {
				logger.Warn("Failed to register steward-registry heartbeat bridge", "error", subErr)
			} else {
				logger.Info("Steward-registry heartbeat bridge registered (Issue #1986)")
			}
		}

		// Initialize command publisher (Story #198, Story #363, Story #514, Story #919)
		// Issue #1844: commandSigner is a DynamicSigner — see block above.
		// Issue #3390: haManager is passed as TermSource so every outbound command
		// carries the current Raft term for steward-side fencing (#3436).
		logger.Info("Initializing command publisher...")
		commandPublisher, err = commands.New(&commands.Config{
			ControlPlane: controlPlane,
			Signer:       commandSigner,
			TermSource:   haManager,
			Logger:       logger,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize command publisher: %w", err)
		}
		logger.Info("Command publisher initialized successfully", "signing_enabled", commandSigner != nil)

		// Issue #1817: Wire the publisher into the signing rotation service now
		// that it is available. The service was created before the provider to
		// break the init cycle (hook → provider → publisher → provider).
		if signingRotationSvc != nil {
			signingRotationSvc.SetPublisher(commandPublisher)
			logger.Info("Signing rotation service wired (refresh-on-connect enabled)")
		}

		// Issue #2524: Wire DNA hash mismatch detection so that a heartbeat
		// carrying an unexpected DNA hash automatically triggers a full sync.
		// Guard on both non-nil: transport can be disabled at runtime, so
		// commandPublisher may be nil in degraded configurations.
		if heartbeatService != nil && commandPublisher != nil {
			heartbeatService.SetOnDNAHashMismatch(func(stewardID string) {
				if _, err := commandPublisher.TriggerDNASync(context.Background(), stewardID); err != nil {
					logger.Warn("Failed to trigger DNA sync after hash mismatch",
						"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
				}
			})
			logger.Info("DNA hash mismatch detection wired (Issue #2524)")
		}

		// Issue #2524: Wire post-DNA-sync hook so each successful full sync
		// updates the expected hash in the heartbeat service, suppressing
		// repeated mismatch triggers once the steward's DNA is in sync.
		// Issue #3329: uses the aggregate-root-first dnaStorage.ContentHash in
		// place of the retired stewarddna.ComputeHash(dna.Attributes) — the
		// mismatch-detection wiring above depends on expectedDNAHash actually
		// being set, or it can never fire (see dna_handler.go HandleHeartbeatRoot).
		if controllerService != nil && heartbeatService != nil {
			controllerService.SetPostDNASyncHook(func(stewardID string, dna *common.DNA) {
				hash, hashErr := dnaStorage.ContentHash(dna)
				if hashErr != nil {
					logger.Warn("Failed to compute DNA content hash for expected-hash wiring",
						"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(hashErr.Error()))
					return
				}
				heartbeatService.SetExpectedDNAHash(stewardID, hash)
			})
			logger.Info("Post-DNA-sync hook wired (Issue #2524)")
		}

		// Issue #2524: Warm expectedDNAHash for every previously-known steward
		// from durable storage.  Without this, a controller restart silently
		// disables mismatch detection for all known stewards until each runs a
		// fresh full sync — even though their DNA is already durably stored and
		// loaded by LoadFromStorage (ControllerService.LoadFromStorage comment
		// calls out the identical startup-gap pattern this mirrors).
		if controllerService != nil && heartbeatService != nil {
			warmed := 0
			for _, steward := range controllerService.GetAllStewards() {
				if steward.DNA != nil {
					hash, hashErr := dnaStorage.ContentHash(steward.DNA)
					if hashErr != nil {
						logger.Warn("Failed to compute DNA content hash while warming expected hashes",
							"steward_id", logging.SanitizeLogValue(steward.ID), "error", logging.SanitizeLogValue(hashErr.Error()))
						continue
					}
					if hash != "" {
						heartbeatService.SetExpectedDNAHash(steward.ID, hash)
						warmed++
					}
				}
			}
			logger.Info("Expected DNA hashes warmed from durable storage (Issue #2524)", "warmed", warmed)
		}

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
	var configHandler *controllerTransport.ConfigHandler
	var signerCertSerial string // Story #378: Track cert serial for registration handler
	if dataPlane != nil {
		// Story #378: registration handler reports the boot signer serial.
		signerCertSerial = hoistedSignerCertSerial

		// Config signing must always use the CURRENT signing certificate, not the
		// one captured at boot. After a signing-cert rotation with a short (or zero)
		// overlap window, stewards retire the old cert; a boot-pinned signer would
		// keep signing configs with the retired cert and every steward would reject
		// the payload (Issue #1816 fleet-e2e OfflinePastWindow). The DynamicSigner
		// resolves the live signing serial per sign and rebuilds the underlying
		// signer only when that serial changes (once per rotation). The command
		// publisher uses the same DynamicSigner pattern (Issue #1844).
		configSigner := hoistedSigner
		if certManager != nil {
			cm := certManager
			configSigner = signature.NewDynamicSigner(func() (string, func() (signature.SigningKeyExport, error), error) {
				current, err := cm.GetCurrentCertForPurpose(cert.PurposeSigning)
				if err != nil {
					return "", nil, err
				}
				serial := current.SerialNumber
				return serial, func() (signature.SigningKeyExport, error) {
					certPEM, keyPEM, exportErr := cm.ExportCertificate(serial, true)
					if exportErr != nil {
						return signature.SigningKeyExport{}, exportErr
					}
					return signature.SigningKeyExport{CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}, nil
				}, nil
			})
		}

		configHandler = controllerTransport.NewConfigHandler(configService, logger, configSigner).
			WithControllerService(controllerService)
		logger.Debug("Config handler initialized for data plane", "signing_enabled", configSigner != nil)
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

	// Initialize installer artifact blob store (Issue #1702).
	// Cluster mode: S3-compatible blob store so all nodes share one installer
	// repository (bucket from CFGMS_S3_INSTALLER_BUCKET, credentials from the
	// default AWS credential chain). Single-node: filesystem blob store with the
	// node-local path resolved from config (Issue #2118).
	var installerBlobStore blob.BlobStore
	var blobErr error
	if isClusterMode {
		bucket := os.Getenv("CFGMS_S3_INSTALLER_BUCKET") // guaranteed non-empty by assertClusterBackendsReady
		s3Cfg := map[string]interface{}{
			"bucket": bucket,
		}
		if region := os.Getenv("CFGMS_S3_INSTALLER_REGION"); region != "" {
			s3Cfg["region"] = region
		}
		if endpoint := os.Getenv("CFGMS_S3_INSTALLER_ENDPOINT_URL"); endpoint != "" {
			s3Cfg["endpoint_url"] = endpoint
		}
		installerBlobStore, blobErr = blob.CreateBlobStoreFromConfig("s3", s3Cfg)
		if blobErr != nil {
			return nil, fmt.Errorf("failed to initialize S3 installer blob store: %w", blobErr)
		}
		logger.Info("Cluster mode: S3 installer blob store initialized", "bucket", bucket)
	} else {
		// Derive the default only after the full configuration is loaded so YAML
		// overrides cannot retain a stale relative path from DefaultConfig.
		blobRoot := resolveInstallerBlobRoot(cfg)
		installerBlobStore, blobErr = blob.CreateBlobStoreFromConfig("filesystem",
			map[string]interface{}{"root": blobRoot})
		if blobErr != nil {
			return nil, fmt.Errorf("failed to initialize installer blob store: %w", blobErr)
		}
		logger.Info("Installer artifact blob store initialized", "root", blobRoot)
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
		installerBlobStore,            // Issue #1702: installer artifact storage
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP API server: %w", err)
	}

	logger.Info("HTTP API server initialized successfully")

	// Issue #3409: Wire absent optional capabilities so GET /api/v1/ha/status
	// reports them. Computed once above at composition; never recomputed per request.
	if len(absentCaps) > 0 {
		httpServer.SetAbsentCapabilities(absentCaps)
	}

	// Issue #2545: Wire the durable tag store into the HTTP API server too. The
	// service layer was wired above (line ~371) so the selector engine / role
	// adapter can read tags, but the REST admin endpoints (`/api/v1/stewards/
	// {id}/tags`, handlers_tags.go) read the API server's OWN tagStore field —
	// without this call it stays nil and every tag REST request returns 503
	// TAG_STORE_UNAVAILABLE even though tags resolve fine internally. Nil when
	// SQLite is unconfigured (SetTagStore is a no-op on nil; endpoints degrade to
	// 503 by design in that case).
	if tagStoreInstance != nil {
		httpServer.SetTagStore(tagStoreInstance)
	}

	// Issue #2543: Wire the role-config store into the HTTP API server. Same
	// wiring gap as the tag store above — the role-config REST endpoints
	// (`/api/v1/roles`, handlers_roles.go) read the API server's roleConfigStore
	// field, which is otherwise nil, so every author/list/delete returns 503
	// "Role config store not available". The canonical store is the controller's
	// config store under the role-policies namespace (the same store the
	// selector-driven role adapter reads via GetConfigStore, config_service_v2.go).
	if cs := storageManager.GetConfigStore(); cs != nil {
		httpServer.SetRoleConfigStore(cs)
	}

	// Issue #3253: Wire entity graph provider and its ConfigStore desired-state
	// writer into the HTTP API server. egProvider was constructed above and
	// registered in openedStores; both Set* calls are unconditional because
	// initializeEntityGraphProvider always returns a non-nil provider or an error.
	httpServer.SetEntityGraphProvider(egProvider)
	egWriter, egWriterErr := egconfigstorewriter.New(egProvider)
	if egWriterErr != nil {
		return nil, fmt.Errorf("failed to initialize entity graph configstore writer: %w", egWriterErr)
	}
	httpServer.SetConfigStoreWriter(egWriter)
	// Also wire the same provider as the write path so operator-asserted edge
	// assertions share the same store (Issue #3374).
	httpServer.SetEntityGraphWriteProvider(egProvider)
	// Issue #3613: Also wire the same provider as the watch path so the cockpit
	// WebSocket handler's Watch subscription is reachable in a running
	// controller (else s.egWatchProv stays nil and every /watch request 503s).
	httpServer.SetEntityGraphWatchProvider(egProvider)

	// Issue #2098: Wire registration-refresh stores into the HTTP API server so the
	// challenge/complete endpoints and the admin approve/reject/policy endpoints are
	// operational. GetStewardStore is always non-nil for the OSS composite (flatfile
	// provider creates it); the refresh stores are nil when the non-bundle SQLite
	// fallback path was taken (unit-test-only scenario).
	if ss := storageManager.GetStewardStore(); ss != nil {
		httpServer.SetStewardStore(ss)
	}
	if prs := storageManager.GetPendingRefreshStore(); prs != nil {
		httpServer.SetPendingRefreshStore(prs)
	}
	if rps := storageManager.GetRefreshPolicyStore(); rps != nil {
		httpServer.SetRefreshPolicyStore(rps)
	}
	if aps := storageManager.GetAssurancePolicyStore(); aps != nil {
		httpServer.SetAssurancePolicyStore(aps)
	}
	if tcs := storageManager.GetTenantCrossingStore(); tcs != nil {
		httpServer.SetTenantCrossingStore(tcs)
	}
	if cs := storageManager.GetCaseStore(); cs != nil {
		httpServer.SetCasesStore(cs)
	}
	// TenantStore is core and always present; wire unconditionally for the assurance resolver.
	httpServer.SetTenantStore(storageManager.GetTenantStore())
	if as := storageManager.GetAuditStore(); as != nil {
		httpServer.SetAuditStore(as)
	}

	// Issue #2464: Wire durable SQLite-backed upgrade store; falls back to in-memory
	// when SQLite is not configured so controller startup is never blocked on storage.
	// The store is held in srv.upgradeStore so Stop() can close the SQLite handle.
	upgradeStore := initializeUpgradeStore(context.Background(), cfg, logger)
	httpServer.SetUpgradeStore(upgradeStore)

	// Issue #2774: Wire durable SQLite-backed session token store; falls back to
	// in-memory when SQLite is not configured. SetDurableSessionStore wires both the
	// CLI session manager (ADR-014 defaults) and the web session manager (60m/12h/30s)
	// from a single shared store, so POST /api/v1/sessions and POST /api/v1/auth/login
	// are operational on every startup path and never return 503 SESSION_UNAVAILABLE.
	// The store is held in srv.sessionStore so Stop() can close the SQLite handle.
	sessionStore := initializeSessionStore(context.Background(), cfg, logger)
	httpServer.SetDurableSessionStore(sessionStore)

	// Issue #2296: Wire batch job store and rolling-batch executor so that
	// POST /api/v1/jobs and GET /api/v1/jobs/{id} are operational.
	// The in-memory store is used for the OSS composite deployment; a durable
	// SQLite-backed store is a follow-on story that shares batchjob/store_sqlite.go.
	batchJobStore := memoryprovider.NewBatchJobStore()
	batchJobFleetQuery := &serverBatchjobFleetQuery{svc: controllerService}
	batchJobExecutor := batchjob.NewRollingBatchExecutor(
		batchJobStore,
		batchJobFleetQuery,
		commandPublisher,
		batchjob.NewDnaRoleQuorumChecker(),
		logger,
	)
	httpServer.SetBatchJobStore(batchJobStore)
	httpServer.SetBatchJobExecutor(batchJobExecutor)
	logger.Info("Batch job store and executor wired to HTTP API server (Issue #2296)")

	// Wire the shared connection registry into the API server so
	// GET /api/v1/stewards/{id} reports the live connection_state (Issue #1572).
	if connRegistry != nil {
		httpServer.SetRegistry(connRegistry)
	}

	// Issue #1816: Wire signing rotation service so the rotate endpoint is available.
	if signingRotationSvc != nil {
		signingRotationSvc.SetControllerService(controllerService)
		httpServer.SetSigningRotationService(signingRotationSvc)
		logger.Info("Signing rotation service wired to HTTP API server (Issue #1816)")
	}

	// Wire the registration admission stores the REST handlers read from.
	wireRegistrationAPIStores(httpServer,
		storageManager.GetPendingRegistrationStore(),
		storageManager.GetIPTrustStore(),
		logger)

	// Issue #1697: Create background expiry jobs.
	// IPTrustExpiryJob is only wired when the IPTrustStore is available (database provider).
	// PendingExpiryJob is only wired when the PendingRegistrationStore is available.
	var ipTrustExpiryJob *controllerRegistration.IPTrustExpiryJob
	if ipTrustStore := storageManager.GetIPTrustStore(); ipTrustStore != nil {
		darkWindow := cfg.Registration.GetIPTrustDarkWindow()
		ipTrustExpiryJob = controllerRegistration.NewIPTrustExpiryJob(controllerRegistration.IPTrustExpiryConfig{
			Store:         ipTrustStore,
			TenantStore:   storageManager.GetTenantStore(),
			DarkWindow:    darkWindow,
			CheckInterval: time.Hour,
			Logger:        logger,
		})
		logger.Info("IP-trust expiry job created (Issue #1697)", "dark_window", darkWindow)
	}

	var pendingExpiryJob *controllerRegistration.PendingExpiryJob
	if pendingStore := storageManager.GetPendingRegistrationStore(); pendingStore != nil {
		pendingTimeout := cfg.Registration.GetPendingReviewTimeout()
		pendingExpiryJob = controllerRegistration.NewPendingExpiryJob(controllerRegistration.PendingExpiryConfig{
			Store:         pendingStore,
			Timeout:       pendingTimeout,
			CheckInterval: time.Hour,
			Logger:        logger,
		})
		logger.Info("Pending-registration expiry job created (Issue #1697)", "timeout", pendingTimeout)
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
		upgradeStore:            upgradeStore,     // Issue #2464: closed in Stop() to release SQLite handle on Windows
		tagStore:                tagStoreInstance, // Issue #2542: closed in Stop() to release SQLite handle on Windows
		sessionStore:            sessionStore,     // Issue #2774: closed in Stop() to release SQLite handle on Windows
		executionQueue:          executionQueue,   // Issue #1672
		jobDispatcher:           jobDispatcher,    // Issue #1672
		ipTrustExpiryJob:        ipTrustExpiryJob, // Issue #1697
		pendingExpiryJob:        pendingExpiryJob, // Issue #1697
		egProvider:              egProvider,       // Issue #3253: closed in Stop() to release DB handle
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
	reportsHandler, reportsDataProvider := initializeReportsHandler(egProvider, controllerService, storageManager.GetAlertStore(), logger)
	if reportsHandler != nil {
		httpServer.SetReportsHandler(reportsHandler)
		httpServer.SetDataProvider(reportsDataProvider)
		logger.Info("Reports engine wired to HTTP API server")
	}

	// Issue #3266: Wire alert store into controller API server for the
	// acknowledge/silence endpoints added in S5.
	if as := storageManager.GetAlertStore(); as != nil {
		httpServer.SetAlertStore(as)
		logger.Info("Alert store wired to HTTP API server (Issue #3266)")
	}

	// Issue #414: Wire workflow engine and trigger manager into API server.
	// Issue #1914: Create the controller module cache and workflow module runtime
	// so the factory can fork/exec controller-kind bundles instead of returning
	// ErrWorkflowRuntimeNotAvailable on every cache hit.
	moduleCacheDir := filepath.Join(resolveDNADataRoot(cfg), "module-cache")
	moduleCache, moduleCacheErr := modulecache.New(moduleCacheDir)
	if moduleCacheErr != nil {
		logger.Warn("Failed to initialize controller module cache; workflow modules will be unavailable",
			"error", moduleCacheErr, "dir", moduleCacheDir)
	}
	workflowRuntimeDir := filepath.Join(resolveDNADataRoot(cfg), "workflow-runtime")
	workflowModuleRuntime := workflowruntime.NewModuleRuntime(workflowRuntimeDir)
	workflowHandler, triggerMgr := initializeWorkflowHandler(storageManager, moduleCache, workflowModuleRuntime, logger, httpServer.GetSecretStore(), configService)
	if workflowHandler != nil {
		httpServer.SetWorkflowHandler(workflowHandler)
		srv.triggerManager = triggerMgr
		logger.Info("Workflow engine wired to HTTP API server")
	}

	// Wire Tier-2 observe-module manifest provider from the module cache.
	// When the cache failed to initialize, moduleCache is nil and Tier-2 is disabled.
	// (Issue #3104, ADR-024 Amendment 1 §3)
	if moduleCache != nil {
		srv.observeManifestProvider = &moduleManifestAdapter{cache: moduleCache}
		logger.Info("Tier-2 observe manifest provider wired to module cache")
	}

	// Issue #1695: Wire the registration approval hook based on registration.workflow.
	// ip-trust is the new default and does not require the workflow engine.
	{
		workflowName := resolveRegistrationWorkflow(cfg)

		switch workflowName {
		case registrationWorkflowIPTrust:
			// ip-trust hook is code-wired; seedBuiltinRegistrationWorkflow is a no-op for this path.
			ipTrustStore := storageManager.GetIPTrustStore()
			httpServer.SetApprovalHook(api.NewIPTrustApprovalHook(ipTrustStore, logger))
			if ipTrustStore != nil {
				logger.Info("IP-trust registration approval hook wired (Issue #1695)")
			}

		case registrationWorkflowManualReview:
			// Issue #1527: Seed the manual-review workflow before wiring the hook.
			if workflowHandler != nil {
				seedBuiltinRegistrationWorkflow(cfg, storageManager.GetConfigStore(), logger)
			}
			// Issue #1599: Use ManualReviewApprovalHook which persists requests to
			// PendingRegistrationStore for CLI approve/deny (#1522-B).
			pendingStore := storageManager.GetPendingRegistrationStore()
			if pendingStore == nil {
				// Unreachable in a correctly composed deployment: this workflow
				// contributes ManualReviewApprovalHookStoreRequirements to
				// collectActiveStorageRequirements, so ValidateStorageRequirements
				// already rejected this StorageManager at startup (Issue #3491).
				// Kept as a fail-closed backstop: substituting a different approval
				// hook here would silently apply an admission policy the operator did
				// not configure (#3400 condition).
				return nil, fmt.Errorf("registration.workflow %q requires PendingRegistrationStore but provider %q does not supply it", workflowName, storageManager.GetProviderName())
			}
			hook := api.NewManualReviewApprovalHook(pendingStore, 24*time.Hour, logger)
			httpServer.SetApprovalHook(hook)
			srv.manualReviewHook = hook
			logger.Info("Manual-review registration approval hook wired (Issue #1599)")

		case registrationWorkflowAutoApprove:
			// Deprecated: log a warning but continue to support dev environments.
			logger.Warn("registration.workflow 'auto-approve' is deprecated; use 'ip-trust' (Issue #1695)")
			if workflowHandler != nil {
				seedBuiltinRegistrationWorkflow(cfg, storageManager.GetConfigStore(), logger)
			}
			httpServer.SetApprovalHook(&api.AlwaysApproveHook{})
			logger.Info("auto-approve registration approval hook wired (deprecated)")

		default:
			logger.Warn("Unknown registration.workflow value, defaulting to ip-trust (Issue #1695)",
				"workflow", logging.SanitizeLogValue(workflowName))
			ipTrustStore := storageManager.GetIPTrustStore()
			httpServer.SetApprovalHook(api.NewIPTrustApprovalHook(ipTrustStore, logger))
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

	// The Server now owns the storage manager and releases it in Stop.
	constructed = true
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
// No-op when Workflow == "ip-trust": the IP-trust hook is wired in code, not via a
// workflow entry (Issue #1695).
//
// If the workflow field is empty and a custom "steward-registration-approval" workflow
// already exists in the root scope, seeding is skipped to preserve operator-authored workflows.
func seedBuiltinRegistrationWorkflow(cfg *config.Config, configStore cfgconfig.ConfigStore, logger logging.Logger) {
	// ip-trust hook is code-wired; no workflow seeding is needed.
	if cfg.Registration != nil && cfg.Registration.Workflow == "ip-trust" {
		return
	}

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

// initializeReportsHandler creates the reports API handler backed by the entity
// graph central provider (Issue #3328). Returns nil, nil when egProvider is nil.
// controllerService supplies device→tenant ownership so tenant-scoped callers
// cannot select another tenant's devices.
// alertStore supplies alert acknowledgement and silence state for the dashboard
// alerts feed (Issue #3267); nil disables ack/silence annotation gracefully.
// The DataProvider is returned alongside the Handler so callers can wire it into
// the compliance endpoints for drift-based compliance derivation (Issue #3265).
func initializeReportsHandler(egProvider eginterfaces.EntityGraphProvider, controllerService *service.ControllerService, alertStore business.AlertStore, logger logging.Logger) (*reportapi.Handler, reportinterfaces.DataProvider) {
	if egProvider == nil {
		return nil, nil
	}

	// Build the reports engine from its components
	dataProvider := reportsprovider.New(egProvider, logger)
	templateProcessor := reportstemplates.New(logger)
	exporter := reportsexporters.New(logger)
	reportsCache := reportscache.NewMemoryCache()
	reportEngine := reportsengine.New(dataProvider, templateProcessor, exporter, reportsCache, logger)

	logger.Info("Reports engine initialized")
	// The steward registry is the device→tenant authority for the reports
	// endpoints; a report device ID is a steward ID.
	return reportapi.New(reportEngine, exporter, controllerService, alertStore, logger), dataProvider
}

// initializeWorkflowHandler creates the workflow engine, trigger manager, and API handler.
// Returns nil, nil on failure so the controller starts without workflow support rather than failing.
// secrets is the controller's central secret store (Issue #2374); it is threaded through
// NewEngine → NewProviderRegistry → GitHubAppProvider so the github provider can mint
// App-JWTs on a live controller without failing with "secrets store not configured".
func initializeWorkflowHandler(
	storageManager *interfaces.StorageManager,
	moduleCache *modulecache.ModuleCache,
	workflowRT *workflowruntime.ModuleRuntime,
	logger logging.Logger,
	secrets secretsif.SecretStore,
	configService *service.ConfigurationServiceV2,
) (*api.WorkflowHandler, *workflowtrigger.TriggerManagerImpl) {
	// Workflow module factory: looks up controller-kind module bundles by
	// name in the controller's module cache (#1883) and fork/execs them as
	// workflow-kind module subprocesses connected over the WorkflowModuleClient
	// gRPC contract (#1881, #1914).
	//
	// moduleCache and workflowRT may be nil when initialization failed; in that
	// case the factory surfaces descriptive errors on any module instantiation.
	// REST-only deployments that never resolve modules through the engine are unaffected.
	moduleFactory := workflow.NewWorkflowModuleFactory(moduleCache, workflowRT)

	configStore := storageManager.GetConfigStore()

	setHARoleExecutor := workflownodes.NewSetHARoleNodeExecutor(configStore, configService)
	moveResourceToClusterExecutor := workflownodes.NewMoveResourceToClusterNodeExecutor(configStore, configService)
	workflowEngine := workflow.NewEngine(moduleFactory, logger, secrets, nil, nil, setHARoleExecutor, moveResourceToClusterExecutor)

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

		// The HA manager's context is its LIFETIME, not a startup deadline.
		//
		// ha.Manager.Start derives m.ctx from the context passed here and bounds
		// every background goroutine it launches on it. This used to be a
		// 30-second context.WithTimeout with a deferred cancel, so the moment
		// Server.Start returned, that cancel fired and killed the manager's
		// background work while the manager still reported itself started.
		//
		// The visible damage was cluster membership. publishNodeInfo waits for
		// leader election and then replicates this node's metadata through the
		// Raft log; it observed the cancelled context first and returned without
		// proposing anything, on every node. ClusterState.Nodes stayed empty for
		// the life of the cluster, so GET /api/v1/ha/cluster reported no members
		// and no leader while Raft was electing and replicating normally — only
		// GET /api/v1/ha/status looked correct, because IsLeader reads the raft
		// state directly rather than through the replicated map.
		//
		// Start does not block on the network, so it needs no timeout of its
		// own; shutdown is Server.Stop's job, which calls haManager.Stop.
		if err := s.haManager.Start(context.Background()); err != nil {
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
		ql, err := quictransport.ListenWithLimits(
			s.cfg.Transport.ListenAddr,
			grpcTLSConfig,
			nil,
			quictransport.LimitsForMaxConnections(s.cfg.Transport.MaxConnections),
		)
		if err != nil {
			return fmt.Errorf("failed to start shared QUIC listener: %w", err)
		}
		s.quicListener = ql

		// Re-initialize CP provider with the fresh gRPC server
		// Re-initializing creates a fresh registry unless the shared one is
		// passed back in — keep the same instance the API server holds so
		// connection_state stays accurate across the Start() re-init (Issue #1572).
		if err := s.controlPlane.Initialize(context.Background(), map[string]interface{}{
			"mode":                     "server",
			"addr":                     s.cfg.Transport.ListenAddr,
			"tls_config":               grpcTLSConfig,
			"grpc_server":              s.grpcServer,
			"registry":                 s.connRegistry,
			"max_connections":          s.cfg.Transport.MaxConnections,
			"registration_token_store": s.storageManager.GetRegistrationTokenStore(),
			"require_security_stores":  true,
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
		dnaHandler := controllerTransport.NewDNAHandler(s.logger, tenantQueue, s.controllerService)

		// Wire fragment-root partial-sync detection (Issue #3329). The DNA handler
		// compares the steward-claimed aggregate root against the stored manifest root
		// and requests only changed fragments on mismatch (ADR-017 §7). Must be wired
		// before the heartbeat service starts so no heartbeats are missed.
		if s.heartbeatService != nil {
			s.heartbeatService.SetOnFragmentRoot(dnaHandler.HandleHeartbeatRoot)
			s.logger.Info("Fragment-root partial-sync detection wired (Issue #3329)")
		}

		bulkHandler := controllerTransport.NewBulkHandler(s.logger, tenantQueue)
		logStreamHandler := controllerTransport.NewLogStreamHandler(
			s.stewardEventManager,
			s.controllerService,
			s.logger,
			controllerTransport.DefaultLogStreamConfig(),
		)
		s.logStreamHandler = logStreamHandler
		telemetryHandler := controllerTransport.NewTelemetryHandler(s.logger, nil)
		composite := newCompositeTransportServer(cpHandler, s.logger)
		composite.SetConfigHandler(s.configHandler)
		composite.SetDNAHandler(dnaHandler)
		composite.SetBulkHandler(bulkHandler)
		composite.SetLogStreamHandler(logStreamHandler)
		composite.SetTelemetryHandler(telemetryHandler)

		// Wire terminal relay (Issue #2761). Parse allowed origins from env
		// (mirrors CFGMS_ALLOWED_ORIGINS: comma-separated, trimmed, empty filtered).
		var terminalOrigins []string
		if raw := os.Getenv("CFGMS_TERMINAL_ALLOWED_ORIGINS"); raw != "" {
			for _, o := range strings.Split(raw, ",") {
				if trimmed := strings.TrimSpace(o); trimmed != "" {
					terminalOrigins = append(terminalOrigins, trimmed)
				}
			}
		}
		// Session recordings capture raw keystrokes and shell output of privileged
		// admin sessions, so they are stored under the controller's data directory
		// (same resolution as DNA reports and installer blobs) with owner-only
		// permissions — never a shared, world-writable location such as /tmp.
		terminalCfg := terminal.DefaultConfig()
		terminalCfg.RecordingStoragePath = filepath.Join(resolveDNADataRoot(s.cfg), "terminal-recordings")
		terminalSessionMgr, terminalMgrErr := terminal.NewSessionManager(terminalCfg, s.logger)
		if terminalMgrErr != nil {
			return fmt.Errorf("failed to create terminal session manager: %w", terminalMgrErr)
		}
		// Retained so Stop can finalize recordings of sessions still live at
		// shutdown; without the finalizing .meta sidecar a recording is treated as
		// unverifiable and discarded on the next start.
		s.terminalSessionMgr = terminalSessionMgr
		// Avoid a non-nil interface with a nil pointer (would bypass the nil-check in ServeWebSocket).
		var terminalCmdPub controllerTransport.TerminalCommandPublisher
		if s.commandPublisher != nil {
			terminalCmdPub = s.commandPublisher
		}
		// The audited client IP of a privileged shell session must not be
		// attacker-controlled, so forwarding headers are believed only from the
		// configured reverse proxies (same list that gates the registration
		// IP-trust decision, Issue #1695). Unset means headers are ignored and
		// the TCP peer address is audited.
		var terminalTrustedProxies []string
		if s.cfg.Registration != nil {
			terminalTrustedProxies = s.cfg.Registration.TrustedProxies
		}
		terminalHandler := controllerTransport.NewTerminalHandler(
			s.logger, terminalCmdPub, terminalSessionMgr, s.auditManager, terminalOrigins,
			terminalTrustedProxies,
		)
		composite.SetTerminalHandler(terminalHandler)
		if s.httpServer != nil {
			s.httpServer.SetTerminalHandler(http.HandlerFunc(terminalHandler.ServeWebSocket))
		}

		// Wire osquery ad-hoc fleet query dispatch (Issue #3569).
		// The controller side of OsqueryHandler manages the stream registry (HandleGRPC,
		// QuerySteward); Execute is steward-side only so binPath is irrelevant here.
		osqueryHandler := stewardosquery.NewOsqueryHandler(s.logger, "")
		composite.SetOsqueryHandler(osqueryHandler)
		if s.httpServer != nil {
			s.httpServer.SetOsqueryDispatcher(osqueryHandler)
		}

		transportpb.RegisterStewardTransportServer(s.grpcServer, composite)
		// Wire telemetry WebSocket fan-out into the REST API (Issue #2765).
		if s.httpServer != nil {
			s.httpServer.SetTelemetryHandler(http.HandlerFunc(telemetryHandler.ServeWebSocket))
		}

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

	// Start background expiry jobs (Issue #1697).
	if s.ipTrustExpiryJob != nil {
		if err := s.ipTrustExpiryJob.Start(context.Background()); err != nil {
			s.logger.Warn("Failed to start IP-trust expiry job", "error", err)
		} else {
			s.logger.Info("IP-trust expiry job started (Issue #1697)")
		}
	}
	if s.pendingExpiryJob != nil {
		if err := s.pendingExpiryJob.Start(context.Background()); err != nil {
			s.logger.Warn("Failed to start pending-registration expiry job", "error", err)
		} else {
			s.logger.Info("Pending-registration expiry job started (Issue #1697)")
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
		// api.Server.Start performs synchronous TLS preflight before launching
		// its serving goroutine. Propagate any failure so controller startup
		// cannot report success while the public API is absent or downgraded.
		if err := s.httpServer.Start(); err != nil {
			return fmt.Errorf("failed to start HTTPS API server: %w", err)
		}
		s.logger.Info("HTTP API server started")
	}

	// Observational only (Issue #3389 classification) — stays on IsRaftLeader(), not
	// HasLeadership(): this is a startup log line, not an admission decision.
	s.logger.Info("Controller server started (gRPC-over-QUIC transport mode)",
		"ha_mode", s.haManager.GetDeploymentMode().String(),
		"is_leader", s.haManager.IsRaftLeader()) //architecture:allow-raw-leader -- observational only: startup log records raw protocol state for diagnostics, not an admission decision

	// Issue #1320: On startup, if this node holds lease-backed authority, replay any
	// push operations that were interrupted before a previous leader could complete
	// delivery. Nil haManager means OSS single-node mode, which is always authoritative.
	// HasLeadership(), not IsLeader() (Issue #3389): a replay is side-effecting —
	// it re-delivers to real stewards outside the replicated log, so it belongs on
	// the same admission primitive as handleConfigPush, not the raw Raft flag.
	if (s.haManager == nil || s.haManager.HasLeadership()) && s.commandPublisher != nil {
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

	// Stop the terminal session manager (Issue #2761): closes live shells and the
	// recorder, flushing each recording and writing its .meta sidecar so sessions
	// active at shutdown keep a verifiable audit trail.
	if s.terminalSessionMgr != nil {
		if err := s.terminalSessionMgr.Stop(context.Background()); err != nil {
			s.logger.Warn("Failed to stop terminal session manager", "error", err)
		}
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

	// Stop background expiry jobs (Issue #1697)
	if s.ipTrustExpiryJob != nil {
		s.ipTrustExpiryJob.Stop()
	}
	if s.pendingExpiryJob != nil {
		s.pendingExpiryJob.Stop()
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

	// Close upgrade store — releases the SQLite connection so temp-directory cleanup
	// succeeds on Windows (Issue #2464).
	if s.upgradeStore != nil {
		if err := s.upgradeStore.Close(); err != nil {
			s.logger.Warn("Failed to close upgrade store", "error", err)
		}
	}

	// Close tag store — releases the SQLite connection so temp-directory cleanup
	// succeeds on Windows (Issue #2542).
	if s.tagStore != nil {
		if err := s.tagStore.Close(); err != nil {
			s.logger.Warn("Failed to close tag store", "error", err)
		}
	}

	// Close entity graph provider — releases the SQLite or Postgres connection
	// so temp-directory cleanup succeeds on Windows (Issue #3253).
	if s.egProvider != nil {
		if err := s.egProvider.Close(); err != nil {
			s.logger.Warn("Failed to close entity graph provider", "error", err)
		}
	}

	// Close session store — releases the connection so temp-directory cleanup
	// succeeds on Windows (Issue #2774). MemStore.Close() has no error return while
	// SQLiteSessionTokenStore and DatabaseSessionTokenStore do — use a type switch
	// since the concrete Close signatures do not unify into a shared interface.
	if s.sessionStore != nil {
		switch st := s.sessionStore.(type) {
		case *session.MemStore:
			st.Close()
		case *sqliteprovider.SQLiteSessionTokenStore:
			if err := st.Close(); err != nil {
				s.logger.Warn("Failed to close session store", "error", err)
			}
		case *dbprovider.DatabaseSessionTokenStore:
			if err := st.Close(); err != nil {
				s.logger.Warn("Failed to close session store", "error", err)
			}
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

	// Close the REST API server — releases the public HTTPS listener and the
	// private metrics listener it owns.
	//
	// The metrics listener binds a FIXED port: ValidatePrivateListenerAddress
	// rejects port 0 so a private listener can never land somewhere unpredictable.
	// Leaking it therefore breaks the next Start with "address already in use",
	// where the public listener hid the same leak by taking an OS-assigned port
	// and silently rebinding elsewhere.
	//
	// Runs after the managers that serve requests have stopped and before the
	// storage manager closes: api.Server.Close also releases the secret store and
	// nonce cache, which the audit drain above still needs.
	if s.httpServer != nil {
		apiCtx, apiCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := s.httpServer.Close(apiCtx); err != nil {
			s.logger.Warn("Failed to close REST API server", "error", err)
		}
		apiCancel()
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

// pushStoreRequirements declares the storage dependency for the push-resumption
// subsystem. Push resumption re-delivers interrupted push operations on leader
// startup and cannot query or update delivery records without a durable store.
var pushStoreRequirements = []interfaces.StoreRequirement{
	{Subsystem: "push", Store: interfaces.StoreNamePush, Severity: interfaces.RequirementRequired},
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

// GetAuditManager returns the audit manager instance
func (s *Server) GetAuditManager() *audit.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auditManager
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
	// StoragePath must be the parent of the "ca/" subdirectory; NewManager always derives
	// the real CA directory as filepath.Join(StoragePath,"ca").
	certPath := filepath.Dir(filepath.Clean(cfg.Certificate.CAPath))

	// Cluster-mode CA: the private key lives only in the shared OpenBao vault
	// (cert.NewManagerFromSecretStore never writes it to local disk), so it must
	// be re-fetched from the vault on every regular startup, not just --init.
	// Without this branch, cert.NewManager's LoadExistingCA path below would try
	// (and fail) to read a local ca.key that a cluster-mode node never has.
	if cfg.HA.IsClusterMode() && cfg.Certificate.ClusterCA != nil {
		manager, err := initialization.BuildClusterCertManager(context.Background(), cfg, certPath, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to load cluster CA from vault: %w", err)
		}
		logger.Info("Loaded cluster Certificate Authority from vault", "vault_key_path", cfg.Certificate.ClusterCA.VaultKeyPath)
		return manager, nil
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

func validatePublicBetaControllerRoots(manager *cert.Manager, now time.Time) error {
	caPEM, err := manager.GetCACertificate()
	if err != nil {
		return fmt.Errorf("load controller CA: %w", err)
	}
	remaining := caPEM
	validRoots := 0
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("controller CA contains unexpected PEM block %q", block.Type)
		}
		root, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return fmt.Errorf("parse controller CA certificate: %w", parseErr)
		}
		if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("controller root %q is not a certificate authority", root.Subject.CommonName)
		}
		if now.Before(root.NotBefore) || now.After(root.NotAfter) {
			return fmt.Errorf("controller root %q is not currently valid", root.Subject.CommonName)
		}
		validRoots++
	}
	if strings.TrimSpace(string(remaining)) != "" {
		return fmt.Errorf("controller CA contains malformed trailing data")
	}
	if validRoots == 0 {
		return fmt.Errorf("controller CA contains no valid certificate roots")
	}
	return nil
}

// initializeHAManager initializes the HA manager, transferring the deployment
// mode from the YAML config before loading environment overrides. This ordering
// is required because ha.NewManager calls Validate() before LoadFromEnvironment(),
// and Validate() requires Node.ID for non-single modes; Node.ID comes exclusively
// from CFGMS_NODE_ID (env), never from YAML. Pre-loading env here populates
// Node.ID first so the subsequent NewManager call does not fail Validate().
// CFGMS_HA_MODE env overrides YAML (env > YAML precedence) via the re-run inside NewManager.
// certManager is passed through to ha.NewManager and is required in ClusterMode for mTLS
// peer transport; it may be nil when cluster mode is not in use.
// raftLogDir is the directory for the per-node Raft WAL; pass empty in tests.
func initializeHAManager(cfg *config.Config, logger logging.Logger, storageManager *interfaces.StorageManager, certManager *cert.Manager, raftLogDir string) (*ha.Manager, error) {
	haConfig := ha.DefaultConfig()

	if cfg != nil && cfg.HA != nil && cfg.HA.Mode != "" {
		mode, err := ha.ModeFromString(cfg.HA.Mode)
		if err != nil {
			return nil, fmt.Errorf("invalid ha.mode in config: %w", err)
		}
		haConfig.Mode = mode
	}

	if err := haConfig.LoadFromEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to load HA configuration from environment: %w", err)
	}

	haManager, err := ha.NewManager(haConfig, logger, storageManager, certManager, raftLogDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create HA manager: %w", err)
	}
	return haManager, nil
}

// buildGRPCControlPlaneTLSConfig creates TLS configuration for the gRPC control plane provider.
// Uses GetCurrentCertForPurpose(PurposeTransport) to resolve the InternalServer certificate.
// EnsureSeparatedCertificates guarantees the cert exists before this function is called.
func buildGRPCControlPlaneTLSConfig(cfg *config.Config, certManager *cert.Manager, logger logging.Logger) (*tls.Config, error) {
	serverCert, err := certManager.GetCurrentCertForPurpose(cert.PurposeTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to load gRPC control plane transport certificate: %w", err)
	}
	logger.Info("gRPC control plane using transport certificate", "serial", serverCert.SerialNumber)

	caCertPEM, err := certManager.GetCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate for gRPC control plane: %w", err)
	}

	// Build mTLS server config using pkg/cert helper
	tlsConfig, err := cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, caCertPEM, tls.VersionTLS13)
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
	case controlplaneTypes.EventObserveSweepRequest:
		return s.handleObserveSweepRequest(ctx, event)
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
// Issue #3330: re-homed from flat attribute delta to fragment-based payload.
func (s *Server) handleDNAEvent(ctx context.Context, event *controlplaneTypes.Event) error {
	s.logger.Info("Received DNA change event",
		"steward_id", event.StewardID,
		"event_id", event.ID)

	// Extract DNA data from event details
	dna := &common.DNA{
		Id:          event.StewardID,
		LastUpdated: timestamppb.New(event.Timestamp),
	}

	// Extract fragment list from event details. The payload is a protojson-encoded
	// JSON array string produced by the steward's marshalFragmentsToJSONString —
	// the transport envelope round-trips it as []interface{} via encoding/json, so
	// we re-marshal to bytes and protojson-unmarshal each element back. (Issue #3330)
	if details := event.Details; details != nil {
		if rawDNA, ok := details["dna"]; ok {
			frags, fragErr := extractFragmentsFromDetails(rawDNA)
			if fragErr != nil {
				s.logger.Warn("Failed to extract fragment list from DNA event; skipping DNA field",
					"steward_id", event.StewardID,
					"error", logging.SanitizeLogValue(fragErr.Error()))
			} else {
				dna.Fragments = frags
				// Fragments are the sole DNA payload this path builds (Issue #3330).
				// The flat attribute map is deliberately NOT rebuilt here: every
				// controller consumer of this record projects it from the fragments
				// themselves via service.FlattenDNAFragments (fleet inventory and
				// attribute filters in features/controller/api, the cluster hostname
				// lookup in handlers_clusters.go, and the DNA fingerprint below).
				// AttributeCount is still derived because re-registration change
				// detection compares it (features/controller/service).
				attrCount := len(service.FlattenDNAFragments(frags))
				if attrCount <= math.MaxInt32 {
					// #nosec G115 -- explicitly bounded above
					dna.AttributeCount = int32(attrCount)
				}
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
			"error", logging.SanitizeLogValue(err.Error()))
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

// extractFragmentsFromDetails decodes the "dna" value from a DNA change event's
// Details map into a []*common.Fragment slice.
//
// The steward pre-marshals fragments with protojson into a JSON array string.
// The control-plane transport envelope's encoding/json pass decodes that string
// back to []interface{} via stringMapToInterfaceMap, so this function
// re-marshals the decoded value to bytes and protojson-unmarshals each element.
// Fragments that fail to unmarshal are skipped rather than failing the whole
// extraction — a compromised steward must not block a valid fragment set.
func extractFragmentsFromDetails(raw interface{}) ([]*common.Fragment, error) {
	payloadBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-marshal fragment payload: %w", err)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(payloadBytes, &elems); err != nil {
		return nil, fmt.Errorf("unmarshal fragment array: %w", err)
	}
	frags := make([]*common.Fragment, 0, len(elems))
	for _, elem := range elems {
		frag := &common.Fragment{}
		if err := protojson.Unmarshal(elem, frag); err != nil {
			continue // skip malformed fragments; hostile input must not blank the set
		}
		frags = append(frags, frag)
	}
	return frags, nil
}

// handleConfigAppliedEvent processes configuration applied events from stewards.
// Story #363: Replaces handleConfigStatusReport which used direct topic subscription.
// Issue #3375: adds entity-graph ingestion of apply-outcome records via ReportObservations.
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
			"config_version", logging.SanitizeLogValue(configVersion),
			"overall_status", logging.SanitizeLogValue(overallStatus))

		// Log module details if present (existing behaviour — unchanged).
		if modules, ok := details["modules"].(map[string]interface{}); ok {
			for moduleName, moduleData := range modules {
				if moduleMap, ok := moduleData.(map[string]interface{}); ok {
					moduleStatus, _ := moduleMap["status"].(string)
					moduleMessage, _ := moduleMap["message"].(string)
					s.logger.Info("Module status",
						"steward_id", event.StewardID,
						"module", logging.SanitizeLogValue(moduleName),
						"status", logging.SanitizeLogValue(moduleStatus),
						"message", logging.SanitizeLogValue(moduleMessage))
				}
			}
		}

		// Ingest per-resource apply-outcome records into the entity graph (Issue #3375).
		// apply_outcomes arrives as []interface{} of map[string]interface{} after the
		// Event.Details JSON round-trip through interfaceMapToStringMap/stringMapToInterfaceMap.
		// Decode defensively — same approach as the "modules" branch above.
		if s.egProvider != nil {
			if err := s.ingestApplyOutcomes(ctx, event.StewardID, configVersion, details); err != nil {
				// Log and continue: a write failure here must not prevent the event from
				// being acknowledged. The next apply cycle will produce fresh records.
				s.logger.Error("Failed to ingest apply-outcome records",
					"steward_id", event.StewardID,
					"error", logging.SanitizeLogValue(err.Error()))
			}
		}
	}

	// TODO: Store status report in database/audit log for MSP admin visibility

	return nil
}

// maxApplyOutcomeRecordsPerEvent bounds how many apply-outcome records a single
// config_applied event may contribute. details["apply_outcomes"] carries no length
// limit on the wire and every record costs an entity-graph read plus an observation
// write, so one peer must not be able to size the controller's work per event
// (CLAUDE.md threat model: stewards run on hosts that may be compromised). A steward
// that legitimately applies more resources than this in one cycle reports the
// remainder on its next cycle; the records are additive, so nothing is lost
// permanently.
const maxApplyOutcomeRecordsPerEvent = 1000

// ingestApplyOutcomes decodes apply_outcomes from event details and writes one
// ObservationKindApplyOutcome observation per record into the entity graph.
//
// EID resolution is cluster-aware (Issue #3376): a record lands under
// cluster:<clusterName>/<resourceID> — the EID form used by entity-state (#3367) — when
// a cluster-membership verifier corroborates the peer's cluster independently of the
// peer's own claim AND the graph already holds cluster-scoped entity state for that
// exact resource. Otherwise the record falls back to
// host:<peerHostAuthority>/<resourceID>. Resolution is delegated to
// dnasync.ResolveSubjectEID so both record types share one gate; the gates and their
// rationale are documented on applyOutcomeEIDResolver.
//
// The record list is steward-supplied and unbounded on the wire, so it is capped at
// maxApplyOutcomeRecordsPerEvent before any per-record work is done.
func (s *Server) ingestApplyOutcomes(ctx context.Context, peerHostAuthority, configVersion string, details map[string]interface{}) error {
	rawOutcomes, ok := details["apply_outcomes"].([]interface{})
	if !ok || len(rawOutcomes) == 0 {
		return nil
	}
	if len(rawOutcomes) > maxApplyOutcomeRecordsPerEvent {
		s.logger.Warn("ingestApplyOutcomes: apply_outcomes exceeds per-event cap; truncating",
			"steward_id", logging.SanitizeLogValue(peerHostAuthority),
			"received", len(rawOutcomes),
			"cap", maxApplyOutcomeRecordsPerEvent)
		rawOutcomes = rawOutcomes[:maxApplyOutcomeRecordsPerEvent]
	}

	now := time.Now().UTC()
	var observations []egtypes.Observation

	// One resolver per event: cluster membership is a property of the peer, so the
	// membership query is performed at most once no matter how many records arrive.
	resolver := s.newApplyOutcomeEIDResolver(peerHostAuthority)

	for _, rawRec := range rawOutcomes {
		rec, ok := rawRec.(map[string]interface{})
		if !ok {
			continue
		}
		resourceID, _ := rec["resource_id"].(string)
		if resourceID == "" {
			continue
		}
		moduleName, _ := rec["module_name"].(string)
		status, _ := rec["status"].(string)
		errDetail, _ := rec["error"].(string)

		// Resolve observed timestamp; fall back to now when absent or unparseable.
		observedAt := now
		if tsStr, _ := rec["timestamp"].(string); tsStr != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
				observedAt = parsed.UTC()
			}
		}

		eid, err := resolver.resolveApplyOutcomeEID(ctx, resourceID)
		if err != nil {
			s.logger.Warn("ingestApplyOutcomes: skipping record with invalid resource_id",
				"steward_id", peerHostAuthority,
				"resource_id", logging.SanitizeLogValue(resourceID),
				"error", logging.SanitizeLogValue(err.Error()))
			continue
		}

		payload := map[string]interface{}{
			"status":         status,
			"module_name":    moduleName,
			"config_version": configVersion,
		}
		if errDetail != "" {
			payload["error"] = errDetail
		}

		observations = append(observations, egtypes.Observation{
			Source:     peerHostAuthority,
			ObservedAt: observedAt,
			RecordedAt: now,
			Subject:    eid.String(),
			Kind:       egtypes.ObservationKindApplyOutcome,
			Confidence: egtypes.ConfidenceHigh,
			Payload:    payload,
		})
	}

	if len(observations) == 0 {
		return nil
	}

	batch := eginterfaces.ObservationBatch{
		Source:       peerHostAuthority,
		Observations: observations,
	}
	return s.egProvider.ReportObservations(ctx, batch)
}

// SetEntityGraphClusterMembership wires the controller-side verifier that decides
// which cluster names may become an EID authority segment for a given steward
// (dnasync.ClusterMembership).
//
// The same verifier instance MUST be given to the DNA-sync entity-graph writer
// (dnasync.WithClusterMembership). Both record types for one resource are then gated
// by one answer, so an apply-outcome can never be filed under a cluster authority that
// entity-state does not also use.
//
// Leaving it unset denies every cluster claim. That is the safe state and it keeps the
// two paths in agreement: both resolve host-scoped.
// Deferred: tracked in #2853 — supply this verifier, and the DNA-sync writer that
// shares it, from controller start-up.
func (s *Server) SetEntityGraphClusterMembership(m dnasync.ClusterMembership) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.egClusterMembership = m
}

// entityGraphClusterMembership returns the wired cluster-membership verifier, or nil
// when none is configured (in which case every cluster claim is denied).
func (s *Server) entityGraphClusterMembership() dnasync.ClusterMembership {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.egClusterMembership
}

// applyOutcomeEIDResolver resolves the entity-graph EID for the apply-outcome
// records of ONE config_applied event from ONE mTLS-verified peer (Issue #3376).
//
// The EID is minted by dnasync.ResolveSubjectEID — the same function that mints
// entity-state EIDs — so the two record types for one resource cannot disagree about
// where the record belongs. A private copy of the cluster-redirect rule would drift and
// file outcomes at an EID entity-state never uses.
//
// Three gates must all pass before a record leaves the host namespace:
//
//  1. Taxonomy. Only kinds a host authority may name (AuthorityClasses contains "host")
//     are handed to the resolver. A resourceID such as "cluster:<name>" would otherwise
//     take ResolveSubjectEID's bare cluster-kind branch, where the authority segment is
//     the identifier itself — a value carried in the event being ingested. Those kinds
//     are filed under the mTLS-verified peer instead, so nothing from the event can
//     reach an authority segment (SE threat #1 — authority confusion).
//
//  2. Peer membership, corroborated independently of the asserting peer. The
//     controller's tenant-scoped DNA registry supplies a CANDIDATE cluster name; its
//     Members are built from cluster:<name> fragments carried in each steward's own DNA
//     (features/controller/clusterregistry), and a steward can equally declare a
//     cluster:<name> --contains--> host:<self> edge, so neither signal is more than the
//     peer's own claim. The candidate becomes an authority segment only when the wired
//     dnasync.ClusterMembership verifier — contractually required to answer from state
//     the controller holds independently of the asserting peer — confirms it, and
//     ResolveSubjectEID re-checks that verifier before minting the EID. With no verifier
//     wired every candidate is denied, so a compromised steward that publishes a
//     cluster:<victim> fragment cannot move its records into another cluster's (or,
//     since cluster EIDs are not tenant-qualified, another tenant's) namespace — where
//     they could never be retracted, apply-outcome observations carrying no ClaimScope.
//     Membership is a property of the peer, so this is resolved at most once per event:
//     the ingest loop must not scale controller-side lookups with a steward-supplied
//     record count.
//
//  3. Per-resource cluster evidence. The entity graph must already hold a
//     cluster:<name>/<resourceID> ENTITY for that exact resource, which only the dnasync
//     writer's membership-gated cluster branch can have created (it requires that
//     resource's OWN ha_role.cluster_name). Peer membership alone does not make a
//     resource cluster-scoped: a cluster node also runs node-local VMs, and redirecting
//     those would collapse same-named local VMs on two nodes onto one EID and leave the
//     outcome pointing at an entity whose state lives elsewhere. Apply-outcome
//     observations project into no entity table (sqlite/observations.go
//     updateEntityProjection), so this evidence can never be manufactured by the
//     apply-outcome path itself.
//
// Falling back to host:<peerHostAuthority>/<resourceID> is NOT an error. It is the
// expected state for a standalone host, for a node-local resource on a cluster member,
// and for a clustered resource whose entity state has not synced yet — the self-heal
// ordering choice recorded in #3376.
type applyOutcomeEIDResolver struct {
	server            *Server
	peerHostAuthority string
	taxonomy          *egtypes.Taxonomy
	membership        dnasync.ClusterMembership

	// clusterName caches the verified cluster authority for this peer for the lifetime
	// of one event; clusterLoaded distinguishes "not resolved yet" from "resolved, none
	// verified", so a peer costs at most one registry pass per event and a record whose
	// kind is not cluster-eligible costs none at all.
	clusterName   string
	clusterLoaded bool
}

// newApplyOutcomeEIDResolver returns a resolver scoped to one event from one peer.
func (s *Server) newApplyOutcomeEIDResolver(peerHostAuthority string) *applyOutcomeEIDResolver {
	return &applyOutcomeEIDResolver{
		server:            s,
		peerHostAuthority: peerHostAuthority,
		taxonomy:          egtypes.DefaultTaxonomy(),
		membership:        s.entityGraphClusterMembership(),
	}
}

// resolveApplyOutcomeEID resolves the EID for a single apply-outcome record, applying
// the three gates documented on applyOutcomeEIDResolver.
func (r *applyOutcomeEIDResolver) resolveApplyOutcomeEID(ctx context.Context, resourceID string) (egtypes.EID, error) {
	kind := resourceID
	if idx := strings.Index(resourceID, ":"); idx >= 0 {
		kind = resourceID[:idx]
	}

	// Gate 1: taxonomy. Kinds a host authority may not name never reach the resolver.
	if desc, ok := r.taxonomy.LookupEntityType(kind); ok && !applyOutcomeAuthorityHasHost(desc.AuthorityClasses) {
		return egtypes.NewEID("host", r.peerHostAuthority, resourceID)
	}

	// Gate 2: the verified cluster name travels to the resolver in the same payload
	// field a steward's own fragment uses for entity-state, so both go through the
	// identical membership check inside ResolveSubjectEID.
	var payload map[string]interface{}
	if clusterName := r.verifiedClusterName(); clusterName != "" {
		payload = map[string]interface{}{
			"ha_role": map[string]interface{}{"cluster_name": clusterName},
		}
	}

	eid, _, _, err := dnasync.ResolveSubjectEID(kind, r.peerHostAuthority, resourceID, payload, r.taxonomy, r.membership)
	if err != nil {
		return egtypes.EID{}, err
	}

	// Gate 3: a cluster-scoped result needs entity state at that exact EID.
	if eid.AuthorityType() == "cluster" && !r.hasClusterScopedEntity(ctx, eid) {
		return egtypes.NewEID("host", r.peerHostAuthority, resourceID)
	}
	return eid, nil
}

// verifiedClusterName returns the cluster name that BOTH the controller's tenant-scoped
// DNA registry and the wired membership verifier attribute to this peer, or "" when no
// such name exists. The result is computed at most once per event.
//
// Tenant scoping stops identically-named clusters in sibling tenants from vouching for
// each other; the verifier is what turns a self-attested candidate into a name that may
// become an authority segment. A nil verifier short-circuits to "" — no registry work is
// done and no candidate can be accepted.
func (r *applyOutcomeEIDResolver) verifiedClusterName() string {
	if r.clusterLoaded {
		return r.clusterName
	}
	r.clusterLoaded = true

	if r.membership == nil {
		return ""
	}

	s := r.server
	s.mu.RLock()
	controllerSvc := s.controllerService
	s.mu.RUnlock()

	if controllerSvc == nil {
		return ""
	}
	info, exists := controllerSvc.GetStewardInfo(r.peerHostAuthority)
	if !exists || info == nil {
		return ""
	}
	tenantID := info.TenantID

	allStewards := controllerSvc.GetAllStewards()
	fleetData := make([]controllerFleet.StewardData, 0, len(allStewards))
	for _, si := range allStewards {
		if si == nil || si.TenantID != tenantID {
			continue
		}
		var frags []*common.Fragment
		if si.DNA != nil {
			frags = si.DNA.Fragments
		}
		fleetData = append(fleetData, controllerFleet.StewardData{
			ID:           si.ID,
			TenantID:     si.TenantID,
			DNAFragments: frags,
		})
	}

	candidates := clusterregistry.BuildRegistry(fleetData).MemberClusters(r.peerHostAuthority)
	for _, name := range candidates {
		if r.membership.IsClusterMember(r.peerHostAuthority, name) {
			r.clusterName = name
			return r.clusterName
		}
	}
	if len(candidates) > 0 {
		s.logger.Debug("resolveApplyOutcomeEID: cluster claim not corroborated; resolving host-scoped",
			"steward_id", logging.SanitizeLogValue(r.peerHostAuthority),
			"candidate_count", len(candidates))
	}
	return ""
}

// hasClusterScopedEntity reports whether the entity graph already holds entity state for
// eid — the per-resource cluster evidence required by gate 3. A missing entity
// (ErrNotFound) is the ordinary answer for a node-local resource and is not logged.
func (r *applyOutcomeEIDResolver) hasClusterScopedEntity(ctx context.Context, eid egtypes.EID) bool {
	// TenantFilter is deliberately empty: this is controller-internal resolution, not an
	// API read, and the entity-graph tenant cut is applied by the read APIs that serve
	// these records. The cluster name reaching this point was already confirmed for the
	// mTLS-verified peer within its own tenant by gate 2.
	view, err := r.server.egProvider.GetEntity(ctx, eid, eginterfaces.GetEntityOpts{})
	if err != nil {
		if !errors.Is(err, eginterfaces.ErrNotFound) {
			r.server.logger.Warn("resolveApplyOutcomeEID: cluster evidence lookup failed; resolving host-scoped",
				"steward_id", logging.SanitizeLogValue(r.peerHostAuthority),
				"eid", logging.SanitizeLogValue(eid.String()),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return false
	}
	return view != nil && view.Entity != nil
}

// applyOutcomeAuthorityHasHost reports whether "host" is among a kind's authority
// classes, i.e. whether the mTLS-verified peer may name that entity itself.
func applyOutcomeAuthorityHasHost(classes []string) bool {
	for _, c := range classes {
		if c == "host" {
			return true
		}
	}
	return false
}

// handleObserveSweepRequest processes EventObserveSweepRequest from a steward.
// It extracts the baseline DNA, resolves the observe-module set via the manifest
// provider, and sends CommandObserveModules back to the originating steward.
// (Issue #3104, ADR-024 Amendment 1 §3)
func (s *Server) handleObserveSweepRequest(ctx context.Context, event *controlplaneTypes.Event) error {
	s.mu.RLock()
	provider := s.observeManifestProvider
	publisher := s.commandPublisher
	s.mu.RUnlock()

	if provider == nil {
		s.logger.Debug("Tier-2 observe sweep request received but provider not configured",
			"steward_id", event.StewardID)
		return nil
	}
	if publisher == nil {
		s.logger.Warn("Tier-2 observe sweep request: command publisher not available",
			"steward_id", event.StewardID)
		return nil
	}

	// Extract baseline DNA from the event details.
	var baselineDNA map[string]string
	if details := event.Details; details != nil {
		if raw, ok := details["baseline_dna"].(string); ok && raw != "" {
			if err := json.Unmarshal([]byte(raw), &baselineDNA); err != nil {
				s.logger.Warn("Tier-2 observe sweep: failed to parse baseline_dna",
					"steward_id", event.StewardID, "error", err)
				return nil
			}
		}
	}

	// Resolve the observe-module set from the baseline DNA.
	manifests, err := provider.ListObservableManifests()
	if err != nil {
		s.logger.Warn("Tier-2 observe sweep: failed to list manifests",
			"steward_id", event.StewardID, "error", err)
		return nil
	}

	names := resolution.ResolveObserveModules(baselineDNA, manifests)
	if len(names) == 0 {
		s.logger.Debug("Tier-2 observe sweep: no modules resolved",
			"steward_id", event.StewardID)
		return nil
	}

	// Build ObserveModuleSpec list from resolved names and their ownership declarations.
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	var specs []controlplaneTypes.ObserveModuleSpec
	for _, m := range manifests {
		if !nameSet[m.Name] {
			continue
		}
		for _, own := range m.Owns {
			specs = append(specs, controlplaneTypes.ObserveModuleSpec{
				Name: m.Name,
				Kind: own.Kind,
			})
		}
	}
	if len(specs) == 0 {
		// All resolved modules have no ownership declarations — nothing to observe.
		s.logger.Debug("Tier-2 observe sweep: resolved modules have no ownership declarations",
			"steward_id", event.StewardID, "names", names)
		return nil
	}

	specsJSON, err := json.Marshal(specs)
	if err != nil {
		return fmt.Errorf("tier-2 observe sweep: marshal specs: %w", err)
	}

	if _, err := publisher.PublishCommand(ctx, event.StewardID, controlplaneTypes.CommandObserveModules, map[string]interface{}{
		"modules": string(specsJSON),
	}); err != nil {
		return fmt.Errorf("tier-2 observe sweep: publish command: %w", err)
	}

	s.logger.Info("Tier-2 observe sweep dispatched",
		"steward_id", event.StewardID,
		"module_count", len(specs))

	return nil
}

// SetStewardEventManager injects the dedicated steward-event LoggingManager.
// Called by the Controller before Start so the LogStream handler (S2) can
// write ingested steward events to this manager.
func (s *Server) SetStewardEventManager(m *logging.LoggingManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stewardEventManager = m
}

// GetStewardEventManager returns the dedicated steward-event LoggingManager.
func (s *Server) GetStewardEventManager() *logging.LoggingManager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stewardEventManager
}

// GetAPIServer returns the REST API server owned by this transport server.
// Used by Controller.New to inject shared dependencies after both servers are created.
func (s *Server) GetAPIServer() *api.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.httpServer
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

	store, err := controllerrun.NewRunStoreSQLFromDSN(dsn)
	if err != nil {
		logger.Warn("Run manager: failed to open SQLite", "error", err)
		return nil
	}
	if err := store.Init(ctx); err != nil {
		logger.Warn("Run manager: failed to initialize schema", "error", err)
		_ = store.Close()
		return nil
	}

	logger.Info("Run manager initialized", "sqlite_path", cfg.Storage.SQLitePath)
	return controllerrun.NewManager(store, executionQueue)
}

// initializeUpgradeStore opens a SQLite-backed UpgradeStore at cfg.Storage.SQLitePath,
// initializes its schema, and returns it as the interface. Falls back to an in-memory
// store (logging a warning, no startup failure) when SQLitePath is empty or either
// open/Initialize fails — mirroring the degrade-gracefully pattern of initializeRunManager.
func initializeUpgradeStore(
	ctx context.Context,
	cfg *config.Config,
	logger logging.Logger,
) business.UpgradeStore {
	if cfg.Storage == nil || cfg.Storage.SQLitePath == "" {
		logger.Warn("Upgrade store: SQLite path not configured, using in-memory store (records will not survive restart)")
		return memoryprovider.NewUpgradeStore()
	}

	dsn := cfg.Storage.SQLitePath
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}

	store, err := sqliteprovider.NewUpgradeStoreSQLFromDSN(dsn)
	if err != nil {
		logger.Warn("Upgrade store: failed to open SQLite, falling back to in-memory store", "error", err)
		return memoryprovider.NewUpgradeStore()
	}
	if err := store.Initialize(ctx); err != nil {
		logger.Warn("Upgrade store: failed to initialize schema, falling back to in-memory store", "error", err)
		_ = store.Close()
		return memoryprovider.NewUpgradeStore()
	}

	logger.Info("Upgrade store initialized with SQLite backend (Issue #2464)", "sqlite_path", cfg.Storage.SQLitePath)
	return store
}

// initializeTagStore opens a SQLite-backed tag store at cfg.Storage.SQLitePath,
// initializes its schema, and returns it. Returns nil (logging a warning) when
// SQLitePath is empty or either open/Initialize fails — controller startup is
// never blocked on tag store availability.
func initializeTagStore(
	ctx context.Context,
	cfg *config.Config,
	logger logging.Logger,
) *tagstore.Store {
	if cfg.Storage == nil || cfg.Storage.SQLitePath == "" {
		logger.Warn("Tag store: SQLite path not configured, tag persistence disabled")
		return nil
	}

	dsn := cfg.Storage.SQLitePath
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}

	store, err := tagstore.NewFromDSN(dsn, logger)
	if err != nil {
		logger.Warn("Tag store: failed to open SQLite, tag persistence disabled", "error", err)
		return nil
	}
	if err := store.Initialize(ctx); err != nil {
		logger.Warn("Tag store: failed to initialize schema, tag persistence disabled", "error", err)
		_ = store.Close()
		return nil
	}

	logger.Info("Tag store initialized with SQLite backend (Issue #2542)", "sqlite_path", cfg.Storage.SQLitePath)
	return store
}

// initializeEntityGraphProvider constructs the entity graph provider that
// matches the controller's active storage backend (Issue #3253 / ADR-022):
//
//   - Cluster mode: PostgreSQL-backed DatabaseEntityGraphProvider using the
//     cluster Postgres DSN. SQLite would give each node its own isolated graph,
//     so the database provider is required — not optional.
//   - Legacy single-provider "database" mode: DatabaseEntityGraphProvider using
//     cfg.Storage.Config["dsn"].
//   - OSS composite mode (FlatfileRoot set): SQLiteEntityGraphProvider at a
//     dedicated file alongside cfg.Storage.SQLitePath so the two stores never
//     share the same *sql.DB handle.
func initializeEntityGraphProvider(cfg *config.Config, logger logging.Logger) (egServerProvider, error) {
	if cfg.Storage == nil {
		return nil, fmt.Errorf("storage configuration required for entity graph provider")
	}

	if cfg.HA.IsClusterMode() {
		pgDSN := ""
		if cfg.Storage.Cluster != nil {
			pgDSN = cfg.Storage.Cluster.PostgresDSN
		}
		p, err := egdatabase.NewDatabaseEntityGraphProvider(pgDSN)
		if err != nil {
			return nil, fmt.Errorf("entity graph (cluster/postgres): %w", err)
		}
		logger.Info("Entity graph provider initialized with Postgres backend (cluster mode, Issue #3253)")
		return p, nil
	}

	if cfg.Storage.Provider == "database" {
		dsn, dsnErr := entityGraphDatabaseDSN(cfg.Storage.Config)
		if dsnErr != nil {
			return nil, fmt.Errorf("entity graph (database single-provider): %w", dsnErr)
		}
		p, err := egdatabase.NewDatabaseEntityGraphProvider(dsn)
		if err != nil {
			return nil, fmt.Errorf("entity graph (database single-provider): %w", err)
		}
		logger.Info("Entity graph provider initialized with Postgres backend (database mode, Issue #3253)")
		return p, nil
	}

	// OSS composite mode — use a dedicated SQLite file next to the main store.
	if cfg.Storage.SQLitePath == "" {
		return nil, fmt.Errorf("storage.sqlite_path is required for the entity graph provider in OSS composite mode")
	}
	egPath := filepath.Join(filepath.Dir(cfg.Storage.SQLitePath), "entitygraph.db")
	p, err := egsqlite.NewSQLiteEntityGraphProvider(egPath)
	if err != nil {
		return nil, fmt.Errorf("entity graph (sqlite): %w", err)
	}
	logger.Info("Entity graph provider initialized with SQLite backend (OSS composite mode, Issue #3253)",
		"path", egPath)
	return p, nil
}

// entityGraphDatabaseDSN extracts a Postgres DSN for the entity graph provider
// in legacy "database" single-provider mode. It mirrors
// pkg/storage/providers/database/plugin.go's unexported getDSN exactly —
// preferring a complete "dsn" string, otherwise building one from discrete
// host/port/database/username/password/sslmode keys — so the entity graph
// always tracks the same connection the storage provider itself opens.
// Duplicated locally rather than imported: features/ business logic must not
// import pkg/storage/providers directly (see CLAUDE.md central provider
// rules), and the entity graph provider takes a raw DSN string, not a config
// map, so this extraction has to live on this side of that boundary.
//
// Deployments that configure discrete fields instead of a single "dsn" string
// (e.g. docker-compose.test.yml's CFGMS_DB_HOST/PORT/... fixtures, and
// server_security_test.go's createDockerTestStorageConfig) previously made
// this branch silently pass an empty DSN to lib/pq, which defaults to dialing
// localhost:5432 instead of the configured host (Issue #3253 merge-queue
// regression).
func entityGraphDatabaseDSN(storageConfig map[string]interface{}) (string, error) {
	if dsn, ok := storageConfig["dsn"].(string); ok && dsn != "" {
		return dsn, nil
	}

	host := entityGraphConfigString(storageConfig, "host", "localhost")
	port := entityGraphConfigInt(storageConfig, "port", 5432)
	database := entityGraphConfigString(storageConfig, "database", "cfgms")
	username := entityGraphConfigString(storageConfig, "username", "cfgms")
	password := entityGraphConfigString(storageConfig, "password", "")
	sslmode := entityGraphConfigString(storageConfig, "sslmode", "require")

	if password == "" {
		return "", fmt.Errorf("database password is required")
	}

	return fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		host, port, database, username, password, sslmode), nil
}

func entityGraphConfigString(config map[string]interface{}, key, defaultValue string) string {
	if val, ok := config[key].(string); ok {
		return val
	}
	return defaultValue
}

func entityGraphConfigInt(config map[string]interface{}, key string, defaultValue int) int {
	if val, ok := config[key].(int); ok {
		return val
	}
	if val, ok := config[key].(float64); ok {
		return int(val)
	}
	return defaultValue
}

// initializeSessionStore selects and opens a session.Store.
//
// Cluster mode (Issue #2775): when cfg.HA.IsClusterMode() is true and a cluster
// Postgres DSN is configured, a Postgres-backed DatabaseSessionTokenStore is returned
// so session tokens issued on one node are validated and revoked correctly across the
// full cluster. Single-node deployments are unaffected.
//
// Single-node fallback: opens a SQLite-backed store at cfg.Storage.SQLitePath so
// sessions survive controller restarts. Falls back to an in-memory store (with a
// warning) when SQLitePath is empty or the SQLite open fails — startup is never blocked
// on session store availability.
func initializeSessionStore(
	ctx context.Context,
	cfg *config.Config,
	logger logging.Logger,
) session.Store {
	_ = ctx // reserved for future use (consistent with initializeUpgradeStore)

	// Cluster mode: use the shared Postgres backend for cross-node session validation.
	if cfg.HA.IsClusterMode() {
		pgDSN := ""
		if cfg.Storage != nil && cfg.Storage.Cluster != nil {
			pgDSN = cfg.Storage.Cluster.PostgresDSN
		}
		if pgDSN != "" {
			store, err := (&dbprovider.DatabaseProvider{}).CreateSessionTokenStore(map[string]interface{}{"dsn": pgDSN})
			if err != nil {
				logger.Warn("Session store: failed to open Postgres cluster store, falling back to SQLite/mem", "error", err)
			} else {
				logger.Info("Session store initialized with Postgres backend for cluster mode (Issue #2775)")
				return store
			}
		}
	}

	if cfg.Storage == nil || cfg.Storage.SQLitePath == "" {
		logger.Warn("Session store: SQLite path not configured, using in-memory store (sessions will not survive restart)")
		return session.NewMemStore(session.DefaultConfig(), time.Now)
	}

	store, err := (&sqliteprovider.SQLiteProvider{}).CreateSessionTokenStore(map[string]interface{}{"path": cfg.Storage.SQLitePath})
	if err != nil {
		logger.Warn("Session store: failed to open SQLite, falling back to in-memory store", "error", err)
		return session.NewMemStore(session.DefaultConfig(), time.Now)
	}

	logger.Info("Session store initialized with SQLite backend (Issue #2774)", "sqlite_path", cfg.Storage.SQLitePath)
	return store
}

// seedFleetCascadeTestData seeds the tenant hierarchy and MSP-level parent policy
// required by the fleet E2E cascade test (Issue #1723). Called only when
// CFGMS_SEED_TEST_TOKENS=1 is set. Creates a two-level tenant tree:
//
//	fleet-root (parent)
//	  fleet-root/fleet-child-a (steward-1 tenant)
//	  fleet-root/fleet-child-b (steward-2 tenant)
//
// Stores an MSP-level policy under fleet-root/msp-policies/global so the
// InheritanceResolver delivers it to stewards in both child tenants via cascade.
// Errors are logged as warnings (idempotent — tolerated on controller restart).
func seedFleetCascadeTestData(ctx context.Context, sm *interfaces.StorageManager, logger logging.Logger) {
	ts := sm.GetTenantStore()
	cs := sm.GetConfigStore()

	tenants := []business.TenantData{
		{ID: "fleet-root", Name: "Fleet Root", Status: business.TenantStatusActive},
		{ID: "fleet-root/fleet-child-a", Name: "Fleet Child A", ParentID: "fleet-root", Status: business.TenantStatusActive},
		{ID: "fleet-root/fleet-child-b", Name: "Fleet Child B", ParentID: "fleet-root", Status: business.TenantStatusActive},
	}
	for i := range tenants {
		if err := ts.CreateTenant(ctx, &tenants[i]); err != nil {
			logger.Warn("fleet cascade seed: tenant (may already exist)", "id", tenants[i].ID, "error", err)
		} else {
			logger.Info("fleet cascade seed: tenant created", "id", tenants[i].ID)
		}
	}

	// Parent policy: two file resources on /test-workspace tmpfs.
	// cascade-policy: inherited by both children; child device config may override it.
	// cascade-parent-only: present only at MSP level — proves cascade delivery when it
	// appears on a steward whose device config does not include it.
	parentPolicyYAML := `steward:
  id: ""
  mode: controller
  converge_interval: "10s"
  drift_mode: apply
resources:
  - name: cascade-policy
    module: file
    config:
      path: /test-workspace/cascade-policy
      state: present
      content: "parent-policy-content\n"
      mode: "0644"
      allowed_base_path: /test-workspace
  - name: cascade-parent-only
    module: file
    config:
      path: /test-workspace/cascade-parent-only
      state: present
      content: "parent-only-content\n"
      mode: "0644"
      allowed_base_path: /test-workspace
`
	if err := cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{
			TenantID:  "fleet-root",
			Namespace: "msp-policies",
			Name:      "global",
		},
		Data:   []byte(parentPolicyYAML),
		Format: cfgconfig.ConfigFormatYAML,
	}); err != nil {
		logger.Warn("fleet cascade seed: failed to store MSP-level parent policy", "error", err)
	} else {
		logger.Info("fleet cascade seed: MSP-level parent policy stored under fleet-root")
	}
}

// serverBatchjobFleetQuery adapts *service.ControllerService to batchjob.FleetQuery
// so the rolling-batch executor can resolve fleet selectors without importing the
// api package (which would create an import cycle). Issue #2296.
type serverBatchjobFleetQuery struct {
	svc *service.ControllerService
}

func (a *serverBatchjobFleetQuery) Search(ctx context.Context, selectorStr, tenantID string) ([]batchjob.StewardMeta, error) {
	filter, _, err := fleetSelector.Parse(selectorStr)
	if err != nil {
		return nil, fmt.Errorf("invalid selector %q: %w", selectorStr, err)
	}
	filter.TenantID = tenantID
	q := controllerFleet.NewMemoryQuery(&serverFleetStewardProvider{svc: a.svc})
	results, err := q.Search(ctx, filter)
	if err != nil {
		return nil, err
	}
	metas := make([]batchjob.StewardMeta, 0, len(results))
	for _, r := range results {
		metas = append(metas, batchjob.StewardMeta{
			ID:            r.ID,
			DNAAttributes: r.DNAAttributes,
		})
	}
	return metas, nil
}

// serverFleetStewardProvider adapts *service.ControllerService to
// controllerFleet.StewardProvider for use by MemoryQuery.
type serverFleetStewardProvider struct {
	svc *service.ControllerService
}

// serverFleetStewardProvider adapts *service.ControllerService to
// controllerFleet.StewardProvider for use by MemoryQuery.
// Population source is deliberately node-local (GetAllStewards, dispatch-safe). Field
// composition — tags merged, DNAFragments populated — must match controllerServiceAdapter
// in features/controller/api/server.go for any steward both adapters can see. (Issue #3495)
func (p *serverFleetStewardProvider) GetAllStewards() []controllerFleet.StewardData {
	infos := p.svc.GetAllStewards()
	tagStore := p.svc.TagStore()
	result := make([]controllerFleet.StewardData, 0, len(infos))
	for _, info := range infos {
		var attrs map[string]string
		var frags []*common.Fragment
		if info.DNA != nil {
			attrs = service.FlattenDNAFragments(info.DNA.Fragments)
			frags = info.DNA.Fragments
		}
		if tagStore != nil {
			attrs = mergeControllerTags(attrs, tagStore.TagsFor(info.ID))
		}
		result = append(result, controllerFleet.StewardData{
			ID:            info.ID,
			TenantID:      info.TenantID,
			Status:        info.Status,
			LastHeartbeat: info.LastHeartbeat,
			DNAAttributes: attrs,
			DNAFragments:  frags,
			Hidden:        info.Hidden,
		})
	}
	return result
}

// mergeControllerTags returns a copy of attrs with controller-stored ctrlTags
// merged into the "tags" key. If attrs already carries a DNA-reported "tags"
// value, the two sets are unioned (DNA tags first, then controller tags;
// duplicates dropped). Returns attrs unchanged when ctrlTags is empty.
// Never mutates the input map — attrs is the fresh map returned by
// FlattenDNAFragments; copying before merge preserves the no-mutation contract
// so the caller's view of the attrs slice is not altered.
func mergeControllerTags(attrs map[string]string, ctrlTags []string) map[string]string {
	if len(ctrlTags) == 0 {
		return attrs
	}
	// Copy to avoid mutating the FlattenDNAFragments output shared by the caller.
	merged := make(map[string]string, len(attrs)+1)
	for k, v := range attrs {
		merged[k] = v
	}
	// Union DNA-reported tags with controller-stored tags; DNA tags come first.
	seen := make(map[string]struct{})
	var all []string
	for _, t := range strings.Split(merged["tags"], ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; !dup {
			seen[t] = struct{}{}
			all = append(all, t)
		}
	}
	for _, t := range ctrlTags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; !dup {
			seen[t] = struct{}{}
			all = append(all, t)
		}
	}
	merged["tags"] = strings.Join(all, ",")
	return merged
}

// Registration approval workflow names accepted by registration.workflow (Issue #1695).
const (
	registrationWorkflowIPTrust      = "ip-trust"
	registrationWorkflowManualReview = "manual-review"
	registrationWorkflowAutoApprove  = "auto-approve"
)

// resolveRegistrationWorkflow returns the effective registration approval workflow
// for cfg, applying the legacy approval_mode alias and the ip-trust default.
//
// New and collectActiveStorageRequirements must agree on this value: the former
// decides which subsystems are constructed, the latter decides which store
// requirements are enforced at startup. Deriving both from one function keeps a
// subsystem from being built without its storage having been validated (#3491).
func resolveRegistrationWorkflow(cfg *config.Config) string {
	workflowName := ""
	if cfg != nil && cfg.Registration != nil {
		workflowName = cfg.Registration.Workflow
		// Legacy: if Workflow is empty but ApprovalMode is set, honour it.
		if workflowName == "" && cfg.Registration.ApprovalMode == registrationWorkflowManualReview {
			workflowName = registrationWorkflowManualReview
		}
	}
	// Default to ip-trust (Issue #1695).
	if workflowName == "" {
		workflowName = registrationWorkflowIPTrust
	}
	return workflowName
}

// collectActiveStorageRequirements returns the union of store requirements from all
// subsystems that are enabled in this deployment. Requirements are collected from
// each subsystem's own declaration (adjacent to the code that uses the store), then
// gated here on whether the subsystem is active — so a deployment that does not run
// a subsystem cannot be blocked by its requirements.
//
// Registration (#3491) is wired: the manual-review approval hook
// (api.ManualReviewApprovalHookStoreRequirements) and the pending-registration
// expiry job that sweeps the records it writes (registration.StoreRequirements)
// both require PendingRegistrationStore, and both are active only when the
// effective registration workflow is "manual-review". Under any other workflow
// neither runs, so neither imposes a requirement. Push (#3492) is wired
// unconditionally via pushStoreRequirements. Workflow-trigger (#3493) is wired
// unconditionally via workflowtrigger.StoreRequirements — the subsystem is
// always active when the controller starts.
func collectActiveStorageRequirements(cfg *config.Config) []interfaces.StoreRequirement {
	var reqs []interfaces.StoreRequirement
	reqs = append(reqs, pushStoreRequirements...)
	reqs = append(reqs, workflowtrigger.StoreRequirements...)

	if resolveRegistrationWorkflow(cfg) == registrationWorkflowManualReview {
		// The approval hook persists incoming requests; the expiry job ages them out.
		// Both are constructed in New when this workflow is selected.
		reqs = append(reqs, api.ManualReviewApprovalHookStoreRequirements...)
		reqs = append(reqs, controllerRegistration.StoreRequirements...)
	}

	return reqs
}

// storageProviderName returns a short, human-readable name for the storage
// provider in cfg. Used as the operator-facing provider label passed to
// interfaces.CollectAbsentOptionalCapabilities — distinct from
// StorageManager.GetProviderName(), which reports the internal composition name
// ("composite") for the OSS composite shape rather than a backend an operator can
// actually switch to.
func storageProviderName(cfg *config.Config) string {
	if cfg == nil || cfg.Storage == nil {
		return "unknown"
	}
	if cfg.HA.IsClusterMode() {
		return "database"
	}
	if cfg.Storage.FlatfileRoot != "" {
		return "flatfile"
	}
	if cfg.Storage.Provider != "" {
		return cfg.Storage.Provider
	}
	return "unknown"
}

// assertClusterBackendsReady verifies cluster-mode prerequisites before any state is read
// or written. Called immediately after CreateClusterStorageManager in New(), still inside
// the cfg.HA.IsClusterMode() block, so callers need not re-check the mode.
//
// Gates (in order):
//  1. Storage provider must be cluster-capable (shared state across controller nodes).
//  2. CFGMS_S3_INSTALLER_BUCKET must be set (S3-compatible blob store for installer
//     artifacts).
func assertClusterBackendsReady(cfg *config.Config, storageManager *interfaces.StorageManager) error {
	if p := storageManager.GetProvider(); p != nil && !p.ClusterCapable() {
		return fmt.Errorf("cluster mode requires a cluster-capable storage backend; provider %q does not support cluster coordination", storageManager.GetProviderName())
	}
	if os.Getenv("CFGMS_S3_INSTALLER_BUCKET") == "" {
		return fmt.Errorf("cluster mode requires S3-compatible blob storage: set CFGMS_S3_INSTALLER_BUCKET")
	}
	_ = cfg // reserved for future per-config gate extensions
	return nil
}
