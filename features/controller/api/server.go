// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/features/controller/cluster"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/features/controller/modules/resolution"
	"github.com/cfgis/cfgms/features/controller/push"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/controller/tagstore"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/authdefense"
	reportapi "github.com/cfgis/cfgms/features/reports/api"
	"github.com/cfgis/cfgms/features/tenant"
	tenantsecurity "github.com/cfgis/cfgms/features/tenant/security"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cache"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/registration"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops" // Auto-register SOPS provider
	"github.com/cfgis/cfgms/pkg/session"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/cfgis/cfgms/web"
)

// Server represents the REST API server component of the controller
type Server struct {
	mu                             sync.RWMutex
	cfg                            *config.Config
	logger                         logging.Logger
	httpServer                     *http.Server
	router                         *mux.Router
	apiRouter                      *mux.Router // /api/v1 subrouter; used by Set* methods for lazy route registration
	controllerService              *service.ControllerService
	configService                  *service.ConfigurationServiceV2
	certProvisioningService        *service.CertificateProvisioningService
	rbacService                    *service.RBACService
	certManager                    *cert.Manager
	tenantManager                  *tenant.Manager
	rbacManager                    *rbac.Manager
	systemMonitor                  *monitoring.SystemMonitor
	healthCollector                *health.Collector
	haManager                      *ha.Manager
	apiKeys                        map[string]*APIKey                    // In-memory cache for fast lookup
	secretStore                    secretsif.SecretStore                 // M-AUTH-1: Central secrets provider for API keys
	webAccounts                    map[string]*webAccount                // Issue #2490: web-admin account cache (lazy-init, guarded by mu; durable copy lives in secretStore)
	webAccountLockouts             map[string]*webAccountLockout         // Issue #2490: per-account lockout state (lazy-init, guarded by mu; in-memory only)
	registrationTokenStore         registration.Store                    // Registration token store for steward registration
	corsConfig                     *CORSConfig                           // CORS configuration
	signerCertSerial               string                                // Story #378: Serial of cert used for config signing
	authDefense                    *authdefense.AuthDefenseSystem        // Story #380: Three-tier auth defense
	rollbackManager                rollback.RollbackManager              // Story #416: Rollback system
	reportsHandler                 *reportapi.Handler                    // Story #416: Reports engine
	workflowHandler                *WorkflowHandler                      // Story #414: Workflow engine REST API
	approvalHook                   RegistrationApprovalHook              // Issue #422: Registration approval hook
	fleetQuery                     fleet.FleetQuery                      // Issue #603: Single query path for device filtering
	gitSyncWebhookHandler          http.Handler                          // Issue #666: git-sync webhook endpoint (optional)
	auditManager                   *audit.Manager                        // Issue #775: registration audit events
	scriptTracker                  script.ExecutionTracker               // Issue #708: durable execution audit records
	scriptAuditLogger              *script.AuditLogger                   // Issue #708: in-memory execution metrics
	scriptMonitor                  *script.ExecutionMonitor              // Issue #708: active execution tracking
	scriptRepo                     script.ScriptRepository               // Issue #1670: git-backed script library
	privilegeStore                 cfgconfig.ConfigStore                 // Issue #1670: controller-side script privilege metadata
	pushLeaderStatus               leaderStatus                          // Issue #1318: leader check for config push (nil = leader)
	commandPublisher               *commands.Publisher                   // Issue #1319: fan-out config push to active stewards
	pushStore                      business.PushStore                    // Issue #1320: durable push-state persistence for HA failover
	registry                       registry.Registry                     // Issue #1323: active steward connection registry
	mountPointValidator            MountPointValidator                   // Issue #1396: config source connection test
	configSourceSecretStore        secretsif.SecretStore                 // Issue #1396: secrets for config source validator
	configSourceRateLimits         sync.Map                              // Issue #1396: per-tenant rate-limit counters
	pendingStore                   business.PendingRegistrationStore     // Issue #1696: durable pending-registration queue
	ipTrustStore                   business.IPTrustStore                 // Issue #1698: operator IP-trust management
	runManager                     *controllerrun.Manager                // Issue #1673: run/job/execution model
	runExecutionQueue              *script.ExecutionQueue                // Issue #1673: queue for ad-hoc run synthesis
	trustedProxies                 []net.IPNet                           // Issue #1695: parsed from TrustedProxies config; XFF honored only when peer is in this list
	blobStore                      blob.BlobStore                        // Issue #1702: installer artifact storage
	signingRotationService         *service.SigningRotationService       // Issue #1816: signing cert rotation endpoint
	moduleCacheLister              resolution.CacheLister                // Issue #1884: controller module cache for required_modules resolution
	moduleBundleResolver           resolution.BundleResolver             // Issue #1884: git source resolver for uncached modules
	moduleBundleApprover           resolution.BundleApprover             // Issue #1884: approval workflow for newly resolved modules
	moduleTrustStore               trust.TrustStore                      // Issue #1884: publisher trust store consulted during approval
	moduleBundleReviewer           resolution.BundleReviewer             // Issue #2728: human approve/reject for queued module bundles
	stewardBinaryTrustStore        trust.TrustStore                      // Issue #1944: overridable trust store for steward binary signature verification (injected in tests)
	testAutoApproveStewardBinaries bool                                  // Issue #1948: when true, publish sets approved_by automatically (test-only, CFGMS_SEED_TEST_API_KEYS gate)
	upgradeStore                   business.UpgradeStore                 // Issue #1945: durable per-steward upgrade state; nil means dispatch is refused with 503
	stewardStore                   business.StewardStore                 // Issue #2096: durable fleet-registry store for device-ID refresh gate
	pendingRefreshStore            business.PendingRefreshStore          // Issue #2096: durable pending-refresh queue
	refreshPolicyStore             business.RefreshPolicyStore           // Issue #2096: per-tenant refresh policy
	auditStore                     business.AuditStore                   // Issue #2098: direct audit store for test-mode count endpoint
	nonceCache                     *cache.Cache                          // Issue #2096: in-memory nonce store (TTL 65s)
	popVerifier                    PoPVerifier                           // Issue #2096: injectable for revoked-before-PoP testing
	isolationEngine                *tenantsecurity.TenantIsolationEngine // Issue #2123: tenant isolation enforcement for scoped API keys
	stewardEventLoggingManager     *logging.LoggingManager               // Issue #2139: dedicated sink for steward events; queried by handleGetStewardLogs (S6)
	sessionManager                 session.Manager                       // Issue #2232: admin session token issuance/revocation
	sessionCfg                     session.Config                        // Issue #2232: session lifecycle tunables (idle TTL, absolute cap, grace window)
	webSessionManager              session.Manager                       // Issue #2492: second session manager for browser cookie auth (ADR-018 §1,2)
	csrfTokens                     sync.Map                              // Issue #2493: sessionID → session-bound CSRF token; populated on login, deleted on logout/revoke
	membershipStore                cluster.MembershipStore               // Issue #2283: cluster node membership (nil when cluster not configured)
	clusterDraining                atomic.Bool                           // Issue #2283: true after drain is initiated; causes /health to return 503
	batchJobStore                  business.BatchJobStore                // Issue #2296: durable batch-job persistence
	batchJobExecutor               jobExecutor                           // Issue #2296: rolling-batch executor for fleet-wide updates
	rolloutStore                   business.RolloutStore                 // Issue #2340: durable rollout-orchestration-state persistence
	onRolloutSoak                  func(rolloutID string)                // Issue #2340: test-only lifecycle hook; nil in production. Fired when runRollout enters a ring soak.
	onRolloutTerminal              func(rolloutID string)                // Issue #2340: test-only lifecycle hook; nil in production. Fired after runRollout commits a terminal (completed/halted) store update.
	stopCleanup                    chan struct{}                         // signals startAPIKeyCleanup to exit
	cleanupDone                    chan struct{}                         // closed when cleanup goroutine exits
	closeOnce                      sync.Once                             // idempotent Close
	roleConfigStore                cfgconfig.ConfigStore                 // Issue #2543: role-config storage under role-policies namespace
	tagStore                       *tagstore.Store                       // Issue #2545: steward tag store for tag: selector support
	webAuthn                       *webauthn.WebAuthn                    // Issue #2782: WebAuthn RP instance; nil → endpoints return 503
	webAuthnSessions               sync.Map                              // Issue #2782: pending registration sessions; key=username, value=*webAuthnPendingSession
	webAuthnPresenceSessions       sync.Map                              // Issue #2784: pending presence-assertion sessions; key=principalID, value=*webAuthnPendingSession
	presenceTokens                 sync.Map                              // Issue #2784: short-lived single-use presence tokens; key=tokenHash, value=*presenceTokenRecord
	telemetryHandler               http.Handler                          // Issue #2765: telemetry fan-out WebSocket handler
}

// SetDraining implements cluster.DrainHealthRegistrar. When draining is true,
// GET /api/v1/health returns HTTP 503 so the load balancer stops routing new
// steward connections to this node. Called by cluster.Drain() after setting the
// membership state; safe to call concurrently with handleHealth.
func (s *Server) SetDraining(draining bool) {
	s.clusterDraining.Store(draining)
}

// APIKey represents an API key for external authentication
type APIKey struct {
	ID          string     `json:"id"`
	Key         string     `json:"key"`
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	TenantID    string     `json:"tenant_id"`
}

// ServerConfig contains configuration for the REST API server
type ServerConfig struct {
	ListenAddr string
	TLSEnabled bool
	CertFile   string
	KeyFile    string
}

// CORSConfig contains CORS configuration for the API server
type CORSConfig struct {
	AllowedOrigins []string
}

// New creates a new REST API server instance
func New(
	cfg *config.Config,
	logger logging.Logger,
	controllerService *service.ControllerService,
	configService *service.ConfigurationServiceV2,
	certProvisioningService *service.CertificateProvisioningService,
	rbacService *service.RBACService,
	certManager *cert.Manager,
	tenantManager *tenant.Manager,
	rbacManager *rbac.Manager,
	systemMonitor *monitoring.SystemMonitor,
	haManager *ha.Manager,
	registrationTokenStore registration.Store,
	signerCertSerial string, // Story #378: Serial of cert used for config signing
	healthCollector *health.Collector, // Story #417: CFGMS health monitoring
	auditManager *audit.Manager, // Issue #775: registration audit events
	commandPublisher *commands.Publisher, // Issue #1319: fan-out config push to active stewards
	pushStore business.PushStore, // Issue #1320: durable push-state persistence for HA failover
	blobStore blob.BlobStore, // Issue #1702: installer artifact storage
) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// M-AUTH-1: Initialize central secrets provider for API key storage
	secretStore, err := NewSecretStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secret store: %w", err)
	}

	// Issue #1695: Parse TrustedProxies CIDRs once at startup so per-request
	// extractSourceIP calls never parse strings.
	var trustedProxies []net.IPNet
	if cfg.Registration != nil {
		for _, cidr := range cfg.Registration.TrustedProxies {
			_, ipNet, parseErr := net.ParseCIDR(cidr)
			if parseErr != nil {
				logger.Warn("Invalid trusted_proxy CIDR, skipping",
					"cidr", logging.SanitizeLogValue(cidr), "error", parseErr)
				continue
			}
			trustedProxies = append(trustedProxies, *ipNet)
		}
	}

	server := &Server{
		cfg:                     cfg,
		logger:                  logger,
		controllerService:       controllerService,
		configService:           configService,
		certProvisioningService: certProvisioningService,
		rbacService:             rbacService,
		certManager:             certManager,
		tenantManager:           tenantManager,
		rbacManager:             rbacManager,
		systemMonitor:           systemMonitor,
		healthCollector:         healthCollector,
		haManager:               haManager,
		registrationTokenStore:  registrationTokenStore,
		signerCertSerial:        signerCertSerial,         // Story #378: For registration handler
		apiKeys:                 make(map[string]*APIKey), // In-memory cache
		secretStore:             secretStore,              // M-AUTH-1: Central secrets provider
		approvalHook:            &IPTrustApprovalHook{},   // Issue #1695: nil store → fail-closed (quarantine all)
		trustedProxies:          trustedProxies,           // Issue #1695: parsed from TrustedProxies config
		auditManager:            auditManager,             // Issue #775: registration audit events
		commandPublisher:        commandPublisher,         // Issue #1319: fan-out config push to active stewards
		pushStore:               pushStore,                // Issue #1320: durable push-state persistence for HA failover
		blobStore:               blobStore,                // Issue #1702: installer artifact storage
		nonceCache:              newNonceCache(),          // Issue #2096: nonce store for registration-refresh
		popVerifier:             ed25519PoPVerifier{},     // Issue #2096: default PoP verifier; override in tests
		sessionCfg:              session.DefaultConfig(),  // Issue #2232: ADR-014 session lifecycle tunables
		stopCleanup:             make(chan struct{}),
		cleanupDone:             make(chan struct{}),
	}

	// Issue #1318: wire leader-check for config push; nil haManager = OSS single-node = always leader
	if haManager != nil {
		server.pushLeaderStatus = haManager
	}

	// Story #380: Initialize three-tier auth defense system
	server.authDefense = authdefense.New(
		authdefense.DefaultConfig(),
		logger,
		authdefense.WithTenantExtractor(func(r *http.Request) string {
			if tid, ok := r.Context().Value(ctxkeys.TenantID).(string); ok {
				return tid
			}
			return ""
		}),
	)

	// Configure CORS settings (H-AUTH-3)
	server.configureCORS()

	// Initialize router with middleware
	server.setupRouter()

	// M-AUTH-1: Load existing API keys from secret store
	if err := server.loadAPIKeysFromStore(); err != nil {
		logger.Warn("Failed to load API keys from store", "error", err)
	}

	// Issue #2226: Scan for API keys holding Tier-3 permissions so operators can revoke them.
	if err := server.scanAPIKeysForPrivilegedAccess(context.Background()); err != nil {
		logger.Warn("Startup scan for privileged API keys failed; continuing", "error", err)
	}

	// Seed test API keys only when explicitly requested via environment variable.
	// Never runs in production — must be set deliberately in test environments.
	if os.Getenv("CFGMS_SEED_TEST_API_KEYS") == "1" {
		for _, envVar := range []string{"CFGMS_API_KEY_EAST", "CFGMS_API_KEY_CENTRAL", "CFGMS_API_KEY_WEST"} {
			if keyVal := os.Getenv(envVar); keyVal != "" {
				server.apiKeys[keyVal] = &APIKey{ //nolint:gosec // test-only seeding, env-gated
					Key:         keyVal,
					Permissions: []string{"steward:read", "steward:auth-refresh", "workflow:execute", "workflow:read"},
					TenantID:    "default",
				}
			}
		}

		// Issue #1709: installer key uses a separate block (not the EAST/CENTRAL/WEST loop)
		// because it requires different permissions and must upload under the "root" tenant
		// so the public download endpoint (which always looks up tenant "root") can find it.
		if keyVal := os.Getenv("CFGMS_API_KEY_INSTALLER"); keyVal != "" {
			server.apiKeys[keyVal] = &APIKey{ //nolint:gosec // test-only seeding, env-gated
				Key:         keyVal,
				Permissions: []string{"installer:upload", "installer:read", "installer:delete", "steward:list"},
				TenantID:    "root",
			}
		}

		// Issue #1948: upgrade test key — publishes + dispatches under the fleet-child-a
		// tenant so E2E upgrade tests target real fleet stewards without requiring a
		// manual API key creation step in every test run.
		if keyVal := os.Getenv("CFGMS_API_KEY_UPGRADE_TEST"); keyVal != "" {
			server.apiKeys[keyVal] = &APIKey{ //nolint:gosec // test-only seeding, env-gated
				Key:         keyVal,
				Permissions: []string{"installer:publish:steward", "installer:dispatch:steward", "installer:read"},
				TenantID:    "fleet-root/fleet-child-a",
			}
		}

		// Issue #1948: override the steward binary trust store with a test Ed25519 key,
		// and enable auto-approval so published binaries can be dispatched immediately.
		// Both are only active when CFGMS_SEED_TEST_API_KEYS=1 — never in production.
		if pubKeyBase64 := os.Getenv("CFGMS_TEST_STEWARD_PUBLISHER_KEY"); pubKeyBase64 != "" {
			pubKeyBytes, decErr := base64.StdEncoding.DecodeString(pubKeyBase64)
			if decErr == nil && len(pubKeyBytes) == ed25519.PublicKeySize {
				testTrust := trust.NewInMemoryTrustStore()
				_ = testTrust.AddPublisher(trust.PublisherIdentity{
					Name:      "cfgms",
					PublicKey: pubKeyBytes,
					Algorithm: "ed25519",
				})
				server.stewardBinaryTrustStore = testTrust
				server.testAutoApproveStewardBinaries = true
				logger.Info("Test mode: steward binary trust store overridden with test key; auto-approve enabled (Issue #1948)")
			}
		}
	}

	// M-AUTH-1: Do NOT generate default API keys (security anti-pattern)
	// API keys must be explicitly created by administrators

	// Issue #603: Initialize fleet query using the controller service as the steward provider
	server.fleetQuery = fleet.NewMemoryQuery(&controllerServiceAdapter{svc: controllerService})

	// Issue #1521: register save=deploy fanout callback so every successful SetConfiguration
	// automatically distributes to all active stewards of the affected tenant.
	if configService != nil && commandPublisher != nil {
		configService.RegisterFanoutCallback(func(ctx context.Context, tenantID, cfgID string) {
			if checker := server.pushLeaderStatus; checker != nil && !checker.IsLeader() {
				return
			}
			cfg := &push.StewardConfiguration{
				ConfigID:  cfgID,
				TenantID:  tenantID,
				Version:   fmt.Sprintf("%d", time.Now().UnixNano()),
				AppliedAt: time.Now().UTC(),
				Source:    "save-deploy",
			}
			allStewards := controllerService.GetAllStewards()
			var tenantStewards []*service.StewardInfo
			for _, st := range allStewards {
				if st.TenantID == tenantID {
					tenantStewards = append(tenantStewards, st)
				}
			}
			go func() {
				result := push.Fanout(context.Background(), cfg, tenantStewards, commandPublisher, logger)
				logger.Info("Save=deploy fan-out complete",
					"tenant_id", logging.SanitizeLogValue(tenantID),
					"cfg_id", logging.SanitizeLogValue(cfgID),
					"succeeded", len(result.Succeeded),
					"failed", len(result.Failed))
			}()
		})
		logger.Info("Save=deploy fanout callback registered on config service")
	}

	// Start background cleanup for expired API keys
	server.startAPIKeyCleanup()

	return server, nil
}

// controllerServiceAdapter adapts *service.ControllerService to fleet.StewardProvider.
type controllerServiceAdapter struct {
	svc *service.ControllerService
}

func (a *controllerServiceAdapter) GetAllStewards() []fleet.StewardData {
	infos := a.svc.GetAllStewards()
	result := make([]fleet.StewardData, 0, len(infos))
	for _, info := range infos {
		var attrs map[string]string
		if info.DNA != nil {
			attrs = info.DNA.Attributes
		}
		result = append(result, fleet.StewardData{
			ID:            info.ID,
			TenantID:      info.TenantID,
			Status:        info.Status,
			LastHeartbeat: info.LastHeartbeat,
			DNAAttributes: attrs,
		})
	}
	return result
}

// setupRouter initializes the HTTP router with all routes and middleware
func (s *Server) setupRouter() {
	s.router = mux.NewRouter()

	// Add middleware
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.corsMiddleware)
	s.router.Use(s.contentTypeMiddleware)

	// API routes with authentication and validation
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.authDefense.Middleware)   // Story #380: rate limiting before auth
	api.Use(s.authenticationMiddleware) // extract principal (API key or mTLS)
	// requireTier(TierAny) removed: it was a no-op passthrough (Issue #2780 migrates to assurance-based enforcement).
	api.Use(s.validationMiddleware)
	api.Use(s.csrfMiddleware) // Issue #2493: session-bound CSRF for unsafe cookie-auth methods
	s.apiRouter = api         // saved so Set* methods can lazy-register routes after construction

	// --- Tier 0 (TierPublic) — no authentication required ---
	//   GET  /api/v1/health
	//   GET  /api/v1/ready
	//   POST /api/v1/register
	//   GET  /api/v1/registration/status/{pending_id}
	//   POST /api/v1/stewards/{device_id}/refresh/challenge   (PoP-auth in handler)
	//   POST /api/v1/stewards/{device_id}/refresh/complete    (PoP-auth in handler)
	//   GET  /api/v1/installer/download/{platform}/{arch}
	//   GET  /api/v1/public/steward-binaries/{version}/{platform}/{arch}
	//   POST /raft/message                                     (internal mTLS peer CN in handler)

	// Health check (no auth required) — liveness / object-presence.
	s.router.HandleFunc("/api/v1/health", s.handleHealth).Methods("GET", "OPTIONS")

	// Readiness probe (no auth required) — real-state: round-trips durable
	// storage. Used by the blue/green cutover smoketest (Issue #2012).
	s.router.HandleFunc("/api/v1/ready", s.handleReady).Methods("GET", "OPTIONS")

	// Steward registration (no auth required - uses registration token)
	s.router.HandleFunc("/api/v1/register", s.handleRegister).Methods("POST", "OPTIONS")

	// Registration status poll (no API-key auth — authenticated by regtoken Bearer header)
	s.router.HandleFunc("/api/v1/registration/status/{pending_id}", s.handleRegistrationStatus).Methods("GET")

	// Test-mode config upload (no auth required - for integration tests only)
	// Use separate path to avoid conflict with authenticated subrouter
	// TODO: Remove or protect this endpoint in production
	s.router.HandleFunc("/api/v1/test/stewards/{id}/config", s.handleUpdateStewardConfig).Methods("PUT", "OPTIONS")

	// Issue #2098: Test-mode admin endpoints — active only when CFGMS_ENABLE_TEST_ENDPOINTS=true.
	// Fleet E2E tests use these instead of sqlite3 CLI (not installed in Alpine container).
	s.router.HandleFunc("/api/v1/test/stewards/{id}/status", s.handleTestSetStewardStatus).Methods("PUT")
	s.router.HandleFunc("/api/v1/test/audit/count", s.handleTestAuditCount).Methods("GET")

	// Registration-refresh endpoints (unauthenticated — authenticated by device key PoP).
	// Registered on the base router like /api/v1/register (Issue #2096).
	s.router.HandleFunc("/api/v1/stewards/{device_id}/refresh/challenge", s.handleRefreshChallenge).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/v1/stewards/{device_id}/refresh/complete", s.handleRefreshComplete).Methods("POST", "OPTIONS")

	// All routes on the api subrouter require authentication (enforced by authenticationMiddleware).
	// Routes whose permissions appear in permissionAssurance additionally enforce an assurance-level
	// minimum via requirePermission — see assurance.go and Issue #2780 (ADR-021 migration).

	// Feature route registrars — each named-subrouter block is self-registered from its own
	// routes_*.go file via package init(). Adding a new endpoint only requires a new file;
	// no edit to this function body is needed (Issue #2796).
	for _, register := range routeRegistrars {
		register(s, api)
	}

	// Audit log readback endpoint (Issue #2190)
	api.Handle("/audit/entries", s.requirePermission("audit", "list")(http.HandlerFunc(s.handleListAuditEntries))).Methods("GET")

	// Configuration list endpoint (Issue #1570)
	api.Handle("/configs", s.requirePermission("config", "list")(http.HandlerFunc(s.handleListConfigs))).Methods("GET")

	// Configuration deployments endpoint (Issue #1598)
	api.Handle("/configs/{id}/deployments", s.requirePermission("config", "list-deployments")(http.HandlerFunc(s.handleGetConfigDeployments))).Methods("GET")

	// Session management endpoints (Issue #2232, #2368, #2780).
	// POST /sessions mints a new long-lived Bearer credential — requirePermission enforces
	// session:create which is in permissionAssurance with Min: AssuranceStrong, closing the
	// self-perpetuating-compromise gap (a web-session principal cannot mint new sessions).
	// GET /sessions and DELETE /sessions/{id} are ordinary grant permissions (session:list /
	// session:revoke) deliberately absent from permissionAssurance — revoking a session is
	// a de-escalation action that must work even when the strong authenticator is unavailable.
	api.Handle("/sessions", s.requirePermission("session", "create")(http.HandlerFunc(s.handleSessionCreate))).Methods("POST")
	api.Handle("/sessions", s.requirePermission("session", "list")(http.HandlerFunc(s.handleSessionList))).Methods("GET")
	api.Handle("/sessions/{id}", s.requirePermission("session", "revoke")(http.HandlerFunc(s.handleSessionRevoke))).Methods("DELETE")

	// Registration approval endpoints (Issue #1568)
	api.Handle("/registration/pending", s.requirePermission("registration", "list-pending")(http.HandlerFunc(s.handleListPendingRegistrations))).Methods("GET")
	api.Handle("/registration/{id}/approve", s.requirePermission("registration", "approve")(http.HandlerFunc(s.handleApproveRegistration))).Methods("POST")
	api.Handle("/registration/{id}/deny", s.requirePermission("registration", "deny")(http.HandlerFunc(s.handleDenyRegistration))).Methods("POST")

	// Bulk registration approval and IP-trust management (Issue #1698)
	api.Handle("/registration/approve-all", s.requirePermission("registration", "approve")(http.HandlerFunc(s.handleApproveAllRegistrations))).Methods("POST")
	api.Handle("/registration/approve-by-cidr", s.requirePermission("registration", "approve")(http.HandlerFunc(s.handleApproveByCIDR))).Methods("POST")
	api.Handle("/registration/ip-trust", s.requirePermission("registration", "manage-ip-trust")(http.HandlerFunc(s.handleAddIPTrust))).Methods("POST")
	// {cidr:.+} allows the CIDR slash to appear literally in the URL path after decoding.
	api.Handle("/registration/ip-trust/{tenant_id}/{cidr:.+}", s.requirePermission("registration", "manage-ip-trust")(http.HandlerFunc(s.handleRevokeIPTrust))).Methods("DELETE")

	// Refresh approval queue endpoints (Issue #2097). Registered on the api subrouter
	// (not the stewards subrouter) so they are not confused with /{id} parameterized routes.
	api.Handle("/stewards/refresh/pending",
		s.requirePermission("refresh", "list-pending")(http.HandlerFunc(s.handleListPendingRefreshes))).Methods("GET")
	api.Handle("/stewards/refresh/{pending_id}/approve",
		s.requirePermission("refresh", "approve")(http.HandlerFunc(s.handleApproveRefresh))).Methods("POST")
	api.Handle("/stewards/refresh/{pending_id}/reject",
		s.requirePermission("refresh", "reject")(http.HandlerFunc(s.handleRejectRefresh))).Methods("POST")

	// Web login / CSRF / logout endpoints (Issue #2493, ADR-018 §3,4).
	// Registered on the BASE router (TierPublic pattern) and explicitly wrapped in
	// authDefense.Middleware. The api subrouter chain at line ~414 does NOT cover
	// base-router routes (security A5.4), so wrapping is mandatory here.
	s.router.Handle("/api/v1/web/csrf",
		s.authDefense.Middleware(http.HandlerFunc(s.handleGetWebCSRF))).Methods("GET")
	s.router.Handle("/api/v1/web/login",
		s.authDefense.Middleware(http.HandlerFunc(s.handleWebLogin))).Methods("POST")
	s.router.Handle("/api/v1/web/logout",
		s.authDefense.Middleware(http.HandlerFunc(s.handleWebLogout))).Methods("POST")

	// Installer package download — public, no auth required (Issue #1704).
	// Assembles a per-platform tar.gz on the fly. The download URL is the distribution mechanism.
	s.router.HandleFunc("/api/v1/installer/download/{platform}/{arch}", s.handleDownloadInstallPackage).Methods("GET")

	// Steward binary public download — no auth required (Issue #1948).
	// The binary's Ed25519 signature authenticates content at the steward side.
	// Steward mTLS certs lack the admin marker required by the authenticated GET endpoint.
	s.router.HandleFunc("/api/v1/public/steward-binaries/{version}/{platform}/{arch}", s.handleGetStewardBinaryPublic).Methods("GET")

	// Git-sync webhook is registered lazily by SetGitSyncWebhookHandler (Issue #666).
	// No route is pre-registered here; the endpoint only exists when a git-sync
	// handler is explicitly wired in after server creation.

	// Raft message endpoint: mTLS peer CN verification is enforced inside HandleMessage
	s.router.HandleFunc("/raft/message", s.handleRaftMessage).Methods("POST")
	// Raft status endpoint: requires HA read-status permission via API authentication
	api.Handle("/raft/status", s.requirePermission("ha", "read-status")(http.HandlerFunc(s.handleRaftStatus))).Methods("GET")

	// TODO(#997): Wire terminal WebSocket handler when HTTP route is added (gated on epic #750).
	// When the terminal route is registered, parse CFGMS_TERMINAL_ALLOWED_ORIGINS and pass the
	// resulting slice to terminal.NewWebSocketHandler as the third argument. Parsing pattern
	// mirrors CFGMS_ALLOWED_ORIGINS (comma-separated, strings.TrimSpace per entry, empty filtered):
	//
	//   var terminalOrigins []string
	//   if raw := os.Getenv("CFGMS_TERMINAL_ALLOWED_ORIGINS"); raw != "" {
	//       for _, o := range strings.Split(raw, ",") {
	//           if trimmed := strings.TrimSpace(o); trimmed != "" {
	//               terminalOrigins = append(terminalOrigins, trimmed)
	//           }
	//       }
	//   }
	//   terminalHandler, err := terminal.NewWebSocketHandler(sessionManager, s.logger, terminalOrigins)
	//   // then register: api.Handle("/terminal/ws/{steward_id}", ...).Methods("GET")

	// SPA catch-all: lowest-precedence handler for the embedded web UI (Issue #2494).
	// All /api/* and /raft/* routes registered above take precedence via gorilla/mux
	// ordering; unmatched paths in those namespaces are refused by spaHandler itself.
	distFS, subErr := fs.Sub(web.Assets, "dist")
	if subErr != nil {
		s.logger.Error("Failed to initialise embedded SPA assets; web UI will be unavailable", "error", subErr)
	} else {
		s.router.PathPrefix("/").Handler(newSPAHandler(distFS))
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Determine listen address for HTTP server (different from gRPC)
	httpAddr := s.getHTTPListenAddr()

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         httpAddr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Configure TLS if available
	if s.shouldUseTLS() {
		tlsConfig, err := s.setupTLS()
		if err != nil {
			s.logger.Warn("Failed to setup TLS for HTTP server, starting without TLS", "error", err)
		} else if tlsConfig != nil {
			s.httpServer.TLSConfig = tlsConfig
		}
	}

	// Start server in goroutine
	go func() {
		s.mu.RLock()
		server := s.httpServer
		s.mu.RUnlock()

		if server != nil {
			var err error
			if server.TLSConfig != nil {
				s.logger.Info("Starting HTTPS REST API server", "address", httpAddr)
				err = server.ListenAndServeTLS("", "") // Certificates in TLSConfig
			} else {
				s.logger.Info("Starting HTTP REST API server", "address", httpAddr)
				err = server.ListenAndServe()
			}

			if err != nil && err != http.ErrServerClosed {
				s.logger.Error("HTTP server failed", "error", err)
			}
		}
	}()

	s.logger.Info("REST API server started", "address", httpAddr)
	return nil
}

// Close gracefully stops all background goroutines owned by this Server and
// shuts down the HTTP listener. It is safe to call more than once (idempotent).
func (s *Server) Close(ctx context.Context) error {
	var firstErr error
	s.closeOnce.Do(func() {
		// Signal the cleanup goroutine to exit — do this before acquiring s.mu
		// to avoid deadlock: cleanupExpiredAPIKeys also holds s.mu.
		close(s.stopCleanup)
		select {
		case <-s.cleanupDone:
		case <-ctx.Done():
			firstErr = fmt.Errorf("api server close: timed out waiting for cleanup goroutine: %w", ctx.Err())
		}

		// Stop audit manager before closing the HTTP server so that any
		// in-flight audit writes can still reach storage.
		if s.auditManager != nil {
			if err := s.auditManager.Stop(ctx); err != nil && firstErr == nil {
				firstErr = err
			}
		}

		// Close nonce cache to stop its background cleanup goroutine (Issue #2096).
		if s.nonceCache != nil {
			s.nonceCache.Close()
		}

		// Stop the execution queue, which also stops its EphemeralKeyManager goroutine.
		if s.runExecutionQueue != nil {
			s.runExecutionQueue.Stop()
		}

		// Stop the config service's router cache goroutine (configrouting source cache).
		if s.configService != nil {
			s.configService.Close()
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		// authDefense.Stop() and secretStore.Close() both call cache.Close() →
		// c.cleanupDone.Wait() with no built-in timeout. On Windows, slower goroutine
		// scheduling can cause them to block well past ctx's deadline. Run them in a
		// single goroutine so Close() always honours the caller's context.
		authDef := s.authDefense
		secStore := s.secretStore
		cacheDone := make(chan error, 1)
		go func() {
			// Story #380: Stop auth defense system
			if authDef != nil {
				authDef.Stop()
			}
			// M-AUTH-1: Close secret store to stop its internal cache cleanup goroutine.
			var storeErr error
			if secStore != nil {
				storeErr = secStore.Close()
			}
			cacheDone <- storeErr
		}()
		select {
		case storeErr := <-cacheDone:
			if storeErr != nil && firstErr == nil {
				firstErr = storeErr
			}
		case <-ctx.Done():
			if firstErr == nil {
				firstErr = fmt.Errorf("api server close: timed out stopping auth defense and secret store: %w", ctx.Err())
			}
		}

		if s.httpServer != nil {
			if err := s.httpServer.Shutdown(ctx); err != nil && firstErr == nil {
				s.logger.Error("Failed to shutdown HTTP server gracefully", "error", err)
				firstErr = err
			}
		}
	})
	return firstErr
}

// Stop gracefully shuts down the HTTP server. Prefer Close when a context is available.
func (s *Server) Stop() error {
	s.logger.Info("Shutting down REST API server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.Close(ctx)
}

// SetRollbackManager sets the rollback manager and registers rollback API routes (Story #416).
// Call this after New() returns but before Start() is called.
func (s *Server) SetRollbackManager(m rollback.RollbackManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollbackManager = m
	if m == nil {
		return
	}
	// Read the principal from the request context (set by authenticationMiddleware)
	// so both mTLS admin principals and scoped API-key principals are evaluated.
	rollbackPrincipalExtractor := func(r *http.Request) *Principal {
		p, _ := r.Context().Value(principalContextKey).(*Principal)
		return p
	}
	// Resolve the steward's registered tenant from the controller registry.
	// This is the authoritative cross-tenant check — it cannot be bypassed by
	// the caller supplying a fabricated steward_tenant_path in the request body.
	stewardTenantLookup := func(stewardID string) string {
		if s.controllerService != nil {
			if info, ok := s.controllerService.GetStewardInfo(stewardID); ok {
				return info.TenantID
			}
		}
		return ""
	}
	rollbackHandler := NewRollbackHandler(m, rollbackPrincipalExtractor, stewardTenantLookup, s.auditManager)
	rollbackRouter := s.apiRouter.PathPrefix("/rollback").Subrouter()
	// Require config/rollback permission for all rollback endpoints — same gate pattern
	// as every other mutating endpoint in this server.
	rollbackRouter.Use(s.requirePermission("config", "rollback"))
	rollbackHandler.RegisterRoutes(rollbackRouter)
	s.logger.Info("Rollback API routes registered")
}

// SetReportsHandler sets the reports handler and registers reports API routes (Story #416).
// Call this after New() returns but before Start() is called.
func (s *Server) SetReportsHandler(h *reportapi.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reportsHandler = h
	if h == nil {
		return
	}
	reportsRouter := s.apiRouter.PathPrefix("/reports").Subrouter()
	h.RegisterRoutes(reportsRouter)
	s.logger.Info("Reports API routes registered")
}

// SetWorkflowHandler sets the workflow handler and registers workflow and trigger API routes
// (Issue #414). Propagates the server's fleet query so that script dispatch targeting is wired
// at setup time (Issue #609). Wires requirePermission into the handler so every workflow route
// is RBAC-gated and the trigger subrouter carries a coarse-grained trigger:manage gate (Issue #2725).
// Call this after New() returns but before Start() is called.
func (s *Server) SetWorkflowHandler(h *WorkflowHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workflowHandler = h
	if h != nil && s.fleetQuery != nil {
		h.SetFleetQuery(s.fleetQuery)
	}
	if h == nil {
		return
	}
	h.SetRequirePermFn(s.requirePermission)
	workflowRouter := s.apiRouter.PathPrefix("/workflows").Subrouter()
	h.RegisterWorkflowRoutes(workflowRouter)
	triggerRouter := s.apiRouter.PathPrefix("/triggers").Subrouter()
	triggerRouter.Use(s.requirePermission("trigger", "manage"))
	h.RegisterTriggerRoutes(triggerRouter)
	s.logger.Info("Workflow and trigger API routes registered")
}

// GetRouter returns the HTTP router for testing purposes.
func (s *Server) GetRouter() http.Handler {
	return s.router
}

// GetSecretStore returns the central secrets provider so callers outside the api
// package (e.g. server.initializeWorkflowHandler) can thread it into subsystems
// that require secret access (Issue #2374).
func (s *Server) GetSecretStore() secretsif.SecretStore {
	return s.secretStore
}

// SetApprovalHook replaces the registration approval hook (Issue #422).
// Called during server startup when a workflow engine is available.
func (s *Server) SetApprovalHook(hook RegistrationApprovalHook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hook != nil {
		s.approvalHook = hook
	}
}

// SetScriptModule wires the script module components so the script API handlers
// return real execution data (Issue #708). Call this after New() returns but
// before Start() is called.
func (s *Server) SetScriptModule(tracker script.ExecutionTracker, auditLogger *script.AuditLogger, monitor *script.ExecutionMonitor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scriptTracker = tracker
	s.scriptAuditLogger = auditLogger
	s.scriptMonitor = monitor
}

// SetScriptRepository wires the git-backed script library so that
// GET /api/v1/scripts returns real script metadata (Issue #1670).
// Call this after New() returns but before Start() is called.
func (s *Server) SetScriptRepository(r script.ScriptRepository) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scriptRepo = r
}

// SetPrivilegeStore wires the config store used to persist controller-side
// script privilege metadata (Issue #1670).
// Call this after New() returns but before Start() is called.
func (s *Server) SetPrivilegeStore(cs cfgconfig.ConfigStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.privilegeStore = cs
}

// SetRoleConfigStore wires the config store used to persist role configs under
// the role-policies namespace (Issue #2543).
// Call this after New() returns but before Start() is called.
func (s *Server) SetRoleConfigStore(cs cfgconfig.ConfigStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roleConfigStore = cs
}

// SetTagStore wires the tag store for steward tag management (Issue #2545).
// Call this after New() returns but before Start() is called.
func (s *Server) SetTagStore(ts *tagstore.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tagStore = ts
}

// TagStore returns the wired tag store, or nil when unwired. Exposed so
// controller startup wiring can be regression-tested (the tag REST endpoints
// 503 when this is nil — Issue #2545/#2548).
func (s *Server) TagStore() *tagstore.Store {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tagStore
}

// RoleConfigStore returns the wired role-config store, or nil when unwired.
// Exposed so controller startup wiring can be regression-tested (the role REST
// endpoints 503 when this is nil — Issue #2543/#2548).
func (s *Server) RoleConfigStore() cfgconfig.ConfigStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.roleConfigStore
}

// SetRegistry wires the active-steward connection registry so that
// GET /api/v1/stewards/{id} can report connection_state and active_sessions
// (Issue #1323). Call this after New() returns but before Start() is called.
func (s *Server) SetRegistry(r registry.Registry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registry = r
}

// Registry returns the wired active-steward connection registry, or nil if
// none has been set. Used by controller wiring and tests to verify the API
// server and the control-plane provider share a single registry instance.
func (s *Server) Registry() registry.Registry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.registry
}

// SetGitSyncWebhookHandler registers the git-sync push-event webhook handler.
// The handler is mounted at POST /api/v1/webhooks/git-push and uses its own
// HMAC-SHA256 signature validation (no API-key auth). Call this after New()
// returns but before Start() is called (Issue #666).
func (s *Server) SetGitSyncWebhookHandler(h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gitSyncWebhookHandler = h
	if h != nil {
		s.router.Handle("/api/v1/webhooks/git-push", h).Methods("POST")
		s.logger.Info("git-sync webhook endpoint registered at /api/v1/webhooks/git-push")
	}
}

// SetRunManager wires the run manager and execution queue for ad-hoc run endpoints
// (Issue #1673). Call this after New() returns but before Start() is called.
func (s *Server) SetRunManager(m *controllerrun.Manager, queue *script.ExecutionQueue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runManager = m
	s.runExecutionQueue = queue
}

// SetPendingStore wires the durable pending-registration store (Issue #1696).
// Call this after New() returns but before Start() is called.
func (s *Server) SetPendingStore(store business.PendingRegistrationStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingStore = store
}

// SetIPTrustStore wires the IP-trust store for operator ip-trust management (Issue #1698).
// Call this after New() returns but before Start() is called.
func (s *Server) SetIPTrustStore(store business.IPTrustStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipTrustStore = store
}

// SetUpgradeStore wires the durable UpgradeStore used by the steward upgrade
// dispatch endpoint (Issue #1945). When nil, POST /api/v1/stewards/upgrade
// returns 503. No silent in-memory fallback.
func (s *Server) SetUpgradeStore(store business.UpgradeStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upgradeStore = store
}

// SetRolloutStore wires the durable RolloutStore used by the ring-advance rollout
// endpoints (Issue #2340). When nil, POST /api/v1/rollout returns 503.
func (s *Server) SetRolloutStore(store business.RolloutStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rolloutStore = store
}

// SetStewardStore wires the durable StewardStore used by the registration-refresh
// endpoints (Issue #2096). When nil, the refresh endpoints return 503.
func (s *Server) SetStewardStore(store business.StewardStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stewardStore = store
}

// SetPendingRefreshStore wires the durable PendingRefreshStore for the
// registration-refresh approval queue (Issue #2096).
func (s *Server) SetPendingRefreshStore(store business.PendingRefreshStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingRefreshStore = store
}

// SetRefreshPolicyStore wires the per-tenant RefreshPolicyStore (Issue #2096).
func (s *Server) SetRefreshPolicyStore(store business.RefreshPolicyStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshPolicyStore = store
}

// SetAuditStore wires a direct AuditStore reference for the test-mode count endpoint
// (Issue #2098). Production code uses s.auditManager; this allows test endpoints to
// query audit entries without needing sqlite3 CLI in the controller container.
func (s *Server) SetAuditStore(store business.AuditStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditStore = store
}

// SetPoPVerifier replaces the proof-of-possession verifier.
// Used in tests to assert the verifier is never called for revoked devices.
func (s *Server) SetPoPVerifier(v PoPVerifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v != nil {
		s.popVerifier = v
	}
}

// SetIsolationEngine wires the tenant isolation engine used by requirePermission
// to enforce tenant-scoped API-key isolation (Issue #2123). When nil (default),
// isolation checks are skipped — only set in deployments that require tenant
// boundary enforcement for agent credentials.
func (s *Server) SetIsolationEngine(engine *tenantsecurity.TenantIsolationEngine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isolationEngine = engine
}

// SetSigningRotationService wires the signing rotation service for the
// POST /api/v1/certificates/signing/rotate endpoint (Issue #1816).
// Call this after New() returns but before Start() is called.
func (s *Server) SetSigningRotationService(svc *service.SigningRotationService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signingRotationService = svc
}

// SetSessionManager wires the session Manager for admin session-token issuance and
// revocation (Issue #2232). When nil (default), POST /api/v1/sessions and
// DELETE /api/v1/sessions/{id} return 503. Call after New() but before Start().
func (s *Server) SetSessionManager(mgr session.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionManager = mgr
}

// SetWebSessionManager wires the web session Manager used to authenticate browser
// clients via the cfgms_session HttpOnly cookie (Issue #2492, ADR-018 §1,2).
// Uses explicit Config (idle 60m / absolute 12h / grace 30s) — distinct from the
// cfg-CLI sessionManager (idle 15m / absolute 8h). When nil (default), the cookie
// branch in authenticationMiddleware is bypassed. Call after New() but before Start().
func (s *Server) SetWebSessionManager(mgr session.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webSessionManager = mgr
}

// SetDurableSessionStore wires both session managers with a shared durable session.Store
// (Issue #2736, epic #2735). The CLI manager uses ADR-014 defaults (idle 15m / absolute 8h /
// grace 30s); the web manager uses a longer-lived config (idle 60m / absolute 12h / grace 30s).
// Sharing the same store lets sessions survive controller restarts and validate across cluster
// nodes. Call after New() but before Start(); it overwrites any prior SetSessionManager /
// SetWebSessionManager wiring.
func (s *Server) SetDurableSessionStore(store session.Store) {
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionManager = session.NewManager(s.sessionCfg, store, time.Now)
	s.webSessionManager = session.NewManager(webCfg, store, time.Now)
}

// SetMembershipStore wires the cluster MembershipStore used by the drain endpoint
// (Issue #2283). When nil (default), POST /api/v1/cluster/nodes/{id}/drain returns
// 503. Call after New() but before Start().
func (s *Server) SetMembershipStore(store cluster.MembershipStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.membershipStore = store
}

// SetBatchJobStore wires the durable BatchJobStore used by the batch job endpoints
// (Issue #2296). When nil (default), POST /api/v1/jobs and GET /api/v1/jobs/{id}
// return 503. Call after New() but before Start().
func (s *Server) SetBatchJobStore(store business.BatchJobStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batchJobStore = store
}

// SetBatchJobExecutor wires the rolling-batch executor used to run batch jobs
// asynchronously (Issue #2296). When nil (default), job creation still persists
// the record but does not start execution. Call after New() but before Start().
func (s *Server) SetBatchJobExecutor(exec jobExecutor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batchJobExecutor = exec
}

// SetStewardEventLoggingManager injects the dedicated steward-event
// LoggingManager. Call after New() and before Start(). The manager is used by
// handleGetStewardLogs (S6) to serve per-steward event queries.
func (s *Server) SetStewardEventLoggingManager(m *logging.LoggingManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stewardEventLoggingManager = m
}

// SetTelemetryHandler wires the telemetry fan-out WebSocket handler and lazily
// registers GET /api/v1/telemetry/ws/{id} behind the steward:telemetry permission
// gate with cross-tenant isolation (Issue #2765). The wrapper enforces the same
// tenant-ancestry check as handleGetStewardDNA: a scoped API-key principal can only
// subscribe to stewards in its own tenant subtree; 404 is returned for out-of-scope
// stewards. Call after New() and before Start().
func (s *Server) SetTelemetryHandler(h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.telemetryHandler = h
	if h == nil {
		return
	}
	s.apiRouter.Handle(
		"/telemetry/ws/{id}",
		s.requirePermission("steward", "telemetry")(s.tenantScopedTelemetryWrapper(h)),
	).Methods("GET")
	s.logger.Info("Telemetry WebSocket endpoint registered at /api/v1/telemetry/ws/{id}")
}

// tenantScopedTelemetryWrapper wraps a WebSocket handler with cross-tenant isolation.
// It replicates the steward-scoping logic from handleGetStewardDNA so that a scoped
// API-key principal cannot subscribe to telemetry for stewards outside its tenant tree.
// The {id} path variable carries the steward ID, consistent with other steward routes.
func (s *Server) tenantScopedTelemetryWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		stewardID := vars["id"]
		if stewardID == "" {
			s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
			return
		}
		callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
		info, exists := s.controllerService.GetStewardInfo(stewardID)
		if callerTenant != "" {
			stewardTenant := ""
			if exists {
				stewardTenant = info.TenantID
			}
			sameTenant := stewardTenant == callerTenant
			ancestorTenant := strings.HasPrefix(stewardTenant, callerTenant+"/")
			if !exists || (!sameTenant && !ancestorTenant) {
				// 404 instead of 403 to avoid disclosing steward existence across tenants.
				s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
				return
			}
		} else if !exists {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SetModuleResolution wires the controller-side module resolution dependencies
// used by handleUpdateStewardConfig to enforce required_modules: on cfg push
// (Issue #1884). When all four are non-nil, a cfg upload that declares
// required_modules is blocked with HTTP 422 until every listed module is cached
// and approved. When any dependency is nil the cfg upload proceeds without
// module resolution — required_modules: is parsed and stored but not enforced.
// This nil-tolerant wiring keeps existing deployments and tests that do not yet
// run the module subsystem unaffected.
func (s *Server) SetModuleResolution(
	cache resolution.CacheLister,
	resolver resolution.BundleResolver,
	approver resolution.BundleApprover,
	store trust.TrustStore,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.moduleCacheLister = cache
	s.moduleBundleResolver = resolver
	s.moduleBundleApprover = approver
	s.moduleTrustStore = store
}

// SetModuleBundleReviewer wires the human-decision interface for module bundle approval.
// When nil (default), POST .../approve and POST .../reject return 503.
// Call after New() but before Start().
func (s *Server) SetModuleBundleReviewer(r resolution.BundleReviewer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.moduleBundleReviewer = r
}

// getHTTPListenAddr determines the HTTP listen address with the
// precedence established by Story #1919:
//
//	CLI flag --listen-api-addr (already applied to cfg.ListenAddr by
//	cmd/controller/main.go's applyListenOverrides) >
//	env var CFGMS_HTTP_LISTEN_ADDR >
//	cfg file listen_addr >
//	built-in default 0.0.0.0:9080.
//
// The CLI flag and env var are both applied to cfg.ListenAddr before
// the server starts (the env var by config.LoadWithPath, the CLI flag
// by main's applyListenOverrides), so reading cfg.ListenAddr here
// honours both. The env-var-direct fast path is retained for callers
// that bypass cfg (none in the regular startup flow, but defensive).
func (s *Server) getHTTPListenAddr() string {
	// If environment variable is set explicitly and cfg didn't reflect it,
	// honour it. This is a safety net — config.LoadWithPath already pulls
	// CFGMS_HTTP_LISTEN_ADDR into cfg.ListenAddr, so this branch only
	// fires for non-config-managed callers (none today).
	if addr := os.Getenv("CFGMS_HTTP_LISTEN_ADDR"); addr != "" {
		return addr
	}

	// cfg.ListenAddr carries the resolved CLI flag / env var / cfg-file
	// value from controller startup. This is what makes the blue/green
	// substrate work: a green controller spawned with --listen-api-addr
	// :9081 actually binds on :9081 instead of the default :9080.
	if s.cfg != nil && s.cfg.ListenAddr != "" {
		return s.cfg.ListenAddr
	}

	// Default to port 9080 for HTTP API (gRPC typically on 8080)
	// Bind to 0.0.0.0 for Docker compatibility
	return "0.0.0.0:9080"
}

// shouldUseTLS determines if TLS should be enabled for the HTTP server
func (s *Server) shouldUseTLS() bool {
	return s.certManager != nil || s.hasLegacyCertificates()
}

// hasLegacyCertificates checks if legacy certificate files exist
func (s *Server) hasLegacyCertificates() bool {
	certFile := filepath.Join(s.cfg.CertPath, "server.crt")
	keyFile := filepath.Join(s.cfg.CertPath, "server.key")

	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)

	return certErr == nil && keyErr == nil
}

// setupTLS configures TLS for the HTTP server
func (s *Server) setupTLS() (*tls.Config, error) {
	// If certificate management is enabled, use managed certificates
	if s.certManager != nil {
		return s.setupManagedTLS()
	}

	// Fall back to legacy certificates
	return s.setupLegacyTLS()
}

// setupManagedTLS configures TLS using managed certificates.
func (s *Server) setupManagedTLS() (*tls.Config, error) {
	// External source: load API cert from disk (e.g., certbot/Let's Encrypt)
	if s.cfg.Certificate != nil && s.cfg.Certificate.GetPublicAPISource() == "external" {
		return s.setupExternalPublicAPICert()
	}

	// Internal source: use or generate a purpose-scoped PublicAPI certificate
	serverCert, err := s.getServerCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get server certificate: %w", err)
	}

	// Populate ClientCAs with the controller CA so that presented admin certs
	// are chain-verified at the TLS handshake layer (Story #1415).
	controllerCACertPEM, err := s.certManager.GetCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get controller CA certificate: %w", err)
	}

	tlsConfig, err := cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, controllerCACertPEM, tls.VersionTLS12)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	// Use VerifyClientCertIfGiven (not RequireAndVerifyClientCert): when a client
	// presents a cert the TLS stack verifies it against ClientCAs; clients without
	// a cert fall through to API-key auth in the application layer. This implements
	// mTLS admin auth alongside the existing API-key path (H2).
	tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven

	// Cluster mode (HA): merge the HA peer CA into ClientCAs so that both admin
	// certs (controller CA) and HA peer certs (HA CA) pass TLS chain verification.
	inClusterMode := s.haManager != nil && s.haManager.GetDeploymentMode() == ha.ClusterMode
	if inClusterMode {
		if haCACertPEM := s.haManager.GetCACertPEM(); len(haCACertPEM) > 0 {
			tlsConfig.ClientCAs.AppendCertsFromPEM(haCACertPEM)
		}
	}

	return tlsConfig, nil
}

// setupExternalPublicAPICert loads TLS certificates from external files (e.g., certbot/Let's Encrypt)
func (s *Server) setupExternalPublicAPICert() (*tls.Config, error) {
	if s.cfg.Certificate.PublicAPI == nil {
		return nil, fmt.Errorf("public API certificate configuration required for external source")
	}

	certPath := s.cfg.Certificate.PublicAPI.CertPath
	keyPath := s.cfg.Certificate.PublicAPI.KeyPath
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("cert_path and key_path required for external public API certificate")
	}

	// #nosec G304 - Certificate paths are controlled via configuration
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read external public API certificate: %w", err)
	}

	// #nosec G304 - Certificate paths are controlled via configuration
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read external public API key: %w", err)
	}

	tlsConfig, err := cert.CreateServerTLSConfig(certPEM, keyPEM, nil, tls.VersionTLS12)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config from external certificates: %w", err)
	}

	s.logger.Info("HTTP API using external public API certificate",
		"cert_path", certPath)

	return tlsConfig, nil
}

// setupLegacyTLS configures TLS using legacy certificate files
func (s *Server) setupLegacyTLS() (*tls.Config, error) {
	certFile := filepath.Join(s.cfg.CertPath, "server.crt")
	keyFile := filepath.Join(s.cfg.CertPath, "server.key")

	// Load certificate PEM data from files
	// #nosec G304 - Certificate paths are controlled via configuration
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	// #nosec G304 - Certificate paths are controlled via configuration
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Create TLS config using pkg/cert helper (no client auth for legacy mode)
	tlsConfig, err := cert.CreateBasicTLSConfig(certPEM, keyPEM, tls.VersionTLS12)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	return tlsConfig, nil
}

// getServerCertificate returns the current public API certificate (PurposeAPI).
// Falls back to generating a new PublicAPI cert if none exists and cert management is enabled.
func (s *Server) getServerCertificate() (*cert.Certificate, error) {
	apiCert, err := s.certManager.GetCurrentCertForPurpose(cert.PurposeAPI)
	if err == nil {
		s.logger.Info("Using existing API certificate for HTTP server",
			"serial", apiCert.SerialNumber,
			"expires", apiCert.ExpiresAt.Format("2006-01-02"))
		return apiCert, nil
	}

	// No valid cert found — generate if cert management is enabled
	if !s.cfg.Certificate.EnableCertManagement {
		return nil, fmt.Errorf("no valid API certificate found and certificate lifecycle management is disabled")
	}

	s.logger.Info("Generating new API certificate for HTTP server",
		"common_name", s.cfg.Certificate.Server.CommonName)

	serverConfig := &cert.ServerCertConfig{
		CommonName:   s.cfg.Certificate.Server.CommonName,
		DNSNames:     s.cfg.Certificate.Server.DNSNames,
		IPAddresses:  s.cfg.Certificate.Server.IPAddresses,
		Organization: s.cfg.Certificate.Server.Organization,
		ValidityDays: s.cfg.Certificate.ServerCertValidityDays,
	}

	serverCert, err := s.certManager.GenerateServerCertificate(serverConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate API certificate: %w", err)
	}

	s.logger.Info("Generated new API certificate for HTTP server",
		"serial", serverCert.SerialNumber,
		"expires", serverCert.ExpiresAt.Format("2006-01-02"))

	return serverCert, nil
}

// GetListenAddr returns the HTTP server's listen address
func (s *Server) GetListenAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.httpServer != nil {
		return s.httpServer.Addr
	}
	return s.getHTTPListenAddr()
}

// startAPIKeyCleanup starts a background goroutine to clean up expired API keys.
// The goroutine exits when Close is called.
func (s *Server) startAPIKeyCleanup() {
	go func() {
		defer close(s.cleanupDone)
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		s.logger.Info("Started API key cleanup background process", "interval", "10 minutes")

		for {
			select {
			case <-s.stopCleanup:
				return
			case <-ticker.C:
				s.cleanupExpiredAPIKeys()
			}
		}
	}()
}

// cleanupExpiredAPIKeys removes expired API keys from memory to prevent memory leaks
func (s *Server) cleanupExpiredAPIKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	expiredKeys := make([]string, 0)
	cleanedCount := 0

	// Find expired keys
	for keyString, apiKey := range s.apiKeys {
		if apiKey.ExpiresAt != nil && now.After(*apiKey.ExpiresAt) {
			expiredKeys = append(expiredKeys, keyString)
		}
	}

	// Remove expired keys
	for _, keyString := range expiredKeys {
		apiKey := s.apiKeys[keyString]
		delete(s.apiKeys, keyString)
		cleanedCount++

		s.logger.Debug("Cleaned up expired API key",
			"id", apiKey.ID,
			"name", apiKey.Name,
			"tenant_id", apiKey.TenantID,
			"expired_at", apiKey.ExpiresAt.Format(time.RFC3339),
			"expired_ago", now.Sub(*apiKey.ExpiresAt).String())
	}

	if cleanedCount > 0 {
		s.logger.Info("API key cleanup completed",
			"cleaned_count", cleanedCount,
			"remaining_keys", len(s.apiKeys),
			"next_cleanup", now.Add(10*time.Minute).Format(time.RFC3339))
	} else {
		s.logger.Debug("API key cleanup completed - no expired keys found",
			"remaining_keys", len(s.apiKeys))
	}
}

// configureCORS sets up CORS allowed origins configuration
// H-AUTH-3: Replace wildcard CORS with configurable allowed origins list
func (s *Server) configureCORS() {
	// Default allowed origins for development and production
	defaultOrigins := []string{
		"http://localhost:3000", // Development frontend
		"http://localhost:3001", // Alternative dev frontend
		"http://localhost:9080", // API itself (for testing)
	}

	// Load from environment variable if specified
	// Format: CFGMS_ALLOWED_ORIGINS="https://portal.example.com,https://app.example.com"
	if envOrigins := os.Getenv("CFGMS_ALLOWED_ORIGINS"); envOrigins != "" {
		s.corsConfig = &CORSConfig{
			AllowedOrigins: strings.Split(envOrigins, ","),
		}
		s.logger.Info("CORS configured from environment",
			"allowed_origins", s.corsConfig.AllowedOrigins)
	} else {
		s.corsConfig = &CORSConfig{
			AllowedOrigins: defaultOrigins,
		}
		s.logger.Info("CORS configured with default origins",
			"allowed_origins", defaultOrigins)
	}
}

// NewSecretStore initializes and returns the central secrets provider for the controller.
// It is exported so that cmd/controller/main.go can initialize the store before logging
// is configured, while server.New continues to call it internally unchanged.
func NewSecretStore(cfg *config.Config) (secretsif.SecretStore, error) {
	logger := logging.ForComponent("controller")
	// Determine secrets storage path
	secretsPath := os.Getenv("CFGMS_SECRETS_REPO_PATH")
	if secretsPath == "" {
		// Use temporary directory for testing/development
		tmpDir := os.TempDir()
		secretsPath = filepath.Join(tmpDir, "cfgms-secrets-test")
		logger.Debug("Using temporary secrets storage for testing", "path", secretsPath)
	}

	// Create secrets provider configuration
	// M-AUTH-1: Use global storage provider for secrets (flatfile or database)
	secretsConfig := map[string]interface{}{
		"storage_provider": cfg.Storage.Provider, // Use controller's global storage provider
		"cache_enabled":    true,
		"cache_ttl":        300,  // 5 minutes
		"cache_max_size":   1000, // Cache up to 1000 secrets
	}

	// Pass storage config based on provider type
	if cfg.Storage.Provider == "database" {
		// For database provider, use the full database configuration
		secretsConfig["storage_config"] = cfg.Storage.Config
	} else {
		// For flatfile provider, set the root directory
		secretsConfig["storage_config"] = map[string]interface{}{
			"root": secretsPath,
		}
	}

	// Optional: KMS key ID for SOPS encryption
	if kmsKeyID := os.Getenv("CFGMS_SOPS_KMS_KEY"); kmsKeyID != "" {
		secretsConfig["kms_key_id"] = kmsKeyID
		logger.Info("Using KMS key for secrets encryption", "key_id", kmsKeyID)
	}

	// Create secret store using SOPS provider
	store, err := secretsif.CreateSecretStoreFromConfig("sops", secretsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret store: %w", err)
	}

	// Verify store is healthy
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.HealthCheck(ctx); err != nil {
		logger.Warn("Secret store health check failed", "error", err)
		// Don't fail on health check - store may still be usable
	}

	logger.Info("Secret store initialized",
		"provider", "sops",
		"backend", cfg.Storage.Provider,
		"secrets_path", secretsPath,
		"encryption", "SOPS (AES-256-GCM)")
	return store, nil
}

// M-AUTH-1: Load API keys from secret store into memory cache
func (s *Server) loadAPIKeysFromStore() error {
	// API keys are now stored in the central secrets provider
	// They are loaded on-demand when authentication is performed
	// This lazy-loading approach provides better performance and security

	s.logger.Info("Secret store ready - API keys will be loaded on first access")
	return nil
}

// Issue #2226, #2780: scanAPIKeysForPrivilegedAccess reports API keys that hold permissions
// requiring assurance levels above AssuranceMachine. Those permissions are unreachable via
// API key (requirePermission returns 403 without a step-up challenge); operators should
// revoke or reprovision the affected keys. The scan consumes permissionAssurance from
// assurance.go so the enforcement and the scan can never drift.
func (s *Server) scanAPIKeysForPrivilegedAccess(ctx context.Context) error {
	if s.secretStore == nil {
		return nil
	}
	secrets, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
		},
	})
	if err != nil {
		s.logger.Warn("Startup scan: failed to list API keys from secret store", "error", err)
		return err
	}
	for _, meta := range secrets {
		var overlapping []string
		for _, p := range parsePermissions(meta.Metadata["permissions"]) {
			if req, found := permissionAssurance[p]; found && req.Min > session.AssuranceMachine {
				overlapping = append(overlapping, p)
			}
		}
		if len(overlapping) > 0 {
			s.logger.Warn(
				"API key holds permissions requiring elevated assurance; "+
					"unreachable via API key — consider revoking this key",
				"key_id", logging.SanitizeLogValue(meta.Metadata["id"]),
				"tenant_id", logging.SanitizeLogValue(meta.TenantID),
				"overlapping_permissions", logging.SanitizeLogValue(strings.Join(overlapping, ",")),
			)
		}
	}
	return nil
}

// newNonceCache creates the short-lived nonce cache for registration-refresh (Issue #2096).
// Entries have a 65-second TTL; the 60-second enforcement window is applied in the handler.
func newNonceCache() *cache.Cache {
	return cache.NewCache(cache.CacheConfig{
		MaxRuntimeItems: 10000,
		DefaultTTL:      nonceTTL,
		CleanupInterval: 30 * time.Second,
		EvictionPolicy:  cache.EvictionLRU,
	})
}
