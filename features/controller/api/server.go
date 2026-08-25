// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
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
	reportinterfaces "github.com/cfgis/cfgms/features/reports/interfaces"
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
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// Server represents the REST API server component of the controller
type Server struct {
	mu                             sync.RWMutex
	cfg                            *config.Config
	logger                         logging.Logger
	httpServer                     *http.Server
	metricsHTTPServer              *http.Server
	internalHTTPServer             *http.Server
	router                         *mux.Router
	metricsRouter                  *mux.Router
	internalRouter                 *mux.Router
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
	registrationTokenStore         registration.Store                    // Registration token store for steward registration
	corsConfig                     *CORSConfig                           // CORS configuration
	signerCertSerial               string                                // Story #378: Serial of cert used for config signing
	authDefense                    *authdefense.AuthDefenseSystem        // Story #380: Three-tier auth defense
	publicDownloadGuard            *publicDownloadGuard                  // PB-015: successful anonymous-download rate/concurrency budgets
	publicDownloadCache            *publicDownloadCache                  // PB-015: bounded/coalesced installer and steward-binary response cache
	rollbackManager                rollback.RollbackManager              // Story #416: Rollback system
	reportsHandler                 *reportapi.Handler                    // Story #416: Reports engine
	dataProvider                   reportinterfaces.DataProvider         // Issue #3265: drift-based compliance derivation
	workflowHandler                *WorkflowHandler                      // Story #414: Workflow engine REST API
	approvalHook                   RegistrationApprovalHook              // Issue #422: Registration approval hook
	fleetQuery                     fleet.FleetQuery                      // Issue #603: node-local (controllerServiceAdapter); dispatch-safe consumers only
	clusterFleetQuery              fleet.FleetQuery                      // Issue #3495: cluster-wide (clusterServiceAdapter); individually-vetted consumers only
	gitSyncWebhookHandler          http.Handler                          // Issue #666: git-sync webhook endpoint (optional)
	auditManager                   *audit.Manager                        // Issue #775: registration audit events
	scriptTracker                  script.ExecutionTracker               // Issue #708: durable execution audit records
	scriptAuditLogger              *script.AuditLogger                   // Issue #708: in-memory execution metrics
	scriptMonitor                  *script.ExecutionMonitor              // Issue #708: active execution tracking
	scriptRepo                     script.ScriptRepository               // Issue #1670: git-backed script library
	privilegeStore                 cfgconfig.ConfigStore                 // Issue #1670: controller-side script privilege metadata
	pushLeaderStatus               leaderStatus                          // Issue #1318: leader check for config push (nil = leader)
	registrationLeaderStatus       registrationLeaderStatus              // Issue #3471: leader check for registration/token endpoints (nil = always leader)
	commandPublisher               *commands.Publisher                   // Issue #1319: fan-out config push to active stewards
	pushStore                      business.PushStore                    // Issue #1320: durable push-state persistence for HA failover
	registry                       registry.Registry                     // Issue #1323: active steward connection registry
	mountPointValidator            MountPointValidator                   // Issue #1396: config source connection test
	configSourceSecretStore        secretsif.SecretStore                 // Issue #1396: secrets for config source validator
	configSourceRateLimits         sync.Map                              // Issue #1396: per-tenant rate-limit counters
	pendingStore                   business.PendingRegistrationStore     // Issue #1696: durable pending-registration queue
	ipTrustStore                   business.IPTrustStore                 // Issue #1698: operator IP-trust management
	alertStore                     business.AlertStore                   // Issue #3266: alert acknowledge and silence
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
	webAuthnElevateSessions        sync.Map                              // Issue #2965: pending step-up elevation sessions; key=sessionID, value=*webAuthnElevateSession
	webAuthnElevateThrottle        sync.Map                              // Issue #2965: per-session/per-IP failed elevation throttle; key="session:<id>"|"ip:<ip>", value=*elevateThrottleRecord
	passkeyLoginSessions           sync.Map                              // Issue #2993: pending passkey login ceremonies; key=ceremonyID, value=*passkeyLoginSession
	passkeyLoginThrottle           sync.Map                              // Issue #2993: per-account/per-IP failed login throttle; key="account:<username>"|"ip:<ip>", value=*elevateThrottleRecord
	passkeyEnrollSessions          sync.Map                              // Issue #2966: first-passkey enrollment ceremonies; key=tokenHash, value=*webAuthnPendingSession
	credentialMu                   sync.Mutex                            // Issue #2992: guards the credential CAS section in handleWebAuthnRevokeCredential
	telemetryHandler               http.Handler                          // Issue #2765: telemetry fan-out WebSocket handler
	egConfigstoreWriter            egConfigstoreIngestor                 // Issue #2879: desired-state entity-graph internal writer (nil = disabled)
	egProvider                     egReadProvider                        // Issue #2880: entity graph read API
	egWriter                       egWriteProvider                       // Issue #3374: operator edge assertion write path
	terminalHandler                http.Handler                          // Issue #2761: terminal WebSocket relay handler
	tenantStore                    business.TenantStore                  // Issue #2839: tenant hierarchy for per-tenant assurance resolution
	assurancePolicyStore           business.AssurancePolicyStore         // Issue #2839: per-tenant assurance-policy overrides
	tenantCrossingStore            business.TenantCrossingStore          // ADR-025 Decision 2: tenant-crossing grants and break-glass
	absentCapabilities             []interfaces.AbsentCapability         // Issue #3409: declared-optional capabilities absent in this deployment

	// Listeners retained so Close can shut them regardless of whether their serve
	// goroutine has reached Serve yet: http.Server.Shutdown closes only listeners
	// it already tracks, and tracking begins inside Serve. A Start followed
	// promptly by a Close would otherwise leak a bound socket — fatal for the
	// metrics listener, which binds a fixed port and cannot silently rebind.
	publicTLSListener   net.Listener
	metricsTLSListener  net.Listener
	internalTLSListener net.Listener
}

// SetDraining implements cluster.DrainHealthRegistrar. When draining is true,
// GET /api/v1/health returns HTTP 503 so the load balancer stops routing new
// steward connections to this node. Called by cluster.Drain() after setting the
// membership state; safe to call concurrently with handleHealth.
func (s *Server) SetDraining(draining bool) {
	s.clusterDraining.Store(draining)
}

// SetAbsentCapabilities stores the declared-optional capabilities that are absent
// in this deployment. Call once at composition time; the value is served verbatim
// by GET /api/v1/ha/status (Issue #3409). Thread-safe.
func (s *Server) SetAbsentCapabilities(caps []interfaces.AbsentCapability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.absentCapabilities = caps
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
		publicDownloadGuard:     newPublicDownloadGuard(defaultPublicDownloadGuardConfig()),
		publicDownloadCache:     newPublicDownloadCache(),
		popVerifier:             ed25519PoPVerifier{},    // Issue #2096: default PoP verifier; override in tests
		sessionCfg:              session.DefaultConfig(), // Issue #2232: ADR-014 session lifecycle tunables
		stopCleanup:             make(chan struct{}),
		cleanupDone:             make(chan struct{}),
	}

	// Issue #1318: wire leader-check for config push; nil haManager = OSS single-node = always leader
	if haManager != nil {
		server.pushLeaderStatus = haManager
	}

	// Issue #3471: wire lease-backed leader-check for registration and token endpoints;
	// nil haManager = OSS single-node = always authoritative (Decision 4, ADR-029).
	if haManager != nil {
		server.registrationLeaderStatus = haManager
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
					Key: keyVal,
					// The ha:read-* grants let test/integration/ha observe the
					// cluster it just started. Every HA route is permission-gated
					// (routes_ha.go), so without them the suite's polling helpers
					// read 403 bodies as "no leader" and "empty node ID" and fail
					// with assertion messages that never mention authorization.
					//
					// steward:read-dna and config:push cover the other endpoints
					// that suite calls: GET /stewards/{id}/dna for the config hash
					// and POST /config/push for configuration continuity.
					Permissions: []string{
						"steward:read", "steward:read-dna", "steward:auth-refresh",
						"config:push",
						"workflow:execute", "workflow:read",
						"ha:read-status", "ha:read-cluster", "ha:read-leader", "ha:read-nodes",
					},
					// Steward lookups are tenant-scoped. These keys exist to observe
					// the stewards started by the HA compose profile, which register
					// with the seeded "integration_reusable" token and therefore land
					// in test-tenant-integration (features/controller/server.Server,
					// CFGMS_SEED_TEST_TOKENS block). Scoping the keys to "default"
					// put them in a tenant containing no stewards at all, so
					// GET /api/v1/stewards/{id} answered STEWARD_NOT_FOUND for a
					// steward that had registered successfully seconds earlier.
					TenantID: "test-tenant-integration",
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

	// Issue #603: node-local fleet query for dispatch-safe consumers.
	server.fleetQuery = fleet.NewMemoryQuery(&controllerServiceAdapter{svc: controllerService})
	// Issue #3495: cluster-wide fleet query for individually-vetted consumers only.
	// New callers must independently verify delivery-path safety before using this field.
	server.clusterFleetQuery = fleet.NewMemoryQuery(&clusterServiceAdapter{svc: controllerService})

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
			// #nosec G118 -- save-deploy fan-out is an explicitly asynchronous,
			// tenant-bounded callback and publisher operations enforce deadlines.
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
// Population source is deliberately node-local (GetAllStewards, dispatch-safe). Field
// composition — tags merged, DNAFragments populated — must match serverFleetStewardProvider
// for any steward both adapters can see; use buildStewardFleetData to keep them in sync.
// (Issue #603, #3495)
type controllerServiceAdapter struct {
	svc *service.ControllerService
}

func (a *controllerServiceAdapter) GetAllStewards() []fleet.StewardData {
	infos := a.svc.GetAllStewards()
	tagStore := a.svc.TagStore()
	result := make([]fleet.StewardData, 0, len(infos))
	for _, info := range infos {
		var ctrlTags []string
		if tagStore != nil {
			ctrlTags = tagStore.TagsFor(info.ID)
		}
		result = append(result, buildStewardFleetData(info, ctrlTags))
	}
	return result
}

// clusterServiceAdapter adapts *service.ControllerService to fleet.StewardProvider using the
// cluster-aware GetAllStewardsCluster method. Its population source is cluster-wide — NOT
// node-local like controllerServiceAdapter — so every new caller must be independently vetted
// for delivery-path safety before being pointed at it or at s.clusterFleetQuery. Do not assume
// it is safe by default. (Issue #3495)
type clusterServiceAdapter struct {
	svc *service.ControllerService
}

func (a *clusterServiceAdapter) GetAllStewards() []fleet.StewardData {
	// context.Background: tenant scoping is applied downstream by MemoryQuery.Search via
	// Filter.TenantSubtree/TenantID, not at the provider level.
	infos := a.svc.GetAllStewardsCluster(context.Background())
	result := make([]fleet.StewardData, 0, len(infos))
	for _, info := range infos {
		// GetAllStewardsCluster already copies Tags from the tag store on each refresh.
		result = append(result, buildStewardFleetData(info, info.Tags))
	}
	return result
}

// buildStewardFleetData converts *service.StewardInfo to fleet.StewardData with both
// DNAAttributes (flattened from fragments + ctrlTags merged) and DNAFragments populated.
// controllerServiceAdapter passes tagStore.TagsFor(info.ID) as ctrlTags; clusterServiceAdapter
// passes info.Tags (already populated by GetAllStewardsCluster). Using this helper for both
// adapters ensures their field composition stays identical for any steward both can see.
// (Issue #3495)
func buildStewardFleetData(info *service.StewardInfo, ctrlTags []string) fleet.StewardData {
	var attrs map[string]string
	var frags []*commonpb.Fragment
	if info.DNA != nil {
		attrs = service.FlattenDNAFragments(info.DNA.Fragments)
		frags = info.DNA.Fragments
	}
	if len(ctrlTags) > 0 {
		attrs = mergeControllerTags(attrs, ctrlTags)
	}
	return fleet.StewardData{
		ID:            info.ID,
		TenantID:      info.TenantID,
		Status:        info.Status,
		LastHeartbeat: info.LastHeartbeat,
		DNAAttributes: attrs,
		DNAFragments:  frags,
		Hidden:        info.Hidden,
	}
}

// mergeControllerTags returns a copy of attrs with controller-stored ctrlTags merged into the
// "tags" key. If attrs already carries a DNA-reported "tags" value, the two sets are unioned
// (DNA tags first, duplicates dropped). Returns attrs unchanged when ctrlTags is empty.
// Never mutates the input map.
func mergeControllerTags(attrs map[string]string, ctrlTags []string) map[string]string {
	if len(ctrlTags) == 0 {
		return attrs
	}
	merged := make(map[string]string, len(attrs)+1)
	for k, v := range attrs {
		merged[k] = v
	}
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

// setupRouter initializes the HTTP router with all routes and middleware
func (s *Server) setupRouter() {
	s.router = mux.NewRouter()
	s.metricsRouter = mux.NewRouter()
	s.internalRouter = mux.NewRouter()

	// Add middleware
	s.router.Use(s.securityHeadersMiddleware)
	s.router.Use(s.authDefense.Middleware) // Per-source budget covers public and authenticated surfaces.
	s.router.Use(s.requestBodyLimitMiddleware)
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.corsMiddleware)
	s.router.Use(s.contentTypeMiddleware)

	// The private metrics listener retains the same source budgets, browser
	// hardening, authentication, and request validation as the public API.
	// It intentionally has no SPA fallback or non-metrics product routes.
	s.metricsRouter.Use(s.securityHeadersMiddleware)
	s.metricsRouter.Use(s.authDefense.Middleware)
	s.metricsRouter.Use(s.requestBodyLimitMiddleware)
	s.metricsRouter.Use(s.loggingMiddleware)
	s.metricsRouter.Use(s.contentTypeMiddleware)
	registerPrivateMetricsRoutes(s, s.metricsRouter)

	// API routes with authentication and validation
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.authenticationMiddleware) // extract principal (API key or mTLS)
	// requireTier(TierAny) removed: it was a no-op passthrough (Issue #2780 migrates to assurance-based enforcement).
	api.Use(s.validationMiddleware)
	api.Use(s.csrfMiddleware) // Issue #2493: session-bound CSRF for unsafe cookie-auth methods
	// Issue #2966: enrollment confinement — a cookie-authenticated session with zero enrolled
	// passkeys is refused all api routes; first-passkey enrollment is on the base router.
	api.Use(s.enrollmentConfinementMiddleware)
	s.apiRouter = api // saved so Set* methods can lazy-register routes after construction

	// --- Tier 0 (TierPublic) — no authentication required ---
	//   GET  /api/v1/health
	//   GET  /api/v1/ready
	//   POST /api/v1/register
	//   GET  /api/v1/registration/status/{pending_id}
	//   POST /api/v1/stewards/{device_id}/refresh/challenge   (PoP-auth in handler)
	//   POST /api/v1/stewards/{device_id}/refresh/complete    (PoP-auth in handler)
	//   GET  /api/v1/installer/download/{platform}/{arch}
	//   GET  /api/v1/public/steward-binaries/{version}/{platform}/{arch}

	// Health check (no auth required) — liveness / object-presence.
	s.router.HandleFunc("/api/v1/health", s.handleHealth).Methods("GET", "OPTIONS")

	// Readiness probe (no auth required) — real-state: round-trips durable
	// storage. Used by the blue/green cutover smoketest (Issue #2012).
	s.router.HandleFunc("/api/v1/ready", s.handleReady).Methods("GET", "OPTIONS")

	// Steward registration (no auth required - uses registration token)
	s.router.HandleFunc("/api/v1/register", s.handleRegister).Methods("POST", "OPTIONS")

	// Registration status poll (no API-key auth — authenticated by regtoken Bearer header)
	s.router.HandleFunc("/api/v1/registration/status/{pending_id}", s.handleRegistrationStatus).Methods("GET")

	// Integration-test administration routes are registered only in binaries
	// compiled with -tags=cfgms_test_endpoints. The production implementation
	// of registerTestRoutes is a no-op, so an environment variable can never
	// expose these handlers in a release binary.
	registerTestRoutes(s)

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

	// Bulk registration approval and IP-trust management (Issue #1698, #2969)
	api.Handle("/registration/approve-all", s.requirePermission("registration", "approve")(http.HandlerFunc(s.handleApproveAllRegistrations))).Methods("POST")
	// Preview (dry-run) must be registered before the mutation POST to avoid path ambiguity.
	api.Handle("/registration/approve-by-cidr/preview", s.requirePermission("registration", "list-pending")(http.HandlerFunc(s.handleApproveByCIDRPreview))).Methods("GET")
	api.Handle("/registration/approve-by-cidr", s.requirePermission("registration", "approve-by-cidr")(http.HandlerFunc(s.handleApproveByCIDR))).Methods("POST")
	api.Handle("/registration/ip-trust", s.requirePermission("registration", "list-ip-trust")(http.HandlerFunc(s.handleListIPTrust))).Methods("GET")
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

	// Web CSRF / logout / passkey-login endpoints (Issue #2493, #2993, ADR-018 §3,4).
	// Registered on the BASE router (TierPublic pattern) and explicitly wrapped in
	// authDefense.Middleware. The api subrouter chain at line ~414 does NOT cover
	// base-router routes (security A5.4), so wrapping is mandatory here.
	s.router.Handle("/api/v1/web/csrf",
		s.authDefense.Middleware(http.HandlerFunc(s.handleGetWebCSRF))).Methods("GET")
	s.router.Handle("/api/v1/web/logout",
		s.authDefense.Middleware(http.HandlerFunc(s.handleWebLogout))).Methods("POST")
	s.router.Handle("/api/v1/web/passkey/login/begin",
		s.authDefense.Middleware(http.HandlerFunc(s.handlePasskeyLoginBegin))).Methods("POST")
	s.router.Handle("/api/v1/web/passkey/login/finish",
		s.authDefense.Middleware(http.HandlerFunc(s.handlePasskeyLoginFinish))).Methods("POST")

	// First-passkey enrollment routes (Issue #2966: ADR-021 Amendment 1).
	// Registered on the BASE router (public pattern): the enrollment token is the bearer
	// credential; no web session is required. Self-scoped to the account the token identifies —
	// never to a caller-supplied {username}. Token is passed via X-Enrollment-Token header.
	s.router.Handle("/api/v1/web/passkey/enroll/begin",
		s.authDefense.Middleware(http.HandlerFunc(s.handlePasskeyEnrollBegin))).Methods("POST")
	s.router.Handle("/api/v1/web/passkey/enroll/finish",
		s.authDefense.Middleware(http.HandlerFunc(s.handlePasskeyEnrollFinish))).Methods("POST")

	// Installer package download — public, no auth required (Issue #1704).
	// Assembles a per-platform tar.gz on the fly. The download URL is the distribution mechanism.
	s.router.Handle(
		"/api/v1/installer/download/{platform}/{arch}",
		s.publicDownloadGuard.middleware(s.trustedProxies, http.HandlerFunc(s.handleDownloadInstallPackage)),
	).Methods("GET")

	// Steward binary public download — no auth required (Issue #1948).
	// The binary's Ed25519 signature authenticates content at the steward side.
	// Steward mTLS certs lack the admin marker required by the authenticated GET endpoint.
	s.router.Handle(
		"/api/v1/public/steward-binaries/{version}/{platform}/{arch}",
		s.publicDownloadGuard.middleware(s.trustedProxies, http.HandlerFunc(s.handleGetStewardBinaryPublic)),
	).Methods("GET")

	// Git-sync webhook (Issue #666, #3263): pre-registered here so gorilla/mux can
	// match it before the SPA PathPrefix("/") catch-all below (routes are matched in
	// registration order).  The handler is resolved lazily at request time so it can
	// be wired via SetGitSyncWebhookHandler after New() returns.  Returns 503 until
	// the handler is wired; delegates via h.ServeHTTP once it is.
	s.router.HandleFunc("/api/v1/webhooks/git-push", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		h := s.gitSyncWebhookHandler
		s.mu.RUnlock()
		if h == nil {
			http.Error(w, "git-sync webhook service not available", http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	}).Methods("POST")

	// Raft messages are deliberately absent from the public product router.
	// Cluster mode serves this handler on the separately configured private
	// mTLS-only listener created by Start.
	s.internalRouter.Use(s.requestBodyLimitMiddleware)
	s.internalRouter.Use(s.loggingMiddleware)
	s.internalRouter.Use(s.contentTypeMiddleware)
	s.internalRouter.HandleFunc("/raft/message", s.handleRaftMessage).Methods("POST")
	// Raft status endpoint: requires HA read-status permission via API authentication
	api.Handle("/raft/status", s.requirePermission("ha", "read-status")(http.HandlerFunc(s.handleRaftStatus))).Methods("GET")

	// Terminal WebSocket relay is registered by routes_terminal.go (Issue #2761).
	// The handler is wired via SetTerminalHandler after server construction.

	// SPA catch-all: lowest-precedence handler for the embedded web UI (Issue #2494).
	// All /api/* and /raft/* routes registered above take precedence via gorilla/mux
	// ordering; unmatched paths in those namespaces are refused by spaHandler itself.
	// A binary built without a frontend build embeds only the tracked
	// web/dist/index.html placeholder. Serving that would look like a working
	// (but permanently stale) SPA, so "/" is left unrouted and the reason is
	// logged loudly instead (Issue #3043).
	spa, spaErr := newEmbeddedSPAHandler(spaAssets)
	if spaErr != nil {
		s.logger.Error("Embedded SPA assets unavailable; refusing to route \"/\" (web UI will be unavailable)",
			"error", logging.SanitizeLogValue(spaErr.Error()))
	} else {
		s.router.PathPrefix("/").Handler(spa)
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Determine listen address for HTTP server (different from gRPC)
	httpAddr := s.getHTTPListenAddr()
	metricsAddr := s.cfg.MetricsListenAddr
	if err := config.ValidatePrivateListenerAddress(metricsAddr); err != nil {
		return fmt.Errorf("invalid private metrics listener: %w", err)
	}

	// Public API TLS is mandatory. Certificate discovery and validation happen
	// synchronously before a listener goroutine is started, so unreadable,
	// malformed, expired, or identity-mismatched material cannot silently
	// downgrade the controller to plaintext HTTP.
	tlsConfig, err := s.setupTLS()
	if err != nil {
		return fmt.Errorf("refusing to start public API without valid TLS: %w", err)
	}
	if err := s.validatePublicAPITLSConfig(tlsConfig); err != nil {
		return fmt.Errorf("refusing to start public API without valid TLS: %w", err)
	}

	var internalAddr string
	var internalTLSConfig *tls.Config
	if s.cfg.HA.IsClusterMode() {
		internalAddr = s.cfg.InternalListenAddr
		if err := validatePrivateListenAddr(internalAddr); err != nil {
			return fmt.Errorf("invalid internal Raft listener: %w", err)
		}
		internalTLSConfig, err = s.internalRaftTLSConfig(tlsConfig)
		if err != nil {
			return fmt.Errorf("refusing to start internal Raft listener without mTLS: %w", err)
		}
	}

	// Bind synchronously so Start cannot report success while a listener is
	// unavailable. The TLS wrappers use the already preflighted configurations.
	publicListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("bind public API listener: %w", err)
	}
	metricsListener, err := net.Listen("tcp", metricsAddr)
	if err != nil {
		_ = publicListener.Close()
		return fmt.Errorf("bind private metrics listener: %w", err)
	}
	var internalListener net.Listener
	if internalTLSConfig != nil {
		internalListener, err = net.Listen("tcp", internalAddr)
		if err != nil {
			_ = publicListener.Close()
			_ = metricsListener.Close()
			return fmt.Errorf("bind private Raft listener: %w", err)
		}
	}

	// Create HTTPS server only after TLS preflight and listener binding succeed.
	s.httpServer = &http.Server{
		Addr:              publicListener.Addr().String(),
		Handler:           s.router,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         tlsConfig,
	}
	metricsTLSConfig := tlsConfig.Clone()
	metricsTLSConfig.MinVersion = tls.VersionTLS13
	s.metricsHTTPServer = &http.Server{
		Addr:              metricsListener.Addr().String(),
		Handler:           s.metricsRouter,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         metricsTLSConfig,
	}
	if internalTLSConfig != nil {
		s.internalHTTPServer = &http.Server{
			Addr:              internalListener.Addr().String(),
			Handler:           s.internalRouter,
			ReadTimeout:       15 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 20,
			TLSConfig:         internalTLSConfig,
		}
	}

	// Start server in goroutine
	publicServer := s.httpServer
	publicTLSListener := tls.NewListener(publicListener, tlsConfig)
	metricsServer := s.metricsHTTPServer
	metricsTLSListener := tls.NewListener(metricsListener, metricsTLSConfig)
	s.publicTLSListener = publicTLSListener
	s.metricsTLSListener = metricsTLSListener
	go func() {
		s.logger.Info("Starting HTTPS REST API server", "address", publicServer.Addr)
		if serveErr := publicServer.Serve(publicTLSListener); serveErr != nil && serveErr != http.ErrServerClosed {
			s.logger.Error("HTTP server failed", "error", serveErr)
		}
	}()
	go func() {
		s.logger.Info("Starting private HTTPS metrics server", "address", metricsServer.Addr)
		if serveErr := metricsServer.Serve(metricsTLSListener); serveErr != nil && serveErr != http.ErrServerClosed {
			s.logger.Error("Private metrics server failed", "error", serveErr)
		}
	}()
	if s.internalHTTPServer != nil {
		internalServer := s.internalHTTPServer
		internalTLSListener := tls.NewListener(internalListener, internalTLSConfig)
		s.internalTLSListener = internalTLSListener
		go func() {
			s.logger.Info("Starting private mTLS Raft server", "address", internalServer.Addr)
			if serveErr := internalServer.Serve(internalTLSListener); serveErr != nil && serveErr != http.ErrServerClosed {
				s.logger.Error("Private Raft server failed", "error", serveErr)
			}
		}()
	}

	s.logger.Info("REST API server started", "address", publicServer.Addr, "private_metrics_address", metricsServer.Addr)
	return nil
}

func validatePrivateListenAddr(address string) error {
	return config.ValidatePrivateListenerAddress(address)
}

func (s *Server) internalRaftTLSConfig(publicTLS *tls.Config) (*tls.Config, error) {
	if publicTLS == nil || len(publicTLS.Certificates) == 0 {
		return nil, fmt.Errorf("server certificate is unavailable")
	}
	internalTLS := publicTLS.Clone()
	internalTLS.MinVersion = tls.VersionTLS13
	internalTLS.ClientAuth = tls.RequireAndVerifyClientCert

	var haCA []byte
	if s.haManager != nil {
		haCA = s.haManager.GetCACertPEM()
	}

	if internalTLS.ClientCAs == nil {
		// The inherited public TLS config carries no client CA pool, so the HA
		// peer CA is the only trust anchor available for the internal Raft
		// listener. pkg/cert is the single construction point for CA pools; it
		// also rejects empty or unparseable PEM, which keeps this listener from
		// starting with a pool that trusts nothing.
		pool, err := cert.NewCertPoolFromPEM(haCA)
		if err != nil {
			return nil, fmt.Errorf("no trusted client CA is configured: %w", err)
		}
		internalTLS.ClientCAs = pool
		return internalTLS, nil
	}

	if len(haCA) > 0 {
		// Adding the HA peer CA to an inherited pool must not silently no-op:
		// unparseable PEM means peers would be rejected at handshake time.
		if _, err := cert.NewCertPoolFromPEM(haCA); err != nil {
			return nil, fmt.Errorf("HA peer CA is invalid: %w", err)
		}
		internalTLS.ClientCAs.AppendCertsFromPEM(haCA)
		return internalTLS, nil
	}

	// Inherited pool with no HA CA to add: reject an empty pool rather than
	// serving mTLS that can never verify a client.
	if len(internalTLS.ClientCAs.Subjects()) == 0 { //nolint:staticcheck // SA1019: Subjects() is only deprecated for system pools; this pool is built in-process from PEM, where it is the only way to detect an empty trust store.
		return nil, fmt.Errorf("no trusted client CA is configured")
	}
	return internalTLS, nil
}

// validatePublicAPITLSConfig binds the loaded certificate to the configured
// public API identity. Go's server-side TLS stack validates the key pair during
// handshakes but does not verify that a server certificate covers the hostname
// clients are told to use.
func (s *Server) validatePublicAPITLSConfig(tlsConfig *tls.Config) error {
	if tlsConfig == nil || len(tlsConfig.Certificates) == 0 {
		return fmt.Errorf("TLS configuration has no server certificate")
	}

	leaf, err := cert.ValidateServerCertificate(tlsConfig.Certificates[0], time.Now())
	if err != nil {
		return err
	}

	if s.cfg == nil || s.cfg.ExternalURL == "" {
		return fmt.Errorf("external_url is required to verify the public API certificate identity")
	}
	publicURL, err := url.Parse(s.cfg.ExternalURL)
	if err != nil {
		return fmt.Errorf("invalid external_url: %w", err)
	}
	if !strings.EqualFold(publicURL.Scheme, "https") {
		return fmt.Errorf("external_url must use https")
	}
	hostname := publicURL.Hostname()
	if hostname == "" {
		return fmt.Errorf("external_url must include a hostname")
	}
	if err := leaf.VerifyHostname(hostname); err != nil {
		return fmt.Errorf("public API certificate does not match external_url hostname %q: %w", hostname, err)
	}
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
		if s.metricsHTTPServer != nil {
			if err := s.metricsHTTPServer.Shutdown(ctx); err != nil && firstErr == nil {
				s.logger.Error("Failed to shutdown private metrics server gracefully", "error", err)
				firstErr = err
			}
		}
		if s.internalHTTPServer != nil {
			if err := s.internalHTTPServer.Shutdown(ctx); err != nil && firstErr == nil {
				s.logger.Error("Failed to shutdown private Raft server gracefully", "error", err)
				firstErr = err
			}
		}

	})

	// Deliberately OUTSIDE closeOnce. The once above guards one-shot teardown of
	// caches, stores and goroutines, but listeners are re-created by every Start.
	// A Server that is stopped and started again therefore holds fresh listeners
	// that a once-guarded Close could never reach, leaking the socket for the life
	// of the process.
	//
	// Shutdown normally closes these already; it only closes listeners its server
	// is tracking, and tracking starts inside Serve, which runs in a goroutine
	// spawned just after bind. A Start followed promptly by a Close can outrun it.
	//
	// The public and Raft listeners take an OS-assigned port, so a leak there is
	// invisible and the next Start just binds elsewhere. The metrics listener binds
	// a FIXED port — ValidatePrivateListenerAddress rejects port 0 — so the same
	// leak makes the next Start fail with "address already in use".
	//
	// Closing an already-closed listener is a harmless no-op error.
	//
	// Guarded by s.mu because Start writes these fields under the same lock. The
	// once-body above releases s.mu via defer before returning, and on a second
	// Close it never runs at all, so acquiring here cannot deadlock.
	s.mu.Lock()
	listeners := []net.Listener{s.publicTLSListener, s.metricsTLSListener, s.internalTLSListener}
	s.publicTLSListener, s.metricsTLSListener, s.internalTLSListener = nil, nil, nil
	s.mu.Unlock()
	for _, l := range listeners {
		if l != nil {
			_ = l.Close()
		}
	}

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
// Wires requirePermission into the handler so every reports route is RBAC-gated:
// report:read for all GET endpoints, report:generate for POST /reports/generate (Issue #3282).
// Call this after New() returns but before Start() is called.
func (s *Server) SetReportsHandler(h *reportapi.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reportsHandler = h
	if h == nil {
		return
	}
	h.SetRequirePermFn(s.requirePermission)
	reportsRouter := s.apiRouter.PathPrefix("/reports").Subrouter()
	h.RegisterRoutes(reportsRouter)
	s.logger.Info("Reports API routes registered")
}

// SetDataProvider wires the reports DataProvider for drift-based compliance derivation (Issue #3265).
// Call this after New() returns but before Start() is called.
func (s *Server) SetDataProvider(dp reportinterfaces.DataProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dataProvider = dp
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
	// Use clusterFleetQuery for consistency. Both workflow nodes that would consume a
	// propagated fleet.FleetQuery are unreachable in production (see Issue #3495, Problem
	// being fixed), so this rewiring has no behavioural effect today.
	if h != nil && s.clusterFleetQuery != nil {
		h.SetFleetQuery(s.clusterFleetQuery)
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

// SetGitSyncWebhookHandler wires the git-sync push-event webhook handler.
// The route POST /api/v1/webhooks/git-push is pre-registered in setupRouter()
// and resolves this handler lazily at request time; it returns 503 until this
// method is called.  Call this after New() returns but before Start() is called
// (Issue #666, #3263).
func (s *Server) SetGitSyncWebhookHandler(h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gitSyncWebhookHandler = h
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

// IPTrustStore returns the wired IP-trust store, or nil when unwired. Exposed so
// controller startup wiring can be regression-tested: the three
// /api/v1/registration/ip-trust endpoints 503 when this is nil, which is exactly
// what shipped until story #3096 found the setter had no production caller.
func (s *Server) IPTrustStore() business.IPTrustStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ipTrustStore
}

// PendingStore returns the wired pending-registration store, or nil when
// unwired. Exposed alongside IPTrustStore so both halves of the registration
// admission path can be regression-tested from controller startup (#3096).
func (s *Server) PendingStore() business.PendingRegistrationStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pendingStore
}

// SetAlertStore wires the alert store for alert acknowledge and silence (Issue #3266).
// Call this after New() returns but before Start() is called.
func (s *Server) SetAlertStore(store business.AlertStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertStore = store
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

// SetTenantStore wires the TenantStore for tenant-hierarchy resolution (Issue #2839).
// TenantStore is a core, always-present store — wired unconditionally at startup.
func (s *Server) SetTenantStore(store business.TenantStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenantStore = store
}

// SetAssurancePolicyStore wires the per-tenant AssurancePolicyStore (Issue #2839).
// When nil (default), resolveAssuranceRequirement returns the global permissionAssurance
// floor unchanged — no behavior change for existing tests that build a bare Server.
func (s *Server) SetAssurancePolicyStore(store business.AssurancePolicyStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assurancePolicyStore = store
}

// SetAuditStore wires a direct AuditStore reference for the test-mode count endpoint
// (Issue #2098). Production code uses s.auditManager; this allows test endpoints to
// query audit entries without needing sqlite3 CLI in the controller container.
func (s *Server) SetAuditStore(store business.AuditStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditStore = store
}

// SetTenantCrossingStore wires the ADR-025 Decision 2 tenant-crossing grant/break-glass
// store. When nil (default), isCallerAuthorizedForTenant fails closed: a root-scoped
// caller is denied access to any strict descendant of "root" (no crossing mechanism
// available means no crossing can be active) — no behavior change for existing tests
// that build a bare Server.
func (s *Server) SetTenantCrossingStore(store business.TenantCrossingStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenantCrossingStore = store
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
		Channel:         "web",
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Copy the CLI config and assign the "cli" channel so the CLI manager rejects
	// tokens issued by the web manager, and vice versa (Issue #3310).
	cliCfg := s.sessionCfg
	cliCfg.Channel = "cli"
	s.sessionManager = session.NewManager(cliCfg, store, time.Now)
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

// SetTerminalHandler wires the terminal WebSocket relay handler (Issue #2761).
// The route GET /api/v1/terminal/ws/{steward_id} is already registered by
// routes_terminal.go; this call stores the handler so that the route closure can
// dispatch to it. Call after New() and before Start().
func (s *Server) SetTerminalHandler(h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminalHandler = h
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

// SetConfigStoreWriter wires the ConfigStore → desired-state entity-graph writer
// (Issue #2879). When set, handleConfigPush records desired-state observations
// for every targeted steward immediately on push acceptance.
func (s *Server) SetConfigStoreWriter(w egConfigstoreIngestor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.egConfigstoreWriter = w
}

// SetEntityGraphProvider wires the entity graph read provider into the REST
// API, enabling the /api/v1/entities/* endpoints (Issue #2880).
func (s *Server) SetEntityGraphProvider(p egReadProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.egProvider = p
}

// SetEntityGraphWriteProvider wires the entity graph write provider into the REST
// API, enabling the POST /api/v1/entities/edges endpoint (Issue #3374).
func (s *Server) SetEntityGraphWriteProvider(p egWriteProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.egWriter = p
}

// EntityGraphProvider returns the wired entity graph read provider, or nil when
// unwired. Exposed so controller startup wiring can be regression-tested (the
// entity REST endpoints 503 when this is nil — Issue #2880/#3253).
func (s *Server) EntityGraphProvider() egReadProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.egProvider
}

// ConfigStoreWriter returns the wired ConfigStore desired-state entity-graph
// writer, or nil when unwired. Exposed so controller startup wiring can be
// regression-tested (Issue #2879/#3253).
func (s *Server) ConfigStoreWriter() egConfigstoreIngestor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.egConfigstoreWriter
}

// EntityGraphWriteProvider returns the wired entity graph write provider, or
// nil when unwired. Exposed so controller startup wiring can be
// regression-tested (the POST /api/v1/entities/edges endpoint 503s when this
// is nil — Issue #3374/#3253).
func (s *Server) EntityGraphWriteProvider() egWriteProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.egWriter
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

// GetMetricsListenAddr returns the dedicated private metrics server address.
func (s *Server) GetMetricsListenAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.metricsHTTPServer != nil {
		return s.metricsHTTPServer.Addr
	}
	if s.cfg == nil {
		return ""
	}
	return s.cfg.MetricsListenAddr
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

// envAllowEphemeralSecrets is the dev/test-only override that downgrades the
// ephemeral-secret-store hard fail to a WARN. Never set in production: an
// ephemeral store loses all passkeys and web-account records on controller
// restart, locking out every human account (ADR-021 Amendment 1).
//
// Scope: this flag governs the storage-location decision only. Store creation
// failures and a failing store health check remain fail-closed regardless of
// its value — one flag must not switch off two independent controls.
const envAllowEphemeralSecrets = "CFGMS_ALLOW_EPHEMERAL_SECRETS"

// resolveEphemeralPath normalises p for prefix comparison.
//
// filepath.EvalSymlinks only succeeds on a path that exists, which made the
// comparison asymmetric: os.TempDir() always exists and was resolved, while a
// candidate secrets path that has not been created yet was left as written. The
// two sides then normalised differently and the prefix check missed — on macOS
// (/var/folders/… → /private/var/folders/…) and on Windows (8.3 short names such
// as C:\Users\RUNNER~1 → C:\Users\runneradmin). Linux CI has neither a symlinked
// TMPDIR nor short-name aliasing, so both sides matched there and the defect was
// invisible until the cross-platform build ran in the merge queue.
//
// Because the caller is a fail-closed guard, a miss returns "not ephemeral" and
// lets a controller start with its secret store on a volume that is wiped on
// reboot — the guard failed open on exactly the two platforms it was not
// exercised on.
//
// Resolving the deepest existing ancestor and re-appending the remainder gives
// both sides the same normalisation whether or not the full path exists yet.
func resolveEphemeralPath(p string) string {
	p = filepath.Clean(p)
	rest := ""
	for cur := p; ; {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			if rest == "" {
				return filepath.Clean(resolved)
			}
			return filepath.Clean(filepath.Join(resolved, rest))
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Reached the root without finding an existing ancestor: nothing is
			// resolvable, so compare the path as written.
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// hasPathPrefix reports whether path sits under prefix, honouring the platform's
// path-case semantics. Windows paths are case-insensitive, so a configured
// C:\TEMP\secrets must match an os.TempDir() of C:\Temp — a case-sensitive
// comparison there would fail open the same way the symlink asymmetry did.
func hasPathPrefix(path, prefix string) bool {
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(strings.ToLower(path), strings.ToLower(prefix))
	}
	return strings.HasPrefix(path, prefix)
}

// isEphemeralSecretsPath returns true when secretsPath lives under a directory
// that is wiped on reboot: os.TempDir(), /dev/shm/, or /run/user/. Symlinks and
// Windows short names are resolved first (see resolveEphemeralPath) so that
// macOS /tmp → /private/tmp, or a path written through an 8.3 alias, cannot
// bypass the check.
func isEphemeralSecretsPath(secretsPath string) bool {
	withSep := func(p string) string {
		return resolveEphemeralPath(p) + string(filepath.Separator)
	}
	p := withSep(secretsPath)
	if hasPathPrefix(p, withSep(os.TempDir())) {
		return true
	}
	// The tmpfs prefixes below are written with forward slashes, but
	// filepath.Clean inside resolveEphemeralPath rewrites separators to the
	// host's — on Windows "/dev/shm/cfgms" becomes "\dev\shm\cfgms" and no
	// forward-slash prefix can ever match. Comparing in slash form keeps the
	// check platform-independent. A POSIX tmpfs path configured on Windows is
	// nonsense either way, but this guard is fail-closed: classifying it as
	// ephemeral is the safe direction.
	slashed := filepath.ToSlash(p)
	for _, prefix := range []string{"/dev/shm/", "/run/user/"} {
		if hasPathPrefix(slashed, prefix) {
			return true
		}
	}
	return false
}

// isDatabaseDSNEphemeral returns true when the database DSN points to an
// in-memory or tmp-path SQLite database that will not survive a restart.
func isDatabaseDSNEphemeral(dsn string) bool {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return false
	}
	if dsn == ":memory:" {
		return true
	}
	// Handle SQLite file URIs: file::memory:, file:/tmp/foo.db, file::memory:?cache=shared
	if strings.HasPrefix(dsn, "file:") {
		filePart := strings.SplitN(dsn[len("file:"):], "?", 2)[0]
		if filePart == ":memory:" || filePart == "" {
			return true
		}
		return isEphemeralSecretsPath(filePart)
	}
	// Bare absolute paths (e.g. "/tmp/foo.db")
	if filepath.IsAbs(dsn) {
		return isEphemeralSecretsPath(dsn)
	}
	return false
}

// isEphemeralSQLitePath returns true when a SQLite database path resolves to a
// database that does not survive a restart: an in-memory database (":memory:"
// or any "mode=memory" DSN) or a file under a directory wiped on reboot.
func isEphemeralSQLitePath(path string) bool {
	if path == ":memory:" || strings.Contains(path, "mode=memory") {
		return true
	}
	if strings.HasPrefix(path, "file:") {
		return isDatabaseDSNEphemeral(path)
	}
	return isEphemeralSecretsPath(path)
}

// sqliteSecretsPath resolves the SQLite database file that backs the secret
// store: storage.config.path first, then storage.sqlite_path (the key the OSS
// composite storage manager uses). An empty result means the sqlite backend
// would fall back to an in-memory database.
func sqliteSecretsPath(storage *config.StorageConfig) string {
	if v, ok := storage.Config["path"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(storage.SQLitePath)
}

// resolveSecretsBackend builds the storage-provider configuration handed to the
// secrets backend and reports why that configuration is ephemeral, if it is.
//
// Constructing the configuration and judging its durability in one place is
// deliberate: the guard must inspect the exact map the backend receives.
// Branching on cfg.Storage.Provider alone let storage.provider: sqlite through
// on the strength of a persistent CFGMS_SECRETS_REPO_PATH — a value the sqlite
// backend never reads, since it keys off "path" and treats an absent "path" as
// ":memory:" (pkg/storage/providers/sqlite/plugin.go getPath).
//
// The returned map is the storage_config passed to the SOPS provider, so the
// judged configuration and the used configuration can no longer diverge.
func resolveSecretsBackend(storage *config.StorageConfig, secretsPath string) (map[string]interface{}, string) {
	switch strings.ToLower(strings.TrimSpace(storage.Provider)) {
	case "database":
		// Database provider consumes the full connection configuration; only an
		// in-memory or tmp-path SQLite DSN is non-durable.
		dsn, _ := storage.Config["dsn"].(string)
		if isDatabaseDSNEphemeral(dsn) {
			return storage.Config, fmt.Sprintf(
				"database DSN %q is ephemeral (in-memory or tmp-path SQLite). "+
					"Passkeys and web-account records will be lost on controller restart. "+
					"Fix: use a persistent database DSN. "+
					"Dev/test only: set %s=true to override.",
				dsn, envAllowEphemeralSecrets)
		}
		return storage.Config, ""

	case "sqlite":
		backend := make(map[string]interface{}, len(storage.Config)+1)
		for k, v := range storage.Config {
			backend[k] = v
		}
		path := sqliteSecretsPath(storage)
		backend["path"] = path
		switch {
		case path == "":
			return backend, fmt.Sprintf(
				"storage.provider is sqlite but no database path is configured, so the secret "+
					"store resolves to an in-memory database that is discarded on controller "+
					"restart, locking out all human accounts. CFGMS_SECRETS_REPO_PATH does not "+
					"apply to a sqlite-backed secret store. "+
					"Fix: set storage.sqlite_path (or storage.config.path) to a persistent file "+
					"such as /var/lib/cfgms/secrets.db, or use storage.provider: flatfile. "+
					"Dev/test only: set %s=true to override.",
				envAllowEphemeralSecrets)
		case isEphemeralSQLitePath(path):
			return backend, fmt.Sprintf(
				"sqlite database path %q is ephemeral (in-memory, or under a directory wiped on "+
					"reboot). Passkeys and web-account records will be lost on controller restart. "+
					"Fix: set storage.sqlite_path to a persistent file outside %s. "+
					"Dev/test only: set %s=true to override.",
				path, os.TempDir(), envAllowEphemeralSecrets)
		}
		return backend, ""

	default:
		// File-backed providers (flatfile) store secret data under secretsPath.
		// storage.flatfile_root configures the business-data composite manager,
		// not the secret store, so the resolved secrets path is what matters here.
		backend := map[string]interface{}{"root": secretsPath}
		if isEphemeralSecretsPath(secretsPath) {
			return backend, fmt.Sprintf(
				"secrets path %q is under an ephemeral directory (%s). "+
					"Passkeys and web-account records stored here will be lost on "+
					"controller restart, locking out all human accounts. "+
					"Fix: set CFGMS_SECRETS_REPO_PATH to a persistent directory outside %s, "+
					"or use storage.provider: database. "+
					"Dev/test only: set %s=true to override.",
				secretsPath, os.TempDir(), os.TempDir(), envAllowEphemeralSecrets)
		}
		return backend, ""
	}
}

// NewSecretStore initializes and returns the central secrets provider for the controller.
// It is exported so that cmd/controller/main.go can initialize the store before logging
// is configured, while server.New continues to call it internally unchanged.
//
// Fail-closed guard: the function refuses to start when the storage
// configuration handed to the secrets backend resolves to an ephemeral location
// — a secrets path under a tmp directory, /dev/shm or /run/user, an in-memory or
// tmp-path database DSN, or a sqlite backend with a missing/in-memory/tmp-path
// database file — because a controller restart would wipe every passkey and
// web-account record, locking out all human accounts (ADR-021 Amendment 1).
// Set CFGMS_ALLOW_EPHEMERAL_SECRETS=true to downgrade that rejection to a WARN
// for dev/test environments only; store creation and health-check failures stay
// fail-closed regardless.
func NewSecretStore(cfg *config.Config) (secretsif.SecretStore, error) {
	logger := logging.ForComponent("controller")
	if cfg == nil || cfg.Storage == nil {
		return nil, fmt.Errorf("storage configuration is required for secret storage")
	}

	// Determine the explicit secret-data path. Production must never fall back
	// to a shared temporary directory.
	secretsPath := os.Getenv("CFGMS_SECRETS_REPO_PATH")
	if secretsPath == "" {
		if strings.TrimSpace(cfg.DataDir) == "" {
			return nil, fmt.Errorf("secret storage path is required: configure data_dir or CFGMS_SECRETS_REPO_PATH")
		}
		secretsPath = filepath.Join(cfg.DataDir, "secrets")
	}

	keyFile := strings.TrimSpace(os.Getenv("CFGMS_SECRETS_KEY_FILE"))
	if keyFile == "" {
		return nil, fmt.Errorf("CFGMS_SECRETS_KEY_FILE is required; plaintext secret storage is prohibited")
	}

	allowEphemeral := strings.EqualFold(strings.TrimSpace(os.Getenv(envAllowEphemeralSecrets)), "true")

	// Guard: fail closed on ephemeral secret storage (ADR-021 Amendment 1).
	// A controller restart wipes passkeys and web-account records stored in
	// ephemeral locations, locking out all human accounts. The decision is made
	// from the storage configuration actually handed to the secrets backend, so
	// no provider can pass the guard on a value it never reads.
	storageConfig, ephemeralReason := resolveSecretsBackend(cfg.Storage, secretsPath)

	if ephemeralReason != "" {
		if !allowEphemeral {
			return nil, fmt.Errorf("refusing ephemeral secret storage — %s", ephemeralReason)
		}
		logger.Warn("DANGER: secret store is using ephemeral storage",
			"reason", logging.SanitizeLogValue(ephemeralReason),
			"risk", "passkeys and web-account records will be lost on controller restart; all human accounts will be locked out",
			"override", envAllowEphemeralSecrets+"=true")
	}

	// Create secrets provider configuration
	// M-AUTH-1: Encrypt before handing bytes to flat-file or database storage.
	secretsConfig := map[string]interface{}{
		"storage_provider": cfg.Storage.Provider, // Use controller's global storage provider
		"cache_enabled":    true,
		"cache_ttl":        300,  // 5 minutes
		"cache_max_size":   1000, // Cache up to 1000 secrets
		"key_file":         keyFile,
		// storageConfig is the same map the ephemeral guard judged above.
		"storage_config": storageConfig,
	}

	// Create secret store using SOPS provider
	store, err := secretsif.CreateSecretStoreFromConfig("sops", secretsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret store: %w", err)
	}

	// Verify store is healthy. Fail closed unconditionally: a broken store at
	// startup means passkeys and web-account records are inaccessible. This is
	// a separate control from the ephemeral-path guard and is deliberately not
	// governed by envAllowEphemeralSecrets — that flag only downgrades the
	// ephemeral-location rejection, and must never disable store-health
	// validation as a side effect.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.HealthCheck(ctx); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("secret store health check failed: %w", err)
	}

	logger.Info("Secret store initialized",
		"provider", "sops",
		"backend", cfg.Storage.Provider,
		"secrets_path", secretsPath,
		"encryption", "AES-256-GCM envelope")
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
