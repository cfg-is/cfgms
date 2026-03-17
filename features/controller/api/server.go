// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/commercial/ha"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/ctxkeys"
	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/authdefense"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgmonitoring "github.com/cfgis/cfgms/pkg/monitoring"
	"github.com/cfgis/cfgms/pkg/registration"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops" // Auto-register SOPS provider
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// QUICTriggerFunc is a function that triggers a QUIC connection for a steward
type QUICTriggerFunc func(ctx context.Context, stewardID string) (string, error)

// Server represents the REST API server component of the controller
type Server struct {
	mu                      sync.RWMutex
	cfg                     *config.Config
	logger                  logging.Logger
	httpServer              *http.Server
	router                  *mux.Router
	controllerService       *service.ControllerService
	configService           *service.ConfigurationServiceV2
	certProvisioningService *service.CertificateProvisioningService
	rbacService             *service.RBACService
	certManager             *cert.Manager
	tenantManager           *tenant.Manager
	rbacManager             *rbac.Manager
	systemMonitor           *monitoring.SystemMonitor
	platformMonitor         pkgmonitoring.PlatformMonitor
	healthCollector         *health.Collector
	tracer                  *telemetry.Tracer
	haManager               *ha.Manager
	apiKeys                 map[string]*APIKey             // In-memory cache for fast lookup
	secretStore             secretsif.SecretStore          // M-AUTH-1: Central secrets provider for API keys
	registrationTokenStore  registration.Store             // Registration token store for steward registration
	registeredStewards      map[string]*RegisteredSteward  // In-memory store for registered stewards
	corsConfig              *CORSConfig                    // CORS configuration
	quicTriggerFunc         QUICTriggerFunc                // Function to trigger QUIC connections
	signerCertSerial        string                         // Story #378: Serial of cert used for config signing
	authDefense             *authdefense.AuthDefenseSystem // Story #380: Three-tier auth defense
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

// RegisteredSteward represents a steward that has registered with the controller
type RegisteredSteward struct {
	StewardID     string    `json:"steward_id"`
	TenantID      string    `json:"tenant_id"`
	Group         string    `json:"group"`
	RegisteredAt  time.Time `json:"registered_at"`
	LastHeartbeat time.Time `json:"last_heartbeat,omitempty"`
	Status        string    `json:"status"` // online, offline, unknown
	MQTTBroker    string    `json:"mqtt_broker,omitempty"`
	QUICAddress   string    `json:"quic_address,omitempty"`
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
	platformMonitor pkgmonitoring.PlatformMonitor,
	tracer *telemetry.Tracer,
	haManager *ha.Manager,
	registrationTokenStore registration.Store,
	signerCertSerial string, // Story #378: Serial of cert used for config signing
	healthCollector *health.Collector, // Story #417: CFGMS health monitoring
) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// M-AUTH-1: Initialize central secrets provider for API key storage
	secretStore, err := initializeSecretStore(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secret store: %w", err)
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
		platformMonitor:         platformMonitor,
		healthCollector:         healthCollector,
		tracer:                  tracer,
		haManager:               haManager,
		registrationTokenStore:  registrationTokenStore,
		signerCertSerial:        signerCertSerial,                    // Story #378: For registration handler
		apiKeys:                 make(map[string]*APIKey),            // In-memory cache
		secretStore:             secretStore,                         // M-AUTH-1: Central secrets provider
		registeredStewards:      make(map[string]*RegisteredSteward), // In-memory steward registry
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

	// M-AUTH-1: Do NOT generate default API keys (security anti-pattern)
	// API keys must be explicitly created by administrators

	// Start background cleanup for expired API keys
	server.startAPIKeyCleanup()

	return server, nil
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
	api.Use(s.authDefense.Middleware) // Story #380: Rate limiting before auth
	api.Use(s.authenticationMiddleware)
	api.Use(s.validationMiddleware)

	// Health check (no auth required)
	s.router.HandleFunc("/api/v1/health", s.handleHealth).Methods("GET", "OPTIONS")

	// Steward registration (no auth required - uses registration token)
	s.router.HandleFunc("/api/v1/register", s.handleRegister).Methods("POST", "OPTIONS")

	// Test-mode config upload (no auth required - for integration tests only)
	// Use separate path to avoid conflict with authenticated subrouter
	// TODO: Remove or protect this endpoint in production
	s.router.HandleFunc("/api/v1/test/stewards/{id}/config", s.handleUpdateStewardConfig).Methods("PUT", "OPTIONS")

	// Test-mode QUIC trigger (no auth required - for integration tests only)
	// TODO: Remove or protect this endpoint in production
	s.router.HandleFunc("/api/v1/test/stewards/{id}/quic/connect", s.handleTriggerQUICConnection).Methods("POST", "OPTIONS")

	// Steward management endpoints (require API key authentication)
	stewards := api.PathPrefix("/stewards").Subrouter()
	stewards.Handle("", s.requirePermission("steward", "list")(http.HandlerFunc(s.handleListStewards))).Methods("GET")
	stewards.Handle("/{id}", s.requirePermission("steward", "read")(http.HandlerFunc(s.handleGetSteward))).Methods("GET")
	stewards.Handle("/{id}/dna", s.requirePermission("steward", "read-dna")(http.HandlerFunc(s.handleGetStewardDNA))).Methods("GET")

	// Configuration management endpoints
	stewards.Handle("/{id}/config", s.requirePermission("steward", "read-config")(http.HandlerFunc(s.handleGetStewardConfig))).Methods("GET")
	stewards.Handle("/{id}/config", s.requirePermission("steward", "write-config")(http.HandlerFunc(s.handleUpdateStewardConfig))).Methods("PUT")
	stewards.Handle("/{id}/config/validate", s.requirePermission("steward", "validate-config")(http.HandlerFunc(s.handleValidateConfig))).Methods("POST")
	stewards.Handle("/{id}/config/status", s.requirePermission("steward", "read-config")(http.HandlerFunc(s.handleGetConfigStatus))).Methods("GET")
	stewards.Handle("/{id}/config/effective", s.requirePermission("steward", "read-config")(http.HandlerFunc(s.handleGetEffectiveConfig))).Methods("GET")

	// QUIC connection management endpoints
	stewards.Handle("/{id}/quic/connect", s.requirePermission("steward", "manage")(http.HandlerFunc(s.handleTriggerQUICConnection))).Methods("POST")

	// Script management endpoints
	stewards.Handle("/{id}/scripts/executions", s.requirePermission("steward", "read-scripts")(http.HandlerFunc(s.handleGetScriptExecutions))).Methods("GET")
	stewards.Handle("/{id}/scripts/executions/{execution_id}", s.requirePermission("steward", "read-scripts")(http.HandlerFunc(s.handleGetScriptExecution))).Methods("GET")
	stewards.Handle("/{id}/scripts/executions/{execution_id}/retry", s.requirePermission("steward", "execute-scripts")(http.HandlerFunc(s.handlePostScriptRetry))).Methods("POST")
	stewards.Handle("/{id}/scripts/metrics", s.requirePermission("steward", "read-scripts")(http.HandlerFunc(s.handleGetScriptMetrics))).Methods("GET")
	stewards.Handle("/{id}/scripts/status", s.requirePermission("steward", "read-scripts")(http.HandlerFunc(s.handleGetScriptStatus))).Methods("GET")

	// Certificate management endpoints
	certs := api.PathPrefix("/certificates").Subrouter()
	certs.Handle("", s.requirePermission("certificate", "list")(http.HandlerFunc(s.handleListCertificates))).Methods("GET")
	certs.Handle("/provision", s.requirePermission("certificate", "provision")(http.HandlerFunc(s.handleProvisionCertificate))).Methods("POST")
	certs.Handle("/{serial}/revoke", s.requirePermission("certificate", "revoke")(http.HandlerFunc(s.handleRevokeCertificate))).Methods("POST")

	// RBAC management endpoints
	rbac := api.PathPrefix("/rbac").Subrouter()

	// Permissions
	rbac.Handle("/permissions", s.requirePermission("rbac", "list-permissions")(http.HandlerFunc(s.handleListPermissions))).Methods("GET")
	rbac.Handle("/permissions/{id}", s.requirePermission("rbac", "read-permission")(http.HandlerFunc(s.handleGetPermission))).Methods("GET")

	// Roles
	rbac.Handle("/roles", s.requirePermission("rbac", "list-roles")(http.HandlerFunc(s.handleListRoles))).Methods("GET")
	rbac.Handle("/roles", s.requirePermission("rbac", "create-role")(http.HandlerFunc(s.handleCreateRole))).Methods("POST")
	rbac.Handle("/roles/{id}", s.requirePermission("rbac", "read-role")(http.HandlerFunc(s.handleGetRole))).Methods("GET")
	rbac.Handle("/roles/{id}", s.requirePermission("rbac", "update-role")(http.HandlerFunc(s.handleUpdateRole))).Methods("PUT")
	rbac.Handle("/roles/{id}", s.requirePermission("rbac", "delete-role")(http.HandlerFunc(s.handleDeleteRole))).Methods("DELETE")

	// Subjects
	rbac.Handle("/subjects", s.requirePermission("rbac", "list-subjects")(http.HandlerFunc(s.handleListSubjects))).Methods("GET")
	rbac.Handle("/subjects", s.requirePermission("rbac", "create-subject")(http.HandlerFunc(s.handleCreateSubject))).Methods("POST")
	rbac.Handle("/subjects/{id}", s.requirePermission("rbac", "read-subject")(http.HandlerFunc(s.handleGetSubject))).Methods("GET")
	rbac.Handle("/subjects/{id}", s.requirePermission("rbac", "update-subject")(http.HandlerFunc(s.handleUpdateSubject))).Methods("PUT")
	rbac.Handle("/subjects/{id}", s.requirePermission("rbac", "delete-subject")(http.HandlerFunc(s.handleDeleteSubject))).Methods("DELETE")

	// Role assignments
	rbac.Handle("/subjects/{id}/roles", s.requirePermission("rbac", "read-assignments")(http.HandlerFunc(s.handleGetSubjectRoles))).Methods("GET")
	rbac.Handle("/subjects/{id}/roles", s.requirePermission("rbac", "assign-role")(http.HandlerFunc(s.handleAssignRole))).Methods("POST")
	rbac.Handle("/subjects/{id}/roles/{role_id}", s.requirePermission("rbac", "revoke-role")(http.HandlerFunc(s.handleRevokeRole))).Methods("DELETE")

	// Permission checking
	rbac.Handle("/subjects/{id}/permissions", s.requirePermission("rbac", "read-permissions")(http.HandlerFunc(s.handleGetSubjectPermissions))).Methods("GET")
	rbac.Handle("/check", s.requirePermission("rbac", "check-permission")(http.HandlerFunc(s.handleCheckPermission))).Methods("POST")

	// API key management endpoints (for managing API keys themselves)
	apiKeys := api.PathPrefix("/api-keys").Subrouter()
	apiKeys.Handle("", s.requirePermission("api-key", "list")(http.HandlerFunc(s.handleListAPIKeys))).Methods("GET")
	apiKeys.Handle("", s.requirePermission("api-key", "create")(http.HandlerFunc(s.handleCreateAPIKey))).Methods("POST")
	apiKeys.Handle("/{id}", s.requirePermission("api-key", "read")(http.HandlerFunc(s.handleGetAPIKey))).Methods("GET")
	apiKeys.Handle("/{id}", s.requirePermission("api-key", "delete")(http.HandlerFunc(s.handleDeleteAPIKey))).Methods("DELETE")

	// Registration token management endpoints (Story #264)
	regTokens := api.PathPrefix("/registration/tokens").Subrouter()
	regTokens.Handle("", s.requirePermission("registration", "list-tokens")(http.HandlerFunc(s.handleListRegistrationTokens))).Methods("GET")
	regTokens.Handle("", s.requirePermission("registration", "create-token")(http.HandlerFunc(s.handleCreateRegistrationToken))).Methods("POST")
	regTokens.Handle("/{token}", s.requirePermission("registration", "read-token")(http.HandlerFunc(s.handleGetRegistrationToken))).Methods("GET")
	regTokens.Handle("/{token}", s.requirePermission("registration", "delete-token")(http.HandlerFunc(s.handleDeleteRegistrationToken))).Methods("DELETE")
	regTokens.Handle("/{token}/revoke", s.requirePermission("registration", "revoke-token")(http.HandlerFunc(s.handleRevokeRegistrationToken))).Methods("POST")

	// Monitoring endpoints
	monitoring := api.PathPrefix("/monitoring").Subrouter()
	monitoring.Handle("/health", s.requirePermission("monitoring", "read-health")(http.HandlerFunc(s.handleSystemHealth))).Methods("GET")
	monitoring.Handle("/metrics", s.requirePermission("monitoring", "read-metrics")(http.HandlerFunc(s.handleSystemMetrics))).Methods("GET")
	monitoring.Handle("/resources", s.requirePermission("monitoring", "read-resources")(http.HandlerFunc(s.handleResourceMetrics))).Methods("GET")
	monitoring.Handle("/logs", s.requirePermission("monitoring", "read-logs")(http.HandlerFunc(s.handleMonitoringLogs))).Methods("GET")
	monitoring.Handle("/traces", s.requirePermission("monitoring", "read-traces")(http.HandlerFunc(s.handleMonitoringTraces))).Methods("GET")
	monitoring.Handle("/events", s.requirePermission("monitoring", "read-events")(http.HandlerFunc(s.handleMonitoringEvents))).Methods("GET")
	monitoring.Handle("/config", s.requirePermission("monitoring", "read-config")(http.HandlerFunc(s.handleMonitoringConfig))).Methods("GET")

	// Steward-specific monitoring
	monitoring.Handle("/stewards/{id}/metrics", s.requirePermission("monitoring", "read-steward-metrics")(http.HandlerFunc(s.handleStewardMetrics))).Methods("GET")

	// Controller service monitoring
	monitoring.Handle("/controller/services", s.requirePermission("monitoring", "read-services")(http.HandlerFunc(s.handleControllerServices))).Methods("GET")

	// New platform monitoring endpoints
	monitoring.Handle("/anomalies", s.requirePermission("monitoring", "read-anomalies")(http.HandlerFunc(s.handleMonitoringAnomalies))).Methods("GET")
	monitoring.Handle("/components/{component}/health", s.requirePermission("monitoring", "read-component-health")(http.HandlerFunc(s.handleMonitoringComponentHealth))).Methods("GET")
	monitoring.Handle("/components/{component}/metrics", s.requirePermission("monitoring", "read-component-metrics")(http.HandlerFunc(s.handleMonitoringComponentMetrics))).Methods("GET")

	// High Availability (HA) endpoints
	ha := api.PathPrefix("/ha").Subrouter()
	ha.Handle("/status", s.requirePermission("ha", "read-status")(http.HandlerFunc(s.handleHAStatus))).Methods("GET")
	ha.Handle("/cluster", s.requirePermission("ha", "read-cluster")(http.HandlerFunc(s.handleHACluster))).Methods("GET")
	ha.Handle("/leader", s.requirePermission("ha", "read-leader")(http.HandlerFunc(s.handleHALeader))).Methods("GET")
	ha.Handle("/nodes", s.requirePermission("ha", "read-nodes")(http.HandlerFunc(s.handleHANodes))).Methods("GET")

	// Compliance reporting endpoints (Story #212)
	// Steward-specific compliance endpoints
	stewards.Handle("/{id}/compliance", s.requirePermission("steward", "read-compliance")(http.HandlerFunc(s.handleGetStewardCompliance))).Methods("GET")
	stewards.Handle("/{id}/compliance/report", s.requirePermission("steward", "read-compliance")(http.HandlerFunc(s.handleGetStewardComplianceReport))).Methods("GET")

	// System-wide compliance endpoints
	compliance := api.PathPrefix("/compliance").Subrouter()
	compliance.Handle("/summary", s.requirePermission("compliance", "read-summary")(http.HandlerFunc(s.handleGetComplianceSummary))).Methods("GET")

	// Raft consensus endpoints (no auth required - internal cluster communication)
	s.router.HandleFunc("/raft/message", s.handleRaftMessage).Methods("POST")
	s.router.HandleFunc("/raft/status", s.handleRaftStatus).Methods("GET")
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

// Stop gracefully shuts down the HTTP server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("Shutting down REST API server")

	// Story #380: Stop auth defense system
	if s.authDefense != nil {
		s.authDefense.Stop()
	}

	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error("Failed to shutdown HTTP server gracefully", "error", err)
			return err
		}
	}

	return nil
}

// SetQUICTriggerFunc sets the function used to trigger QUIC connections
func (s *Server) SetQUICTriggerFunc(fn QUICTriggerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quicTriggerFunc = fn
}

// getHTTPListenAddr determines the HTTP listen address
// For now, we'll use the gRPC port + 1000 to avoid conflicts
func (s *Server) getHTTPListenAddr() string {
	// If environment variable is set, use it
	if addr := os.Getenv("CFGMS_HTTP_LISTEN_ADDR"); addr != "" {
		return addr
	}

	// Default to port 9080 for HTTP API (gRPC typically on 8080)
	// Bind to 0.0.0.0 for Docker compatibility
	return "0.0.0.0:9080"
}

// shouldUseTLS determines if TLS should be enabled for the HTTP server
func (s *Server) shouldUseTLS() bool {
	// Alpha (Story #198): Disable TLS for HTTP API if MQTT TLS is disabled
	if s.cfg.MQTT != nil && !s.cfg.MQTT.EnableTLS {
		return false
	}
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

// setupManagedTLS configures TLS using managed certificates
func (s *Server) setupManagedTLS() (*tls.Config, error) {
	// Story #377: In separated mode with external source, load from disk
	if s.cfg.Certificate != nil && s.cfg.Certificate.IsSeparatedArchitecture() {
		if s.cfg.Certificate.GetPublicAPISource() == "external" {
			return s.setupExternalPublicAPICert()
		}
		// separated + internal: generate/use a PublicAPI cert type
		// Falls through to standard managed TLS (uses same cert generation logic)
	}

	// Get server certificate (reuse the same logic as gRPC server)
	serverCert, err := s.getServerCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get server certificate: %w", err)
	}

	// Load the certificate and key
	// Create TLS config using pkg/cert helper (no client auth for API server)
	tlsConfig, err := cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, nil, tls.VersionTLS12)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
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

// getServerCertificate gets or generates a server certificate (reused from gRPC server logic)
func (s *Server) getServerCertificate() (*cert.Certificate, error) {
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

			s.logger.Info("Using existing server certificate for HTTP server",
				"common_name", certInfo.CommonName,
				"serial", certInfo.SerialNumber,
				"expires", certInfo.ExpiresAt.Format("2006-01-02"))
			return fullCert, nil
		}
	}

	// Generate new server certificate if certificate lifecycle management is enabled
	if !s.cfg.Certificate.EnableCertManagement {
		return nil, fmt.Errorf("no valid server certificate found and certificate lifecycle management is disabled")
	}

	s.logger.Info("Generating new server certificate for HTTP server",
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
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	s.logger.Info("Generated new server certificate for HTTP server",
		"common_name", serverCert.CommonName,
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

// startAPIKeyCleanup starts a background goroutine to clean up expired API keys
func (s *Server) startAPIKeyCleanup() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute) // Clean up every 10 minutes
		defer ticker.Stop()

		s.logger.Info("Started API key cleanup background process", "interval", "10 minutes")

		for range ticker.C {
			s.cleanupExpiredAPIKeys()
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

// M-AUTH-1: Initialize central secrets provider for API key storage
// Replaces the incorrect file-based APIKeyStore implementation
func initializeSecretStore(cfg *config.Config, logger logging.Logger) (secretsif.SecretStore, error) {
	// Determine repository path for secrets (git+SOPS backend)
	repoPath := os.Getenv("CFGMS_SECRETS_REPO_PATH")
	if repoPath == "" {
		// Use temporary directory for testing/development
		tmpDir := os.TempDir()
		repoPath = filepath.Join(tmpDir, "cfgms-secrets-test")
		logger.Debug("Using temporary secrets repository for testing", "path", repoPath)
	}

	// Create secrets provider configuration
	// M-AUTH-1: Use global storage provider for secrets (git or database)
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
		// For git provider, set the repository path
		secretsConfig["storage_config"] = map[string]interface{}{
			"repository_path": repoPath,
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
		"repo_path", repoPath,
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
