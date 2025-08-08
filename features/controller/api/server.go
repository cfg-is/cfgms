package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
	"github.com/gorilla/mux"
)

// Server represents the REST API server component of the controller
type Server struct {
	mu                      sync.RWMutex
	cfg                     *config.Config
	logger                  logging.Logger
	httpServer              *http.Server
	router                  *mux.Router
	controllerService       *service.ControllerService
	configService           *service.ConfigurationService
	certProvisioningService *service.CertificateProvisioningService
	rbacService             *service.RBACService
	certManager             *cert.Manager
	tenantManager           *tenant.Manager
	rbacManager             *rbac.Manager
	systemMonitor           *monitoring.SystemMonitor
	tracer                  *telemetry.Tracer
	apiKeys                 map[string]*APIKey // Simple API key storage
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

// New creates a new REST API server instance
func New(
	cfg *config.Config,
	logger logging.Logger,
	controllerService *service.ControllerService,
	configService *service.ConfigurationService,
	certProvisioningService *service.CertificateProvisioningService,
	rbacService *service.RBACService,
	certManager *cert.Manager,
	tenantManager *tenant.Manager,
	rbacManager *rbac.Manager,
	systemMonitor *monitoring.SystemMonitor,
	tracer *telemetry.Tracer,
) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
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
		tracer:                  tracer,
		apiKeys:                 make(map[string]*APIKey),
	}

	// Initialize router with middleware
	server.setupRouter()

	// Generate default API key for initial setup
	if err := server.generateDefaultAPIKey(); err != nil {
		logger.Warn("Failed to generate default API key", "error", err)
	}

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

	// API routes with authentication
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.authenticationMiddleware)

	// Health check (no auth required)
	s.router.HandleFunc("/api/v1/health", s.handleHealth).Methods("GET", "OPTIONS")

	// Steward management endpoints
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

// getHTTPListenAddr determines the HTTP listen address
// For now, we'll use the gRPC port + 1000 to avoid conflicts
func (s *Server) getHTTPListenAddr() string {
	// If environment variable is set, use it
	if addr := os.Getenv("CFGMS_HTTP_LISTEN_ADDR"); addr != "" {
		return addr
	}

	// Default to port 9080 for HTTP API (gRPC typically on 8080)
	return "127.0.0.1:9080"
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

// setupManagedTLS configures TLS using managed certificates
func (s *Server) setupManagedTLS() (*tls.Config, error) {
	// Get server certificate (reuse the same logic as gRPC server)
	serverCert, err := s.getServerCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get server certificate: %w", err)
	}

	// Load the certificate and key
	cert, err := tls.X509KeyPair(serverCert.CertificatePEM, serverCert.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// For REST API, we'll use TLS but not require client certificates by default
	// This allows for API key authentication instead
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert, // API key auth instead
	}

	return tlsConfig, nil
}

// setupLegacyTLS configures TLS using legacy certificate files
func (s *Server) setupLegacyTLS() (*tls.Config, error) {
	certFile := filepath.Join(s.cfg.CertPath, "server.crt")
	keyFile := filepath.Join(s.cfg.CertPath, "server.key")

	// Load certificate
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load legacy certificates: %w", err)
	}

	// Basic TLS configuration for legacy mode
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert,
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

	// Generate new server certificate if auto-generation is enabled
	if !s.cfg.Certificate.AutoGenerate {
		return nil, fmt.Errorf("no valid server certificate found and auto-generation is disabled")
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
