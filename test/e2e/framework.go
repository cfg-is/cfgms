// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneGRPC "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"

	"github.com/cfgis/cfgms/features/controller"
	controllerConfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	testutil "github.com/cfgis/cfgms/pkg/testing"

	// Import storage providers for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

// RegisteredSteward represents a steward registered with the controller via gRPC transport
// Story #294 Phase 3: Track transport-connected stewards for E2E testing
type RegisteredSteward struct {
	StewardID        string
	TenantID         string
	Group            string
	ControlPlane     controlplaneInterfaces.ControlPlaneProvider
	TransportAddress string
	ControllerURL    string
	ClientCert       string
	ClientKey        string
	CACert           string
	heartbeatDone    chan bool
}

// E2ETestFramework provides a comprehensive end-to-end testing environment
// optimized for GitHub Actions and CI/CD pipelines
type E2ETestFramework struct {
	t       *testing.T
	tempDir string
	logger  logging.Logger
	ctx     context.Context
	cancel  context.CancelFunc

	// Core components
	controller         *controller.Controller
	stewards           map[string]*steward.Steward   // Standalone stewards (Phase 1)
	registeredStewards map[string]*RegisteredSteward // MQTT-connected stewards (Phase 3)
	certManager        *cert.Manager
	rbacManager        rbac.RBACManager
	terminalMgr        terminal.SessionManager
	workflowEngine     *workflow.Engine

	// Test configuration
	config *E2EConfig

	// Test data generation
	dataGenerator *TestDataGenerator

	// Runtime state
	startTime    time.Time
	metrics      *TestMetrics
	cleanupFuncs []func() error
	mu           sync.RWMutex
}

// E2EConfig contains configuration for E2E testing
type E2EConfig struct {
	// Test execution settings
	TestTimeout        time.Duration `json:"test_timeout"`
	ComponentStartup   time.Duration `json:"component_startup"`
	MaxConcurrentTests int           `json:"max_concurrent_tests"`

	// Component configuration
	ControllerPort int  `json:"controller_port"` // gRPC port (default 8080)
	HTTPPort       int  `json:"http_port"`       // HTTP API port (default 9080)
	EnableTLS      bool `json:"enable_tls"`
	EnableRBAC     bool `json:"enable_rbac"`
	EnableTerminal bool `json:"enable_terminal"`
	EnableWorkflow bool `json:"enable_workflow"`

	// Test data generation
	GenerateTestData bool   `json:"generate_test_data"`
	TestDataSize     string `json:"test_data_size"` // small, medium, large

	// CI/CD optimizations
	OptimizeForCI     bool `json:"optimize_for_ci"`
	ParallelExecution bool `json:"parallel_execution"`
	ReducedLogging    bool `json:"reduced_logging"`

	// Performance testing
	PerformanceMode  bool          `json:"performance_mode"`
	LoadTestDuration time.Duration `json:"load_test_duration"`
	MaxConnections   int           `json:"max_connections"`
}

// TestMetrics tracks performance and reliability metrics during testing
type TestMetrics struct {
	StartTime           time.Time                  `json:"start_time"`
	ComponentStartTimes map[string]time.Time       `json:"component_start_times"`
	TestResults         []TestResult               `json:"test_results"`
	PerformanceMetrics  PerformanceMetrics         `json:"performance_metrics"`
	ResourceUsage       ResourceUsage              `json:"resource_usage"`
	LatencyMetrics      map[string][]time.Duration `json:"latency_metrics"`
	mu                  sync.RWMutex
}

// TestResult represents the result of a single test
type TestResult struct {
	Name     string                 `json:"name"`
	Category string                 `json:"category"`
	Duration time.Duration          `json:"duration"`
	Success  bool                   `json:"success"`
	Error    string                 `json:"error,omitempty"`
	Metrics  map[string]interface{} `json:"metrics,omitempty"`
}

// PerformanceMetrics tracks system performance during tests
type PerformanceMetrics struct {
	TotalRequests      int64         `json:"total_requests"`
	SuccessfulRequests int64         `json:"successful_requests"`
	FailedRequests     int64         `json:"failed_requests"`
	AverageLatency     time.Duration `json:"average_latency"`
	P95Latency         time.Duration `json:"p95_latency"`
	P99Latency         time.Duration `json:"p99_latency"`
	ThroughputRPS      float64       `json:"throughput_rps"`
}

// ResourceUsage tracks resource consumption during tests
type ResourceUsage struct {
	MaxMemoryMB         float64 `json:"max_memory_mb"`
	MaxCPUPercent       float64 `json:"max_cpu_percent"`
	TotalGoroutines     int     `json:"total_goroutines"`
	OpenFileDescriptors int     `json:"open_file_descriptors"`
}

// NewE2EFramework creates a new end-to-end testing framework
func NewE2EFramework(t *testing.T, config *E2EConfig) (*E2ETestFramework, error) {
	if config == nil {
		config = DefaultE2EConfig()
	}

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "cfgms-e2e-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Create logger with appropriate level for CI
	var logger logging.Logger
	if config.ReducedLogging {
		logger = testutil.NewMockLogger(false) // No debug output in CI
	} else {
		logger = testutil.NewMockLogger(true) // Full output for local testing
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), config.TestTimeout)

	framework := &E2ETestFramework{
		t:                  t,
		tempDir:            tempDir,
		logger:             logger,
		ctx:                ctx,
		cancel:             cancel,
		stewards:           make(map[string]*steward.Steward),
		registeredStewards: make(map[string]*RegisteredSteward), // Story #294 Phase 3
		config:             config,
		dataGenerator:      NewTestDataGenerator(config),
		startTime:          time.Now(),
		metrics: &TestMetrics{
			StartTime:           time.Now(),
			ComponentStartTimes: make(map[string]time.Time),
			TestResults:         make([]TestResult, 0),
		},
		cleanupFuncs: make([]func() error, 0),
	}

	return framework, nil
}

// Initialize sets up all the components for testing
func (f *E2ETestFramework) Initialize() error {
	f.logger.Info("Initializing E2E test framework")

	// Initialize certificate manager
	if err := f.initializeCertificates(); err != nil {
		return fmt.Errorf("failed to initialize certificates: %w", err)
	}

	// Initialize RBAC if enabled
	if f.config.EnableRBAC {
		if err := f.initializeRBAC(); err != nil {
			return fmt.Errorf("failed to initialize RBAC: %w", err)
		}
	}

	// Initialize controller
	if err := f.initializeController(); err != nil {
		return fmt.Errorf("failed to initialize controller: %w", err)
	}

	// Initialize terminal manager if enabled
	if f.config.EnableTerminal {
		if err := f.initializeTerminal(); err != nil {
			return fmt.Errorf("failed to initialize terminal: %w", err)
		}
	}

	// Initialize workflow engine if enabled
	if f.config.EnableWorkflow {
		if err := f.initializeWorkflow(); err != nil {
			return fmt.Errorf("failed to initialize workflow: %w", err)
		}
	}

	// Generate test data if requested
	if f.config.GenerateTestData {
		if err := f.generateTestData(); err != nil {
			return fmt.Errorf("failed to generate test data: %w", err)
		}
	}

	f.logger.Info("E2E test framework initialized successfully")
	return nil
}

// initializeCertificates sets up the certificate infrastructure
func (f *E2ETestFramework) initializeCertificates() error {
	f.metrics.ComponentStartTimes["certificates"] = time.Now()

	certPath := filepath.Join(f.tempDir, "certs")
	if err := os.MkdirAll(certPath, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	certManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certPath,
		CAConfig: &cert.CAConfig{
			Organization:       "CFGMS Test CA",
			Country:            "US",
			State:              "Test",
			City:               "Test",
			OrganizationalUnit: "Integration Tests",
			ValidityDays:       1, // Short validity for testing
			KeySize:            2048,
		},
		LoadExistingCA:       false, // Create new CA for each test
		RenewalThresholdDays: 1,
	})
	if err != nil {
		return fmt.Errorf("failed to create cert manager: %w", err)
	}

	f.certManager = certManager
	f.addCleanup(func() error {
		return nil // Certificate cleanup handled by temp dir removal
	})

	return nil
}

// initializeRBAC sets up the RBAC system
func (f *E2ETestFramework) initializeRBAC() error {
	f.metrics.ComponentStartTimes["rbac"] = time.Now()

	// Use git storage for durable E2E testing - minimum storage requirement
	storageConfig := map[string]interface{}{
		"repository_path": filepath.Join(f.tempDir, "rbac-storage"),
		"branch":          "main",
		"auto_init":       true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", storageConfig)
	if err != nil {
		return fmt.Errorf("failed to setup E2E storage: %w", err)
	}

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	if err := rbacManager.Initialize(f.ctx); err != nil {
		return fmt.Errorf("failed to initialize RBAC: %w", err)
	}

	// Create test tenants and users
	if err := f.createTestTenants(); err != nil {
		return fmt.Errorf("failed to create test tenants: %w", err)
	}

	f.rbacManager = rbacManager
	return nil
}

// initializeController sets up the controller component
func (f *E2ETestFramework) initializeController() error {
	f.metrics.ComponentStartTimes["controller"] = time.Now()

	config := &controllerConfig.Config{
		ListenAddr: fmt.Sprintf("localhost:%d", f.config.ControllerPort),
		CertPath:   filepath.Join(f.tempDir, "certs"), // Legacy cert path
		DataDir:    filepath.Join(f.tempDir, "controller-data"),
		LogLevel:   "info",
		Storage: &controllerConfig.StorageConfig{
			Provider: "git",
			Config: map[string]interface{}{
				"repository_path": filepath.Join(f.tempDir, "storage-git"),
				"encryption": map[string]interface{}{
					"enabled": false, // Disable encryption for tests
				},
			},
		},
		Certificate: &controllerConfig.CertificateConfig{
			EnableCertManagement:   f.config.EnableTLS,
			CAPath:                 filepath.Join(f.tempDir, "certs", "ca"),
			RenewalThresholdDays:   1,
			ServerCertValidityDays: 1,
			ClientCertValidityDays: 1,
			Server: &controllerConfig.ServerCertificateConfig{
				CommonName:   "localhost",
				DNSNames:     []string{"localhost", "127.0.0.1"},
				IPAddresses:  []string{"127.0.0.1", "::1"},
				Organization: "Test Organization",
			},
		},
		// Issue #516: Enable gRPC-over-QUIC transport for steward connections
		Transport: &controllerConfig.TransportConfig{
			ListenAddr:      "localhost:4433",
			UseCertManager:  true,
			MaxConnections:  100,
			KeepalivePeriod: controllerConfig.Duration(30 * time.Second),
			IdleTimeout:     controllerConfig.Duration(5 * time.Minute),
		},
	}

	// Create storage directory
	storageDir := filepath.Join(f.tempDir, "storage-git")
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	ctrl, err := controller.New(config, f.logger)
	if err != nil {
		return fmt.Errorf("failed to create controller: %w", err)
	}

	// Start controller in background
	go func() {
		if err := ctrl.Start(f.ctx); err != nil {
			f.logger.Error("Controller start failed", "error", err)
		}
	}()

	// Wait for controller to start (give it some time)
	time.Sleep(f.config.ComponentStartup)

	f.controller = ctrl
	f.addCleanup(func() error {
		err := ctrl.Stop(context.Background())
		// Ignore "controller not running" errors during cleanup
		if err != nil && err.Error() == "controller not running" {
			return nil
		}
		return err
	})

	return nil
}

// initializeTerminal sets up the terminal system
func (f *E2ETestFramework) initializeTerminal() error {
	f.metrics.ComponentStartTimes["terminal"] = time.Now()

	// TODO: Initialize terminal manager when terminal package is available
	f.logger.Info("Terminal initialization skipped - not yet implemented")

	return nil
}

// initializeWorkflow sets up the workflow engine
func (f *E2ETestFramework) initializeWorkflow() error {
	f.metrics.ComponentStartTimes["workflow"] = time.Now()

	// TODO: Initialize workflow engine when workflow package is available
	f.logger.Info("Workflow engine initialization skipped - not yet implemented")

	return nil
}

// CreateSteward creates a new steward instance for testing
func (f *E2ETestFramework) CreateSteward(stewardID string) (*steward.Steward, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if existingSteward, exists := f.stewards[stewardID]; exists {
		f.logger.Info("Reusing existing steward for test", "steward_id", stewardID)
		return existingSteward, nil
	}

	// Story #294 Phase 1: Standalone steward mode doesn't need TLS certificates or controller connection
	// Phase 2 will add controller + MQTT broker + registration flow with certificates

	// Story #294 Phase 1: Implement standalone steward creation for E2E tests
	// Use steward.NewStandalone() like integration tests do (see test/integration/standalone_steward_test.go)

	// Create a simple YAML configuration file for standalone mode
	configPath := filepath.Join(f.tempDir, fmt.Sprintf("steward-%s-config.yaml", stewardID))
	configContent := fmt.Sprintf(`steward:
  id: %s

resources:
  # Basic test resource to verify steward works
  - name: test-directory
    module: directory
    config:
      path: %s
      state: present
      mode: "0755"
`, stewardID, filepath.Join(f.tempDir, "test-resource"))

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return nil, fmt.Errorf("failed to write steward config file: %w", err)
	}

	// Create standalone steward using the same approach as integration tests
	stwd, err := steward.NewStandalone(configPath, f.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create standalone steward %s: %w", stewardID, err)
	}

	f.stewards[stewardID] = stwd
	f.logger.Info("Created standalone steward for E2E testing", "steward_id", stewardID, "config_path", configPath)

	return stwd, nil
}

// CreateRegistrationToken generates a registration token for steward registration
// Story #294 Phase 2: Enable controller + steward registration via MQTT
func (f *E2ETestFramework) CreateRegistrationToken(tenantID string) (string, error) {
	if f.controller == nil {
		return "", fmt.Errorf("controller not initialized - cannot create registration token")
	}

	// Get the registration token store from the controller
	tokenStoreInterface := f.controller.GetRegistrationTokenStore()
	if tokenStoreInterface == nil {
		return "", fmt.Errorf("registration token store not available")
	}

	// Type assert to registration.Store
	tokenStore, ok := tokenStoreInterface.(registration.Store)
	if !ok {
		return "", fmt.Errorf("invalid registration token store type")
	}

	// Create a new registration token
	tokenReq := &registration.TokenCreateRequest{
		TenantID:      tenantID,
		ControllerURL: "grpc://localhost:4433",
		Group:         "e2e-test",
		ExpiresIn:     "",    // Never expires for testing
		SingleUse:     false, // Can be reused for testing
	}

	token, err := registration.CreateToken(tokenReq)
	if err != nil {
		return "", fmt.Errorf("failed to create registration token: %w", err)
	}

	// Save the token to the store
	if err := tokenStore.SaveToken(context.Background(), token); err != nil {
		return "", fmt.Errorf("failed to save registration token: %w", err)
	}

	f.logger.Info("Created registration token", "tenant_id", tenantID, "token", token.Token)
	return token.Token, nil
}

// RegistrationResponse represents the HTTP registration response
// Story #294 Phase 3: Used for steward registration via controller API
type RegistrationResponse struct {
	StewardID        string `json:"steward_id"`
	TenantID         string `json:"tenant_id"`
	Group            string `json:"group"`
	ControllerURL    string `json:"controller_url"`
	TransportAddress string `json:"transport_address"`
	ClientCert       string `json:"client_cert,omitempty"`
	ClientKey        string `json:"client_key,omitempty"`
	CACert           string `json:"ca_cert,omitempty"`
}

// RegisterStewardWithController performs full steward registration flow via HTTP + MQTT
// Story #294 Phase 3: Complete registration flow for E2E testing
func (f *E2ETestFramework) RegisterStewardWithController(stewardName, tenantID string) (*RegisteredSteward, error) {
	// Check if already registered (with read lock)
	f.mu.RLock()
	if existing, exists := f.registeredStewards[stewardName]; exists {
		if existing.ControlPlane != nil && existing.ControlPlane.IsConnected() {
			f.mu.RUnlock()
			f.logger.Info("Reusing existing registered steward", "steward_name", stewardName)
			return existing, nil
		}
		// Stale entry — client was disconnected (e.g., by a failover test).
		// Remove it and re-register below.
		f.mu.RUnlock()
		f.mu.Lock()
		delete(f.registeredStewards, stewardName)
		f.mu.Unlock()
		f.logger.Info("Evicting disconnected steward, will re-register", "steward_name", stewardName)
	} else {
		f.mu.RUnlock()
	}

	// Step 1: Create registration token (no lock needed)
	token, err := f.CreateRegistrationToken(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration token: %w", err)
	}

	// Step 2: POST to /api/v1/register
	// Note: HTTP API runs on separate port from gRPC (typically 9080 vs 8080)
	protocol := "http"
	if f.config.EnableTLS {
		protocol = "https"
	}
	registrationURL := fmt.Sprintf("%s://localhost:%d/api/v1/register", protocol, f.config.HTTPPort)
	reqBody := map[string]string{
		"token": token,
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12, // #nosec G402 -- TLS 1.2+ for test environment
				InsecureSkipVerify: true,             // #nosec G402 -- Test environment with self-signed certs
			},
		},
	}

	resp, err := httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("HTTP registration request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Step 3: Parse registration response
	var regResp RegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	f.logger.Info("HTTP registration successful",
		"steward_id", regResp.StewardID,
		"tenant_id", regResp.TenantID,
		"transport_address", regResp.TransportAddress)

	// Step 4: Create TLS config from registration certificates
	tlsConfig, err := f.createTLSConfigFromPEM(
		[]byte(regResp.CACert),
		[]byte(regResp.ClientCert),
		[]byte(regResp.ClientKey),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	// Step 5: Create gRPC control plane client
	controlPlane := controlplaneGRPC.New(controlplaneGRPC.ModeClient)
	if err := controlPlane.Initialize(f.ctx, map[string]interface{}{
		"addr":       regResp.TransportAddress,
		"tls_config": tlsConfig,
		"steward_id": regResp.StewardID,
		"tenant_id":  regResp.TenantID,
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize gRPC control plane: %w", err)
	}

	// Step 6: Connect to gRPC transport
	if err := controlPlane.Start(f.ctx); err != nil {
		return nil, fmt.Errorf("gRPC control plane start failed: %w", err)
	}

	f.logger.Info("gRPC control plane connected", "steward_id", regResp.StewardID)

	// Step 7: Subscribe to commands
	if err := controlPlane.SubscribeCommands(f.ctx, regResp.StewardID, func(ctx context.Context, cmd *controlplaneTypes.Command) error {
		f.logger.Info("Received command",
			"steward_id", regResp.StewardID,
			"command_id", cmd.ID,
			"type", string(cmd.Type))
		return nil
	}); err != nil {
		_ = controlPlane.Stop(f.ctx)
		return nil, fmt.Errorf("failed to subscribe to commands: %w", err)
	}

	f.logger.Info("Subscribed to commands", "steward_id", regResp.StewardID)

	// Step 8: Create RegisteredSteward and start heartbeat
	heartbeatDone := make(chan bool)
	registeredSteward := &RegisteredSteward{
		StewardID:        regResp.StewardID,
		TenantID:         regResp.TenantID,
		Group:            regResp.Group,
		ControlPlane:     controlPlane,
		TransportAddress: regResp.TransportAddress,
		ControllerURL:    regResp.ControllerURL,
		ClientCert:       regResp.ClientCert,
		ClientKey:        regResp.ClientKey,
		CACert:           regResp.CACert,
		heartbeatDone:    heartbeatDone,
	}

	// Start heartbeat publishing goroutine
	go f.publishHeartbeats(registeredSteward)

	// Store registered steward (with write lock)
	f.mu.Lock()
	f.registeredStewards[stewardName] = registeredSteward

	// Add cleanup function
	f.cleanupFuncs = append(f.cleanupFuncs, func() error {
		close(heartbeatDone)
		if controlPlane.IsConnected() {
			_ = controlPlane.Stop(context.Background())
		}
		return nil
	})
	f.mu.Unlock()

	return registeredSteward, nil
}

// createTLSConfigFromPEM creates a TLS config from PEM-encoded certificates
// Story #294 Phase 3: Helper for MQTT TLS setup
func (f *E2ETestFramework) createTLSConfigFromPEM(caCertPEM, clientCertPEM, clientKeyPEM []byte) (*tls.Config, error) {
	// Load CA certificate
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Load client certificate and key
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Create TLS config with ALPN protocol for gRPC-over-QUIC
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   "localhost",                    // Connect via localhost in tests
		NextProtos:   []string{quictransport.ALPNProtocol}, // Required for QUIC transport
	}

	return tlsConfig, nil
}

// publishHeartbeats sends periodic heartbeat messages via the gRPC control plane
// Story #294 Phase 3: Heartbeat mechanism for failover detection
func (f *E2ETestFramework) publishHeartbeats(steward *RegisteredSteward) {
	ticker := time.NewTicker(30 * time.Second) // Production interval
	defer ticker.Stop()

	sequence := 0
	ctx := context.Background()
	for {
		select {
		case <-steward.heartbeatDone:
			f.logger.Info("Stopping heartbeat publishing", "steward_id", steward.StewardID)
			return
		case <-ticker.C:
			sequence++
			if err := steward.ControlPlane.SendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
				StewardID: steward.StewardID,
				TenantID:  steward.TenantID,
				Status:    controlplaneTypes.StatusHealthy,
				Timestamp: time.Now(),
				Metrics: map[string]interface{}{
					"sequence": sequence,
				},
			}); err != nil {
				f.logger.Error("Heartbeat send failed", "steward_id", steward.StewardID, "error", err)
				continue
			}
			f.logger.Debug("Heartbeat sent", "steward_id", steward.StewardID, "sequence", sequence)
		}
	}
}

// RunTest executes a single test scenario with metrics collection and smart retry
func (f *E2ETestFramework) RunTest(name, category string, testFunc func() error) error {
	startTime := time.Now()
	f.logger.Info("Running test", "name", name, "category", category)

	// Get optimization settings for this test category
	optimizer := NewGitHubActionsOptimizer(f.config)
	optimization := optimizer.OptimizeTestExecution(category)

	// Check if test should be skipped
	if !optimization.Enabled {
		f.logger.Info("Test skipped", "name", name, "reason", optimization.SkipReason)
		result := TestResult{
			Name:     name,
			Category: category,
			Duration: time.Since(startTime),
			Success:  true, // Skipped tests are considered "success" for metrics
			Error:    "SKIPPED: " + optimization.SkipReason,
		}

		f.metrics.mu.Lock()
		f.metrics.TestResults = append(f.metrics.TestResults, result)
		f.metrics.mu.Unlock()

		return nil
	}

	var testError error
	attempt := 1
	maxRetries := optimization.MaxRetries

	// Execute test with retry logic
	for attempt <= maxRetries {
		if attempt > 1 {
			f.logger.Info("Retrying test", "name", name, "attempt", attempt, "max_retries", maxRetries)
			time.Sleep(optimization.RetryDelay)
		}

		// Execute test with timeout
		testChan := make(chan error, 1)
		go func() {
			testChan <- testFunc()
		}()

		select {
		case testError = <-testChan:
			// Test completed normally
		case <-time.After(optimization.Timeout):
			testError = fmt.Errorf("test timeout after %v", optimization.Timeout)
		}

		// Check if we should retry
		if testError == nil || !optimizer.ShouldRetryTest(name, attempt, testError) {
			break
		}

		attempt++
	}

	// Record final result
	defer func() {
		duration := time.Since(startTime)
		success := testError == nil

		result := TestResult{
			Name:     name,
			Category: category,
			Duration: duration,
			Success:  success,
		}

		if testError != nil {
			result.Error = testError.Error()
		}

		// Add retry information to metrics
		if attempt > 1 {
			if result.Metrics == nil {
				result.Metrics = make(map[string]interface{})
			}
			result.Metrics["retry_attempts"] = attempt - 1
			result.Metrics["max_retries"] = maxRetries
		}

		f.metrics.mu.Lock()
		f.metrics.TestResults = append(f.metrics.TestResults, result)
		f.metrics.mu.Unlock()

		status := "PASS"
		if !success {
			status = "FAIL"
		}

		retryInfo := ""
		if attempt > 1 {
			retryInfo = fmt.Sprintf(" (after %d retries)", attempt-1)
		}

		f.logger.Info("Test completed",
			"name", name,
			"status", status,
			"duration", duration,
			"attempts", attempt,
			"retry_info", retryInfo)
	}()

	return testError
}

// GetMetrics returns the current test metrics
func (f *E2ETestFramework) GetMetrics() *TestMetrics {
	f.metrics.mu.RLock()
	defer f.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := &TestMetrics{
		StartTime:           f.metrics.StartTime,
		ComponentStartTimes: make(map[string]time.Time),
		TestResults:         make([]TestResult, len(f.metrics.TestResults)),
		PerformanceMetrics:  f.metrics.PerformanceMetrics,
		ResourceUsage:       f.metrics.ResourceUsage,
	}

	for k, v := range f.metrics.ComponentStartTimes {
		metrics.ComponentStartTimes[k] = v
	}

	copy(metrics.TestResults, f.metrics.TestResults)

	return metrics
}

// GetTestDataGenerator returns the test data generator for use in scenarios
func (f *E2ETestFramework) GetTestDataGenerator() *TestDataGenerator {
	return f.dataGenerator
}

// Cleanup cleans up all resources
func (f *E2ETestFramework) Cleanup() error {
	f.logger.Info("Cleaning up E2E test framework")

	// Cancel context to stop all components
	f.cancel()

	var errors []error

	// Run cleanup functions in reverse order
	for i := len(f.cleanupFuncs) - 1; i >= 0; i-- {
		if err := f.cleanupFuncs[i](); err != nil {
			errors = append(errors, err)
		}
	}

	// Remove temporary directory
	if err := os.RemoveAll(f.tempDir); err != nil {
		errors = append(errors, fmt.Errorf("failed to remove temp dir: %w", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %v", errors)
	}

	return nil
}

// Helper methods

func (f *E2ETestFramework) addCleanup(fn func() error) {
	f.cleanupFuncs = append(f.cleanupFuncs, fn)
}

func (f *E2ETestFramework) createTestTenants() error {
	// Implementation would create test tenants and users
	// Simplified for this example
	return nil
}

func (f *E2ETestFramework) generateTestData() error {
	f.logger.Info("Generating test data", "size", f.config.TestDataSize)

	// Generate tenant data for RBAC testing
	if f.config.EnableRBAC {
		tenantData := f.dataGenerator.GenerateTestTenantData()
		f.logger.Debug("Generated tenant test data", "tenants", len(tenantData))
	}

	// Generate performance test data if enabled
	if f.config.PerformanceMode {
		perfData := f.dataGenerator.GeneratePerformanceTestData()
		f.logger.Debug("Generated performance test data",
			"stewards", perfData.ConcurrentStewards,
			"rps", perfData.RequestsPerSecond,
			"duration", perfData.TestDurationSeconds)
	}

	// Generate multiple steward configs for scalability testing
	stewardCount := 1
	switch f.config.TestDataSize {
	case "medium":
		stewardCount = 3
	case "large":
		stewardCount = 5
	}

	testConfigs := f.dataGenerator.GenerateMultipleStewardConfigs(stewardCount)
	f.logger.Debug("Generated steward configurations", "count", len(testConfigs))

	return nil
}

// DefaultE2EConfig returns the default configuration optimized for CI/CD
func DefaultE2EConfig() *E2EConfig {
	return &E2EConfig{
		TestTimeout:        10 * time.Minute, // Generous for CI
		ComponentStartup:   30 * time.Second, // Allow time for startup
		MaxConcurrentTests: 2,                // Conservative for CI
		ControllerPort:     8080,             // gRPC server port
		HTTPPort:           9080,             // HTTP API server port
		EnableTLS:          true,
		EnableRBAC:         true,
		EnableTerminal:     true,
		EnableWorkflow:     true,
		GenerateTestData:   true,
		TestDataSize:       "small", // Small dataset for CI speed
		OptimizeForCI:      true,
		ParallelExecution:  false, // Serial execution for reliability
		ReducedLogging:     true,  // Reduce noise in CI logs
		PerformanceMode:    false, // Performance tests separate
		LoadTestDuration:   1 * time.Minute,
		MaxConnections:     10,
	}
}

// CIOptimizedConfig returns configuration optimized for GitHub Actions
func CIOptimizedConfig() *E2EConfig {
	config := DefaultE2EConfig()

	// Apply GitHub Actions specific optimizations
	optimizer := NewGitHubActionsOptimizer(config)
	optimizedConfig := optimizer.OptimizeForGitHubActions()

	// Additional CI-specific settings
	optimizedConfig.OptimizeForCI = true
	optimizedConfig.ReducedLogging = true

	return optimizedConfig
}

// LocalDevelopmentConfig returns configuration optimized for local development
func LocalDevelopmentConfig() *E2EConfig {
	config := DefaultE2EConfig()
	config.TestTimeout = 30 * time.Minute // More time for debugging
	config.TestDataSize = "medium"        // Larger dataset for thorough testing
	config.OptimizeForCI = false
	config.ReducedLogging = false   // Full logging for development
	config.ParallelExecution = true // Can use more resources locally
	config.MaxConcurrentTests = 4   // More concurrent tests
	return config
}

// Component accessor methods for integration tests

func (f *E2ETestFramework) getTemplateEngine() interface{} {
	// In real implementation, would return actual template engine
	// For now, return nil to trigger simulation mode
	return nil
}

func (f *E2ETestFramework) getWorkflowEngine() *workflow.Engine {
	return f.workflowEngine
}

func (f *E2ETestFramework) getDNAStorage() interface{} {
	// In real implementation, would return actual DNA storage
	// For now, return nil to trigger simulation mode
	return nil
}

func (f *E2ETestFramework) getDriftDetector() interface{} {
	// In real implementation, would return actual drift detector
	// For now, return nil to trigger simulation mode
	return nil
}

func (f *E2ETestFramework) getRollbackManager() interface{} {
	// In real implementation, would return actual rollback manager
	// For now, return nil to trigger simulation mode
	return nil
}

func (f *E2ETestFramework) getRBACManager() rbac.RBACManager {
	return f.rbacManager
}

func (f *E2ETestFramework) getTerminalManager() terminal.SessionManager {
	return f.terminalMgr
}

func (f *E2ETestFramework) getAuditManager() interface{} {
	// In real implementation, would return actual audit manager
	// For now, return nil to trigger simulation mode
	return nil
}

func (f *E2ETestFramework) getTenantManager() interface{} {
	// In real implementation, would return actual tenant manager
	// For now, return nil to trigger simulation mode
	return nil
}

func (f *E2ETestFramework) getConfigService() interface{} {
	// In real implementation, would return actual config service
	// For now, return nil to trigger simulation mode
	return nil
}

// Performance and metrics methods

func (f *E2ETestFramework) recordLatencyMetric(operation string, latency time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.metrics.LatencyMetrics == nil {
		f.metrics.LatencyMetrics = make(map[string][]time.Duration)
	}

	f.metrics.LatencyMetrics[operation] = append(f.metrics.LatencyMetrics[operation], latency)

	f.logger.Info("Latency metric recorded",
		"operation", operation,
		"latency", latency,
		"samples", len(f.metrics.LatencyMetrics[operation]))
}
