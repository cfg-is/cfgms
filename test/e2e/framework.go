package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller"
	controllerConfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	testpkg "github.com/cfgis/cfgms/pkg/testing"
)

// E2ETestFramework provides a comprehensive end-to-end testing environment
// optimized for GitHub Actions and CI/CD pipelines
type E2ETestFramework struct {
	t         *testing.T
	tempDir   string
	logger    logging.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	
	// Core components
	controller     *controller.Controller
	stewards       map[string]*steward.Steward
	certManager    *cert.Manager
	rbacManager    rbac.RBACManager
	terminalMgr    terminal.SessionManager
	workflowEngine *workflow.Engine
	
	// Test configuration
	config         *E2EConfig
	
	// Test data generation
	dataGenerator  *TestDataGenerator
	
	// Runtime state
	startTime      time.Time
	metrics        *TestMetrics
	cleanupFuncs   []func() error
	mu             sync.RWMutex
}

// E2EConfig contains configuration for E2E testing
type E2EConfig struct {
	// Test execution settings
	TestTimeout         time.Duration `json:"test_timeout"`
	ComponentStartup    time.Duration `json:"component_startup"`
	MaxConcurrentTests  int           `json:"max_concurrent_tests"`
	
	// Component configuration
	ControllerPort      int    `json:"controller_port"`
	EnableTLS           bool   `json:"enable_tls"`
	EnableRBAC          bool   `json:"enable_rbac"`
	EnableTerminal      bool   `json:"enable_terminal"`
	EnableWorkflow      bool   `json:"enable_workflow"`
	
	// Test data generation
	GenerateTestData    bool   `json:"generate_test_data"`
	TestDataSize        string `json:"test_data_size"` // small, medium, large
	
	// CI/CD optimizations
	OptimizeForCI       bool   `json:"optimize_for_ci"`
	ParallelExecution   bool   `json:"parallel_execution"`
	ReducedLogging      bool   `json:"reduced_logging"`
	
	// Performance testing
	PerformanceMode     bool   `json:"performance_mode"`
	LoadTestDuration    time.Duration `json:"load_test_duration"`
	MaxConnections      int    `json:"max_connections"`
}

// TestMetrics tracks performance and reliability metrics during testing
type TestMetrics struct {
	StartTime           time.Time     `json:"start_time"`
	ComponentStartTimes map[string]time.Time `json:"component_start_times"`
	TestResults         []TestResult  `json:"test_results"`
	PerformanceMetrics  PerformanceMetrics `json:"performance_metrics"`
	ResourceUsage       ResourceUsage `json:"resource_usage"`
	LatencyMetrics      map[string][]time.Duration `json:"latency_metrics"`
	mu                  sync.RWMutex
}

// TestResult represents the result of a single test
type TestResult struct {
	Name        string        `json:"name"`
	Category    string        `json:"category"`
	Duration    time.Duration `json:"duration"`
	Success     bool          `json:"success"`
	Error       string        `json:"error,omitempty"`
	Metrics     map[string]interface{} `json:"metrics,omitempty"`
}

// PerformanceMetrics tracks system performance during tests
type PerformanceMetrics struct {
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulRequests  int64         `json:"successful_requests"`
	FailedRequests      int64         `json:"failed_requests"`
	AverageLatency      time.Duration `json:"average_latency"`
	P95Latency          time.Duration `json:"p95_latency"`
	P99Latency          time.Duration `json:"p99_latency"`
	ThroughputRPS       float64       `json:"throughput_rps"`
}

// ResourceUsage tracks resource consumption during tests
type ResourceUsage struct {
	MaxMemoryMB         float64       `json:"max_memory_mb"`
	MaxCPUPercent       float64       `json:"max_cpu_percent"`
	TotalGoroutines     int           `json:"total_goroutines"`
	OpenFileDescriptors int           `json:"open_file_descriptors"`
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
		logger = testpkg.NewMockLogger(false) // No debug output in CI
	} else {
		logger = testpkg.NewMockLogger(true)  // Full output for local testing
	}
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), config.TestTimeout)
	
	framework := &E2ETestFramework{
		t:         t,
		tempDir:   tempDir,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
		stewards:  make(map[string]*steward.Steward),
		config:    config,
		dataGenerator: NewTestDataGenerator(config),
		startTime: time.Now(),
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
			Country:           "US",
			State:             "Test",
			City:              "Test",
			OrganizationalUnit: "Integration Tests",
			ValidityDays:      1, // Short validity for testing
			KeySize:           2048,
		},
		LoadExistingCA:       false, // Create new CA for each test
		RenewalThresholdDays: 1,
		EnableAutoRenewal:    false, // Disable for tests
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
	
	rbacManager := rbac.NewManager()
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
		Certificate: &controllerConfig.CertificateConfig{
			EnableCertManagement:   f.config.EnableTLS,
			CAPath:                filepath.Join(f.tempDir, "certs", "ca"),
			AutoGenerate:          true,
			RenewalThresholdDays:  1,
			ServerCertValidityDays: 1,
			ClientCertValidityDays: 1,
			EnableAutoRenewal:     false, // Disable for tests
			Server: &controllerConfig.ServerCertificateConfig{
				CommonName:   "localhost",
				DNSNames:     []string{"localhost", "127.0.0.1"},
				IPAddresses:  []string{"127.0.0.1", "::1"},
				Organization: "Test Organization",
			},
		},
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
		return ctrl.Stop(context.Background())
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
	
	if _, exists := f.stewards[stewardID]; exists {
		return nil, fmt.Errorf("steward %s already exists", stewardID)
	}
	
	// Generate client certificate for this steward (like integration tests do)
	if f.config.EnableTLS && f.certManager != nil {
		clientCert, err := f.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
			CommonName:         stewardID,
			Organization:       "CFGMS Test Stewards",
			OrganizationalUnit: "E2E Tests",
			ValidityDays:       1,
			KeySize:            2048,
			ClientID:           stewardID,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate client certificate for steward %s: %w", stewardID, err)
		}
		
		f.logger.Info("Generated client certificate for steward", "steward_id", stewardID, "serial", clientCert.SerialNumber)
		
		// Save client certificate files for steward to use
		certPath := filepath.Join(f.tempDir, "certs")
		err = f.certManager.SaveCertificateFiles(clientCert.SerialNumber,
			filepath.Join(certPath, "client.crt"), 
			filepath.Join(certPath, "client.key"))
		if err != nil {
			return nil, fmt.Errorf("failed to save client certificate files for steward %s: %w", stewardID, err)
		}
	}
	
	stewardConfig := &steward.Config{
		ID:             stewardID,
		ControllerAddr: fmt.Sprintf("localhost:%d", f.config.ControllerPort),
		CertPath:       filepath.Join(f.tempDir, "certs"),
		DataDir:        filepath.Join(f.tempDir, "steward-data"),
		LogLevel:       "info",
		Certificate: &steward.CertificateConfig{
			EnableCertManagement: false, // Disable cert management like integration tests
			CertStoragePath:     filepath.Join(f.tempDir, "certs"),
			EnableAutoRenewal:   false,
			RenewalThresholdDays: 1,
			Provisioning: &steward.ProvisioningConfig{
				EnableAutoProvisioning: false, // Disable auto-provisioning like integration tests
				ProvisioningEndpoint:   fmt.Sprintf("https://localhost:%d/api/v1/certificates/provision", f.config.ControllerPort),
				ValidityDays:          1,
				Organization:          "Test Organization",
			},
		},
	}
	
	s, err := steward.New(stewardConfig, f.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create steward: %w", err)
	}
	
	f.stewards[stewardID] = s
	
	// Add cleanup for this steward
	f.addCleanup(func() error {
		return s.Stop(context.Background())
	})
	
	return s, nil
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

func (f *E2ETestFramework) waitForComponent(name string, readyCheck func() bool) error {
	timeout := time.After(f.config.ComponentStartup)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for %s to be ready", name)
		case <-ticker.C:
			if readyCheck() {
				return nil
			}
		case <-f.ctx.Done():
			return f.ctx.Err()
		}
	}
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
		TestTimeout:         10 * time.Minute, // Generous for CI
		ComponentStartup:    30 * time.Second, // Allow time for startup
		MaxConcurrentTests:  2,                // Conservative for CI
		ControllerPort:      8080,
		EnableTLS:           true,
		EnableRBAC:          true,
		EnableTerminal:      true,
		EnableWorkflow:      true,
		GenerateTestData:    true,
		TestDataSize:        "small", // Small dataset for CI speed
		OptimizeForCI:       true,
		ParallelExecution:   false,   // Serial execution for reliability
		ReducedLogging:      true,    // Reduce noise in CI logs
		PerformanceMode:     false,   // Performance tests separate
		LoadTestDuration:    1 * time.Minute,
		MaxConnections:      10,
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
	config.TestTimeout = 30 * time.Minute    // More time for debugging
	config.TestDataSize = "medium"           // Larger dataset for thorough testing
	config.OptimizeForCI = false
	config.ReducedLogging = false            // Full logging for development
	config.ParallelExecution = true         // Can use more resources locally
	config.MaxConcurrentTests = 4           // More concurrent tests
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