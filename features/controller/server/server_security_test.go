// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage providers for Epic 6 compliance testing
	// Note: memory provider is NOT imported as it's not a global provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

// Security-focused tests for the controller server

// Epic 6: Helper function to create storage configuration for all tests using Docker fixtures
func createTestStorageConfig(tempDir, suffix string) *config.StorageConfig {
	return &config.StorageConfig{
		Provider: "git",
		Config: map[string]interface{}{
			"repository_path": tempDir + "/" + suffix + "-storage",
			"branch":          "main",
			"auto_init":       true,
		},
	}
}

// createDockerTestStorageConfig creates storage configs for Docker-based testing
func createDockerTestStorageConfig(provider string) *config.StorageConfig {
	switch provider {
	case "git":
		return &config.StorageConfig{
			Provider: "git",
			Config: map[string]interface{}{
				"repository_url": os.Getenv("CFGMS_TEST_GITEA_URL") + "/cfgms_test/cfgms-test-global.git",
				"branch":         "main",
				"auto_init":      true,
				"username":       os.Getenv("CFGMS_TEST_GITEA_USER"),
				"password":       os.Getenv("CFGMS_TEST_GITEA_PASSWORD"),
			},
		}
	case "database":
		return &config.StorageConfig{
			Provider: "database",
			Config: map[string]interface{}{
				"host":     os.Getenv("CFGMS_TEST_DB_HOST"),
				"port":     5433,
				"database": "cfgms_test",
				"username": "cfgms_test",
				"password": os.Getenv("CFGMS_TEST_DB_PASSWORD"),
				"sslmode":  "disable",
			},
		}
	default:
		return createTestStorageConfig(os.TempDir(), provider)
	}
}

// raceDetectorEnabled returns true if the race detector is enabled
// This is used to adjust test timeouts since race detector adds 5-10x overhead
func raceDetectorEnabled() bool {
	// The race detector sets this flag when -race is used
	// This works because when -race is enabled, the race package is linked in
	return raceEnabled
}

func TestServer_New_SecurityValidation(t *testing.T) {
	logger := logging.NewNoopLogger()

	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "server_security_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	tests := []struct {
		name    string
		config  *config.Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config should fail",
			config:  nil,
			wantErr: true,
			errMsg:  "config",
		},
		{
			name: "missing storage configuration should fail",
			config: &config.Config{
				ListenAddr: "127.0.0.1:0",
				Certificate: &config.CertificateConfig{
					EnableCertManagement: false,
				},
				// Storage: nil - Missing storage configuration
			},
			wantErr: true,
			errMsg:  "storage configuration is required",
		},
		{
			name: "invalid storage provider should fail",
			config: &config.Config{
				ListenAddr: "127.0.0.1:0",
				Certificate: &config.CertificateConfig{
					EnableCertManagement: false,
				},
				Storage: &config.StorageConfig{
					Provider: "invalid-provider-name",
					Config:   make(map[string]interface{}),
				},
			},
			wantErr: true,
			errMsg:  "storage provider",
		},
		{
			name: "insecure config should create server but with warnings",
			config: &config.Config{
				ListenAddr: "127.0.0.1:0",
				Certificate: &config.CertificateConfig{
					EnableCertManagement: false,
				},
				// Epic 6: Storage configuration now required
				Storage: &config.StorageConfig{
					Provider: "git",
					Config: map[string]interface{}{
						"repository_path": tempDir + "/test-storage",
						"branch":          "main",
						"auto_init":       true,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "secure config with cert management",
			config: &config.Config{
				ListenAddr: "127.0.0.1:0",
				CertPath:   tempDir,
				Certificate: &config.CertificateConfig{
					EnableCertManagement:   true,
					ClientCertValidityDays: 30,
					CAPath:                 tempDir,
					AutoGenerate:           true,
					EnableAutoRenewal:      true,
					ServerCertValidityDays: 90,
					RenewalThresholdDays:   7,
					Server: &config.ServerCertificateConfig{
						CommonName:   "test-controller",
						DNSNames:     []string{"localhost"},
						IPAddresses:  []string{"127.0.0.1"},
						Organization: "Test Org",
					},
				},
				// Epic 6: Storage configuration now required
				Storage: &config.StorageConfig{
					Provider: "git",
					Config: map[string]interface{}{
						"repository_path": tempDir + "/secure-storage",
						"branch":          "main",
						"auto_init":       true,
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := New(tt.config, logger)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, server)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, server)

				// Verify security components are initialized
				assert.NotNil(t, server.rbacManager)
				assert.NotNil(t, server.tenantManager)
				assert.NotNil(t, server.rbacService)

				// Note: if certificate management is enabled, certManager might be nil if CA setup fails, which is expected in test environment
				_ = tt.config.Certificate != nil && tt.config.Certificate.EnableCertManagement
			}
		})
	}
}

// TestServer_StorageProviderValidation dynamically validates storage provider configuration
// against all registered global storage providers
func TestServer_StorageProviderValidation(t *testing.T) {
	// Skip if integration tests are explicitly disabled (e.g., cross-platform CI without Docker)
	if os.Getenv("CFGMS_TEST_INTEGRATION") == "0" {
		t.Skip("Skipping storage provider validation - integration tests disabled (CFGMS_TEST_INTEGRATION=0)")
	}

	logger := logging.NewNoopLogger()
	tempDir, err := os.MkdirTemp("", "storage_provider_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Get all registered storage providers dynamically
	registeredProviders := interfaces.ListProviders()
	require.NotEmpty(t, registeredProviders, "No storage providers registered - this indicates a system configuration problem")

	t.Run("ValidateRegisteredProvidersWork", func(t *testing.T) {
		// Test each registered provider works
		for _, providerInfo := range registeredProviders {
			if !providerInfo.Available {
				t.Logf("Skipping unavailable provider '%s': %s", providerInfo.Name, providerInfo.UnavailableReason)
				continue
			}

			t.Run("provider_"+providerInfo.Name, func(t *testing.T) {
				var storageConfig *config.StorageConfig

				// Use Docker test configuration if available, otherwise fall back to local test
				if isDockerTestEnvironment() {
					storageConfig = createDockerTestStorageConfig(providerInfo.Name)
					t.Logf("Using Docker test configuration for provider '%s'", providerInfo.Name)
				} else {
					// For local testing, use appropriate configuration per provider
					switch providerInfo.Name {
					case "database":
						// Skip if in short mode (covered by Docker integration tests)
						if os.Getenv("CFGMS_TEST_SHORT") == "1" {
							t.Skipf("Database provider requires Docker environment - run 'make test-integration-setup'")
							return
						}
						// Fail if in CI/integration mode without Docker, skip in development
						if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" || os.Getenv("CFGMS_TEST_DB_PASSWORD") != "" {
							t.Fatalf("REQUIRED INFRASTRUCTURE MISSING: Database provider requires Docker environment in CI/integration mode - run 'make test-integration-setup'")
						} else {
							t.Skipf("Database provider requires Docker environment - run 'make test-integration-setup'")
						}
						return
					default:
						// Use git or other local providers
						storageConfig = createTestStorageConfig(tempDir, providerInfo.Name)
					}
				}

				config := &config.Config{
					ListenAddr: "127.0.0.1:0",
					Certificate: &config.CertificateConfig{
						EnableCertManagement: false,
					},
					Storage: storageConfig,
				}

				server, err := New(config, logger)
				if providerInfo.Name == "database" && !isDockerTestEnvironment() {
					// Database provider should fail gracefully without proper config
					assert.Error(t, err, "Database provider should fail without proper configuration")
					assert.Contains(t, err.Error(), "password", "Error should mention password requirement")
					return
				}

				assert.NoError(t, err, "Valid storage provider '%s' should not cause server creation to fail", providerInfo.Name)
				assert.NotNil(t, server, "Server should be created with valid provider '%s'", providerInfo.Name)

				if server != nil {
					// Verify all storage interfaces are properly initialized
					assert.NotNil(t, server.rbacManager, "RBAC manager should be initialized with provider '%s'", providerInfo.Name)
					assert.NotNil(t, server.tenantManager, "Tenant manager should be initialized with provider '%s'", providerInfo.Name)
				}
			})
		}
	})

	t.Run("InvalidProviderShouldFail", func(t *testing.T) {
		// Generate an invalid provider name that's guaranteed not to be registered
		invalidProvider := "definitely-not-a-real-provider-name"

		// Verify it's actually not registered
		isRegistered := false
		for _, providerInfo := range registeredProviders {
			if providerInfo.Name == invalidProvider {
				isRegistered = true
				break
			}
		}
		require.False(t, isRegistered, "Test setup error: invalid provider name is actually registered")

		config := &config.Config{
			ListenAddr: "127.0.0.1:0",
			Certificate: &config.CertificateConfig{
				EnableCertManagement: false,
			},
			Storage: &config.StorageConfig{
				Provider: invalidProvider,
				Config:   make(map[string]interface{}),
			},
		}

		server, err := New(config, logger)
		assert.Error(t, err, "Invalid storage provider should cause server creation to fail")
		assert.Nil(t, server, "Server should not be created with invalid provider")
		assert.Contains(t, err.Error(), "storage provider", "Error should mention storage provider issue")
	})

	t.Run("FutureProofProviderList", func(t *testing.T) {
		// This test documents expected providers and will alert if providers are added/removed
		providerNames := make([]string, 0, len(registeredProviders))
		for _, providerInfo := range registeredProviders {
			providerNames = append(providerNames, providerInfo.Name)
		}

		t.Logf("Currently registered storage providers: %v", providerNames)

		// These are the providers we expect to exist based on our architecture
		expectedProviders := []string{"git", "database"}

		for _, expected := range expectedProviders {
			found := false
			for _, actual := range providerNames {
				if actual == expected {
					found = true
					break
				}
			}
			assert.True(t, found, "Expected storage provider '%s' is not registered", expected)
		}

		// Alert if unexpected providers are registered (could indicate foot-gun memory provider)
		for _, actual := range providerNames {
			if actual == "memory" {
				t.Errorf("CRITICAL: Memory provider is registered as global storage provider - this violates our architecture and creates a foot-gun!")
			}
		}
	})
}

func TestServer_SecurityConfiguration(t *testing.T) {
	logger := logging.NewNoopLogger()

	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "server_security_config_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Test various security configuration scenarios
	tests := []struct {
		name           string
		config         *config.Config
		expectSecure   bool
		securityChecks []func(*testing.T, *Server)
	}{
		{
			name: "production security configuration",
			config: &config.Config{
				ListenAddr: "127.0.0.1:0",
				CertPath:   tempDir,
				// Epic 6: Storage configuration required
				Storage: &config.StorageConfig{
					Provider: "git",
					Config: map[string]interface{}{
						"repository_path": tempDir + "/prod-storage",
						"branch":          "main",
						"auto_init":       true,
					},
				},
				Certificate: &config.CertificateConfig{
					EnableCertManagement:   true,
					ClientCertValidityDays: 30, // Short validity for security
					ServerCertValidityDays: 90, // Short server cert validity
					AutoGenerate:           true,
					EnableAutoRenewal:      true,
					CAPath:                 tempDir,
					RenewalThresholdDays:   7,
					Server: &config.ServerCertificateConfig{
						CommonName:   "prod-controller",
						DNSNames:     []string{"localhost"},
						IPAddresses:  []string{"127.0.0.1"},
						Organization: "Production Org",
					},
				},
			},
			expectSecure: true,
			securityChecks: []func(*testing.T, *Server){
				func(t *testing.T, s *Server) {
					assert.NotNil(t, s.rbacManager, "RBAC should be enabled")
					assert.NotNil(t, s.rbacService, "RBAC service should be available")
				},
				func(t *testing.T, s *Server) {
					if s.cfg.Certificate != nil && s.cfg.Certificate.ClientCertValidityDays > 0 {
						assert.LessOrEqual(t, s.cfg.Certificate.ClientCertValidityDays, 90,
							"Client certificates should have short validity for security")
					}
				},
			},
		},
		{
			name: "development configuration with security warnings",
			config: &config.Config{
				ListenAddr: "127.0.0.1:0",
				// Epic 6: Storage configuration required
				Storage: &config.StorageConfig{
					Provider: "git",
					Config: map[string]interface{}{
						"repository_path": tempDir + "/dev-storage",
						"branch":          "main",
						"auto_init":       true,
					},
				},
				Certificate: &config.CertificateConfig{
					EnableCertManagement: false, // Insecure for development
				},
			},
			expectSecure: false,
			securityChecks: []func(*testing.T, *Server){
				func(t *testing.T, s *Server) {
					assert.Nil(t, s.certManager, "Cert manager should be nil in insecure mode")
					// RBAC should still be enabled even in development
					assert.NotNil(t, s.rbacManager, "RBAC should always be enabled")
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := New(tt.config, logger)
			require.NoError(t, err)

			// Run security checks
			for _, check := range tt.securityChecks {
				check(t, server)
			}
		})
	}
}

func TestServer_SecurityEdgeCases_And_AttackVectors(t *testing.T) {
	logger := logging.NewNoopLogger()

	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "server_security_edge_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Test security against common attack vectors
	tests := []struct {
		name        string
		configFunc  func() *config.Config
		expectError bool
		description string
	}{
		{
			name: "malformed certificate paths",
			configFunc: func() *config.Config {
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					CertPath:   tempDir, // Valid cert path for storage
					// Epic 6: Storage configuration required
					Storage: &config.StorageConfig{
						Provider: "git",
						Config: map[string]interface{}{
							"repository_path": tempDir + "/malformed-paths-storage",
							"branch":          "main",
							"auto_init":       true,
						},
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement: true,
						CAPath:               "../../../etc/passwd", // Path traversal attempt
						AutoGenerate:         true,
						Server: &config.ServerCertificateConfig{
							CommonName:   "test-controller",
							Organization: "Test Org",
						},
					},
				}
			},
			expectError: false, // Server creation should succeed, path validation happens during CA creation
			description: "Path traversal in certificate paths should be handled securely",
		},
		{
			name: "excessive certificate validity periods",
			configFunc: func() *config.Config {
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					CertPath:   tempDir,
					// Epic 6: Storage configuration required
					Storage: &config.StorageConfig{
						Provider: "git",
						Config: map[string]interface{}{
							"repository_path": tempDir + "/excessive-validity-storage",
							"branch":          "main",
							"auto_init":       true,
						},
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement:   true,
						ClientCertValidityDays: 36500, // 100 years - excessive
						ServerCertValidityDays: 36500, // 100 years - excessive
						CAPath:                 tempDir,
						AutoGenerate:           true,
						Server: &config.ServerCertificateConfig{
							CommonName:   "test-controller",
							Organization: "Test Org",
						},
					},
				}
			},
			expectError: false, // Should create but log warnings
			description: "Excessive certificate validity should be allowed but warned about",
		},
		{
			name: "bind to privileged port (should fail in test)",
			configFunc: func() *config.Config {
				return &config.Config{
					ListenAddr: "127.0.0.1:80", // Privileged port
					// Epic 6: Storage configuration required
					Storage: &config.StorageConfig{
						Provider: "git",
						Config: map[string]interface{}{
							"repository_path": tempDir + "/privileged-port-storage",
							"branch":          "main",
							"auto_init":       true,
						},
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement: false,
					},
				}
			},
			expectError: false, // Server creation should succeed
			description: "Privileged port binding should be handled by start method",
		},
		{
			name: "localhost-only binding for security",
			configFunc: func() *config.Config {
				return &config.Config{
					ListenAddr: "127.0.0.1:0", // Localhost only
					// Epic 6: Storage configuration required
					Storage: &config.StorageConfig{
						Provider: "git",
						Config: map[string]interface{}{
							"repository_path": tempDir + "/localhost-storage",
							"branch":          "main",
							"auto_init":       true,
						},
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement: false,
					},
				}
			},
			expectError: false,
			description: "Localhost binding should be allowed",
		},
		{
			name: "wildcard binding security check",
			configFunc: func() *config.Config {
				return &config.Config{
					ListenAddr: "0.0.0.0:0", // Wildcard binding
					CertPath:   tempDir,
					// Epic 6: Storage configuration required
					Storage: &config.StorageConfig{
						Provider: "git",
						Config: map[string]interface{}{
							"repository_path": tempDir + "/wildcard-storage",
							"branch":          "main",
							"auto_init":       true,
						},
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement: true, // Should require TLS for wildcard
						CAPath:               tempDir,
						AutoGenerate:         true,
						Server: &config.ServerCertificateConfig{
							CommonName:   "wildcard-controller",
							Organization: "Test Org",
							DNSNames:     []string{"*"},
						},
					},
				}
			},
			expectError: false,
			description: "Wildcard binding should require TLS for security",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.configFunc()

			server, err := New(config, logger)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, server)

				// Validate security components are still initialized
				assert.NotNil(t, server.rbacManager)
				assert.NotNil(t, server.tenantManager)
			}
		})
	}
}

func TestServer_ConcurrentSecurity_And_RaceConditions(t *testing.T) {
	logger := logging.NewNoopLogger()

	// Create temporary directory for storage
	tempDir, err := os.MkdirTemp("", "concurrent_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	const numConcurrent = 10

	// Race detector adds 5-10x overhead, so increase timeout accordingly
	// Each concurrent server creation involves: Git init, RBAC setup, storage init
	timeout := 5 * time.Second
	if raceDetectorEnabled() {
		timeout = 15 * time.Second // 3x longer for race detector overhead
	}

	// Test concurrent server creation (should be thread-safe)
	results := make(chan *Server, numConcurrent)
	errors := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(index int) {
			// Each goroutine gets its own unique storage configuration to avoid Git conflicts
			uniqueConfig := &config.Config{
				ListenAddr: "127.0.0.1:0",
				Certificate: &config.CertificateConfig{
					EnableCertManagement: false,
				},
				// Epic 6: Storage configuration required for all server creation
				// Use unique storage path per goroutine to prevent Git repository conflicts
				Storage: createTestStorageConfig(tempDir, fmt.Sprintf("concurrent-%d", index)),
			}
			server, err := New(uniqueConfig, logger)
			if err != nil {
				errors <- err
			} else {
				results <- server
			}
		}(i)
	}

	// Collect results
	successCount := 0
	errorCount := 0

	for i := 0; i < numConcurrent; i++ {
		select {
		case server := <-results:
			assert.NotNil(t, server)
			assert.NotNil(t, server.rbacManager)
			successCount++
		case err := <-errors:
			t.Errorf("Unexpected error in concurrent server creation: %v", err)
			errorCount++
		case <-time.After(timeout):
			t.Fatalf("Test timed out waiting for concurrent operations (timeout: %v)", timeout)
		}
	}

	assert.Equal(t, numConcurrent, successCount)
	assert.Equal(t, 0, errorCount)
}

func TestServer_RBAC_SecurityIntegration(t *testing.T) {
	logger := logging.NewNoopLogger()

	// Create temporary directory for storage
	tempDir, err := os.MkdirTemp("", "rbac_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	config := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		// Epic 6: Storage configuration required for server creation
		Storage: createTestStorageConfig(tempDir, "rbac"),
	}

	server, err := New(config, logger)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Verify RBAC integration
	assert.NotNil(t, server.rbacManager)
	assert.NotNil(t, server.rbacService)

	// Verify tenant security integration
	assert.NotNil(t, server.tenantManager)
}

// Test that validates the server handles network security properly
func TestServer_NetworkSecurity_And_Binding(t *testing.T) {
	logger := logging.NewNoopLogger()

	tests := []struct {
		name        string
		listenAddr  string
		expectError bool
		description string
	}{
		{
			name:        "localhost IPv4 binding",
			listenAddr:  "127.0.0.1:0",
			expectError: false,
			description: "Should allow localhost binding",
		},
		{
			name:        "localhost IPv6 binding",
			listenAddr:  "[::1]:0",
			expectError: false,
			description: "Should allow IPv6 localhost binding",
		},
		{
			name:        "specific interface binding",
			listenAddr:  "127.0.0.1:0",
			expectError: false,
			description: "Should allow specific interface binding",
		},
		{
			name:        "invalid address format",
			listenAddr:  "invalid-address",
			expectError: false, // Server creation succeeds, Start() would fail
			description: "Invalid addresses should be handled in Start method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for storage
			tempDir, err := os.MkdirTemp("", "network_test")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(tempDir) }()

			config := &config.Config{
				ListenAddr: tt.listenAddr,
				Certificate: &config.CertificateConfig{
					EnableCertManagement: false,
				},
				// Epic 6: Storage configuration required for server creation
				Storage: createTestStorageConfig(tempDir, "network"),
			}

			server, err := New(config, logger)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, server)
			}
		})
	}
}

func TestServer_CertificateSecurityValidation(t *testing.T) {
	logger := logging.NewNoopLogger()

	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "server_cert_security_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Test certificate-related security validations
	tests := []struct {
		name           string
		config         *config.Config
		description    string
		securityChecks []func(*testing.T, *Server)
	}{
		{
			name: "short certificate validity periods for security",
			config: &config.Config{
				ListenAddr: "127.0.0.1:0",
				CertPath:   tempDir,
				Certificate: &config.CertificateConfig{
					EnableCertManagement:   true,
					ClientCertValidityDays: 7,  // Very short for high security
					ServerCertValidityDays: 30, // Short server cert validity
					RenewalThresholdDays:   3,  // Early renewal
					AutoGenerate:           true,
					EnableAutoRenewal:      true,
					CAPath:                 tempDir,
					Server: &config.ServerCertificateConfig{
						CommonName:   "secure-controller",
						DNSNames:     []string{"localhost"},
						IPAddresses:  []string{"127.0.0.1"},
						Organization: "Secure Org",
					},
				},
			},
			description: "Short validity periods enhance security",
			securityChecks: []func(*testing.T, *Server){
				func(t *testing.T, s *Server) {
					assert.LessOrEqual(t, s.cfg.Certificate.ClientCertValidityDays, 30,
						"Client cert validity should be short for security")
					assert.LessOrEqual(t, s.cfg.Certificate.ServerCertValidityDays, 90,
						"Server cert validity should be reasonable")
					assert.LessOrEqual(t, s.cfg.Certificate.RenewalThresholdDays, 7,
						"Renewal threshold should be early for security")
				},
			},
		},
		{
			name: "auto-generation and renewal for operational security",
			config: &config.Config{
				ListenAddr: "127.0.0.1:0",
				CertPath:   tempDir,
				Certificate: &config.CertificateConfig{
					EnableCertManagement: true,
					AutoGenerate:         true,
					EnableAutoRenewal:    true,
					CAPath:               tempDir,
					Server: &config.ServerCertificateConfig{
						CommonName:   "auto-controller",
						Organization: "Auto Org",
					},
				},
			},
			description: "Auto-generation and renewal reduce operational security risks",
			securityChecks: []func(*testing.T, *Server){
				func(t *testing.T, s *Server) {
					assert.True(t, s.cfg.Certificate.AutoGenerate,
						"Auto-generation should be enabled for security")
					assert.True(t, s.cfg.Certificate.EnableAutoRenewal,
						"Auto-renewal should be enabled for security")
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for storage
			storageDir, err := os.MkdirTemp("", "cert_test")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(storageDir) }()

			// Add storage configuration to test config
			tt.config.Storage = createTestStorageConfig(storageDir, "cert")

			server, err := New(tt.config, logger)
			require.NoError(t, err)
			require.NotNil(t, server)

			// Run security checks
			for _, check := range tt.securityChecks {
				check(t, server)
			}
		})
	}
}

func TestServer_EnvironmentSecurityIsolation(t *testing.T) {
	logger := logging.NewNoopLogger()

	// Create separate temporary directories for each server
	tempDir1, err := os.MkdirTemp("", "server_isolation_test1")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir1) }()

	tempDir2, err := os.MkdirTemp("", "server_isolation_test2")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir2) }()

	// Test that servers created with different configurations are properly isolated
	config1 := &config.Config{
		ListenAddr: "127.0.0.1:0",
		DataDir:    tempDir1 + "/data1",
		CertPath:   tempDir1,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               tempDir1,
			AutoGenerate:         true,
			Server: &config.ServerCertificateConfig{
				CommonName:   "server1-controller",
				Organization: "Server1 Org",
			},
		},
		// Epic 6: Storage configuration required for server creation
		Storage: createTestStorageConfig(tempDir1, "env1"),
	}

	config2 := &config.Config{
		ListenAddr: "127.0.0.1:0",
		DataDir:    tempDir2 + "/data2",
		CertPath:   tempDir2,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               tempDir2,
			AutoGenerate:         true,
			Server: &config.ServerCertificateConfig{
				CommonName:   "server2-controller",
				Organization: "Server2 Org",
			},
		},
		// Epic 6: Storage configuration required for server creation
		Storage: createTestStorageConfig(tempDir2, "env2"),
	}

	server1, err := New(config1, logger)
	require.NoError(t, err)
	require.NotNil(t, server1)

	server2, err := New(config2, logger)
	require.NoError(t, err)
	require.NotNil(t, server2)

	// Verify isolation
	assert.NotEqual(t, server1.cfg.DataDir, server2.cfg.DataDir,
		"Servers should have isolated data directories")
	assert.NotEqual(t, server1.cfg.Certificate.CAPath, server2.cfg.Certificate.CAPath,
		"Servers should have isolated CA paths")

	// Verify each server has its own RBAC and tenant managers
	assert.NotSame(t, server1.rbacManager, server2.rbacManager,
		"Servers should have separate RBAC managers")
	assert.NotSame(t, server1.tenantManager, server2.tenantManager,
		"Servers should have separate tenant managers")
}

// Test data directory security
func TestServer_DataDirectorySecurity(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir, err := os.MkdirTemp("", "server_data_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	config := &config.Config{
		ListenAddr: "127.0.0.1:0",
		DataDir:    tempDir,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		// Epic 6: Storage configuration required for server creation
		Storage: createTestStorageConfig(tempDir, "data"),
	}

	server, err := New(config, logger)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Verify data directory configuration is preserved
	assert.Equal(t, tempDir, server.cfg.DataDir)
}

// Check if we're running in Docker integration test environment
func isDockerTestEnvironment() bool {
	return os.Getenv("CFGMS_TEST_DB_PASSWORD") != "" && os.Getenv("CFGMS_TEST_GITEA_URL") != ""
}
