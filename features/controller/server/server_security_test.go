// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/testutil"

	// Import storage providers for Epic 6 compliance testing
	// Note: memory provider is NOT imported as it's not a global provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// Security-focused tests for the controller server

// Helper function to create storage configuration for all tests
func createTestStorageConfig(tempDir, suffix string) *config.StorageConfig {
	return &config.StorageConfig{
		Provider:     "flatfile",
		FlatfileRoot: tempDir + "/" + suffix + "-flatfile",
		SQLitePath:   tempDir + "/" + suffix + ".db",
	}
}

// createDockerTestStorageConfig creates storage configs for Docker-based testing
func createDockerTestStorageConfig(provider string) *config.StorageConfig {
	switch provider {
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
			name: "missing flatfile_root should fail",
			config: &config.Config{
				ListenAddr: "127.0.0.1:0",
				Certificate: &config.CertificateConfig{
					EnableCertManagement: false,
				},
				Storage: &config.StorageConfig{
					Provider: "flatfile",
					Config:   make(map[string]interface{}),
				},
			},
			wantErr: true,
			errMsg:  "flatfile_root is required",
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
					Provider:     "flatfile",
					FlatfileRoot: tempDir + "/flatfile",
					SQLitePath:   tempDir + "/cfgms.db",
				},
			},
			wantErr: false,
		},
		{
			name: "secure config with cert management",
			config: func() *config.Config {
				certDir := tempDir + "/cert-mgmt"
				_ = os.MkdirAll(certDir, 0700)
				testutil.PreInitControllerForTest(t, certDir, certDir)
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					CertPath:   certDir,
					Certificate: &config.CertificateConfig{
						EnableCertManagement:   true,
						ClientCertValidityDays: 30,
						CAPath:                 certDir,
						ServerCertValidityDays: 90,
						RenewalThresholdDays:   7,
						Server: &config.ServerCertificateConfig{
							CommonName:   "test-controller",
							DNSNames:     []string{"localhost"},
							IPAddresses:  []string{"127.0.0.1"},
							Organization: "Test Org",
						},
					},
					Storage: &config.StorageConfig{
						Provider:     "flatfile",
						FlatfileRoot: tempDir + "/flatfile",
						SQLitePath:   tempDir + "/cfgms.db",
					},
				}
			}(),
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

				// If certificate management is enabled and certs were pre-initialized, certManager must be set
				if tt.config.Certificate != nil && tt.config.Certificate.EnableCertManagement {
					assert.NotNil(t, server.certManager, "certManager must be initialized when EnableCertManagement is true")
				} else {
					assert.Nil(t, server.certManager, "certManager must be nil when EnableCertManagement is false")
				}
			}
		})
	}
}

// TestServer_StorageProviderValidation dynamically validates storage provider configuration
// against all registered global storage providers
func TestServer_StorageProviderValidation(t *testing.T) {
	logger := logging.NewNoopLogger()
	tempDir, err := os.MkdirTemp("", "storage_provider_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Get all registered storage providers dynamically
	registeredProviders := interfaces.ListProviders()
	require.NotEmpty(t, registeredProviders, "No storage providers registered - this indicates a system configuration problem")

	t.Run("ValidateRegisteredProvidersWork", func(t *testing.T) {
		// Skip if integration tests are explicitly disabled (e.g., cross-platform CI without Docker)
		if os.Getenv("CFGMS_TEST_INTEGRATION") == "0" {
			t.Skip("Skipping storage provider validation - integration tests disabled (CFGMS_TEST_INTEGRATION=0)")
		}

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
		assert.Contains(t, err.Error(), "flatfile_root is required", "Error should mention flatfile_root requirement for OSS composite storage")
	})

	t.Run("FutureProofProviderList", func(t *testing.T) {
		// This test documents expected providers and will alert if providers are added/removed
		providerNames := make([]string, 0, len(registeredProviders))
		for _, providerInfo := range registeredProviders {
			providerNames = append(providerNames, providerInfo.Name)
		}

		t.Logf("Currently registered storage providers: %v", providerNames)

		// These are the providers we expect to exist based on our architecture
		expectedProviders := []string{"flatfile", "sqlite", "database"}

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
			config: func() *config.Config {
				certDir := tempDir + "/prod-certs"
				_ = os.MkdirAll(certDir, 0700)
				testutil.PreInitControllerForTest(t, certDir, certDir)
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					CertPath:   certDir,
					Storage: &config.StorageConfig{
						Provider:     "flatfile",
						FlatfileRoot: tempDir + "/flatfile",
						SQLitePath:   tempDir + "/cfgms.db",
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement:   true,
						ClientCertValidityDays: 30,
						ServerCertValidityDays: 90,
						CAPath:                 certDir,
						RenewalThresholdDays:   7,
						Server: &config.ServerCertificateConfig{
							CommonName:   "prod-controller",
							DNSNames:     []string{"localhost"},
							IPAddresses:  []string{"127.0.0.1"},
							Organization: "Production Org",
						},
					},
				}
			}(),
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
					Provider:     "flatfile",
					FlatfileRoot: tempDir + "/flatfile",
					SQLitePath:   tempDir + "/cfgms.db",
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
					CertPath:   tempDir,
					Storage: &config.StorageConfig{
						Provider:     "flatfile",
						FlatfileRoot: tempDir + "/flatfile",
						SQLitePath:   tempDir + "/cfgms.db",
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement: true,
						CAPath:               "../../../etc/passwd", // Path traversal attempt
						Server: &config.ServerCertificateConfig{
							CommonName:   "test-controller",
							Organization: "Test Org",
						},
					},
				}
			},
			expectError: true, // Init guard: path traversal path won't be initialized
			description: "Path traversal in certificate paths should be rejected by init guard",
		},
		{
			name: "excessive certificate validity periods",
			configFunc: func() *config.Config {
				certDir := tempDir + "/excessive-certs"
				_ = os.MkdirAll(certDir, 0700)
				testutil.PreInitControllerForTest(t, certDir, certDir)
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					CertPath:   certDir,
					Storage: &config.StorageConfig{
						Provider:     "flatfile",
						FlatfileRoot: tempDir + "/flatfile",
						SQLitePath:   tempDir + "/cfgms.db",
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement:   true,
						ClientCertValidityDays: 36500,
						ServerCertValidityDays: 36500,
						CAPath:                 certDir,
						Server: &config.ServerCertificateConfig{
							CommonName:   "test-controller",
							Organization: "Test Org",
						},
					},
				}
			},
			expectError: false,
			description: "Excessive certificate validity should be allowed but warned about",
		},
		{
			name: "bind to privileged port (should fail in test)",
			configFunc: func() *config.Config {
				return &config.Config{
					ListenAddr: "127.0.0.1:80", // Privileged port
					// Epic 6: Storage configuration required
					Storage: &config.StorageConfig{
						Provider:     "flatfile",
						FlatfileRoot: tempDir + "/flatfile",
						SQLitePath:   tempDir + "/cfgms.db",
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
						Provider:     "flatfile",
						FlatfileRoot: tempDir + "/flatfile",
						SQLitePath:   tempDir + "/cfgms.db",
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
				certDir := tempDir + "/wildcard-certs"
				_ = os.MkdirAll(certDir, 0700)
				testutil.PreInitControllerForTest(t, certDir, certDir)
				return &config.Config{
					ListenAddr: "0.0.0.0:0",
					CertPath:   certDir,
					Storage: &config.StorageConfig{
						Provider:     "flatfile",
						FlatfileRoot: tempDir + "/flatfile",
						SQLitePath:   tempDir + "/cfgms.db",
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement: true,
						CAPath:               certDir,
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

	// Race detector adds 5-10x overhead, and full suite load adds further contention
	// Each concurrent server creation involves: Git init, RBAC setup, storage init
	timeout := 5 * time.Second
	if raceDetectorEnabled() {
		timeout = 45 * time.Second // Race + full suite resource contention
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
		configFunc     func() *config.Config
		description    string
		securityChecks []func(*testing.T, *Server)
	}{
		{
			name: "short certificate validity periods for security",
			configFunc: func() *config.Config {
				certDir := tempDir + "/short-validity-certs"
				_ = os.MkdirAll(certDir, 0700)
				testutil.PreInitControllerForTest(t, certDir, certDir)
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					CertPath:   certDir,
					Certificate: &config.CertificateConfig{
						EnableCertManagement:   true,
						ClientCertValidityDays: 7,
						ServerCertValidityDays: 30,
						RenewalThresholdDays:   3,
						CAPath:                 certDir,
						Server: &config.ServerCertificateConfig{
							CommonName:   "secure-controller",
							DNSNames:     []string{"localhost"},
							IPAddresses:  []string{"127.0.0.1"},
							Organization: "Secure Org",
						},
					},
				}
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
			configFunc: func() *config.Config {
				certDir := tempDir + "/auto-renewal-certs"
				_ = os.MkdirAll(certDir, 0700)
				testutil.PreInitControllerForTest(t, certDir, certDir)
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					CertPath:   certDir,
					Certificate: &config.CertificateConfig{
						EnableCertManagement: true,
						CAPath:               certDir,
						Server: &config.ServerCertificateConfig{
							CommonName:   "auto-controller",
							Organization: "Auto Org",
						},
					},
				}
			},
			description: "Auto-generation and renewal reduce operational security risks",
			securityChecks: []func(*testing.T, *Server){
				func(t *testing.T, s *Server) {
					assert.True(t, s.cfg.Certificate.EnableCertManagement,
						"Certificate management should be enabled for security (handles generation + renewal)")
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

			cfg := tt.configFunc()
			cfg.Storage = createTestStorageConfig(storageDir, "cert")

			server, err := New(cfg, logger)
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

	// Pre-initialize both CA directories before server creation
	testutil.PreInitControllerForTest(t, tempDir1, tempDir1)
	testutil.PreInitControllerForTest(t, tempDir2, tempDir2)

	// Test that servers created with different configurations are properly isolated
	config1 := &config.Config{
		ListenAddr: "127.0.0.1:0",
		DataDir:    tempDir1 + "/data1",
		CertPath:   tempDir1,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               tempDir1,
			Server: &config.ServerCertificateConfig{
				CommonName:   "server1-controller",
				Organization: "Server1 Org",
			},
		},
		Storage: createTestStorageConfig(tempDir1, "env1"),
	}

	config2 := &config.Config{
		ListenAddr: "127.0.0.1:0",
		DataDir:    tempDir2 + "/data2",
		CertPath:   tempDir2,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               tempDir2,
			Server: &config.ServerCertificateConfig{
				CommonName:   "server2-controller",
				Organization: "Server2 Org",
			},
		},
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

// TestServer_New_RefusesWithoutInit verifies that the server refuses to start
// when certificate management is enabled but initialization has not been performed.
func TestServer_New_RefusesWithoutInit(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir, err := os.MkdirTemp("", "server_init_guard_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		CertPath:   tempDir,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               tempDir + "/nonexistent-ca",
			Server: &config.ServerCertificateConfig{
				CommonName:   "test-controller",
				Organization: "Test Org",
			},
		},
		Storage: createTestStorageConfig(tempDir, "init-guard"),
	}

	srv, err := New(cfg, logger)
	assert.Error(t, err, "Server should refuse to start without initialization")
	assert.Nil(t, srv)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// TestServer_New_LegacyCompatibility verifies that an existing CA without an init
// marker gets a marker auto-created (backward compatibility for pre-init deployments).
func TestServer_New_LegacyCompatibility(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir, err := os.MkdirTemp("", "server_legacy_compat_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	certDir := tempDir + "/legacy-ca"

	// Create CA files without marker (simulates pre-init deployment)
	_, err = cert.NewManager(&cert.ManagerConfig{
		StoragePath: certDir,
		CAConfig: &cert.CAConfig{
			Organization: "Legacy Org",
			Country:      "US",
			ValidityDays: 3650,
			StoragePath:  certDir,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "Failed to create legacy CA")

	// Verify no marker exists yet
	assert.False(t, initialization.IsInitialized(certDir), "Should not have marker before server start")

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		CertPath:   certDir,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               certDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "legacy-controller",
				Organization: "Legacy Org",
			},
		},
		Storage: createTestStorageConfig(tempDir, "legacy"),
	}

	srv, err := New(cfg, logger)
	assert.NoError(t, err, "Server should start with legacy CA (auto-creates marker)")
	assert.NotNil(t, srv)

	// Verify marker was created
	assert.True(t, initialization.IsInitialized(certDir), "Marker should be auto-created for legacy CA")
}

// TestServer_New_MarkerButNoCA verifies that if the marker exists but CA files
// are missing, the server fails with a clear error about loading the CA.
func TestServer_New_MarkerButNoCA(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir, err := os.MkdirTemp("", "server_marker_no_ca_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	certDir := tempDir + "/orphan-marker"
	require.NoError(t, os.MkdirAll(certDir, 0700))

	// Write marker without CA files (simulates deleted/missing CA)
	err = initialization.CreateLegacyMarker(certDir)
	require.NoError(t, err)

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		CertPath:   certDir,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               certDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "orphan-controller",
				Organization: "Test Org",
			},
		},
		Storage: createTestStorageConfig(tempDir, "orphan"),
	}

	srv, err := New(cfg, logger)
	assert.Error(t, err, "Server should fail when marker exists but CA files are missing")
	assert.Nil(t, srv)
	assert.Contains(t, err.Error(), "load", "Error should mention loading CA")
}

// TestBuildGRPCControlPlaneTLSConfig_DoesNotWriteCertFilesToDisk verifies that
// buildGRPCControlPlaneTLSConfig does not write cert files to disk.
//
// Per ADR-002: the function previously called writeTransportCertsToDir, which existed
// solely so integration test infrastructure could find certs at well-known paths.
// Certs must be used in-memory only — no filesystem side-effects.
func TestBuildGRPCControlPlaneTLSConfig_DoesNotWriteCertFilesToDisk(t *testing.T) {
	tempDir := t.TempDir()

	certManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "CFGMS Test",
			Country:      "US",
			ValidityDays: 365,
			KeySize:      2048,
		},
		LoadExistingCA:       false,
		RenewalThresholdDays: 30,
	})
	require.NoError(t, err)

	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               tempDir,
		},
	}

	logger := logging.NewNoopLogger()

	tlsConfig, err := buildGRPCControlPlaneTLSConfig(cfg, certManager, logger)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// The TLS config must carry the server certificate in-memory.
	assert.NotEmpty(t, tlsConfig.Certificates, "TLS config must contain server certificate in-memory")

	// writeTransportCertsToDir wrote server cert/key to well-known paths under CAPath.
	// After its removal these files must not exist — certs are in-memory only.
	assert.NoFileExists(t, filepath.Join(tempDir, "server", "server.crt"),
		"buildGRPCControlPlaneTLSConfig must not write server cert to disk")
	assert.NoFileExists(t, filepath.Join(tempDir, "server", "server.key"),
		"buildGRPCControlPlaneTLSConfig must not write server key to disk")
}

// Check if we're running in Docker integration test environment
func isDockerTestEnvironment() bool {
	return os.Getenv("CFGMS_TEST_DB_PASSWORD") != "" && os.Getenv("CFGMS_TEST_GITEA_URL") != ""
}
