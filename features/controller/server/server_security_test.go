// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
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

// createDockerTestStorageConfig creates storage configs for Docker-based testing.
// For non-database providers, the flatfile+sqlite paths are scoped to t.TempDir()
// so each test gets a fresh directory and no state persists in /tmp across runs —
// stale on-disk schemas had previously broken tests after audit_entries migrations.
func createDockerTestStorageConfig(t *testing.T, provider string) *config.StorageConfig {
	t.Helper()
	switch provider {
	case "database":
		// session_hmac_key is required by DatabaseSessionStore; the constructor fails
		// closed with no silent insecure fallback when it is absent. Use the env-override
		// so CI can inject a real key; fall back to a fixed test-only key for local dev.
		hmacKey := os.Getenv("CFGMS_TEST_SESSION_HMAC_KEY")
		if hmacKey == "" {
			hmacKey = "test-hmac-key-for-server-security-tests-only"
		}
		return &config.StorageConfig{
			Provider: "database",
			Config: map[string]interface{}{
				"host":             os.Getenv("CFGMS_TEST_DB_HOST"),
				"port":             5433,
				"database":         "cfgms_test",
				"username":         "cfgms_test",
				"password":         os.Getenv("CFGMS_TEST_DB_PASSWORD"),
				"sslmode":          "disable",
				"session_hmac_key": hmacKey,
			},
		}
	default:
		return createTestStorageConfig(t.TempDir(), provider)
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
				testutil.PreInitControllerForTest(t, certDir, filepath.Join(certDir, "ca"))
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					Certificate: &config.CertificateConfig{
						EnableCertManagement:   true,
						ClientCertValidityDays: 30,
						CAPath:                 filepath.Join(certDir, "ca"),
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
				if server != nil {
					t.Cleanup(func() {
						if err := server.Stop(); err != nil {
							t.Errorf("server.Stop: %v", err)
						}
					})
				}

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
					storageConfig = createDockerTestStorageConfig(t, providerInfo.Name)
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
						// CI is the one place the infrastructure is guaranteed to be
						// provisioned, so a missing database there is a hard failure.
						if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
							t.Fatalf("REQUIRED INFRASTRUCTURE MISSING: Database provider requires Docker environment in CI/integration mode - run 'make test-integration-setup'")
						}
						// Locally, isDockerTestEnvironment has already probed the port, so
						// reaching here means nothing is listening — whether or not stale
						// credentials are still exported. Skip with an actionable message
						// rather than failing on a "connection refused" further down.
						t.Skipf("Database provider requires a running Docker environment (nothing listening on %s) - "+
							"run 'make test-integration-setup', or 'make test-integration-cleanup' to clear a stale .env.test",
							dockerTestDBAddr())
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
				// Database provider has no FlatfileRoot or SQLitePath to derive a blob
				// root from; supply a DataDir so the filesystem blob store can initialize.
				if providerInfo.Name == "database" {
					config.DataDir = t.TempDir()
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
					t.Cleanup(func() {
						if err := server.Stop(); err != nil {
							t.Errorf("server.Stop: %v", err)
						}
					})
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
		expectedProviders := []string{"flatfile", "sqlite"}

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
				testutil.PreInitControllerForTest(t, certDir, filepath.Join(certDir, "ca"))
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					Storage: &config.StorageConfig{
						Provider:     "flatfile",
						FlatfileRoot: tempDir + "/flatfile",
						SQLitePath:   tempDir + "/cfgms.db",
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement:   true,
						ClientCertValidityDays: 30,
						ServerCertValidityDays: 90,
						CAPath:                 filepath.Join(certDir, "ca"),
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
			t.Cleanup(func() {
				if err := server.Stop(); err != nil {
					t.Errorf("server.Stop: %v", err)
				}
			})

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
				testutil.PreInitControllerForTest(t, certDir, filepath.Join(certDir, "ca"))
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					Storage: &config.StorageConfig{
						Provider:     "flatfile",
						FlatfileRoot: tempDir + "/flatfile",
						SQLitePath:   tempDir + "/cfgms.db",
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement:   true,
						ClientCertValidityDays: 36500,
						ServerCertValidityDays: 36500,
						CAPath:                 filepath.Join(certDir, "ca"),
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
				testutil.PreInitControllerForTest(t, certDir, filepath.Join(certDir, "ca"))
				return &config.Config{
					ListenAddr: "0.0.0.0:0",
					Storage: &config.StorageConfig{
						Provider:     "flatfile",
						FlatfileRoot: tempDir + "/flatfile",
						SQLitePath:   tempDir + "/cfgms.db",
					},
					Certificate: &config.CertificateConfig{
						EnableCertManagement: true,
						CAPath:               filepath.Join(certDir, "ca"),
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
				if server != nil {
					t.Cleanup(func() {
						if err := server.Stop(); err != nil {
							t.Errorf("server.Stop: %v", err)
						}
					})
				}

				// Validate security components are still initialized
				assert.NotNil(t, server.rbacManager)
				assert.NotNil(t, server.tenantManager)
			}
		})
	}
}

// TestConcurrentStorageConfigs_GetDistinctEntityGraphDirectories guards the isolation
// TestServer_ConcurrentSecurity_And_RaceConditions depends on.
//
// The entity graph provider takes no configured path. It derives one as
// filepath.Join(filepath.Dir(cfg.Storage.SQLitePath), "entitygraph.db")
// (server.go:3432), so two configs that differ only in SQLite *filename* still share a
// single entitygraph.db. Concurrent opens of one SQLite file fail with SQLITE_BUSY.
//
// This asserts on the derived directory rather than on live concurrency, so it fails
// against the old same-directory layout on every platform. The SQLITE_BUSY itself only
// surfaced on Windows, which is why the defect survived on Linux and macOS.
func TestConcurrentStorageConfigs_GetDistinctEntityGraphDirectories(t *testing.T) {
	tempDir := t.TempDir()
	const numConcurrent = 10

	seen := make(map[string]int, numConcurrent)
	for i := 0; i < numConcurrent; i++ {
		dir := filepath.Join(tempDir, fmt.Sprintf("concurrent-%d", i))
		cfg := createTestStorageConfig(dir, "server")

		// Mirrors server.go:3432 exactly.
		egDir := filepath.Dir(cfg.SQLitePath)
		if prev, dup := seen[egDir]; dup {
			t.Fatalf("goroutines %d and %d would share entity graph directory %s — "+
				"concurrent opens of one entitygraph.db fail with SQLITE_BUSY", prev, i, egDir)
		}
		seen[egDir] = i
	}
	require.Len(t, seen, numConcurrent,
		"every concurrent server must derive its own entity graph directory")
}

func TestServer_ConcurrentSecurity_And_RaceConditions(t *testing.T) {
	logger := logging.NewNoopLogger()

	// Create temporary directory for storage
	tempDir, err := os.MkdirTemp("", "concurrent_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	const numConcurrent = 10

	// Race detector adds 5-10x overhead, and full suite load adds further contention.
	// Windows NTFS + concurrent Git init is significantly slower than Linux tmpfs.
	// Each concurrent server creation involves: RBAC setup, flatfile+SQLite storage init.
	timeout := 5 * time.Second
	if raceDetectorEnabled() || runtime.GOOS == "windows" {
		timeout = 45 * time.Second // Race detector overhead or Windows FS contention
	}
	if runtime.GOOS == "windows" {
		// Windows filesystem ops (SQLite WAL, directory creation) are 5-10x slower
		// than Linux for concurrent workloads on CI runners.
		timeout = 60 * time.Second
	}

	// Each goroutine needs its own storage DIRECTORY, not merely its own filenames.
	// The entity graph provider does not read a configured path: it derives one as
	// filepath.Join(filepath.Dir(cfg.Storage.SQLitePath), "entitygraph.db")
	// (server.go:3432). Configs that differ only in filename therefore still resolve
	// to a single shared entitygraph.db, and N concurrent opens of one SQLite file
	// fail with "database is locked (5) (SQLITE_BUSY)" — measured on the Windows leg
	// of queue commit e8ee121d, where this test reported
	// "failed to initialize entity graph provider ... ping
	// C:\...\concurrent_test*\entitygraph.db: database is locked".
	//
	// The directories are created here, on the test goroutine, for two reasons: the
	// SQLite providers do not create parent directories, and require/t.Fatalf must
	// never be called from a spawned goroutine.
	goroutineDirs := make([]string, numConcurrent)
	for i := range goroutineDirs {
		dir := filepath.Join(tempDir, fmt.Sprintf("concurrent-%d", i))
		require.NoError(t, os.MkdirAll(dir, 0o750),
			"per-goroutine storage directory must be created before the race starts")
		goroutineDirs[i] = dir
	}

	// Test concurrent server creation (should be thread-safe)
	results := make(chan *Server, numConcurrent)
	errors := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(index int) {
			// Each goroutine gets its own unique storage configuration to avoid Git
			// conflicts, and its own directory so the derived entity graph database
			// is unique too.
			uniqueConfig := &config.Config{
				ListenAddr: "127.0.0.1:0",
				Certificate: &config.CertificateConfig{
					EnableCertManagement: false,
				},
				// Epic 6: Storage configuration required for all server creation
				Storage: createTestStorageConfig(goroutineDirs[index], "server"),
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
	var createdServers []*Server

	for i := 0; i < numConcurrent; i++ {
		select {
		case server := <-results:
			assert.NotNil(t, server)
			assert.NotNil(t, server.rbacManager)
			successCount++
			createdServers = append(createdServers, server)
		case err := <-errors:
			t.Errorf("Unexpected error in concurrent server creation: %v", err)
			errorCount++
		case <-time.After(timeout):
			t.Fatalf("Test timed out waiting for concurrent operations (timeout: %v)", timeout)
		}
	}

	assert.Equal(t, numConcurrent, successCount)
	assert.Equal(t, 0, errorCount)

	// Stop all successfully created servers to prevent goroutine leaks.
	t.Cleanup(func() {
		for i, s := range createdServers {
			if err := s.Stop(); err != nil {
				t.Errorf("server[%d].Stop(): %v", i, err)
			}
		}
	})
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
	t.Cleanup(func() {
		if err := server.Stop(); err != nil {
			t.Errorf("server.Stop: %v", err)
		}
	})

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
				if server != nil {
					t.Cleanup(func() {
						if err := server.Stop(); err != nil {
							t.Errorf("server.Stop: %v", err)
						}
					})
				}
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
				testutil.PreInitControllerForTest(t, certDir, filepath.Join(certDir, "ca"))
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					Certificate: &config.CertificateConfig{
						EnableCertManagement:   true,
						ClientCertValidityDays: 7,
						ServerCertValidityDays: 30,
						RenewalThresholdDays:   3,
						CAPath:                 filepath.Join(certDir, "ca"),
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
				testutil.PreInitControllerForTest(t, certDir, filepath.Join(certDir, "ca"))
				return &config.Config{
					ListenAddr: "127.0.0.1:0",
					Certificate: &config.CertificateConfig{
						EnableCertManagement: true,
						CAPath:               filepath.Join(certDir, "ca"),
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
			t.Cleanup(func() {
				if err := server.Stop(); err != nil {
					t.Errorf("server.Stop: %v", err)
				}
			})

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
	testutil.PreInitControllerForTest(t, tempDir1, filepath.Join(tempDir1, "ca"))
	testutil.PreInitControllerForTest(t, tempDir2, filepath.Join(tempDir2, "ca"))

	// Test that servers created with different configurations are properly isolated
	config1 := &config.Config{
		ListenAddr: "127.0.0.1:0",
		DataDir:    tempDir1 + "/data1",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               filepath.Join(tempDir1, "ca"),
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
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               filepath.Join(tempDir2, "ca"),
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
	t.Cleanup(func() {
		if err := server1.Stop(); err != nil {
			t.Errorf("server1.Stop: %v", err)
		}
	})

	server2, err := New(config2, logger)
	require.NoError(t, err)
	require.NotNil(t, server2)
	t.Cleanup(func() {
		if err := server2.Stop(); err != nil {
			t.Errorf("server2.Stop: %v", err)
		}
	})

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
	t.Cleanup(func() {
		if err := server.Stop(); err != nil {
			t.Errorf("server.Stop: %v", err)
		}
	})

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

	// cert.NewManager with StoragePath=certDir creates CA files at certDir/ca/.
	_, err = cert.NewManager(&cert.ManagerConfig{
		StoragePath: certDir,
		CAConfig: &cert.CAConfig{
			Organization: "Legacy Org",
			Country:      "US",
			ValidityDays: 3650,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "Failed to create legacy CA")

	caDir := filepath.Join(certDir, "ca")

	// Verify no marker exists yet at the CA directory.
	assert.False(t, initialization.IsInitialized(caDir), "Should not have marker before server start")

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
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
	if srv != nil {
		t.Cleanup(func() {
			if err := srv.Stop(); err != nil {
				t.Errorf("srv.Stop: %v", err)
			}
		})
	}

	// Verify marker was auto-created at the CA directory.
	assert.True(t, initialization.IsInitialized(caDir), "Marker should be auto-created for legacy CA")
}

// TestServer_New_MarkerButNoCA verifies that if the marker exists but CA files
// are missing, the server fails with a clear error about loading the CA.
func TestServer_New_MarkerButNoCA(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir, err := os.MkdirTemp("", "server_marker_no_ca_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	certParent := tempDir + "/orphan-marker"
	caDir := filepath.Join(certParent, "ca")
	require.NoError(t, os.MkdirAll(caDir, 0700))

	// Write marker at caDir (== CAPath) without CA files — simulates deleted/missing CA.
	err = initialization.CreateLegacyMarker(caDir)
	require.NoError(t, err)

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
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

	// Separated architecture is mandatory: ensure purpose-specific certs exist
	// before buildGRPCControlPlaneTLSConfig is called (mirrors the real boot sequence).
	require.NoError(t, certManager.EnsureSeparatedCertificates(nil, nil))

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

// dockerTestDBAddr returns the host:port the Docker test Postgres is expected on.
// It mirrors createDockerTestStorageConfig, which reads CFGMS_TEST_DB_HOST and uses
// port 5433 (the docker-compose.test.yml published port for postgres-test).
func dockerTestDBAddr() string {
	host := os.Getenv("CFGMS_TEST_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, "5433")
}

// isDockerTestEnvironment reports whether the Docker-backed integration infrastructure
// is actually available to this test run.
//
// Credentials in the environment are NOT evidence that the containers are running.
// `make test-integration-docker` sources .env.test whenever the file exists, and that
// file outlives the containers it was generated for: a previous session that was torn
// down (or a machine with no Docker daemon at all) still leaves CFGMS_TEST_DB_PASSWORD
// and CFGMS_TEST_GITEA_URL exported. Detecting on the credentials alone made the suite
// claim a Docker environment that did not exist and then fail on "connection refused"
// against port 5433. Both the credentials and a live listener are required.
func isDockerTestEnvironment() bool {
	if os.Getenv("CFGMS_TEST_DB_PASSWORD") == "" || os.Getenv("CFGMS_TEST_GITEA_URL") == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", dockerTestDBAddr(), 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
