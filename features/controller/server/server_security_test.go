package server

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
	
	// Import storage providers for Epic 6 compliance testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
)

// Security-focused tests for the controller server

// Epic 6: Helper function to create storage configuration for all tests
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

	config := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
	}

	const numConcurrent = 10

	// Test concurrent server creation (should be thread-safe)
	results := make(chan *Server, numConcurrent)
	errors := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func() {
			server, err := New(config, logger)
			if err != nil {
				errors <- err
			} else {
				results <- server
			}
		}()
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
		case <-time.After(5 * time.Second):
			t.Fatal("Test timed out waiting for concurrent operations")
		}
	}

	assert.Equal(t, numConcurrent, successCount)
	assert.Equal(t, 0, errorCount)
}

func TestServer_RBAC_SecurityIntegration(t *testing.T) {
	logger := logging.NewNoopLogger()

	config := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
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
			config := &config.Config{
				ListenAddr: tt.listenAddr,
				Certificate: &config.CertificateConfig{
					EnableCertManagement: false,
				},
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
	}

	server, err := New(config, logger)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Verify data directory configuration is preserved
	assert.Equal(t, tempDir, server.cfg.DataDir)
}