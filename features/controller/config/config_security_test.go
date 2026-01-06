// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Security-focused tests for controller configuration

func TestDefaultConfig_SecurityDefaults(t *testing.T) {
	config := DefaultConfig()

	// Verify secure defaults
	assert.NotNil(t, config)

	// Network security defaults
	assert.Equal(t, "127.0.0.1:8080", config.ListenAddr,
		"Should default to localhost binding for security")

	// Certificate security defaults
	require.NotNil(t, config.Certificate)
	assert.True(t, config.Certificate.EnableCertManagement,
		"Certificate management should be enabled by default for zero-trust")
	assert.True(t, config.Certificate.AutoGenerate,
		"Auto-generation should be enabled for security")
	assert.True(t, config.Certificate.EnableAutoRenewal,
		"Auto-renewal should be enabled for security")

	// Certificate validity defaults (security-appropriate)
	assert.LessOrEqual(t, config.Certificate.ServerCertValidityDays, 365,
		"Server certificates should have reasonable validity period")
	assert.LessOrEqual(t, config.Certificate.ClientCertValidityDays, 365,
		"Client certificates should have reasonable validity period")
	assert.LessOrEqual(t, config.Certificate.RenewalThresholdDays, 30,
		"Renewal threshold should be reasonable for security")

	// Server certificate security defaults
	require.NotNil(t, config.Certificate.Server)
	assert.NotEmpty(t, config.Certificate.Server.CommonName,
		"Server should have a common name")
	assert.Contains(t, config.Certificate.Server.DNSNames, "localhost",
		"Should include localhost in DNS names")
	assert.Contains(t, config.Certificate.Server.IPAddresses, "127.0.0.1",
		"Should include localhost IP")
}

func TestLoad_EnvironmentVariableSecurityInjection(t *testing.T) {
	// Test that environment variables can't be used for injection attacks

	tests := []struct {
		name     string
		envVar   string
		envValue string
		testFunc func(*testing.T, *Config)
	}{
		{
			name:     "path traversal in listen addr",
			envVar:   "CFGMS_LISTEN_ADDR",
			envValue: "../../../etc/passwd:8080",
			testFunc: func(t *testing.T, cfg *Config) {
				// Should not cause path traversal - just treated as invalid address
				assert.Equal(t, "../../../etc/passwd:8080", cfg.ListenAddr)
			},
		},
		{
			name:     "path traversal in cert path",
			envVar:   "CFGMS_CERT_PATH",
			envValue: "../../../etc/passwd",
			testFunc: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "../../../etc/passwd", cfg.CertPath)
				// This would be validated during actual certificate operations
			},
		},
		{
			name:     "path traversal in data dir",
			envVar:   "CFGMS_DATA_DIR",
			envValue: "../../../var/www",
			testFunc: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "../../../var/www", cfg.DataDir)
				// This would be validated during actual data operations
			},
		},
		{
			name:     "malicious log level",
			envVar:   "CFGMS_LOG_LEVEL",
			envValue: "debug && rm -rf /",
			testFunc: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "debug && rm -rf /", cfg.LogLevel)
				// Log level is validated by logging framework, not config
			},
		},
		{
			name:     "malicious CA path",
			envVar:   "CFGMS_CERT_CA_PATH",
			envValue: "/dev/null; rm -rf /",
			testFunc: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "/dev/null; rm -rf /", cfg.Certificate.CAPath)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original environment
			originalValue := os.Getenv(tt.envVar)
			defer func() {
				if originalValue != "" {
					_ = os.Setenv(tt.envVar, originalValue)
				} else {
					_ = os.Unsetenv(tt.envVar)
				}
			}()

			// Set test environment variable
			_ = os.Setenv(tt.envVar, tt.envValue)

			// Load configuration
			config, err := Load()
			require.NoError(t, err)
			require.NotNil(t, config)

			// Run test-specific validation
			tt.testFunc(t, config)
		})
	}
}

func TestLoad_ConfigFileSecurityValidation(t *testing.T) {
	// Create temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "config_security_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Change to temp directory for testing
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(originalDir) }()

	err = os.Chdir(tempDir)
	require.NoError(t, err)

	tests := []struct {
		name           string
		configContent  string
		expectError    bool
		securityChecks []func(*testing.T, *Config)
	}{
		{
			name: "malformed yaml injection attempt",
			configContent: `
listen_addr: "127.0.0.1:8080"
data_dir: "'; rm -rf /; echo '"
log_level: "info"
`,
			expectError: false, // YAML parsing should succeed but content is just a string
			securityChecks: []func(*testing.T, *Config){
				func(t *testing.T, cfg *Config) {
					// The malicious content should just be treated as a literal string
					assert.Equal(t, "'; rm -rf /; echo '", cfg.DataDir)
				},
			},
		},
		{
			name: "extremely long certificate validity periods",
			configContent: `
certificate:
  server_cert_validity_days: 999999
  client_cert_validity_days: 999999
`,
			expectError: false,
			securityChecks: []func(*testing.T, *Config){
				func(t *testing.T, cfg *Config) {
					assert.Equal(t, 999999, cfg.Certificate.ServerCertValidityDays)
					assert.Equal(t, 999999, cfg.Certificate.ClientCertValidityDays)
					// Application should validate these values separately
				},
			},
		},
		{
			name: "wildcard binding configuration",
			configContent: `
listen_addr: "0.0.0.0:8080"
certificate:
  enable_cert_management: false
`,
			expectError: false,
			securityChecks: []func(*testing.T, *Config){
				func(t *testing.T, cfg *Config) {
					assert.Equal(t, "0.0.0.0:8080", cfg.ListenAddr)
					assert.False(t, cfg.Certificate.EnableCertManagement)
					// This should trigger security warnings in application
				},
			},
		},
		{
			name: "certificate paths with suspicious values",
			configContent: `
cert_path: "/dev/null"
certificate:
  ca_path: "/tmp/../../../etc/passwd"
`,
			expectError: false,
			securityChecks: []func(*testing.T, *Config){
				func(t *testing.T, cfg *Config) {
					assert.Equal(t, "/dev/null", cfg.CertPath)
					assert.Equal(t, "/tmp/../../../etc/passwd", cfg.Certificate.CAPath)
					// Path validation should happen during certificate operations
				},
			},
		},
		{
			name: "valid secure configuration",
			configContent: `
listen_addr: "127.0.0.1:8443"
data_dir: "/var/lib/cfgms"
log_level: "info"
certificate:
  enable_cert_management: true
  auto_generate: true
  enable_auto_renewal: true
  server_cert_validity_days: 90
  client_cert_validity_days: 30
  renewal_threshold_days: 7
  server:
    common_name: "cfgms-controller.example.com"
    dns_names: ["cfgms-controller.example.com", "localhost"]
    ip_addresses: ["127.0.0.1"]
    organization: "Example Corp"
`,
			expectError: false,
			securityChecks: []func(*testing.T, *Config){
				func(t *testing.T, cfg *Config) {
					assert.Equal(t, "127.0.0.1:8443", cfg.ListenAddr)
					assert.True(t, cfg.Certificate.EnableCertManagement)
					assert.Equal(t, 90, cfg.Certificate.ServerCertValidityDays)
					assert.Equal(t, 30, cfg.Certificate.ClientCertValidityDays)
					assert.Equal(t, 7, cfg.Certificate.RenewalThresholdDays)

					// Verify secure server certificate configuration
					assert.Equal(t, "cfgms-controller.example.com", cfg.Certificate.Server.CommonName)
					assert.Contains(t, cfg.Certificate.Server.DNSNames, "localhost")
					assert.Contains(t, cfg.Certificate.Server.IPAddresses, "127.0.0.1")
				},
			},
		},
		{
			name: "invalid yaml structure",
			configContent: `
listen_addr: "127.0.0.1:8080"
invalid_yaml: [unclosed array
data_dir: "test"
`,
			expectError:    true,
			securityChecks: nil, // No checks needed for error case
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write test config file
			configPath := filepath.Join(tempDir, "config.yaml")
			err := os.WriteFile(configPath, []byte(tt.configContent), 0644)
			require.NoError(t, err)

			// Load configuration
			config, err := Load()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, config)

				// Run security checks
				for _, check := range tt.securityChecks {
					check(t, config)
				}
			}

			// Clean up config file for next test
			_ = os.Remove(configPath)
		})
	}
}

func TestConfig_SecurityValidationMethods(t *testing.T) {
	// Test helper functions for validating security aspects of configuration

	tests := []struct {
		name       string
		config     *Config
		expectWarn []string // Expected security warnings
	}{
		{
			name: "insecure wildcard binding",
			config: &Config{
				ListenAddr: "0.0.0.0:8080",
				Certificate: &CertificateConfig{
					EnableCertManagement: false,
				},
			},
			expectWarn: []string{"wildcard", "insecure"},
		},
		{
			name: "long certificate validity",
			config: &Config{
				ListenAddr: "127.0.0.1:8080",
				Certificate: &CertificateConfig{
					EnableCertManagement:   true,
					ServerCertValidityDays: 3650, // 10 years
					ClientCertValidityDays: 3650,
				},
			},
			expectWarn: []string{"validity", "long"},
		},
		{
			name: "disabled certificate management",
			config: &Config{
				ListenAddr: "127.0.0.1:8080",
				Certificate: &CertificateConfig{
					EnableCertManagement: false,
				},
			},
			expectWarn: []string{"certificate", "management", "disabled"},
		},
		{
			name: "secure configuration",
			config: &Config{
				ListenAddr: "127.0.0.1:8443",
				Certificate: &CertificateConfig{
					EnableCertManagement:   true,
					AutoGenerate:           true,
					EnableAutoRenewal:      true,
					ServerCertValidityDays: 90,
					ClientCertValidityDays: 30,
					RenewalThresholdDays:   7,
				},
			},
			expectWarn: []string{}, // No warnings expected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate security validation logic that would exist in the application
			warnings := validateConfigSecurity(tt.config)

			if len(tt.expectWarn) == 0 {
				assert.Empty(t, warnings, "No security warnings expected for secure config")
			} else {
				assert.NotEmpty(t, warnings, "Expected security warnings")
				for _, expectedWarning := range tt.expectWarn {
					found := false
					for _, warning := range warnings {
						if strings.Contains(strings.ToLower(warning), expectedWarning) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected warning containing '%s' not found in warnings: %v", expectedWarning, warnings)
				}
			}
		})
	}
}

func TestConfig_BooleanEnvironmentVariableParsing(t *testing.T) {
	// Test security around boolean environment variable parsing

	tests := []struct {
		name     string
		envVar   string
		envValue string
		expect   bool
		valid    bool
	}{
		{
			name:     "valid true",
			envVar:   "CFGMS_CERT_ENABLE_MANAGEMENT",
			envValue: "true",
			expect:   true,
			valid:    true,
		},
		{
			name:     "valid false",
			envVar:   "CFGMS_CERT_ENABLE_MANAGEMENT",
			envValue: "false",
			expect:   false,
			valid:    true,
		},
		{
			name:     "injection attempt",
			envVar:   "CFGMS_CERT_AUTO_GENERATE",
			envValue: "true && rm -rf /",
			expect:   false, // Should fall back to default due to parse error
			valid:    false,
		},
		{
			name:     "numeric injection",
			envVar:   "CFGMS_CERT_ENABLE_MANAGEMENT",
			envValue: "1; DROP TABLE users;",
			expect:   false, // Should fall back to default
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore environment
			originalValue := os.Getenv(tt.envVar)
			defer func() {
				if originalValue != "" {
					_ = os.Setenv(tt.envVar, originalValue)
				} else {
					_ = os.Unsetenv(tt.envVar)
				}
			}()

			// Set test value
			_ = os.Setenv(tt.envVar, tt.envValue)

			// Load config
			config, err := Load()
			require.NoError(t, err)

			// Check that boolean parsing is secure
			var actualValue bool
			switch tt.envVar {
			case "CFGMS_CERT_ENABLE_MANAGEMENT":
				actualValue = config.Certificate.EnableCertManagement
			case "CFGMS_CERT_AUTO_GENERATE":
				actualValue = config.Certificate.AutoGenerate
			}

			if tt.valid {
				assert.Equal(t, tt.expect, actualValue)
			} else {
				// Should fall back to default (true for these settings)
				// This validates that malformed boolean values don't cause security issues
				assert.True(t, actualValue, "Should fall back to secure default on parse error")
			}
		})
	}
}

// Helper function that simulates security validation logic
func validateConfigSecurity(cfg *Config) []string {
	var warnings []string

	// Check for wildcard binding without TLS
	if strings.HasPrefix(cfg.ListenAddr, "0.0.0.0:") || strings.HasPrefix(cfg.ListenAddr, "[::]") {
		if cfg.Certificate == nil || !cfg.Certificate.EnableCertManagement {
			warnings = append(warnings, "Wildcard binding without TLS is insecure")
		}
	}

	// Check for disabled certificate management
	if cfg.Certificate == nil || !cfg.Certificate.EnableCertManagement {
		warnings = append(warnings, "Certificate management is disabled - insecure for production")
	}

	// Check for excessive certificate validity periods
	if cfg.Certificate != nil {
		if cfg.Certificate.ServerCertValidityDays > 365 {
			warnings = append(warnings, "Server certificate validity period is too long")
		}
		if cfg.Certificate.ClientCertValidityDays > 365 {
			warnings = append(warnings, "Client certificate validity period is too long")
		}
	}

	return warnings
}
