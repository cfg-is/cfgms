// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package storage provides comprehensive testing infrastructure for all storage providers
// Addresses Epic 6 testing requirements by creating standardized test fixtures and helpers
package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// isUnsupportedStoreError reports whether err signals that a provider does not
// implement the requested store type. Post-ADR-003, providers are partitioned
// by data tier (flatfile: config/audit only; sqlite: business data only), so
// calling every Create*Store on every provider is expected to yield these
// errors for out-of-tier combinations. The interfaces package exports
// ErrNotSupported; individual providers (flatfile) define their own sentinel
// with the same meaning. Both contain "operation not supported" in their
// message, so a substring fallback catches provider-local sentinels that do
// not wrap the canonical one.
func isUnsupportedStoreError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, interfaces.ErrNotSupported) {
		return true
	}
	return strings.Contains(err.Error(), "operation not supported")
}

// isInfrastructureRequired determines if infrastructure should be available
// Returns true in CI environments or when Docker/infrastructure is explicitly enabled
// Returns false when running in short mode (unit tests only)
func isInfrastructureRequired() bool {
	// Integration test mode explicitly disabled (e.g., -short flag)
	if os.Getenv("CFGMS_TEST_INTEGRATION") == "0" {
		return false
	}

	// Short mode explicitly requests skipping infrastructure tests
	// This is set by -short flag (used in make test-fast)
	// Database provider tests are covered by dedicated Docker integration job
	if os.Getenv("CFGMS_TEST_SHORT") == "1" {
		return false
	}

	// CI environments (but check short mode first)
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		return true
	}

	// Docker test environment explicitly set up
	if os.Getenv("CFGMS_TEST_DB_PASSWORD") != "" {
		return true
	}

	// Integration test mode
	if os.Getenv("CFGMS_TEST_INTEGRATION") == "1" {
		return true
	}

	return false
}

// requireInfrastructureOrSkip fails the test if infrastructure is required but not available
// In CI or explicit integration modes, missing infrastructure is a test failure
// In development mode, it's acceptable to skip
func requireInfrastructureOrSkip(t *testing.T, err error, component string) {
	if err == nil {
		return
	}

	if isInfrastructureRequired() {
		t.Fatalf("REQUIRED INFRASTRUCTURE MISSING: %s is not available in CI/integration environment: %v", component, err)
	} else {
		t.Skipf("%s not available in development environment: %v", component, err)
	}
}

// StorageTestConfig holds configuration for testing different storage providers
type StorageTestConfig struct {
	Provider string
	Config   map[string]interface{}
	TempDir  string
}

// StorageTestFixture provides a complete testing environment for storage providers
type StorageTestFixture struct {
	TempDir string
	Configs map[string]*StorageTestConfig
	Cleanup func()
}

// NewStorageTestFixture creates a comprehensive test fixture supporting all storage providers
func NewStorageTestFixture(t *testing.T) *StorageTestFixture {
	tempDir, err := os.MkdirTemp("", "cfgms-storage-test-")
	require.NoError(t, err, "Failed to create temporary directory")

	fixture := &StorageTestFixture{
		TempDir: tempDir,
		Configs: make(map[string]*StorageTestConfig),
	}

	// Set up cleanup function
	fixture.Cleanup = func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: Failed to clean up temp directory %s: %v", tempDir, err)
		}
	}

	// Create configurations for all storage providers
	fixture.setupGitConfig(t)
	fixture.setupDatabaseConfig(t)
	fixture.setupFlatfileConfig(t)
	fixture.setupSQLiteConfig(t)

	return fixture
}

// setupGitConfig creates a proper git provider configuration with repository initialization
func (f *StorageTestFixture) setupGitConfig(t *testing.T) {
	gitDir := filepath.Join(f.TempDir, "git-storage")
	err := os.MkdirAll(gitDir, 0755)
	require.NoError(t, err, "Failed to create git storage directory")

	f.Configs["git"] = &StorageTestConfig{
		Provider: "git",
		Config: map[string]interface{}{
			"repository_path": gitDir,
			"branch":          "main",
			"auto_init":       true,
			"user_name":       "Test User",
			"user_email":      "test@cfgms.test",
		},
		TempDir: gitDir,
	}
}

// setupDatabaseConfig creates a proper database provider configuration for testing
func (f *StorageTestFixture) setupDatabaseConfig(t *testing.T) {
	testPassword := testutil.GetTestDBPassword()

	testHost := os.Getenv("CFGMS_TEST_DB_HOST")
	if testHost == "" {
		testHost = "localhost"
	}

	testPort := 5432
	if portStr := os.Getenv("CFGMS_TEST_DB_PORT"); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			testPort = port
		}
	}

	testDB := os.Getenv("CFGMS_TEST_DB_NAME")
	if testDB == "" {
		testDB = fmt.Sprintf("cfgms_test_%d", time.Now().Unix())
	}

	f.Configs["database"] = &StorageTestConfig{
		Provider: "database",
		Config: map[string]interface{}{
			"host":     testHost,
			"port":     testPort,
			"database": testDB,
			"username": "cfgms_test",
			"password": testPassword,
			"sslmode":  "disable", // For testing only
		},
	}
}

// setupFlatfileConfig creates a flatfile provider configuration backed by a temp dir.
func (f *StorageTestFixture) setupFlatfileConfig(t *testing.T) {
	flatfileDir := filepath.Join(f.TempDir, "flatfile-storage")
	err := os.MkdirAll(flatfileDir, 0755)
	require.NoError(t, err, "Failed to create flatfile storage directory")

	f.Configs["flatfile"] = &StorageTestConfig{
		Provider: "flatfile",
		Config: map[string]interface{}{
			"root": flatfileDir,
		},
		TempDir: flatfileDir,
	}
}

// setupSQLiteConfig creates a sqlite provider configuration backed by a temp file.
// Uses a real file path (not :memory:) to avoid parallel-test issues.
func (f *StorageTestFixture) setupSQLiteConfig(t *testing.T) {
	sqliteDir := filepath.Join(f.TempDir, "sqlite-storage")
	err := os.MkdirAll(sqliteDir, 0755)
	require.NoError(t, err, "Failed to create sqlite storage directory")

	f.Configs["sqlite"] = &StorageTestConfig{
		Provider: "sqlite",
		Config: map[string]interface{}{
			"path": filepath.Join(sqliteDir, "cfgms-test.db"),
		},
		TempDir: sqliteDir,
	}
}

// GetProviderConfig returns the configuration for a specific provider
func (f *StorageTestFixture) GetProviderConfig(provider string) (*StorageTestConfig, bool) {
	config, exists := f.Configs[provider]
	return config, exists
}

// CreateControllerConfig creates a complete controller configuration using the specified storage provider
func (f *StorageTestFixture) CreateControllerConfig(provider string) (*config.Config, error) {
	storageConfig, exists := f.GetProviderConfig(provider)
	if !exists {
		return nil, fmt.Errorf("storage provider not configured in test fixture: %s", provider)
	}

	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider: storageConfig.Provider,
			Config:   storageConfig.Config,
		},
	}, nil
}

// ValidateStorageProvider tests that a storage provider can be initialized successfully
func (f *StorageTestFixture) ValidateStorageProvider(t *testing.T, providerName string) {
	t.Helper()

	// Get the registered provider directly
	provider, err := interfaces.GetStorageProvider(providerName)
	if err != nil {
		t.Skipf("Storage provider '%s' not available: %v", providerName, err)
		return
	}

	require.NotNil(t, provider, "Storage provider '%s' not found in registry", providerName)

	// Get test configuration
	testConfig, exists := f.GetProviderConfig(providerName)
	require.True(t, exists, "Test configuration not found for provider '%s'", providerName)

	t.Run(fmt.Sprintf("provider_%s_availability", providerName), func(t *testing.T) {
		available, err := provider.Available()
		if providerName == "database" {
			// Database may not be available in test environment - that's okay
			if !available {
				t.Skipf("Database provider not available for testing: %v", err)
			}
		} else {
			require.NoError(t, err, "Provider availability check failed")
			require.True(t, available, "Provider should be available")
		}
	})

	// Only run store creation tests if provider is available
	available, err := provider.Available()
	if err != nil || !available {
		if providerName == "database" {
			t.Skipf("Skipping store creation tests - database provider not available: %v", err)
		} else {
			require.NoError(t, err, "Provider should be available for store creation tests")
		}
		return
	}

	t.Run(fmt.Sprintf("provider_%s_client_tenant_store", providerName), func(t *testing.T) {
		store, err := provider.CreateClientTenantStore(testConfig.Config)
		if isUnsupportedStoreError(err) {
			t.Skipf("provider %q does not implement ClientTenantStore (ADR-003 tier boundary)", providerName)
			return
		}
		if err != nil && providerName == "database" {
			requireInfrastructureOrSkip(t, err, "Database provider")
			return
		}
		require.NoError(t, err, "ClientTenantStore creation should succeed")
		require.NotNil(t, store, "ClientTenantStore should not be nil")

		if closer, ok := store.(interface{ Close() error }); ok {
			defer func() { _ = closer.Close() }()
		}
	})

	t.Run(fmt.Sprintf("provider_%s_config_store", providerName), func(t *testing.T) {
		store, err := provider.CreateConfigStore(testConfig.Config)
		if isUnsupportedStoreError(err) {
			t.Skipf("provider %q does not implement ConfigStore (ADR-003 tier boundary)", providerName)
			return
		}
		if err != nil && providerName == "database" {
			requireInfrastructureOrSkip(t, err, "Database provider")
			return
		}
		require.NoError(t, err, "ConfigStore creation should succeed")
		require.NotNil(t, store, "ConfigStore should not be nil")

		if closer, ok := store.(interface{ Close() error }); ok {
			defer func() { _ = closer.Close() }()
		}
	})

	t.Run(fmt.Sprintf("provider_%s_audit_store", providerName), func(t *testing.T) {
		store, err := provider.CreateAuditStore(testConfig.Config)
		if isUnsupportedStoreError(err) {
			t.Skipf("provider %q does not implement AuditStore (ADR-003 tier boundary)", providerName)
			return
		}
		if err != nil && providerName == "database" {
			requireInfrastructureOrSkip(t, err, "Database provider")
			return
		}
		require.NoError(t, err, "AuditStore creation should succeed")
		require.NotNil(t, store, "AuditStore should not be nil")

		if closer, ok := store.(interface{ Close() error }); ok {
			defer func() { _ = closer.Close() }()
		}
	})

	t.Run(fmt.Sprintf("provider_%s_runtime_store", providerName), func(t *testing.T) {
		store, err := provider.CreateRuntimeStore(testConfig.Config)
		if isUnsupportedStoreError(err) {
			t.Skipf("provider %q does not implement RuntimeStore (ADR-003 tier boundary)", providerName)
			return
		}
		if err != nil && providerName == "database" {
			requireInfrastructureOrSkip(t, err, "Database provider")
			return
		}
		require.NoError(t, err, "RuntimeStore creation should succeed")
		require.NotNil(t, store, "RuntimeStore should not be nil")

		if closer, ok := store.(interface{ Close() error }); ok {
			defer func() { _ = closer.Close() }()
		}
	})
}

// TestAllStorageProviders runs validation tests against all registered storage providers
func (f *StorageTestFixture) TestAllStorageProviders(t *testing.T) {
	providerNames := interfaces.GetRegisteredProviderNames()
	require.NotEmpty(t, providerNames, "No storage providers are registered")

	for _, providerName := range providerNames {
		t.Run(fmt.Sprintf("provider_%s", providerName), func(t *testing.T) {
			f.ValidateStorageProvider(t, providerName)
		})
	}
}

// SkipIfDatabaseNotAvailable skips the test if database provider is not available
func SkipIfDatabaseNotAvailable(t *testing.T) {
	if os.Getenv("CFGMS_TEST_DB_PASSWORD") == "" {
		t.Skip("Database testing skipped - CFGMS_TEST_DB_PASSWORD not set")
	}
}

// SkipIfGitNotAvailable skips the test if git provider is not available
func SkipIfGitNotAvailable(t *testing.T) {
	// Git should always be available as it uses local filesystem
	// This is a placeholder for future git-specific requirements
}

// CreateTestStorageManager creates a storage manager for testing purposes
func CreateTestStorageManager() (*interfaces.StorageManager, error) {
	// Use git provider as it's always available for testing
	config := map[string]interface{}{
		"repository_path": "/tmp/cfgms-test-storage",
		"branch":          "main",
		"auto_init":       true,
		"user_name":       "Test User",
		"user_email":      "test@cfgms.test",
	}

	return interfaces.CreateAllStoresFromConfig("git", config)
}
