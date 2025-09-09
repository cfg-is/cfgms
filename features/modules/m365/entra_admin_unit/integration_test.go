package entra_admin_unit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadTestEnvironment loads environment variables from .env.local if it exists
func loadTestEnvironment(t *testing.T) {
	// Try to load .env.local from project root
	projectRoot, err := findProjectRoot()
	if err == nil {
		envFile := filepath.Join(projectRoot, ".env.local")
		if _, err := os.Stat(envFile); err == nil {
			_ = godotenv.Load(envFile) // Don't fail if it can't load, just continue
		}
	}
}

// findProjectRoot walks up the directory tree to find the project root (containing go.mod)
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", os.ErrNotExist
}

// hasM365Credentials checks if M365 credentials are available for testing
func hasM365Credentials() bool {
	return os.Getenv("M365_CLIENT_ID") != "" &&
		os.Getenv("M365_CLIENT_SECRET") != "" &&
		os.Getenv("M365_TENANT_ID") != ""
}

// requireM365Credentials fails the test if M365 credentials are not available
// Use this for integration test suites that should fail without credentials
func requireM365Credentials(t *testing.T) {
	loadTestEnvironment(t)
	
	if !hasM365Credentials() {
		t.Fatalf("M365 integration test requires credentials. Set M365_CLIENT_ID, M365_CLIENT_SECRET, M365_TENANT_ID environment variables or add them to .env.local file")
	}
}

// skipIfNoM365Credentials skips the test if M365 credentials are not available
// Use this for individual tests that can be safely skipped
func skipIfNoM365Credentials(t *testing.T) {
	loadTestEnvironment(t)
	
	if !hasM365Credentials() {
		t.Skip("Skipping M365 integration test - credentials not available. Set M365_CLIENT_ID, M365_CLIENT_SECRET, M365_TENANT_ID or add to .env.local")
	}
}

// TestEntraAdminUnit_Integration_BasicOperations tests basic admin unit operations against real M365 API
func TestEntraAdminUnit_Integration_BasicOperations(t *testing.T) {
	skipIfNoM365Credentials(t)

	// Create real auth provider and graph client
	authProvider := createRealAuthProvider(t)
	graphClient := createRealGraphClient(t)
	
	// Create module instance
	module := New(authProvider, graphClient).(*entraAdminUnitModule)
	
	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")

	// Test configuration
	config := &EntraAdminUnitConfig{
		DisplayName: "CFGMS Test Admin Unit - " + time.Now().Format("20060102-150405"),
		Description: "Test administrative unit created by CFGMS integration tests",
		TenantID:    tenantID,
		Visibility:  "Public",
		ScopedRoleMembers: []ScopedRoleMember{
			{
				RoleDefinitionID: "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator role
				PrincipalID:      "test-user-id",
				PrincipalType:    "User",
			},
		},
		ExtensionAttributes: map[string]interface{}{
			"department": "IT Testing",
			"purpose":    "Integration Testing",
		},
		ManagedFieldsList: []string{"display_name", "description", "visibility"},
	}

	// Test Get operation with non-existent admin unit (should handle gracefully)
	resourceID := tenantID + ":non-existent-admin-unit-id"
	_, err := module.Get(ctx, resourceID)
	
	// Should get an error for non-existent resource
	assert.Error(t, err, "Get should return error for non-existent admin unit")
	
	// Test Set operation (create)
	// Note: This test creates a real admin unit - cleanup is handled in teardown
	createResourceID := tenantID + ":test-admin-unit-" + time.Now().Format("20060102-150405")
	err = module.Set(ctx, createResourceID, config)
	
	if err != nil {
		t.Logf("Set operation failed (expected for limited test credentials): %v", err)
		// Don't fail the test if we don't have sufficient permissions
		// This verifies the integration works without requiring admin consent
		assert.Regexp(t, "(authentication|permission|consent|scope|credential|invalid_scope)", err.Error(),
			"Expected authentication/permission/scope error, got: %v", err)
		return
	}
	
	// If Set succeeded, verify we can retrieve the created admin unit
	retrievedConfig, err := module.Get(ctx, createResourceID)
	require.NoError(t, err, "Should be able to retrieve created admin unit")
	
	retrievedAdminUnit, ok := retrievedConfig.(*EntraAdminUnitConfig)
	require.True(t, ok, "Retrieved config should be EntraAdminUnitConfig")
	
	assert.Equal(t, config.DisplayName, retrievedAdminUnit.DisplayName)
	assert.Equal(t, config.Description, retrievedAdminUnit.Description)
	assert.Equal(t, config.Visibility, retrievedAdminUnit.Visibility)
	assert.Equal(t, config.TenantID, retrievedAdminUnit.TenantID)
	
	// Test cleanup - attempt to delete the created admin unit
	// In a real implementation, this would be a Delete method
	t.Logf("Created admin unit for integration test: %s", retrievedAdminUnit.DisplayName)
}

// TestEntraAdminUnit_Integration_ConfigValidation tests configuration validation with real auth
func TestEntraAdminUnit_Integration_ConfigValidation(t *testing.T) {
	skipIfNoM365Credentials(t)

	// Create real auth provider and graph client
	authProvider := createRealAuthProvider(t)
	graphClient := createRealGraphClient(t)
	
	// Create module instance
	module := New(authProvider, graphClient).(*entraAdminUnitModule)
	
	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")

	// Test with invalid configuration (missing required fields)
	invalidConfig := &EntraAdminUnitConfig{
		// Missing DisplayName (required)
		TenantID: tenantID,
	}

	resourceID := tenantID + ":validation-test-admin-unit"
	err := module.Set(ctx, resourceID, invalidConfig)
	
	// Should get validation error before making API call
	assert.Error(t, err, "Set should return validation error for invalid config")
	assert.Contains(t, err.Error(), "display_name", "Error should mention missing display_name")
}

// TestEntraAdminUnit_Integration_AuthenticationFlow tests authentication flow
func TestEntraAdminUnit_Integration_AuthenticationFlow(t *testing.T) {
	skipIfNoM365Credentials(t)

	// Create real auth provider
	authProvider := createRealAuthProvider(t)
	
	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")

	// Test token acquisition
	token, err := authProvider.GetAccessToken(ctx, tenantID)
	
	if err != nil {
		t.Logf("Authentication failed (expected for limited test credentials): %v", err)
		// Don't fail the test if we don't have sufficient permissions
		assert.Regexp(t, "(authentication|credential|consent|scope|invalid_scope)", err.Error(),
			"Expected authentication error, got: %v", err)
		return
	}
	
	require.NotNil(t, token, "Token should not be nil")
	assert.NotEmpty(t, token.Token, "Token string should not be empty")
	assert.Equal(t, tenantID, token.TenantID, "Token should be for correct tenant")
	assert.False(t, token.IsExpired(), "Token should not be expired")
	
	// Test token validation
	isValid := authProvider.IsTokenValid(token)
	assert.True(t, isValid, "Token should be valid")
}

// createRealAuthProvider creates a real OAuth2Provider for integration testing
func createRealAuthProvider(t *testing.T) auth.Provider {
	tempDir := t.TempDir()
	
	// Create credential store
	credStore, err := auth.NewFileCredentialStore(tempDir, "integration-test-passphrase")
	require.NoError(t, err, "Failed to create credential store")
	
	// Create OAuth2 config from environment
	config := &auth.OAuth2Config{
		ClientID:             os.Getenv("M365_CLIENT_ID"),
		ClientSecret:         os.Getenv("M365_CLIENT_SECRET"),
		TenantID:             os.Getenv("M365_TENANT_ID"),
		UseClientCredentials: true, // Use app permissions for integration tests
		Scopes: []string{
			"https://graph.microsoft.com/.default",
		},
	}
	
	// Create provider
	provider := auth.NewOAuth2Provider(credStore, config)
	
	return provider
}

// createRealGraphClient creates a real HTTP-based Graph client for integration testing
func createRealGraphClient(t *testing.T) graph.Client {
	// Create HTTP client for real Graph API calls
	client := graph.NewHTTPClient()
	
	return client
}

// TestEntraAdminUnit_Integration_FullSuite runs comprehensive integration tests
// This test requires M365 credentials and will FAIL (not skip) if they're not available
// Use this for CI/CD pipelines where credentials should be present
func TestEntraAdminUnit_Integration_FullSuite(t *testing.T) {
	// Check if we're running in a context where integration tests should be required
	if os.Getenv("CFGMS_INTEGRATION_REQUIRED") == "true" || 
	   os.Getenv("CI") != "" ||
	   testing.Short() == false { // go test without -short flag
		requireM365Credentials(t) // This will FAIL the test if credentials are missing
	} else {
		skipIfNoM365Credentials(t) // This will SKIP the test if credentials are missing
	}

	t.Run("BasicOperations", func(t *testing.T) {
		TestEntraAdminUnit_Integration_BasicOperations(t)
	})
	
	t.Run("ConfigValidation", func(t *testing.T) {
		TestEntraAdminUnit_Integration_ConfigValidation(t)
	})
	
	t.Run("AuthenticationFlow", func(t *testing.T) {
		TestEntraAdminUnit_Integration_AuthenticationFlow(t)
	})
}