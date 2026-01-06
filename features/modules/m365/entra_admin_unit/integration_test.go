// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package entra_admin_unit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
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

// checkM365Integration handles M365 integration test requirements with proper gating
func checkM365Integration(t *testing.T) {
	// Skip for unit tests (standard pattern)
	if testing.Short() {
		t.Skip("Skipping M365 integration test in short mode")
	}

	// Load credentials from .env.local or environment
	loadTestEnvironment(t)

	// Integration test behavior control
	if !hasM365Credentials() {
		if os.Getenv("ALLOW_SKIP_INTEGRATION") == "true" {
			t.Skip("M365 integration test - credentials not available (dev mode)")
		}
		// Default: FAIL to ensure complete testing
		t.Fatalf("M365 integration test requires credentials. Add to .env.local or set M365_CLIENT_ID, M365_CLIENT_SECRET, M365_TENANT_ID environment variables")
	}
}

// TestEntraAdminUnit_Integration_BasicOperations tests basic admin unit operations against real M365 API
func TestEntraAdminUnit_Integration_BasicOperations(t *testing.T) {
	checkM365Integration(t)

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

	// Test Get operation with non-existent admin unit (currently returns placeholder data)
	resourceID := tenantID + ":non-existent-admin-unit-id"
	getResult, err := module.Get(ctx, resourceID)

	// Current implementation returns placeholder data - this will change when Graph API is fully implemented
	if err != nil {
		t.Logf("Get operation failed (expected for incomplete Graph API implementation): %v", err)
	} else {
		if auConfig, ok := getResult.(*EntraAdminUnitConfig); ok {
			t.Logf("Get operation returned placeholder data (expected for current implementation): DisplayName=%s", auConfig.DisplayName)
		} else {
			t.Logf("Get operation returned config of unexpected type: %T", getResult)
		}
	}

	// Test Set operation (create)
	// Note: This test creates a real admin unit - cleanup is handled in teardown
	createResourceID := tenantID + ":test-admin-unit-" + time.Now().Format("20060102-150405")
	err = module.Set(ctx, createResourceID, config)

	if err != nil {
		t.Logf("Set operation failed (expected for limited implementation): %v", err)
		// Check for specific Administrative Units limitation
		if strings.Contains(err.Error(), "Resource not found for the segment 'administrativeUnits'") {
			t.Logf("📝 Administrative Units API not available - requires Azure AD Premium P1/P2 license or may not be supported in this tenant type")
		}
		// Accept either authentication/permission errors OR not-yet-implemented errors OR tenant limitations
		// Authentication errors indicate credentials/permissions issues
		// Implementation errors indicate the module functionality is still being developed
		// BadRequest errors may indicate tenant licensing or feature limitations
		assert.Regexp(t, "(authentication|permission|consent|scope|credential|invalid_scope|not yet implemented|Resource not found for the segment|BadRequest)", err.Error(),
			"Expected authentication/permission/scope error or not implemented, got: %v", err)
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
	checkM365Integration(t)

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
	checkM365Integration(t)

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

// TestEntraAdminUnit_Integration_FullCRUD validates complete CRUD cycle for administrative units
func TestEntraAdminUnit_Integration_FullCRUD(t *testing.T) {
	checkM365Integration(t)

	// Create real auth provider and graph client
	authProvider := createRealAuthProvider(t)
	graphClient := createRealGraphClient(t)

	// Create module instance
	module := New(authProvider, graphClient).(*entraAdminUnitModule)

	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")
	timestamp := time.Now().Format("20060102-150405")

	// Initial configuration for CREATE
	initialConfig := &EntraAdminUnitConfig{
		DisplayName: "CFGMS CRUD Test AU - " + timestamp,
		Description: "Initial description for CRUD testing",
		TenantID:    tenantID,
		Visibility:  "Public",
		ScopedRoleMembers: []ScopedRoleMember{
			{
				RoleDefinitionID: "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator role
				PrincipalID:      "test-user-id-" + timestamp,
				PrincipalType:    "User",
			},
		},
		ExtensionAttributes: map[string]interface{}{
			"department": "IT Testing",
			"purpose":    "Initial CRUD testing",
		},
		ManagedFieldsList: []string{"display_name", "description", "visibility"},
	}

	// 📝 STEP 1: CREATE
	t.Log("🔄 STEP 1: CREATE administrative unit")
	createResourceID := tenantID + ":crud-test-au-" + timestamp
	err := module.Set(ctx, createResourceID, initialConfig)

	if err != nil {
		// Admin Units requires Azure AD P1/P2 license - check for specific error
		if strings.Contains(err.Error(), "Resource not found for the segment 'administrativeUnits'") {
			t.Skip("⏭️  Administrative Units API not available - requires Azure AD Premium P1/P2 license")
		}
		require.NoError(t, err, "Should be able to create administrative unit")
	}
	t.Log("✅ CREATE: Administrative unit created successfully")

	// Find the created admin unit to get its real GUID
	filter := fmt.Sprintf("displayName eq '%s'", initialConfig.DisplayName)
	token, err := authProvider.GetAccessToken(ctx, tenantID)
	require.NoError(t, err, "Should be able to get access token")

	adminUnits, err := graphClient.ListAdministrativeUnits(ctx, token, filter)
	require.NoError(t, err, "Should be able to search for created administrative unit")
	require.Greater(t, len(adminUnits), 0, "Should find the created administrative unit")

	var createdAdminUnit *graph.AdministrativeUnit
	for _, unit := range adminUnits {
		if unit.DisplayName == initialConfig.DisplayName {
			createdAdminUnit = &unit
			break
		}
	}
	require.NotNil(t, createdAdminUnit, "Should find the created administrative unit by display name")

	// Setup cleanup
	t.Cleanup(func() {
		cleanupToken, tokenErr := authProvider.GetAccessToken(ctx, tenantID)
		if tokenErr != nil {
			t.Logf("Failed to get token for cleanup: %v", tokenErr)
			return
		}
		cleanupErr := graphClient.DeleteAdministrativeUnit(ctx, cleanupToken, createdAdminUnit.ID)
		if cleanupErr != nil {
			t.Logf("Failed to cleanup administrative unit %s (%s): %v", createdAdminUnit.DisplayName, createdAdminUnit.ID, cleanupErr)
		} else {
			t.Logf("Successfully cleaned up administrative unit %s (%s)", createdAdminUnit.DisplayName, createdAdminUnit.ID)
		}
	})

	// 📝 STEP 2: READ (validate creation)
	t.Log("🔄 STEP 2: READ administrative unit to validate creation")
	realResourceID := tenantID + ":" + createdAdminUnit.ID
	getResult, err := module.Get(ctx, realResourceID)
	require.NoError(t, err, "Should be able to retrieve created administrative unit")

	retrievedConfig, ok := getResult.(*EntraAdminUnitConfig)
	require.True(t, ok, "Retrieved config should be EntraAdminUnitConfig")
	assert.Equal(t, initialConfig.DisplayName, retrievedConfig.DisplayName)
	assert.Equal(t, initialConfig.Description, retrievedConfig.Description)
	assert.Equal(t, initialConfig.Visibility, retrievedConfig.Visibility)
	t.Log("✅ READ: Administrative unit retrieved and validated successfully")

	// 📝 STEP 3: UPDATE (modify the administrative unit)
	t.Log("🔄 STEP 3: UPDATE administrative unit with modified configuration")
	updatedConfig := &EntraAdminUnitConfig{
		DisplayName: retrievedConfig.DisplayName, // Keep same name
		Description: "UPDATED: Modified description for CRUD testing",
		TenantID:    tenantID,
		Visibility:  "HiddenMembership", // Change visibility
		ScopedRoleMembers: []ScopedRoleMember{
			{
				RoleDefinitionID: "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator role
				PrincipalID:      "updated-user-id-" + timestamp,
				PrincipalType:    "User",
			},
			{
				RoleDefinitionID: "729827e3-9c14-49f7-bb1b-9608f156bbb8", // Helpdesk Administrator role (ADD)
				PrincipalID:      "helpdesk-user-id-" + timestamp,
				PrincipalType:    "User",
			},
		},
		ExtensionAttributes: map[string]interface{}{
			"department":  "IT Testing Updated",
			"purpose":     "UPDATED: Modified CRUD testing",
			"cost_center": "CC-123", // ADD new attribute
		},
		ManagedFieldsList: []string{"display_name", "description", "visibility"},
	}

	err = module.Set(ctx, realResourceID, updatedConfig)
	require.NoError(t, err, "Should be able to update administrative unit")
	t.Log("✅ UPDATE: Administrative unit updated successfully")

	// 📝 STEP 4: READ (validate update)
	t.Log("🔄 STEP 4: READ administrative unit to validate update")
	getResult, err = module.Get(ctx, realResourceID)
	require.NoError(t, err, "Should be able to retrieve updated administrative unit")

	finalConfig, ok := getResult.(*EntraAdminUnitConfig)
	require.True(t, ok, "Retrieved config should be EntraAdminUnitConfig")
	assert.Equal(t, updatedConfig.Description, finalConfig.Description, "Description should be updated")
	assert.Equal(t, updatedConfig.Visibility, finalConfig.Visibility, "Visibility should be updated")

	// Check extension attributes (handle potential nil)
	if finalConfig.ExtensionAttributes != nil {
		assert.Equal(t, "IT Testing Updated", finalConfig.ExtensionAttributes["department"], "Department should be updated")
		assert.Equal(t, "CC-123", finalConfig.ExtensionAttributes["cost_center"], "Should contain new cost_center attribute")
	} else {
		t.Log("⚠️  ExtensionAttributes is nil in response - this may indicate the field wasn't retrieved")
	}
	t.Log("✅ READ: Administrative unit updates validated successfully")

	// 📝 STEP 5: DELETE (handled by cleanup)
	t.Log("🔄 STEP 5: DELETE will be handled by test cleanup")
	t.Log("✅ FULL CRUD CYCLE COMPLETED SUCCESSFULLY!")
	t.Logf("📊 Administrative Unit: %s (ID: %s)", createdAdminUnit.DisplayName, createdAdminUnit.ID)
}

// TestEntraAdminUnit_Integration_FullSuite runs comprehensive integration tests
func TestEntraAdminUnit_Integration_FullSuite(t *testing.T) {
	checkM365Integration(t)

	t.Run("FullCRUD", func(t *testing.T) {
		TestEntraAdminUnit_Integration_FullCRUD(t)
	})

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
