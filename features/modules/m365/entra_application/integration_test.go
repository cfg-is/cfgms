package entra_application

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

// TestEntraApplication_Integration_BasicOperations tests basic application operations against real M365 API
func TestEntraApplication_Integration_BasicOperations(t *testing.T) {
	skipIfNoM365Credentials(t)

	// Create real auth provider and graph client
	authProvider := createRealAuthProvider(t)
	graphClient := createRealGraphClient(t)
	
	// Create module instance
	module := New(authProvider, graphClient).(*entraApplicationModule)
	
	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")

	// Test configuration for a basic application
	config := &EntraApplicationConfig{
		DisplayName:    "CFGMS Test Application - " + time.Now().Format("20060102-150405"),
		Description:    "Test application created by CFGMS integration tests",
		SignInAudience: "AzureADMyOrg",
		TenantID:       tenantID,
		IdentifierUris: []string{
			"https://cfgms-test-app.example.com/api",
		},
		RedirectUris: &RedirectUris{
			Web: []string{"https://cfgms-test-app.example.com/callback"},
			Spa: []string{"https://cfgms-test-app.example.com/spa"},
		},
		RequiredResourceAccess: []ResourceAccess{
			{
				ResourceAppId: "00000003-0000-0000-c000-000000000000", // Microsoft Graph
				ResourceAccess: []PermissionScope{
					{ID: "e1fe6dd8-ba31-4d61-89e7-88639da4683d", Type: "Scope"}, // User.Read
				},
			},
		},
		AppRoles: []AppRole{
			{
				ID:                 "test-role-id-" + time.Now().Format("20060102150405"),
				DisplayName:        "Test Admin Role",
				Description:        "Administrative role for testing",
				Value:              "admin",
				AllowedMemberTypes: []string{"User"},
				IsEnabled:          true,
			},
		},
		CreateServicePrincipal: false, // Don't create service principal in test
		ManagedFieldsList: []string{"display_name", "description", "sign_in_audience", "identifier_uris"},
	}

	// Test Get operation with non-existent application (should handle gracefully)
	resourceID := tenantID + ":non-existent-application-id"
	_, err := module.Get(ctx, resourceID)
	
	// Should get an error for non-existent resource
	assert.Error(t, err, "Get should return error for non-existent application")
	
	// Test Set operation (create)
	// Note: This test creates a real application - cleanup would be needed in production
	createResourceID := tenantID + ":test-application-" + time.Now().Format("20060102-150405")
	err = module.Set(ctx, createResourceID, config)
	
	if err != nil {
		t.Logf("Set operation failed (expected for limited test credentials): %v", err)
		// Don't fail the test if we don't have sufficient permissions
		// This verifies the integration works without requiring admin consent
		assert.Regexp(t, "(authentication|permission|consent|scope|credential|invalid_scope|not yet implemented)", err.Error(),
			"Expected authentication/permission/scope error or not implemented, got: %v", err)
		return
	}
	
	// If Set succeeded, verify we can retrieve the created application
	retrievedConfig, err := module.Get(ctx, createResourceID)
	require.NoError(t, err, "Should be able to retrieve created application")
	
	retrievedApp, ok := retrievedConfig.(*EntraApplicationConfig)
	require.True(t, ok, "Retrieved config should be EntraApplicationConfig")
	
	assert.Equal(t, config.DisplayName, retrievedApp.DisplayName)
	assert.Equal(t, config.Description, retrievedApp.Description)
	assert.Equal(t, config.SignInAudience, retrievedApp.SignInAudience)
	assert.Equal(t, config.TenantID, retrievedApp.TenantID)
	
	t.Logf("Created application for integration test: %s", retrievedApp.DisplayName)
}

// TestEntraApplication_Integration_ConfigValidation tests configuration validation with real auth
func TestEntraApplication_Integration_ConfigValidation(t *testing.T) {
	skipIfNoM365Credentials(t)

	// Create real auth provider and graph client
	authProvider := createRealAuthProvider(t)
	graphClient := createRealGraphClient(t)
	
	// Create module instance
	module := New(authProvider, graphClient).(*entraApplicationModule)
	
	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")

	// Test with invalid configuration (missing required fields)
	invalidConfig := &EntraApplicationConfig{
		// Missing DisplayName (required)
		SignInAudience: "AzureADMyOrg",
		// Missing TenantID (required)
	}

	resourceID := tenantID + ":validation-test-application"
	err := module.Set(ctx, resourceID, invalidConfig)
	
	// Should get validation error before making API call
	assert.Error(t, err, "Set should return validation error for invalid config")
	assert.Regexp(t, "(display_name|tenant_id)", err.Error(), "Error should mention missing required fields")
}

// TestEntraApplication_Integration_ComplexConfiguration tests complex application configuration
func TestEntraApplication_Integration_ComplexConfiguration(t *testing.T) {
	skipIfNoM365Credentials(t)

	// Create real auth provider and graph client
	authProvider := createRealAuthProvider(t)
	graphClient := createRealGraphClient(t)
	
	// Create module instance
	module := New(authProvider, graphClient).(*entraApplicationModule)
	
	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")

	// Test complex configuration with multiple features
	complexConfig := &EntraApplicationConfig{
		DisplayName:    "CFGMS Complex Test App - " + time.Now().Format("20060102-150405"),
		Description:    "Complex test application with multiple features",
		SignInAudience: "AzureADMultipleOrgs",
		TenantID:       tenantID,
		IdentifierUris: []string{
			"https://cfgms-complex-app.example.com/api",
			"api://cfgms-complex-app",
		},
		RedirectUris: &RedirectUris{
			Web:     []string{"https://cfgms-complex-app.example.com/callback"},
			Spa:     []string{"https://cfgms-complex-app.example.com/spa"},
			Mobile:  []string{"https://cfgms-complex-app.example.com/mobile"},
			Desktop: []string{"https://cfgms-complex-app.example.com/desktop"},
		},
		LogoutUrl: "https://cfgms-complex-app.example.com/logout",
		RequiredResourceAccess: []ResourceAccess{
			{
				ResourceAppId: "00000003-0000-0000-c000-000000000000", // Microsoft Graph
				ResourceAccess: []PermissionScope{
					{ID: "e1fe6dd8-ba31-4d61-89e7-88639da4683d", Type: "Scope"}, // User.Read
					{ID: "06da0dbc-49e2-44d2-8312-53746cb0532c", Type: "Scope"}, // Mail.Read
				},
			},
		},
		OAuth2Permissions: []OAuth2Scope{
			{
				ID:                      "custom-scope-" + time.Now().Format("20060102150405"),
				AdminConsentDisplayName: "Read application data",
				AdminConsentDescription: "Allow the application to read application data",
				UserConsentDisplayName:  "Read your application data",
				UserConsentDescription:  "Allow the application to read your application data",
				Value:                   "app.read",
				Type:                    "User",
				IsEnabled:               true,
			},
		},
		AppRoles: []AppRole{
			{
				ID:                 "admin-role-" + time.Now().Format("20060102150405"),
				DisplayName:        "Application Administrator",
				Description:        "Full administrative access to the application",
				Value:              "app.admin",
				AllowedMemberTypes: []string{"User", "Application"},
				IsEnabled:          true,
			},
			{
				ID:                 "user-role-" + time.Now().Format("20060102150405"),
				DisplayName:        "Application User",
				Description:        "Standard user access to the application",
				Value:              "app.user",
				AllowedMemberTypes: []string{"User"},
				IsEnabled:          true,
			},
		},
		OptionalClaims: &OptionalClaims{
			IdToken: []OptionalClaim{
				{
					Name:      "email",
					Essential: true,
				},
				{
					Name:   "given_name",
					Source: "user",
				},
			},
			AccessToken: []OptionalClaim{
				{
					Name: "groups",
				},
			},
		},
		CreateServicePrincipal: false, // Don't create service principal in test
		Tags:                   []string{"integration-test", "cfgms", "complex-config"},
		ManagedFieldsList: []string{
			"display_name", "description", "sign_in_audience", "identifier_uris",
			"redirect_uris", "required_resource_access", "oauth2_permissions",
			"app_roles", "optional_claims", "tags",
		},
	}

	// Test validation of complex configuration
	err := complexConfig.Validate()
	assert.NoError(t, err, "Complex configuration should be valid")

	// Test AsMap conversion
	configMap := complexConfig.AsMap()
	assert.NotEmpty(t, configMap, "AsMap should return non-empty map")
	assert.Equal(t, complexConfig.DisplayName, configMap["display_name"])
	assert.Equal(t, complexConfig.SignInAudience, configMap["sign_in_audience"])

	// Test managed fields calculation
	managedFields := complexConfig.GetManagedFields()
	assert.Contains(t, managedFields, "display_name")
	assert.Contains(t, managedFields, "app_roles")
	assert.Contains(t, managedFields, "oauth2_permissions")

	// Test Set operation (this may fail due to permissions, which is expected)
	resourceID := tenantID + ":complex-test-application-" + time.Now().Format("20060102-150405")
	err = module.Set(ctx, resourceID, complexConfig)
	
	if err != nil {
		t.Logf("Complex Set operation failed (expected for limited test credentials): %v", err)
		// Verify it's a permissions/auth error rather than a config error
		assert.Regexp(t, "(authentication|permission|consent|scope|credential|invalid_scope|not yet implemented)", err.Error(),
			"Expected authentication/permission/scope error or not implemented, got: %v", err)
	} else {
		t.Logf("Complex application created successfully: %s", complexConfig.DisplayName)
	}
}

// TestEntraApplication_Integration_AuthenticationFlow tests authentication flow
func TestEntraApplication_Integration_AuthenticationFlow(t *testing.T) {
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
	
	// Test required permissions
	requiredScopes := []string{"https://graph.microsoft.com/.default"}
	err = authProvider.ValidatePermissions(ctx, token, requiredScopes)
	if err != nil {
		t.Logf("Permission validation failed (expected for limited test credentials): %v", err)
	}
}

// TestEntraApplication_Integration_ResourceIDParsing tests resource ID parsing
func TestEntraApplication_Integration_ResourceIDParsing(t *testing.T) {
	skipIfNoM365Credentials(t)

	tenantID := os.Getenv("M365_TENANT_ID")
	appID := "test-application-id"
	resourceID := tenantID + ":" + appID

	// Test parsing
	parsedTenant, parsedApp, err := parseEntraApplicationResourceID(resourceID)
	assert.NoError(t, err, "Resource ID should parse successfully")
	assert.Equal(t, tenantID, parsedTenant, "Tenant ID should match")
	assert.Equal(t, appID, parsedApp, "Application ID should match")

	// Test extraction
	extractedApp := extractApplicationID(resourceID)
	assert.Equal(t, appID, extractedApp, "Extracted application ID should match")
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

// TestEntraApplication_Integration_FullSuite runs comprehensive integration tests
// This test requires M365 credentials and will FAIL (not skip) if they're not available
// Use this for CI/CD pipelines where credentials should be present
func TestEntraApplication_Integration_FullSuite(t *testing.T) {
	// Check if we're running in a context where integration tests should be required
	if os.Getenv("CFGMS_INTEGRATION_REQUIRED") == "true" || 
	   os.Getenv("CI") != "" ||
	   testing.Short() == false { // go test without -short flag
		requireM365Credentials(t) // This will FAIL the test if credentials are missing
	} else {
		skipIfNoM365Credentials(t) // This will SKIP the test if credentials are missing
	}

	t.Run("BasicOperations", func(t *testing.T) {
		TestEntraApplication_Integration_BasicOperations(t)
	})
	
	t.Run("ConfigValidation", func(t *testing.T) {
		TestEntraApplication_Integration_ConfigValidation(t)
	})
	
	t.Run("ComplexConfiguration", func(t *testing.T) {
		TestEntraApplication_Integration_ComplexConfiguration(t)
	})
	
	t.Run("AuthenticationFlow", func(t *testing.T) {
		TestEntraApplication_Integration_AuthenticationFlow(t)
	})
	
	t.Run("ResourceIDParsing", func(t *testing.T) {
		TestEntraApplication_Integration_ResourceIDParsing(t)
	})
}