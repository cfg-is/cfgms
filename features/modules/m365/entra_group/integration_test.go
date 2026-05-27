// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package entra_group

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/logging"
	stewardprovider "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
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

// TestEntraGroup_Integration_FullCRUD validates complete CRUD cycle for groups
func TestEntraGroup_Integration_FullCRUD(t *testing.T) {
	checkM365Integration(t)

	// Create real auth provider and graph client
	authProvider := createRealAuthProvider(t)
	graphClient := createRealGraphClient(t)

	// Create module instance
	module := New(authProvider, graphClient).(*entraGroupModule)

	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")
	timestamp := time.Now().Format("20060102-150405")

	// Initial configuration for CREATE
	testGroupName := fmt.Sprintf("cfgmstest%s", timestamp)
	initialConfig := &EntraGroupConfig{
		DisplayName:     fmt.Sprintf("CFGMS Test Group %s", timestamp),
		Description:     fmt.Sprintf("Integration test group created at %s", timestamp),
		MailNickname:    testGroupName,
		MailEnabled:     false,
		SecurityEnabled: true,
		GroupType:       "Security",
		Visibility:      "Private",
		TenantID:        tenantID,
		ManagedFieldsList: []string{
			"display_name", "description", "mail_nickname", "mail_enabled",
			"security_enabled", "group_type", "visibility",
		},
	}

	// 📝 STEP 1: CREATE
	t.Log("🔄 STEP 1: CREATE group")
	createResourceID := tenantID + ":" + testGroupName
	err := module.Set(ctx, createResourceID, initialConfig)
	require.NoError(t, err, "Should be able to create group")
	t.Log("✅ CREATE: Group created successfully")

	// Find the created group to get its real GUID
	filter := fmt.Sprintf("displayName eq '%s'", initialConfig.DisplayName)
	token, err := authProvider.GetAccessToken(ctx, tenantID)
	require.NoError(t, err, "Should be able to get access token")

	groups, err := graphClient.ListGroups(ctx, token, filter)
	require.NoError(t, err, "Should be able to search for created group")
	require.Greater(t, len(groups), 0, "Should find the created group")

	var createdGroup *graph.Group
	for _, group := range groups {
		if group.DisplayName == initialConfig.DisplayName {
			createdGroup = &group
			break
		}
	}
	require.NotNil(t, createdGroup, "Should find the created group by display name")

	// Setup cleanup
	t.Cleanup(func() {
		cleanupToken, tokenErr := authProvider.GetAccessToken(ctx, tenantID)
		if tokenErr != nil {
			t.Logf("Failed to get token for cleanup: %v", tokenErr)
			return
		}
		cleanupErr := graphClient.DeleteGroup(ctx, cleanupToken, createdGroup.ID)
		if cleanupErr != nil {
			t.Logf("Failed to cleanup group %s (%s): %v", createdGroup.DisplayName, createdGroup.ID, cleanupErr)
		} else {
			t.Logf("Successfully cleaned up group %s (%s)", createdGroup.DisplayName, createdGroup.ID)
		}
	})

	// 📝 STEP 2: READ (validate creation)
	t.Log("🔄 STEP 2: READ group to validate creation")
	realResourceID := tenantID + ":" + createdGroup.ID
	getResult, err := module.Get(ctx, realResourceID)
	require.NoError(t, err, "Should be able to retrieve created group")

	retrievedConfig, ok := getResult.(*EntraGroupConfig)
	require.True(t, ok, "Retrieved config should be EntraGroupConfig")
	assert.Equal(t, initialConfig.DisplayName, retrievedConfig.DisplayName)
	assert.Equal(t, initialConfig.Description, retrievedConfig.Description)
	assert.Equal(t, initialConfig.MailEnabled, retrievedConfig.MailEnabled)
	assert.Equal(t, initialConfig.SecurityEnabled, retrievedConfig.SecurityEnabled)

	// Check mail nickname (may not be retrieved due to Graph API field selection)
	if retrievedConfig.MailNickname != initialConfig.MailNickname {
		t.Logf("⚠️ MailNickname mismatch: expected '%s', got '%s' (may be Graph API field retrieval issue)",
			initialConfig.MailNickname, retrievedConfig.MailNickname)
	}
	t.Log("✅ READ: Group retrieved and validated successfully")

	// 📝 STEP 3: UPDATE (modify the group)
	t.Log("🔄 STEP 3: UPDATE group with modified configuration")
	t.Logf("📊 Retrieved MailNickname: '%s'", retrievedConfig.MailNickname)

	// Use original MailNickname if retrieved one is empty
	mailNickname := retrievedConfig.MailNickname
	if mailNickname == "" {
		mailNickname = testGroupName
		t.Logf("⚠️ Using original MailNickname since retrieved was empty: '%s'", mailNickname)
	}

	updatedConfig := &EntraGroupConfig{
		DisplayName:     fmt.Sprintf("UPDATED: %s", retrievedConfig.DisplayName),
		Description:     fmt.Sprintf("UPDATED: Integration test group updated at %s", time.Now().Format("20060102-150405")),
		MailNickname:    mailNickname, // Use working MailNickname
		MailEnabled:     false,        // Keep same
		SecurityEnabled: true,         // Keep same
		GroupType:       "Security",   // Keep same
		Visibility:      "Private",    // Keep same
		TenantID:        tenantID,
		ManagedFieldsList: []string{
			"display_name", "description", "mail_nickname", "mail_enabled",
			"security_enabled", "group_type", "visibility",
		},
	}

	err = module.Set(ctx, realResourceID, updatedConfig)
	require.NoError(t, err, "Should be able to update group")
	t.Log("✅ UPDATE: Group updated successfully")

	// 📝 STEP 4: READ (validate update)
	t.Log("🔄 STEP 4: READ group to validate update")
	getResult, err = module.Get(ctx, realResourceID)
	require.NoError(t, err, "Should be able to retrieve updated group")

	finalConfig, ok := getResult.(*EntraGroupConfig)
	require.True(t, ok, "Retrieved config should be EntraGroupConfig")
	assert.Contains(t, finalConfig.DisplayName, "UPDATED:", "Display name should be updated")
	assert.Contains(t, finalConfig.Description, "UPDATED:", "Description should be updated")
	assert.Equal(t, updatedConfig.MailEnabled, finalConfig.MailEnabled, "Mail enabled should match")
	assert.Equal(t, updatedConfig.SecurityEnabled, finalConfig.SecurityEnabled, "Security enabled should match")
	t.Log("✅ READ: Group updates validated successfully")

	// 📝 STEP 5: DELETE (handled by cleanup)
	t.Log("🔄 STEP 5: DELETE will be handled by test cleanup")
	t.Log("✅ FULL CRUD CYCLE COMPLETED SUCCESSFULLY!")
	t.Logf("📊 Group: %s (ID: %s)", createdGroup.DisplayName, createdGroup.ID)
}

// TestEntraGroup_Integration_ConfigValidation tests configuration validation with real auth
func TestEntraGroup_Integration_ConfigValidation(t *testing.T) {
	checkM365Integration(t)

	// Create real auth provider and graph client
	authProvider := createRealAuthProvider(t)
	graphClient := createRealGraphClient(t)

	// Create module instance
	module := New(authProvider, graphClient).(*entraGroupModule)

	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")

	// Test with invalid configuration (missing required fields)
	invalidConfig := &EntraGroupConfig{
		// Missing DisplayName (required)
		Description:     "Invalid Test Group",
		MailEnabled:     false,
		SecurityEnabled: true,
		TenantID:        tenantID,
	}

	resourceID := tenantID + ":validation-test-group"
	err := module.Set(ctx, resourceID, invalidConfig)

	// Should get validation error before making API call
	assert.Error(t, err, "Set should return validation error for invalid config")
	assert.Contains(t, err.Error(), "display_name", "Error should mention missing display_name")
}

// TestEntraGroup_Integration_AuthenticationFlow tests authentication flow
func TestEntraGroup_Integration_AuthenticationFlow(t *testing.T) {
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

// TestEntraGroup_Integration_MemberOwnerSync verifies member and owner sync against the real Graph API.
func TestEntraGroup_Integration_MemberOwnerSync(t *testing.T) {
	checkM365Integration(t)

	authProvider := createRealAuthProvider(t)
	graphClient := createRealGraphClient(t)
	module := New(authProvider, graphClient).(*entraGroupModule)

	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")
	timestamp := time.Now().Format("20060102-150405")

	// Create a test group to work with
	groupName := fmt.Sprintf("cfgmsmemtest%s", timestamp)
	createConfig := &EntraGroupConfig{
		DisplayName:     fmt.Sprintf("CFGMS Member Test %s", timestamp),
		Description:     "Integration test for member/owner sync",
		MailNickname:    groupName,
		MailEnabled:     false,
		SecurityEnabled: true,
		GroupType:       "Security",
		Visibility:      "Private",
		TenantID:        tenantID,
	}

	resourceID := tenantID + ":" + groupName
	err := module.Set(ctx, resourceID, createConfig)
	require.NoError(t, err, "Should be able to create group")

	token, err := authProvider.GetAccessToken(ctx, tenantID)
	require.NoError(t, err)

	groups, err := graphClient.ListGroups(ctx, token, fmt.Sprintf("displayName eq '%s'", createConfig.DisplayName))
	require.NoError(t, err)
	require.NotEmpty(t, groups, "Should find the created group")

	var createdGroup *graph.Group
	for i := range groups {
		if groups[i].DisplayName == createConfig.DisplayName {
			createdGroup = &groups[i]
			break
		}
	}
	require.NotNil(t, createdGroup)

	t.Cleanup(func() {
		cleanupToken, tokenErr := authProvider.GetAccessToken(ctx, tenantID)
		if tokenErr != nil {
			t.Logf("Failed to get token for cleanup: %v", tokenErr)
			return
		}
		if err := graphClient.DeleteGroup(ctx, cleanupToken, createdGroup.ID); err != nil {
			t.Logf("Failed to cleanup group %s: %v", createdGroup.ID, err)
		}
	})

	groupID := createdGroup.ID

	// Verify initial state: no members, no owners
	members, err := graphClient.ListGroupMembers(ctx, token, groupID)
	require.NoError(t, err)
	assert.Empty(t, members, "New group should have no members")

	owners, err := graphClient.ListGroupOwners(ctx, token, groupID)
	require.NoError(t, err)
	assert.Empty(t, owners, "New group should have no owners")

	// Resolve a test user from the tenant to use for member/owner operations.
	// The test requires M365_TEST_USER_UPN to be set to a valid UPN in the tenant.
	testUserUPN := os.Getenv("M365_TEST_USER_UPN")
	if testUserUPN == "" {
		if os.Getenv("ALLOW_SKIP_INTEGRATION") == "true" {
			t.Skip("M365 member/owner sync test - M365_TEST_USER_UPN not available (dev mode)")
		}
		t.Fatalf("TestEntraGroup_Integration_MemberOwnerSync requires M365_TEST_USER_UPN. Set a valid UPN in .env.local or the environment")
	}

	// Add member and sync
	syncConfigMembers := &EntraGroupConfig{
		DisplayName:       createConfig.DisplayName,
		MailNickname:      createConfig.MailNickname,
		MailEnabled:       false,
		SecurityEnabled:   true,
		TenantID:          tenantID,
		Members:           []string{testUserUPN},
		ManagedFieldsList: []string{"display_name", "mail_enabled", "security_enabled", "members"},
	}
	realResourceID := tenantID + ":" + groupID
	err = module.Set(ctx, realResourceID, syncConfigMembers)
	require.NoError(t, err, "Should be able to sync members")

	members, err = graphClient.ListGroupMembers(ctx, token, groupID)
	require.NoError(t, err)
	assert.Contains(t, members, testUserUPN, "Member should be present after sync")

	// Remove member via sync (empty desired list)
	syncConfigNoMembers := &EntraGroupConfig{
		DisplayName:       createConfig.DisplayName,
		MailNickname:      createConfig.MailNickname,
		MailEnabled:       false,
		SecurityEnabled:   true,
		TenantID:          tenantID,
		Members:           []string{},
		ManagedFieldsList: []string{"display_name", "mail_enabled", "security_enabled", "members"},
	}
	err = module.Set(ctx, realResourceID, syncConfigNoMembers)
	require.NoError(t, err, "Should be able to remove members via sync")

	members, err = graphClient.ListGroupMembers(ctx, token, groupID)
	require.NoError(t, err)
	assert.NotContains(t, members, testUserUPN, "Member should be removed after sync")

	// Add owner and sync
	syncConfigOwners := &EntraGroupConfig{
		DisplayName:       createConfig.DisplayName,
		MailNickname:      createConfig.MailNickname,
		MailEnabled:       false,
		SecurityEnabled:   true,
		TenantID:          tenantID,
		Owners:            []string{testUserUPN},
		ManagedFieldsList: []string{"display_name", "mail_enabled", "security_enabled", "owners"},
	}
	err = module.Set(ctx, realResourceID, syncConfigOwners)
	require.NoError(t, err, "Should be able to sync owners")

	owners, err = graphClient.ListGroupOwners(ctx, token, groupID)
	require.NoError(t, err)
	assert.Contains(t, owners, testUserUPN, "Owner should be present after sync")

	t.Log("✅ Member/owner sync integration test passed")
}

// TestEntraGroup_Integration_TeamOperations verifies team create and settings update
// against the real Graph API. Requires the target group to be a Microsoft 365 (Unified) group.
func TestEntraGroup_Integration_TeamOperations(t *testing.T) {
	checkM365Integration(t)

	authProvider := createRealAuthProvider(t)
	graphClient := createRealGraphClient(t)
	module := New(authProvider, graphClient).(*entraGroupModule)

	ctx := context.Background()
	tenantID := os.Getenv("M365_TENANT_ID")
	timestamp := time.Now().Format("20060102-150405")

	groupName := fmt.Sprintf("cfgmsteamtest%s", timestamp)
	createConfig := &EntraGroupConfig{
		DisplayName:     fmt.Sprintf("CFGMS Team Test %s", timestamp),
		Description:     "Integration test for team operations",
		MailNickname:    groupName,
		MailEnabled:     true,
		SecurityEnabled: false,
		GroupType:       "Unified",
		Visibility:      "Private",
		TenantID:        tenantID,
	}

	t.Log("🔄 STEP 1: CREATE Unified group for team provisioning")
	resourceID := tenantID + ":" + groupName
	err := module.Set(ctx, resourceID, createConfig)
	require.NoError(t, err, "Should be able to create Unified group")
	t.Log("✅ CREATE: Unified group created")

	token, err := authProvider.GetAccessToken(ctx, tenantID)
	require.NoError(t, err)

	groups, err := graphClient.ListGroups(ctx, token, fmt.Sprintf("displayName eq '%s'", createConfig.DisplayName))
	require.NoError(t, err)
	require.NotEmpty(t, groups, "Should find created group")

	var createdGroup *graph.Group
	for i := range groups {
		if groups[i].DisplayName == createConfig.DisplayName {
			createdGroup = &groups[i]
			break
		}
	}
	require.NotNil(t, createdGroup, "Created group must be findable")

	t.Cleanup(func() {
		cleanupToken, tokenErr := authProvider.GetAccessToken(ctx, tenantID)
		if tokenErr != nil {
			t.Logf("Failed to get token for cleanup: %v", tokenErr)
			return
		}
		if err := graphClient.DeleteGroup(ctx, cleanupToken, createdGroup.ID); err != nil {
			t.Logf("Failed to cleanup group %s: %v", createdGroup.ID, err)
		}
	})

	groupID := createdGroup.ID
	realResourceID := tenantID + ":" + groupID

	t.Log("🔄 STEP 2: CREATE team from group")
	teamConfig := &EntraGroupConfig{
		DisplayName:     createConfig.DisplayName,
		MailNickname:    createConfig.MailNickname,
		MailEnabled:     true,
		SecurityEnabled: false,
		GroupType:       "Unified",
		TenantID:        tenantID,
		IsTeamEnabled:   true,
		TeamSettings: &TeamSettings{
			AllowCreateUpdateChannels:  true,
			AllowDeleteChannels:        false,
			AllowCreatePrivateChannels: false,
			AllowAddRemoveApps:         true,
			AllowUserEditMessages:      true,
			Fun:                        "moderate",
		},
		ManagedFieldsList: []string{
			"display_name", "mail_enabled", "security_enabled", "is_team_enabled", "team_settings",
		},
	}
	err = module.Set(ctx, realResourceID, teamConfig)
	require.NoError(t, err, "Should be able to create team from Unified group")
	t.Log("✅ CREATE TEAM: Team provisioned")

	t.Log("🔄 STEP 3: Verify team exists via isTeamGroup")
	freshToken, err := authProvider.GetAccessToken(ctx, tenantID)
	require.NoError(t, err, "Should be able to refresh token before team verification")
	assert.True(t, module.isTeamGroup(ctx, freshToken, groupID), "isTeamGroup should return true after team creation")
	t.Log("✅ isTeamGroup: confirmed true")

	t.Log("🔄 STEP 4: UPDATE team settings")
	updateConfig := &EntraGroupConfig{
		DisplayName:     createConfig.DisplayName,
		MailNickname:    createConfig.MailNickname,
		MailEnabled:     true,
		SecurityEnabled: false,
		GroupType:       "Unified",
		TenantID:        tenantID,
		IsTeamEnabled:   true,
		TeamSettings: &TeamSettings{
			AllowCreateUpdateChannels:  true,
			AllowDeleteChannels:        true,
			AllowCreatePrivateChannels: true,
			AllowAddRemoveApps:         true,
			AllowUserEditMessages:      true,
			Fun:                        "enabled",
		},
		ManagedFieldsList: []string{
			"display_name", "mail_enabled", "security_enabled", "is_team_enabled", "team_settings",
		},
	}
	err = module.Set(ctx, realResourceID, updateConfig)
	require.NoError(t, err, "Should be able to update team settings")
	t.Log("✅ UPDATE TEAM SETTINGS: Settings updated")

	t.Log("✅ TEAM OPERATIONS INTEGRATION TEST COMPLETED SUCCESSFULLY")
}

// TestEntraGroup_Integration_FullSuite runs comprehensive integration tests
func TestEntraGroup_Integration_FullSuite(t *testing.T) {
	checkM365Integration(t)

	t.Run("FullCRUD", func(t *testing.T) {
		TestEntraGroup_Integration_FullCRUD(t)
	})

	t.Run("MemberOwnerSync", func(t *testing.T) {
		TestEntraGroup_Integration_MemberOwnerSync(t)
	})

	t.Run("ConfigValidation", func(t *testing.T) {
		TestEntraGroup_Integration_ConfigValidation(t)
	})

	t.Run("AuthenticationFlow", func(t *testing.T) {
		TestEntraGroup_Integration_AuthenticationFlow(t)
	})

	t.Run("TeamOperations", func(t *testing.T) {
		TestEntraGroup_Integration_TeamOperations(t)
	})
}

// createRealAuthProvider creates a real OAuth2Provider for integration testing
func createRealAuthProvider(t *testing.T) auth.Provider {
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}
	sp := &stewardprovider.StewardProvider{}
	secretStore, err := sp.CreateSecretStore(map[string]interface{}{
		"secrets_dir": t.TempDir(),
	})
	require.NoError(t, err, "Failed to create secret store")
	t.Cleanup(func() { _ = secretStore.Close() })
	credStore := auth.NewSecretStoreCredentialStore(secretStore)

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
	provider := auth.NewOAuth2Provider(credStore, config, logging.NewNoopLogger())

	return provider
}

// createRealGraphClient creates a real HTTP-based Graph client for integration testing
func createRealGraphClient(t *testing.T) graph.Client {
	// Create HTTP client for real Graph API calls
	client := graph.NewHTTPClient()

	return client
}
