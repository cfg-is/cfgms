// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Command m365-test provides interactive testing for M365 delegated permissions
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/testing"
)

var (
	clientID     = flag.String("client-id", "", "M365 Application Client ID")
	clientSecret = flag.String("client-secret", "", "M365 Application Client Secret")
	tenantID     = flag.String("tenant-id", "", "M365 Tenant ID")
	redirectURI  = flag.String("redirect-uri", "http://localhost:8080/callback", "OAuth2 Redirect URI")
	credPath     = flag.String("cred-path", "./m365-test-creds", "Path to store credentials")
	interactive  = flag.Bool("interactive", true, "Enable interactive authentication")
	testScopes   = flag.Bool("test-scopes", true, "Test permission scopes after authentication")
	verbose      = flag.Bool("verbose", false, "Enable verbose logging")
)

func main() {
	flag.Parse()

	// Load from environment if not provided via flags
	if *clientID == "" {
		*clientID = os.Getenv("M365_CLIENT_ID")
	}
	if *clientSecret == "" {
		*clientSecret = os.Getenv("M365_CLIENT_SECRET")
	}
	if *tenantID == "" {
		*tenantID = os.Getenv("M365_TENANT_ID")
	}

	// Validate required parameters
	if *clientID == "" || *clientSecret == "" || *tenantID == "" {
		fmt.Printf("❌ Error: Missing required parameters\n\n")
		fmt.Printf("Required parameters (via flags or environment variables):\n")
		fmt.Printf("  -client-id / M365_CLIENT_ID\n")
		fmt.Printf("  -client-secret / M365_CLIENT_SECRET\n")
		fmt.Printf("  -tenant-id / M365_TENANT_ID\n\n")
		fmt.Printf("Example usage:\n")
		fmt.Printf("  export M365_CLIENT_ID=\"your-client-id\"\n")
		fmt.Printf("  export M365_CLIENT_SECRET=\"your-client-secret\"\n")
		fmt.Printf("  export M365_TENANT_ID=\"your-tenant-id\"\n")
		fmt.Printf("  go run cmd/m365-test/main.go\n\n")
		os.Exit(1)
	}

	ctx := context.Background()

	fmt.Printf("🚀 CFGMS M365 Delegated Permissions Testing Tool\n")
	fmt.Printf("===============================================\n\n")

	if *verbose {
		fmt.Printf("Configuration:\n")
		fmt.Printf("  Client ID: %s\n", *clientID)
		fmt.Printf("  Tenant ID: %s\n", *tenantID)
		fmt.Printf("  Redirect URI: %s\n", *redirectURI)
		fmt.Printf("  Credential Path: %s\n", *credPath)
		fmt.Printf("\n")
	}

	// Test the M365 integration
	if err := testM365Integration(ctx); err != nil {
		fmt.Printf("❌ Test failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ All tests completed successfully!\n")
}

func testM365Integration(ctx context.Context) error {
	// Create credential store
	credStore, err := auth.NewFileCredentialStore(*credPath, "m365-test-key")
	if err != nil {
		return fmt.Errorf("failed to create credential store: %w", err)
	}

	// Create OAuth2 configuration
	config := &auth.OAuth2Config{
		ClientID:                 *clientID,
		ClientSecret:             *clientSecret,
		TenantID:                 *tenantID,
		RedirectURI:              *redirectURI,
		SupportDelegatedAuth:     true,
		FallbackToAppPermissions: true,
		DelegatedScopes: []string{
			"User.Read",
			"User.ReadWrite.All",
			"Directory.Read.All",
			"Directory.ReadWrite.All",
			"Group.Read.All",
			"Group.ReadWrite.All",
			"Policy.ReadWrite.ConditionalAccess",
			"DeviceManagementConfiguration.ReadWrite.All",
			"DeviceManagementApps.ReadWrite.All",
		},
		RequiredDelegatedScopes: []string{
			"User.Read",
			"Directory.Read.All",
		},
	}

	// Create provider
	provider := auth.NewOAuth2Provider(credStore, config)

	fmt.Printf("1. Testing Application Permissions (Client Credentials)\n")
	fmt.Printf("-----------------------------------------------------\n")

	// Test application permissions first
	appToken, err := provider.GetAccessToken(ctx, *tenantID)
	if err != nil {
		fmt.Printf("⚠️  Application permissions test failed: %v\n", err)
		fmt.Printf("    This is expected if the app doesn't have application permissions configured.\n\n")
	} else {
		fmt.Printf("✅ Successfully obtained application token\n")
		fmt.Printf("   Token Type: %s\n", appToken.TokenType)
		fmt.Printf("   Expires At: %s\n", appToken.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("   Is Delegated: %t\n\n", appToken.IsDelegated)
	}

	if !*interactive {
		fmt.Printf("Skipping interactive tests (--interactive=false)\n")
		return nil
	}

	fmt.Printf("2. Testing Delegated Permissions (Interactive Flow)\n")
	fmt.Printf("--------------------------------------------------\n")

	// Create interactive authenticator
	interactiveAuth := auth.NewInteractiveAuthenticator(provider, ":8080")

	// Perform interactive authentication
	userContext, delegatedToken, err := interactiveAuth.AuthenticateUser(ctx, *tenantID)
	if err != nil {
		return fmt.Errorf("interactive authentication failed: %w", err)
	}

	// Display user information
	fmt.Printf("\n👤 Authenticated User Information:\n")
	fmt.Printf("   User ID: %s\n", userContext.UserID)
	fmt.Printf("   UPN: %s\n", userContext.UserPrincipalName)
	fmt.Printf("   Display Name: %s\n", userContext.DisplayName)
	fmt.Printf("   Roles: %s\n", strings.Join(userContext.Roles, ", "))
	fmt.Printf("   Session ID: %s\n", userContext.SessionID)
	fmt.Printf("\n🎫 Token Information:\n")
	fmt.Printf("   Token Type: %s\n", delegatedToken.TokenType)
	fmt.Printf("   Expires At: %s\n", delegatedToken.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("   Is Delegated: %t\n", delegatedToken.IsDelegated)
	if len(delegatedToken.GrantedScopes) > 0 {
		fmt.Printf("   Granted Scopes: %s\n", strings.Join(delegatedToken.GrantedScopes, ", "))
	}
	fmt.Printf("\n")

	if *testScopes {
		fmt.Printf("3. Testing Permission Scopes\n")
		fmt.Printf("----------------------------\n")

		// Test delegated permissions
		testResult, err := interactiveAuth.TestDelegatedPermissions(ctx, userContext, delegatedToken)
		if err != nil {
			return fmt.Errorf("permission testing failed: %w", err)
		}

		// Save test results
		if err := saveTestResults(testResult); err != nil {
			fmt.Printf("⚠️  Failed to save test results: %v\n", err)
		}
	}

	fmt.Printf("4. Testing Delegated Token Storage and Retrieval\n")
	fmt.Printf("------------------------------------------------\n")

	// Test storing delegated token
	if err := credStore.StoreDelegatedToken(*tenantID, userContext.UserID, delegatedToken); err != nil {
		return fmt.Errorf("failed to store delegated token: %w", err)
	}
	fmt.Printf("✅ Successfully stored delegated token\n")

	// Test retrieving delegated token
	retrievedToken, err := credStore.GetDelegatedToken(*tenantID, userContext.UserID)
	if err != nil {
		return fmt.Errorf("failed to retrieve delegated token: %w", err)
	}
	fmt.Printf("✅ Successfully retrieved delegated token\n")

	// Verify token matches
	if retrievedToken.Token != delegatedToken.Token {
		return fmt.Errorf("retrieved token doesn't match stored token")
	}
	fmt.Printf("✅ Token integrity verified\n")

	// Test user context storage
	if err := credStore.StoreUserContext(*tenantID, userContext.UserID, userContext); err != nil {
		return fmt.Errorf("failed to store user context: %w", err)
	}
	fmt.Printf("✅ Successfully stored user context\n")

	retrievedContext, err := credStore.GetUserContext(*tenantID, userContext.UserID)
	if err != nil {
		return fmt.Errorf("failed to retrieve user context: %w", err)
	}
	fmt.Printf("✅ Successfully retrieved user context\n")

	// Verify context matches
	if retrievedContext.UserID != userContext.UserID {
		return fmt.Errorf("retrieved context doesn't match stored context")
	}
	fmt.Printf("✅ User context integrity verified\n\n")

	fmt.Printf("5. Testing Delegated Operations via Provider\n")
	fmt.Printf("--------------------------------------------\n")

	// Test getting delegated token via provider
	providerToken, err := provider.GetDelegatedAccessToken(ctx, *tenantID, userContext)
	if err != nil {
		return fmt.Errorf("failed to get delegated token via provider: %w", err)
	}
	fmt.Printf("✅ Successfully obtained delegated token via provider\n")

	if !providerToken.IsDelegated {
		return fmt.Errorf("provider token is not marked as delegated")
	}
	fmt.Printf("✅ Provider token correctly marked as delegated\n")

	if providerToken.UserContext == nil {
		return fmt.Errorf("provider token missing user context")
	}
	fmt.Printf("✅ Provider token includes user context\n")

	fmt.Printf("   User: %s (%s)\n", providerToken.UserContext.DisplayName, providerToken.UserContext.UserPrincipalName)
	fmt.Printf("   Roles: %s\n\n", strings.Join(providerToken.UserContext.Roles, ", "))

	fmt.Printf("6. Testing Real-World M365 Operations\n")
	fmt.Printf("------------------------------------\n")

	// Run comprehensive scenarios
	scenarioRunner := testing.NewScenarioRunner(provider, *tenantID, userContext, delegatedToken)
	scenarios, err := scenarioRunner.RunAllScenarios(ctx)
	if err != nil {
		return fmt.Errorf("scenario testing failed: %w", err)
	}

	// Save scenario results
	if err := saveScenarioResults(scenarios); err != nil {
		fmt.Printf("⚠️  Failed to save scenario results: %v\n", err)
	}

	return nil
}

func saveTestResults(result *auth.PermissionTestResult) error {
	// Create results directory
	resultsDir := filepath.Join(*credPath, "test-results")
	if err := os.MkdirAll(resultsDir, 0700); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	// Generate filename with timestamp
	timestamp := result.TestTimestamp.Format("20060102-150405")
	filename := fmt.Sprintf("permission-test-%s-%s.json",
		strings.ReplaceAll(result.UserContext.UserPrincipalName, "@", "-at-"), timestamp)
	filepath := filepath.Join(resultsDir, filename)

	// Save results as JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal test results: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return fmt.Errorf("failed to write test results: %w", err)
	}

	fmt.Printf("✅ Test results saved to: %s\n\n", filepath)
	return nil
}

func saveScenarioResults(scenarios []*testing.ScenarioResult) error {
	// Create results directory
	resultsDir := filepath.Join(*credPath, "scenario-results")
	if err := os.MkdirAll(resultsDir, 0700); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("scenario-results-%s.json", timestamp)
	filepath := filepath.Join(resultsDir, filename)

	// Save results as JSON
	data, err := json.MarshalIndent(scenarios, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scenario results: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return fmt.Errorf("failed to write scenario results: %w", err)
	}

	fmt.Printf("✅ Scenario results saved to: %s\n\n", filepath)
	return nil
}
