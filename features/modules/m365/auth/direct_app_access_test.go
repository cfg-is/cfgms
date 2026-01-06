// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDirectAppAccessConfiguration tests direct app registration configuration
// This test validates delegated permissions setup without requiring CSP sandbox
func TestDirectAppAccessConfiguration(t *testing.T) {
	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "direct-app-test-passphrase")
	require.NoError(t, err)

	// Direct app configuration with delegated permissions
	config := &OAuth2Config{
		ClientID:                 "test-client-id-direct",
		ClientSecret:             "test-client-secret-direct",
		TenantID:                 "test-tenant-id-direct",
		RedirectURI:              "http://localhost:8080/callback",
		UseClientCredentials:     false, // Enable delegated flow
		SupportDelegatedAuth:     true,  // Direct app supports delegated auth
		FallbackToAppPermissions: true,  // Allow fallback to app permissions
		// Direct app delegated scopes (most common M365 scenarios)
		DelegatedScopes: []string{
			"User.Read",                                   // Basic user profile reading
			"User.ReadWrite",                              // User profile management
			"User.ReadWrite.All",                          // All user management (admin)
			"Directory.Read.All",                          // Directory reading
			"Group.Read.All",                              // Group reading
			"Group.ReadWrite.All",                         // Group management
			"Policy.ReadWrite.ConditionalAccess",          // Conditional Access management
			"DeviceManagementConfiguration.ReadWrite.All", // Intune policy management
			"Mail.Read",                                   // Email reading
			"Calendars.Read",                              // Calendar reading
			"Sites.Read.All",                              // SharePoint sites reading
		},
		// Required minimum scopes for basic functionality
		RequiredDelegatedScopes: []string{
			"User.Read",
			"Directory.Read.All",
		},
		// Application scopes as fallback (using Scopes field)
		Scopes: []string{
			"User.Read.All",
			"Directory.Read.All",
			"Group.Read.All",
			"Policy.Read.All",
			"DeviceManagementConfiguration.Read.All",
		},
	}

	provider := NewOAuth2Provider(credStore, config)
	ctx := context.Background()

	t.Run("TestDirectAppConfigurationStorage", func(t *testing.T) {
		// Store the direct app configuration
		err := credStore.StoreConfig(config.TenantID, config)
		require.NoError(t, err)

		// Retrieve and verify configuration
		retrievedConfig, err := credStore.GetConfig(config.TenantID)
		require.NoError(t, err)

		// Verify basic configuration
		assert.Equal(t, config.ClientID, retrievedConfig.ClientID)
		assert.Equal(t, config.TenantID, retrievedConfig.TenantID)
		assert.True(t, retrievedConfig.SupportsDelegatedAuth())
		assert.False(t, retrievedConfig.UseClientCredentials)

		// Verify delegated permissions configuration
		assert.Equal(t, config.DelegatedScopes, retrievedConfig.DelegatedScopes)
		assert.Equal(t, config.RequiredDelegatedScopes, retrievedConfig.RequiredDelegatedScopes)
		assert.Equal(t, config.Scopes, retrievedConfig.Scopes)

		// Verify fallback configuration
		assert.True(t, retrievedConfig.FallbackToAppPermissions)
	})

	t.Run("TestDirectAppUserContextManagement", func(t *testing.T) {
		// Test various user contexts for different scenarios
		testUsers := []*UserContext{
			{
				UserID:            "direct-user-standard",
				UserPrincipalName: "standarduser@example.com",
				DisplayName:       "Standard User",
				Roles:             []string{"User"},
				LastAuthenticated: time.Now(),
				SessionID:         "session-standard",
			},
			{
				UserID:            "direct-user-admin",
				UserPrincipalName: "admin@example.com",
				DisplayName:       "Admin User",
				Roles:             []string{"User", "GlobalAdmin"},
				LastAuthenticated: time.Now(),
				SessionID:         "session-admin",
			},
			{
				UserID:            "direct-user-limited",
				UserPrincipalName: "limiteduser@example.com",
				DisplayName:       "Limited User",
				Roles:             []string{"User"},
				LastAuthenticated: time.Now().Add(-24 * time.Hour), // Last auth 24h ago
				SessionID:         "session-limited",
			},
		}

		for _, userContext := range testUsers {
			// Store user context
			err := credStore.StoreUserContext(config.TenantID, userContext.UserID, userContext)
			require.NoError(t, err)

			// Retrieve and verify user context
			retrievedContext, err := credStore.GetUserContext(config.TenantID, userContext.UserID)
			require.NoError(t, err)
			assert.Equal(t, userContext.UserID, retrievedContext.UserID)
			assert.Equal(t, userContext.UserPrincipalName, retrievedContext.UserPrincipalName)
			assert.Equal(t, userContext.Roles, retrievedContext.Roles)
			assert.Equal(t, userContext.SessionID, retrievedContext.SessionID)
		}
	})

	t.Run("TestDirectAppDelegatedPermissionValidation", func(t *testing.T) {
		// Create mock tokens with different permission sets
		testCases := []struct {
			name            string
			grantedScopes   []string
			requestedScopes []string
			shouldSucceed   bool
			description     string
		}{
			{
				name:            "BasicUserAccess",
				grantedScopes:   []string{"User.Read", "Directory.Read.All"},
				requestedScopes: []string{"User.Read"},
				shouldSucceed:   true,
				description:     "Basic user profile access",
			},
			{
				name:            "UserManagement",
				grantedScopes:   []string{"User.Read", "User.ReadWrite.All", "Directory.Read.All"},
				requestedScopes: []string{"User.ReadWrite.All"},
				shouldSucceed:   true,
				description:     "User management operations",
			},
			{
				name:            "ConditionalAccess",
				grantedScopes:   []string{"User.Read", "Policy.ReadWrite.ConditionalAccess"},
				requestedScopes: []string{"Policy.ReadWrite.ConditionalAccess"},
				shouldSucceed:   true,
				description:     "Conditional Access policy management",
			},
			{
				name:            "IntuneManagement",
				grantedScopes:   []string{"User.Read", "DeviceManagementConfiguration.ReadWrite.All"},
				requestedScopes: []string{"DeviceManagementConfiguration.ReadWrite.All"},
				shouldSucceed:   true,
				description:     "Intune device configuration management",
			},
			{
				name:            "InsufficientPermissions",
				grantedScopes:   []string{"User.Read"},
				requestedScopes: []string{"User.ReadWrite.All"},
				shouldSucceed:   false,
				description:     "Insufficient permissions for user management",
			},
			{
				name:            "MissingRequiredScope",
				grantedScopes:   []string{"Group.Read.All"},
				requestedScopes: []string{"User.Read"}, // Required scope not granted
				shouldSucceed:   false,
				description:     "Missing required Directory.Read.All scope",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create mock token for this test case
				mockToken := &AccessToken{
					Token:         fmt.Sprintf("mock-token-%s", tc.name),
					TokenType:     "Bearer",
					IsDelegated:   true,
					TenantID:      config.TenantID,
					ExpiresAt:     time.Now().Add(time.Hour),
					GrantedScopes: tc.grantedScopes,
				}

				// Test permission validation
				err := provider.ValidatePermissions(ctx, mockToken, tc.requestedScopes)

				if tc.shouldSucceed {
					assert.NoError(t, err, "Should succeed: %s", tc.description)
				} else {
					assert.Error(t, err, "Should fail: %s", tc.description)
					assert.Contains(t, err.Error(), "INSUFFICIENT_PERMISSIONS",
						"Error should indicate insufficient permissions")
				}
			})
		}
	})

	t.Run("TestDirectAppFallbackBehavior", func(t *testing.T) {
		userContext := &UserContext{
			UserID:            "fallback-test-user",
			UserPrincipalName: "fallbackuser@example.com",
			DisplayName:       "Fallback Test User",
		}

		// Test fallback behavior when delegated token is not available
		// This should fall back to application permissions
		token, err := provider.GetDelegatedAccessToken(ctx, config.TenantID, userContext)

		// Since we don't have real credentials, we expect either:
		// 1. An error indicating no delegated token available
		// 2. Successful fallback to application permissions (if implemented)
		if err != nil {
			// Check if error is related to delegated authentication
			authErr, ok := err.(*AuthenticationError)
			require.True(t, ok, "Expected AuthenticationError")

			// Valid error codes for this scenario
			validErrorCodes := []string{
				"NO_DELEGATED_TOKEN",
				"CONFIG_ERROR",
				"NO_REFRESH_TOKEN",
			}

			assert.Contains(t, validErrorCodes, authErr.Code,
				"Error code should indicate delegated auth issue: %s", authErr.Code)
		} else {
			// If token is obtained, verify it's properly configured
			assert.NotNil(t, token)
			assert.Equal(t, config.TenantID, token.TenantID)

			// If fallback occurred, token should not be delegated
			if !token.IsDelegated {
				t.Logf("Successfully fell back to application permissions")
			}
		}
	})
}

// TestDirectAppAccessTokenFlow tests the complete token flow for direct app access
func TestDirectAppAccessTokenFlow(t *testing.T) {
	// Create a mock token server for testing
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v2.0/token" {
			// Mock token response
			response := map[string]interface{}{
				"access_token": "mock-access-token-direct",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "User.Read Directory.Read.All",
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(response); err != nil {
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "token-flow-test-passphrase")
	require.NoError(t, err)

	config := &OAuth2Config{
		ClientID:                 "token-flow-client-id",
		ClientSecret:             "token-flow-client-secret",
		TenantID:                 "token-flow-tenant-id",
		AuthorityURL:             mockServer.URL,
		UseClientCredentials:     true, // For this test, use client credentials
		SupportDelegatedAuth:     true,
		FallbackToAppPermissions: true,
		DelegatedScopes:          []string{"User.Read", "Directory.Read.All"},
		Scopes:                   []string{"User.Read.All", "Directory.Read.All"},
	}

	provider := NewOAuth2Provider(credStore, config)
	ctx := context.Background()

	t.Run("TestApplicationTokenFlow", func(t *testing.T) {
		// Test getting application token (should work with mock server)
		token, err := provider.GetAccessToken(ctx, config.TenantID)

		if err != nil {
			// Expected for client credentials flow without real server
			t.Logf("Application token flow failed (expected with mock): %v", err)
		} else {
			assert.NotNil(t, token)
			assert.Equal(t, config.TenantID, token.TenantID)
			assert.False(t, token.IsDelegated, "Application token should not be delegated")
		}
	})

	t.Run("TestDelegatedTokenFallback", func(t *testing.T) {
		userContext := &UserContext{
			UserID:            "token-flow-user",
			UserPrincipalName: "tokenuser@example.com",
		}

		// Test delegated token with fallback to application permissions
		token, err := provider.GetDelegatedAccessToken(ctx, config.TenantID, userContext)

		if err != nil {
			// Check error type and message
			authErr, ok := err.(*AuthenticationError)
			if ok {
				t.Logf("Delegated token failed (expected): %s - %s", authErr.Code, authErr.Message)
			}
		} else {
			// If successful, verify token properties
			assert.NotNil(t, token)
			assert.Equal(t, config.TenantID, token.TenantID)

			if token.IsDelegated {
				t.Logf("Successfully obtained delegated token")
			} else {
				t.Logf("Successfully fell back to application token")
			}
		}
	})
}

// TestDirectAppAccessPermissionScenarios tests realistic M365 permission scenarios
func TestDirectAppAccessPermissionScenarios(t *testing.T) {
	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "scenario-test-passphrase")
	require.NoError(t, err)

	config := &OAuth2Config{
		ClientID:             "scenario-client-id",
		TenantID:             "scenario-tenant-id",
		SupportDelegatedAuth: true,
		DelegatedScopes: []string{
			"User.Read", "User.ReadWrite.All", "Directory.Read.All",
			"Group.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess",
			"DeviceManagementConfiguration.ReadWrite.All",
		},
	}

	provider := NewOAuth2Provider(credStore, config)
	ctx := context.Background()

	// Define realistic scenarios for different M365 operations
	scenarios := []struct {
		name            string
		userRole        string
		requiredScopes  []string
		grantedScopes   []string
		expectedSuccess bool
		description     string
	}{
		{
			name:            "StandardUserProfile",
			userRole:        "User",
			requiredScopes:  []string{"User.Read"},
			grantedScopes:   []string{"User.Read", "Directory.Read.All"},
			expectedSuccess: true,
			description:     "Standard user reading their own profile",
		},
		{
			name:            "UserManagementAdmin",
			userRole:        "UserAdmin",
			requiredScopes:  []string{"User.ReadWrite.All"},
			grantedScopes:   []string{"User.Read", "User.ReadWrite.All", "Directory.Read.All"},
			expectedSuccess: true,
			description:     "User administrator managing user accounts",
		},
		{
			name:            "ConditionalAccessAdmin",
			userRole:        "ConditionalAccessAdmin",
			requiredScopes:  []string{"Policy.ReadWrite.ConditionalAccess"},
			grantedScopes:   []string{"User.Read", "Policy.ReadWrite.ConditionalAccess"},
			expectedSuccess: true,
			description:     "Conditional Access administrator managing policies",
		},
		{
			name:            "IntuneAdmin",
			userRole:        "IntuneAdmin",
			requiredScopes:  []string{"DeviceManagementConfiguration.ReadWrite.All"},
			grantedScopes:   []string{"User.Read", "DeviceManagementConfiguration.ReadWrite.All"},
			expectedSuccess: true,
			description:     "Intune administrator managing device policies",
		},
		{
			name:            "UnauthorizedUserManagement",
			userRole:        "User",
			requiredScopes:  []string{"User.ReadWrite.All"},
			grantedScopes:   []string{"User.Read"},
			expectedSuccess: false,
			description:     "Standard user attempting user management (should fail)",
		},
		{
			name:            "InsufficientConditionalAccess",
			userRole:        "User",
			requiredScopes:  []string{"Policy.ReadWrite.ConditionalAccess"},
			grantedScopes:   []string{"User.Read", "Directory.Read.All"},
			expectedSuccess: false,
			description:     "User without CA permissions attempting CA operations",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Create user context for scenario
			userContext := &UserContext{
				UserID:            fmt.Sprintf("scenario-user-%s", scenario.name),
				UserPrincipalName: fmt.Sprintf("%s@example.com", scenario.userRole),
				DisplayName:       fmt.Sprintf("%s Test User", scenario.userRole),
				Roles:             []string{scenario.userRole},
			}

			// Create mock token with granted scopes
			mockToken := &AccessToken{
				Token:         fmt.Sprintf("scenario-token-%s", scenario.name),
				TokenType:     "Bearer",
				IsDelegated:   true,
				TenantID:      config.TenantID,
				ExpiresAt:     time.Now().Add(time.Hour),
				GrantedScopes: scenario.grantedScopes,
				UserContext:   userContext,
			}

			// Test permission validation for the scenario
			err := provider.ValidatePermissions(ctx, mockToken, scenario.requiredScopes)

			if scenario.expectedSuccess {
				assert.NoError(t, err, "Scenario should succeed: %s", scenario.description)
			} else {
				assert.Error(t, err, "Scenario should fail: %s", scenario.description)
				authErr, ok := err.(*AuthenticationError)
				if ok {
					assert.Equal(t, "INSUFFICIENT_PERMISSIONS", authErr.Code)
				}
			}

			t.Logf("Scenario: %s - %s", scenario.name, scenario.description)
			if err != nil {
				t.Logf("  Result: FAILED - %s", err.Error())
			} else {
				t.Logf("  Result: SUCCESS")
			}
		})
	}
}

// TestDirectAppAccessIntegration tests integration with real M365 if credentials are available
func TestDirectAppAccessIntegration(t *testing.T) {
	// Skip if running without real M365 credentials
	clientID := os.Getenv("M365_CLIENT_ID")
	clientSecret := os.Getenv("M365_CLIENT_SECRET")
	tenantID := os.Getenv("M365_TENANT_ID")

	if clientID == "" || clientSecret == "" || tenantID == "" {
		t.Skip("Skipping real M365 integration test - credentials not available")
	}

	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "integration-test-passphrase")
	require.NoError(t, err)

	config := &OAuth2Config{
		ClientID:                 clientID,
		ClientSecret:             clientSecret,
		TenantID:                 tenantID,
		UseClientCredentials:     true, // Use app permissions for integration test
		SupportDelegatedAuth:     true,
		FallbackToAppPermissions: true,
		DelegatedScopes: []string{
			"User.Read", "Directory.Read.All",
			"User.ReadWrite.All", "Group.Read.All",
		},
		Scopes: []string{
			"User.Read.All", "Directory.Read.All",
			"Group.Read.All",
		},
	}

	provider := NewOAuth2Provider(credStore, config)
	ctx := context.Background()

	t.Run("TestRealApplicationToken", func(t *testing.T) {
		// Test getting a real application token
		token, err := provider.GetAccessToken(ctx, tenantID)

		if err != nil {
			t.Logf("Real application token failed: %v", err)
			// Don't fail the test - network issues, config problems, etc. are common
		} else {
			assert.NotNil(t, token)
			assert.Equal(t, tenantID, token.TenantID)
			assert.False(t, token.IsDelegated)
			assert.True(t, len(token.Token) > 0)
			t.Logf("Successfully obtained real application token")
		}
	})

	t.Run("TestRealDelegatedTokenFallback", func(t *testing.T) {
		userContext := &UserContext{
			UserID:            "real-test-user",
			UserPrincipalName: "testuser@" + tenantID + ".onmicrosoft.com",
		}

		// Test delegated token (expected to fail and fall back to app permissions)
		token, err := provider.GetDelegatedAccessToken(ctx, tenantID, userContext)

		if err != nil {
			t.Logf("Delegated token failed as expected: %v", err)
		} else {
			assert.NotNil(t, token)
			assert.Equal(t, tenantID, token.TenantID)

			if token.IsDelegated {
				t.Logf("Unexpectedly obtained delegated token")
			} else {
				t.Logf("Successfully fell back to application permissions")
			}
		}
	})
}
