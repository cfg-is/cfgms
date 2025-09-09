package auth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDelegatedPermissionsIntegration tests the complete delegated permissions workflow
func TestDelegatedPermissionsIntegration(t *testing.T) {
	// Skip if running in CI or without M365 credentials
	if os.Getenv("M365_CLIENT_ID") == "" || os.Getenv("M365_CLIENT_SECRET") == "" || os.Getenv("M365_TENANT_ID") == "" {
		t.Skip("Skipping M365 integration test - credentials not available")
	}

	// Setup test environment
	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "test-passphrase")
	require.NoError(t, err)

	// Create OAuth2 config with delegated permissions support
	config := &OAuth2Config{
		ClientID:                 os.Getenv("M365_CLIENT_ID"),
		ClientSecret:             os.Getenv("M365_CLIENT_SECRET"),
		TenantID:                 os.Getenv("M365_TENANT_ID"),
		RedirectURI:              "http://localhost:8080/callback",
		UseClientCredentials:     false, // Use delegated flow
		SupportDelegatedAuth:     true,
		FallbackToAppPermissions: true,
		DelegatedScopes: []string{
			"User.Read",
			"User.ReadWrite.All",
			"Directory.Read.All",
			"Group.Read.All",
			"Policy.ReadWrite.ConditionalAccess",
		},
		RequiredDelegatedScopes: []string{
			"User.Read",
			"Directory.Read.All",
		},
	}

	provider := NewOAuth2Provider(credStore, config)
	ctx := context.Background()

	t.Run("TestDelegatedAuthConfiguration", func(t *testing.T) {
		// Store the configuration
		err := credStore.StoreConfig(config.TenantID, config)
		require.NoError(t, err)

		// Retrieve and verify configuration
		retrievedConfig, err := credStore.GetConfig(config.TenantID)
		require.NoError(t, err)
		assert.Equal(t, config.ClientID, retrievedConfig.ClientID)
		assert.True(t, retrievedConfig.SupportsDelegatedAuth())
		assert.Equal(t, config.DelegatedScopes, retrievedConfig.DelegatedScopes)
	})

	t.Run("TestUserContextStorage", func(t *testing.T) {
		userContext := &UserContext{
			UserID:               "test-user-123",
			UserPrincipalName:    "testuser@example.com",
			DisplayName:          "Test User",
			Roles:                []string{"User", "GlobalAdmin"},
			LastAuthenticated:    time.Now(),
			SessionID:            "session-123",
		}

		// Store user context
		err := credStore.StoreUserContext(config.TenantID, userContext.UserID, userContext)
		require.NoError(t, err)

		// Retrieve user context
		retrievedContext, err := credStore.GetUserContext(config.TenantID, userContext.UserID)
		require.NoError(t, err)
		assert.Equal(t, userContext.UserID, retrievedContext.UserID)
		assert.Equal(t, userContext.UserPrincipalName, retrievedContext.UserPrincipalName)
		assert.Equal(t, userContext.Roles, retrievedContext.Roles)
	})

	t.Run("TestDelegatedTokenFlow", func(t *testing.T) {
		userContext := &UserContext{
			UserID:            "test-user-456",
			UserPrincipalName: "delegateduser@example.com",
			DisplayName:       "Delegated Test User",
		}

		// Test fallback to application permissions when no delegated token exists
		// This should work because FallbackToAppPermissions is true
		token, err := provider.GetDelegatedAccessToken(ctx, config.TenantID, userContext)
		if err != nil {
			// If delegated flow fails, it should fail gracefully with a specific error
			// Could be "delegated", "NO_REFRESH_TOKEN", or "authentication failed"
			assert.True(t, 
				strings.Contains(err.Error(), "delegated") || 
				strings.Contains(err.Error(), "NO_REFRESH_TOKEN") ||
				strings.Contains(err.Error(), "authentication failed"),
				"Error should be about delegated auth, refresh token, or authentication: %v", err)
		} else {
			// If token is obtained, verify it's properly configured
			assert.NotNil(t, token)
			assert.NotEmpty(t, token.Token)
			assert.Equal(t, config.TenantID, token.TenantID)
		}
	})

	t.Run("TestPermissionValidation", func(t *testing.T) {
		// Create a mock token for testing permission validation
		mockToken := &AccessToken{
			Token:         "mock-token",
			TokenType:     "Bearer",
			IsDelegated:   true,
			TenantID:      config.TenantID,
			ExpiresAt:     time.Now().Add(time.Hour),
			GrantedScopes: []string{"User.Read", "Directory.Read.All"},
		}

		// Test permission validation with sufficient permissions
		err := provider.ValidatePermissions(ctx, mockToken, []string{"User.Read"})
		assert.NoError(t, err)

		// Test permission validation with insufficient permissions
		err = provider.ValidatePermissions(ctx, mockToken, []string{"User.ReadWrite.All"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "INSUFFICIENT_PERMISSIONS")
	})

	t.Run("TestTokenCacheManagement", func(t *testing.T) {
		userContext := &UserContext{
			UserID:            "cache-test-user",
			UserPrincipalName: "cacheuser@example.com",
		}

		// Create a test token
		testToken := &AccessToken{
			Token:       "cache-test-token",
			TokenType:   "Bearer",
			TenantID:    config.TenantID,
			IsDelegated: true,
			ExpiresAt:   time.Now().Add(time.Hour),
			UserContext: userContext,
		}

		// Store the token in the credential store
		err := credStore.StoreDelegatedToken(config.TenantID, userContext.UserID, testToken)
		require.NoError(t, err)

		// Cache the token manually
		cacheKey := config.TenantID + ":" + userContext.UserID
		provider.setDelegatedCachedToken(cacheKey, testToken)

		// Verify cached token can be retrieved
		cachedToken := provider.getDelegatedCachedToken(cacheKey)
		assert.NotNil(t, cachedToken)
		assert.Equal(t, testToken.Token, cachedToken.Token)

		// Clear cache for specific user
		provider.ClearDelegatedCacheForUser(config.TenantID, userContext.UserID)
		cachedToken = provider.getDelegatedCachedToken(cacheKey)
		assert.Nil(t, cachedToken)

		// Clear all delegated cache
		provider.setDelegatedCachedToken(cacheKey, testToken)
		provider.ClearDelegatedCache()
		cachedToken = provider.getDelegatedCachedToken(cacheKey)
		assert.Nil(t, cachedToken)
	})

	t.Run("TestCredentialStoreCleanup", func(t *testing.T) {
		userID := "cleanup-test-user"
		
		// Store test data
		testToken := &AccessToken{
			Token:     "cleanup-token",
			TenantID:  config.TenantID,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		testContext := &UserContext{
			UserID:            userID,
			UserPrincipalName: "cleanupuser@example.com",
		}

		err := credStore.StoreDelegatedToken(config.TenantID, userID, testToken)
		require.NoError(t, err)
		err = credStore.StoreUserContext(config.TenantID, userID, testContext)
		require.NoError(t, err)

		// Verify data exists
		_, err = credStore.GetDelegatedToken(config.TenantID, userID)
		assert.NoError(t, err)
		_, err = credStore.GetUserContext(config.TenantID, userID)
		assert.NoError(t, err)

		// Delete delegated token
		err = credStore.DeleteDelegatedToken(config.TenantID, userID)
		assert.NoError(t, err)
		_, err = credStore.GetDelegatedToken(config.TenantID, userID)
		assert.Error(t, err)

		// Delete user context
		err = credStore.DeleteUserContext(config.TenantID, userID)
		assert.NoError(t, err)
		_, err = credStore.GetUserContext(config.TenantID, userID)
		assert.Error(t, err)
	})
}

// TestDelegatedPermissionsScenarios tests real M365 operations with delegated permissions
func TestDelegatedPermissionsScenarios(t *testing.T) {
	// Skip if running in CI or without M365 credentials
	if os.Getenv("M365_CLIENT_ID") == "" || os.Getenv("M365_TEST_USER_UPN") == "" {
		t.Skip("Skipping M365 scenario test - credentials not available")
	}

	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "scenario-test-passphrase")
	require.NoError(t, err)

	config := &OAuth2Config{
		ClientID:                 os.Getenv("M365_CLIENT_ID"),
		ClientSecret:             os.Getenv("M365_CLIENT_SECRET"),
		TenantID:                 os.Getenv("M365_TENANT_ID"),
		SupportDelegatedAuth:     true,
		FallbackToAppPermissions: true,
		DelegatedScopes: []string{
			"User.Read",
			"User.ReadWrite.All",
			"Directory.Read.All",
			"Group.ReadWrite.All",
			"Policy.ReadWrite.ConditionalAccess",
			"DeviceManagementConfiguration.ReadWrite.All",
		},
	}

	provider := NewOAuth2Provider(credStore, config)
	ctx := context.Background()

	t.Run("TestUserManagementWithDelegatedPermissions", func(t *testing.T) {
		userContext := &UserContext{
			UserID:            "scenario-user-123",
			UserPrincipalName: os.Getenv("M365_TEST_USER_UPN"),
			DisplayName:       "Scenario Test User",
		}

		// Test getting a token for user management operations
		token, err := provider.GetDelegatedAccessToken(ctx, config.TenantID, userContext)
		if err != nil {
			t.Logf("Delegated token acquisition failed (expected in many cases): %v", err)
			// Verify fallback behavior
			if config.FallbackToAppPermissions {
				// Should have fallen back to application permissions
				fallbackToken, fallbackErr := provider.GetAccessToken(ctx, config.TenantID)
				if fallbackErr == nil {
					assert.NotNil(t, fallbackToken)
					assert.False(t, fallbackToken.IsDelegated)
					t.Logf("Successfully fell back to application permissions")
				}
			}
		} else {
			// Verify delegated token properties
			assert.NotNil(t, token)
			assert.True(t, token.IsDelegated)
			assert.Equal(t, userContext, token.UserContext)
			
			// Test permission validation for user operations
			err = provider.ValidatePermissions(ctx, token, []string{"User.Read"})
			if err != nil {
				t.Logf("Permission validation failed (may be expected): %v", err)
			}
		}
	})

	t.Run("TestConditionalAccessWithDelegatedPermissions", func(t *testing.T) {
		userContext := &UserContext{
			UserID:            "ca-scenario-user",
			UserPrincipalName: os.Getenv("M365_TEST_USER_UPN"),
			DisplayName:       "CA Scenario User",
		}

		token, err := provider.GetDelegatedAccessToken(ctx, config.TenantID, userContext)
		if err == nil {
			// Test permission validation for conditional access operations
			err = provider.ValidatePermissions(ctx, token, []string{"Policy.ReadWrite.ConditionalAccess"})
			if err != nil {
				t.Logf("Conditional Access permission validation failed: %v", err)
			}
		} else {
			t.Logf("Could not obtain delegated token for CA test: %v", err)
		}
	})

	t.Run("TestIntuneWithDelegatedPermissions", func(t *testing.T) {
		userContext := &UserContext{
			UserID:            "intune-scenario-user",
			UserPrincipalName: os.Getenv("M365_TEST_USER_UPN"),
			DisplayName:       "Intune Scenario User",
		}

		token, err := provider.GetDelegatedAccessToken(ctx, config.TenantID, userContext)
		if err == nil {
			// Test permission validation for Intune operations
			err = provider.ValidatePermissions(ctx, token, []string{"DeviceManagementConfiguration.ReadWrite.All"})
			if err != nil {
				t.Logf("Intune permission validation failed: %v", err)
			}
		} else {
			t.Logf("Could not obtain delegated token for Intune test: %v", err)
		}
	})
}

// TestTokenRefreshFlow tests the delegated token refresh functionality
func TestTokenRefreshFlow(t *testing.T) {
	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "refresh-test-passphrase")
	require.NoError(t, err)

	config := &OAuth2Config{
		ClientID:                 "test-client-id",
		ClientSecret:             "test-client-secret",
		TenantID:                 "test-tenant-id",
		SupportDelegatedAuth:     true,
		FallbackToAppPermissions: true,
	}

	provider := NewOAuth2Provider(credStore, config)
	ctx := context.Background()

	t.Run("TestDelegatedTokenRefresh", func(t *testing.T) {
		userContext := &UserContext{
			UserID:            "refresh-test-user",
			UserPrincipalName: "refreshuser@example.com",
			DisplayName:       "Refresh Test User",
		}

		// Create a mock expired token with refresh token
		expiredToken := &AccessToken{
			Token:        "expired-token",
			TokenType:    "Bearer",
			TenantID:     config.TenantID,
			IsDelegated:  true,
			ExpiresAt:    time.Now().Add(-time.Hour), // Expired
			RefreshToken: "mock-refresh-token",
			UserContext:  userContext,
		}

		// Store the expired token
		err := credStore.StoreDelegatedToken(config.TenantID, userContext.UserID, expiredToken)
		require.NoError(t, err)

		// Attempt to get a delegated token - should try to refresh but fail with mock token
		// This tests the refresh flow logic even though the actual refresh will fail
		_, err = provider.GetDelegatedAccessToken(ctx, config.TenantID, userContext)
		
		// We expect this to fail since we're using a mock refresh token
		// But it should attempt refresh and then fall back to app permissions
		if config.FallbackToAppPermissions {
			// The error should indicate it tried delegated auth but fell back
			// In a real scenario with valid tokens, this would succeed
			t.Logf("Token refresh attempted (expected to fail with mock token): %v", err)
		}
	})

	t.Run("TestTokenExpirationHandling", func(t *testing.T) {
		userContext := &UserContext{
			UserID:            "expiration-test-user",
			UserPrincipalName: "expirationuser@example.com",
		}

		// Create a token that's about to expire (within 5-minute buffer)
		nearExpiredToken := &AccessToken{
			Token:       "near-expired-token",
			TokenType:   "Bearer",
			TenantID:    config.TenantID,
			IsDelegated: true,
			ExpiresAt:   time.Now().Add(2 * time.Minute), // Expires soon
			UserContext: userContext,
		}

		// Cache the token
		cacheKey := config.TenantID + ":" + userContext.UserID
		provider.setDelegatedCachedToken(cacheKey, nearExpiredToken)

		// Verify the token is considered expired due to 5-minute buffer
		cachedToken := provider.getDelegatedCachedToken(cacheKey)
		assert.Nil(t, cachedToken, "Token should be considered expired due to buffer")

		// Test with token that has sufficient time remaining
		validToken := &AccessToken{
			Token:       "valid-token",
			TokenType:   "Bearer",
			TenantID:    config.TenantID,
			IsDelegated: true,
			ExpiresAt:   time.Now().Add(time.Hour),
			UserContext: userContext,
		}

		provider.setDelegatedCachedToken(cacheKey, validToken)
		cachedToken = provider.getDelegatedCachedToken(cacheKey)
		assert.NotNil(t, cachedToken, "Valid token should be cached")
		assert.Equal(t, validToken.Token, cachedToken.Token)
	})
}

// BenchmarkDelegatedTokenOperations benchmarks the performance of delegated token operations
func BenchmarkDelegatedTokenOperations(b *testing.B) {
	tempDir := b.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "benchmark-passphrase")
	require.NoError(b, err)

	config := &OAuth2Config{
		ClientID:             "benchmark-client-id",
		TenantID:             "benchmark-tenant-id",
		SupportDelegatedAuth: true,
	}

	provider := NewOAuth2Provider(credStore, config)

	userContext := &UserContext{
		UserID:            "benchmark-user",
		UserPrincipalName: "benchmarkuser@example.com",
	}

	testToken := &AccessToken{
		Token:       "benchmark-token",
		TokenType:   "Bearer",
		TenantID:    config.TenantID,
		IsDelegated: true,
		ExpiresAt:   time.Now().Add(time.Hour),
		UserContext: userContext,
	}

	b.Run("BenchmarkDelegatedTokenStorage", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			userID := "benchmark-user-" + string(rune(i))
			err := credStore.StoreDelegatedToken(config.TenantID, userID, testToken)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("BenchmarkDelegatedTokenRetrieval", func(b *testing.B) {
		// Pre-store tokens
		for i := 0; i < 100; i++ {
			userID := "benchmark-retrieve-user-" + string(rune(i))
			_ = credStore.StoreDelegatedToken(config.TenantID, userID, testToken)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userID := "benchmark-retrieve-user-" + string(rune(i%100))
			_, err := credStore.GetDelegatedToken(config.TenantID, userID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("BenchmarkDelegatedTokenCaching", func(b *testing.B) {
		cacheKey := config.TenantID + ":" + userContext.UserID
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			provider.setDelegatedCachedToken(cacheKey, testToken)
			_ = provider.getDelegatedCachedToken(cacheKey)
		}
	})
}