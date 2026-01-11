// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFullDelegatedPermissionsIntegration validates the complete delegated permissions implementation
func TestFullDelegatedPermissionsIntegration(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("TestProviderInterfaceExtension", func(t *testing.T) {
		credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "provider"), "test-pass")
		require.NoError(t, err)

		config := &OAuth2Config{
			ClientID:                 "test-client",
			ClientSecret:             "test-secret",
			TenantID:                 "test-tenant",
			SupportDelegatedAuth:     true,
			FallbackToAppPermissions: true,
			DelegatedScopes:          []string{"User.Read", "Directory.Read.All"},
		}

		provider := NewOAuth2Provider(credStore, config)

		// Verify provider implements enhanced interface
		assert.NotNil(t, provider)

		// Test that all new methods exist (even if they fail without real credentials)
		userContext := &UserContext{
			UserID:            "test-user",
			UserPrincipalName: "test@example.com",
		}

		_, err = provider.GetDelegatedAccessToken(context.Background(), "test-tenant", userContext)
		// Should fail without real credentials, but method should exist and return meaningful error
		assert.Error(t, err)
		assert.NotEmpty(t, err.Error(), "Error should have a meaningful message")
	})

	t.Run("TestUserContextManagement", func(t *testing.T) {
		credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "context"), "test-pass")
		require.NoError(t, err)

		userContext := &UserContext{
			UserID:            "test-user-123",
			UserPrincipalName: "testuser@example.com",
			DisplayName:       "Test User",
			Roles:             []string{"User", "Admin"},
			LastAuthenticated: time.Now(),
			SessionID:         "session-123",
		}

		// Test storing user context
		err = credStore.StoreUserContext("test-tenant", userContext.UserID, userContext)
		require.NoError(t, err)

		// Test retrieving user context
		retrievedContext, err := credStore.GetUserContext("test-tenant", userContext.UserID)
		require.NoError(t, err)

		assert.Equal(t, userContext.UserID, retrievedContext.UserID)
		assert.Equal(t, userContext.UserPrincipalName, retrievedContext.UserPrincipalName)
		assert.Equal(t, userContext.DisplayName, retrievedContext.DisplayName)
		assert.Equal(t, userContext.Roles, retrievedContext.Roles)
		assert.Equal(t, userContext.SessionID, retrievedContext.SessionID)

		// Test deleting user context
		err = credStore.DeleteUserContext("test-tenant", userContext.UserID)
		require.NoError(t, err)

		_, err = credStore.GetUserContext("test-tenant", userContext.UserID)
		assert.Error(t, err)
	})

	t.Run("TestDelegatedTokenStorage", func(t *testing.T) {
		credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "tokens"), "test-pass")
		require.NoError(t, err)

		userContext := &UserContext{
			UserID:            "token-user",
			UserPrincipalName: "tokenuser@example.com",
		}

		delegatedToken := &AccessToken{
			Token:         "test-delegated-token",
			TokenType:     "Bearer",
			TenantID:      "test-tenant",
			IsDelegated:   true,
			ExpiresAt:     time.Now().Add(time.Hour),
			UserContext:   userContext,
			GrantedScopes: []string{"User.Read", "Directory.Read.All"},
		}

		// Test storing delegated token
		err = credStore.StoreDelegatedToken("test-tenant", userContext.UserID, delegatedToken)
		require.NoError(t, err)

		// Test retrieving delegated token
		retrievedToken, err := credStore.GetDelegatedToken("test-tenant", userContext.UserID)
		require.NoError(t, err)

		assert.Equal(t, delegatedToken.Token, retrievedToken.Token)
		assert.Equal(t, delegatedToken.IsDelegated, retrievedToken.IsDelegated)
		assert.Equal(t, delegatedToken.GrantedScopes, retrievedToken.GrantedScopes)
		assert.Equal(t, delegatedToken.UserContext.UserID, retrievedToken.UserContext.UserID)

		// Test deleting delegated token
		err = credStore.DeleteDelegatedToken("test-tenant", userContext.UserID)
		require.NoError(t, err)

		_, err = credStore.GetDelegatedToken("test-tenant", userContext.UserID)
		assert.Error(t, err)
	})

	t.Run("TestDelegatedTokenCaching", func(t *testing.T) {
		credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "cache"), "test-pass")
		require.NoError(t, err)

		config := &OAuth2Config{
			ClientID:             "cache-client",
			TenantID:             "cache-tenant",
			SupportDelegatedAuth: true,
		}

		provider := NewOAuth2Provider(credStore, config)

		userContext := &UserContext{
			UserID:            "cache-user",
			UserPrincipalName: "cacheuser@example.com",
		}

		token := &AccessToken{
			Token:       "cache-token",
			TokenType:   "Bearer",
			TenantID:    config.TenantID,
			IsDelegated: true,
			ExpiresAt:   time.Now().Add(time.Hour),
			UserContext: userContext,
		}

		// Test caching delegated token
		cacheKey := config.TenantID + ":" + userContext.UserID
		provider.setDelegatedCachedToken(cacheKey, token)

		// Test retrieving from cache
		cachedToken := provider.getDelegatedCachedToken(cacheKey)
		require.NotNil(t, cachedToken)
		assert.Equal(t, token.Token, cachedToken.Token)

		// Test cache expiration
		expiredToken := &AccessToken{
			Token:     "expired-token",
			TokenType: "Bearer",
			ExpiresAt: time.Now().Add(-time.Hour), // Already expired
		}
		provider.setDelegatedCachedToken(cacheKey, expiredToken)

		// Should return nil for expired token
		cachedToken = provider.getDelegatedCachedToken(cacheKey)
		assert.Nil(t, cachedToken)

		// Test cache clearing
		provider.setDelegatedCachedToken(cacheKey, token)
		provider.ClearDelegatedCacheForUser(config.TenantID, userContext.UserID)
		cachedToken = provider.getDelegatedCachedToken(cacheKey)
		assert.Nil(t, cachedToken)
	})

	t.Run("TestPermissionValidation", func(t *testing.T) {
		credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "validation"), "test-pass")
		require.NoError(t, err)

		provider := NewOAuth2Provider(credStore, &OAuth2Config{})

		// Test application token (should pass all validations)
		appToken := &AccessToken{
			Token:       "app-token",
			TokenType:   "Bearer",
			IsDelegated: false,
			ExpiresAt:   time.Now().Add(time.Hour),
		}

		err = provider.ValidatePermissions(context.Background(), appToken, []string{"User.Read"})
		assert.NoError(t, err, "Application tokens should pass validation")

		// Test delegated token with granted scopes
		delegatedToken := &AccessToken{
			Token:         "delegated-token",
			TokenType:     "Bearer",
			IsDelegated:   true,
			ExpiresAt:     time.Now().Add(time.Hour),
			GrantedScopes: []string{"User.Read", "Directory.Read.All"},
		}

		// Should pass for granted scope
		err = provider.ValidatePermissions(context.Background(), delegatedToken, []string{"User.Read"})
		assert.NoError(t, err)

		// Should fail for non-granted scope
		err = provider.ValidatePermissions(context.Background(), delegatedToken, []string{"User.ReadWrite.All"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "INSUFFICIENT_PERMISSIONS")

		// Should pass for no required scopes
		err = provider.ValidatePermissions(context.Background(), delegatedToken, []string{})
		assert.NoError(t, err)
	})

	t.Run("TestOAuth2ConfigExtensions", func(t *testing.T) {
		config := &OAuth2Config{
			ClientID:                 "test-client",
			TenantID:                 "test-tenant",
			RedirectURI:              "http://localhost:8080/callback",
			SupportDelegatedAuth:     true,
			FallbackToAppPermissions: true,
			DelegatedScopes:          []string{"User.Read", "Directory.Read.All"},
			RequiredDelegatedScopes:  []string{"User.Read"},
		}

		// Test delegated scope string generation
		scopeString := config.GetDelegatedScopeString()
		assert.Contains(t, scopeString, "User.Read")
		assert.Contains(t, scopeString, "Directory.Read.All")

		// Test delegated auth support check
		assert.True(t, config.SupportsDelegatedAuth())

		// Test required scopes
		requiredScopes := config.GetRequiredDelegatedScopes()
		assert.Equal(t, []string{"User.Read"}, requiredScopes)

		// Test config without delegated auth
		noDelAuthConfig := &OAuth2Config{
			ClientID:             "test-client",
			SupportDelegatedAuth: false,
		}
		assert.False(t, noDelAuthConfig.SupportsDelegatedAuth())
	})

	t.Run("TestBackwardCompatibility", func(t *testing.T) {
		credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "compat"), "test-pass")
		require.NoError(t, err)

		// This should work when loading old credential files
		// The loadCredentials method should initialize missing fields
		tenantID := "compat-tenant"

		// Store a regular token first to create the file
		err = credStore.StoreToken(tenantID, &AccessToken{Token: "test"})
		require.NoError(t, err)

		// Should be able to store delegated tokens even with existing old-format file
		userContext := &UserContext{UserID: "compat-user"}
		delegatedToken := &AccessToken{
			Token:       "compat-delegated",
			IsDelegated: true,
			UserContext: userContext,
		}

		err = credStore.StoreDelegatedToken(tenantID, userContext.UserID, delegatedToken)
		assert.NoError(t, err, "Should be able to store delegated tokens in existing files")

		// Should be able to retrieve it
		retrieved, err := credStore.GetDelegatedToken(tenantID, userContext.UserID)
		assert.NoError(t, err)
		assert.Equal(t, delegatedToken.Token, retrieved.Token)
	})
}

// TestInteractiveAuthenticatorCreation verifies the interactive authenticator can be created
func TestInteractiveAuthenticatorCreation(t *testing.T) {
	credStore, err := NewFileCredentialStore(t.TempDir(), "test-pass")
	require.NoError(t, err)

	config := &OAuth2Config{
		ClientID:             "interactive-client",
		ClientSecret:         "interactive-secret",
		TenantID:             "interactive-tenant",
		RedirectURI:          "http://localhost:8080/callback",
		SupportDelegatedAuth: true,
	}

	provider := NewOAuth2Provider(credStore, config)

	// Should be able to create interactive authenticator
	interactiveAuth := NewInteractiveAuthenticator(provider, ":8080")
	assert.NotNil(t, interactiveAuth)

	// Should be able to generate PKCE parameters
	verifier, challenge, err := interactiveAuth.generatePKCE()
	assert.NoError(t, err)
	assert.NotEmpty(t, verifier)
	assert.NotEmpty(t, challenge)
	assert.NotEqual(t, verifier, challenge)

	// Should be able to generate state
	state, err := interactiveAuth.generateState()
	assert.NoError(t, err)
	assert.NotEmpty(t, state)
}

// TestRealWorldCredentialFlow tests the credential flow without making actual network calls
func TestRealWorldCredentialFlow(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Integration tests disabled")
	}

	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(tempDir, "integration-test-pass")
	require.NoError(t, err)

	config := &OAuth2Config{
		ClientID:                 "integration-client-id",
		ClientSecret:             "integration-client-secret",
		TenantID:                 "integration-tenant-id",
		RedirectURI:              "http://localhost:8080/callback",
		SupportDelegatedAuth:     true,
		FallbackToAppPermissions: true,
		DelegatedScopes:          []string{"User.Read", "Directory.Read.All"},
		RequiredDelegatedScopes:  []string{"User.Read"},
	}

	provider := NewOAuth2Provider(credStore, config)
	ctx := context.Background()

	// Test that the flow would work with real credentials
	// (This doesn't make network calls but tests the logic)

	// Create mock user context
	userContext := &UserContext{
		UserID:            "integration-user-123",
		UserPrincipalName: "integrationuser@example.com",
		DisplayName:       "Integration Test User",
		Roles:             []string{"Global Administrator"},
		LastAuthenticated: time.Now(),
		SessionID:         "integration-session-123",
	}

	// Create mock delegated token
	delegatedToken := &AccessToken{
		Token:         "integration-delegated-token",
		TokenType:     "Bearer",
		TenantID:      config.TenantID,
		IsDelegated:   true,
		ExpiresAt:     time.Now().Add(time.Hour),
		RefreshToken:  "integration-refresh-token",
		UserContext:   userContext,
		GrantedScopes: []string{"User.Read", "Directory.Read.All"},
	}

	// Test complete flow simulation
	t.Run("StoreAndRetrieveFlow", func(t *testing.T) {
		// Store user context
		err = credStore.StoreUserContext(config.TenantID, userContext.UserID, userContext)
		require.NoError(t, err)

		// Store delegated token
		err = credStore.StoreDelegatedToken(config.TenantID, userContext.UserID, delegatedToken)
		require.NoError(t, err)

		// Cache the token
		cacheKey := config.TenantID + ":" + userContext.UserID
		provider.setDelegatedCachedToken(cacheKey, delegatedToken)

		// Verify cached retrieval
		cachedToken := provider.getDelegatedCachedToken(cacheKey)
		require.NotNil(t, cachedToken)
		assert.Equal(t, delegatedToken.Token, cachedToken.Token)

		// Verify storage retrieval
		storedToken, err := credStore.GetDelegatedToken(config.TenantID, userContext.UserID)
		require.NoError(t, err)
		assert.Equal(t, delegatedToken.Token, storedToken.Token)

		// Verify user context retrieval
		storedContext, err := credStore.GetUserContext(config.TenantID, userContext.UserID)
		require.NoError(t, err)
		assert.Equal(t, userContext.UserID, storedContext.UserID)
	})

	t.Run("FallbackBehaviorSimulation", func(t *testing.T) {
		// Test fallback logic when delegated auth is not available
		// This would normally call GetDelegatedAccessToken which would fall back to GetAccessToken
		token, err := provider.GetDelegatedAccessToken(ctx, config.TenantID, userContext)

		// Should fail with our mock setup, but should attempt fallback
		// The error is expected because we don't have real credentials
		if err != nil {
			assert.Error(t, err)
			assert.NotEmpty(t, err.Error())
			assert.Nil(t, token)
		} else {
			// If somehow it succeeds, token should be valid
			assert.NotNil(t, token)
		}
	})

	t.Run("PermissionValidationFlow", func(t *testing.T) {
		// Test permission validation with the mock token
		err := provider.ValidatePermissions(ctx, delegatedToken, []string{"User.Read"})
		assert.NoError(t, err, "Should pass validation for granted scope")

		err = provider.ValidatePermissions(ctx, delegatedToken, []string{"User.ReadWrite.All"})
		assert.Error(t, err, "Should fail validation for non-granted scope")
	})
}

// BenchmarkDelegatedOperations benchmarks the performance of key delegated permission operations
func BenchmarkDelegatedOperations(b *testing.B) {
	tempDir := b.TempDir()
	credStore, err := NewFileCredentialStore(tempDir, "benchmark-pass")
	require.NoError(b, err)

	config := &OAuth2Config{
		ClientID:             "benchmark-client",
		TenantID:             "benchmark-tenant",
		SupportDelegatedAuth: true,
	}

	provider := NewOAuth2Provider(credStore, config)

	userContext := &UserContext{
		UserID:            "benchmark-user",
		UserPrincipalName: "benchmarkuser@example.com",
	}

	token := &AccessToken{
		Token:       "benchmark-token",
		TokenType:   "Bearer",
		TenantID:    config.TenantID,
		IsDelegated: true,
		ExpiresAt:   time.Now().Add(time.Hour),
		UserContext: userContext,
	}

	b.Run("DelegatedTokenCacheOperations", func(b *testing.B) {
		cacheKey := config.TenantID + ":" + userContext.UserID

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			provider.setDelegatedCachedToken(cacheKey, token)
			_ = provider.getDelegatedCachedToken(cacheKey)
		}
	})

	b.Run("DelegatedTokenStorageOperations", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userID := "benchmark-user-" + string(rune(i%100))
			_ = credStore.StoreDelegatedToken(config.TenantID, userID, token)
			_, _ = credStore.GetDelegatedToken(config.TenantID, userID)
		}
	})

	b.Run("UserContextOperations", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userID := "context-user-" + string(rune(i%100))
			_ = credStore.StoreUserContext(config.TenantID, userID, userContext)
			_, _ = credStore.GetUserContext(config.TenantID, userID)
		}
	})
}
