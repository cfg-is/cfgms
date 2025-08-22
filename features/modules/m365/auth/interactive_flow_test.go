package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInteractiveAuthFlowSetup tests the setup button experience backend
func TestInteractiveAuthFlowSetup(t *testing.T) {
	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "interactive-test-passphrase")
	require.NoError(t, err)

	config := &OAuth2Config{
		ClientID:                 "test-interactive-client-id",
		ClientSecret:             "test-interactive-client-secret",
		TenantID:                 "test-interactive-tenant-id",
		RedirectURI:              "http://localhost:8080/auth/callback",
		UseClientCredentials:     false, // Interactive flow
		SupportDelegatedAuth:     true,
		FallbackToAppPermissions: false, // Pure delegated flow
		DelegatedScopes: []string{
			"User.Read",
			"User.ReadWrite.All",
			"Directory.Read.All",
			"Group.ReadWrite.All",
			"Policy.ReadWrite.ConditionalAccess",
			"DeviceManagementConfiguration.ReadWrite.All",
		},
		RequiredDelegatedScopes: []string{
			"User.Read",
			"Directory.Read.All",
		},
	}

	provider := NewOAuth2Provider(credStore, config)
	flow := NewInteractiveAuthFlow(provider, config)
	ctx := context.Background()

	t.Run("TestSetupButtonFlow", func(t *testing.T) {
		// Step 1: User clicks "Setup" button - backend generates auth URL
		requestedScopes := config.DelegatedScopes
		flowState, authURL, err := flow.StartAuthFlow(ctx, config.TenantID, requestedScopes)
		
		require.NoError(t, err)
		assert.NotNil(t, flowState)
		assert.NotEmpty(t, authURL)
		
		// Verify flow state
		assert.Equal(t, config.TenantID, flowState.TenantID)
		assert.Equal(t, requestedScopes, flowState.RequestedScopes)
		assert.NotEmpty(t, flowState.CodeVerifier)
		assert.NotEmpty(t, flowState.CodeChallenge)
		assert.NotEmpty(t, flowState.State)
		assert.NotEmpty(t, flowState.Nonce)
		
		// Verify auth URL structure
		parsedURL, err := url.Parse(authURL)
		require.NoError(t, err)
		assert.Equal(t, "login.microsoftonline.com", parsedURL.Host)
		assert.Contains(t, parsedURL.Path, config.TenantID)
		
		query := parsedURL.Query()
		assert.Equal(t, config.ClientID, query.Get("client_id"))
		assert.Equal(t, "code", query.Get("response_type"))
		assert.Equal(t, config.RedirectURI, query.Get("redirect_uri"))
		assert.Equal(t, flowState.State, query.Get("state"))
		assert.Equal(t, flowState.CodeChallenge, query.Get("code_challenge"))
		assert.Equal(t, "S256", query.Get("code_challenge_method"))
		assert.Equal(t, "consent", query.Get("prompt"))
		
		// Verify scopes
		requestedScopeString := strings.Join(requestedScopes, " ")
		assert.Equal(t, requestedScopeString, query.Get("scope"))
		
		t.Logf("Setup button would open: %s", authURL)
	})

	t.Run("TestCallbackHandling", func(t *testing.T) {
		// Setup flow state
		flowState, _, err := flow.StartAuthFlow(ctx, config.TenantID, config.DelegatedScopes)
		require.NoError(t, err)
		
		// Step 2: Simulate Microsoft callback with authorization code
		mockCode := "mock-authorization-code-from-microsoft"
		callbackURL := fmt.Sprintf("%s?code=%s&state=%s", 
			config.RedirectURI, mockCode, flowState.State)
		
		// Mock token exchange server
		mockTokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth2/v2.0/token" {
				// Verify PKCE parameters
				r.ParseForm()
				assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
				assert.Equal(t, config.ClientID, r.Form.Get("client_id"))
				assert.Equal(t, config.ClientSecret, r.Form.Get("client_secret"))
				assert.Equal(t, mockCode, r.Form.Get("code"))
				assert.Equal(t, config.RedirectURI, r.Form.Get("redirect_uri"))
				assert.Equal(t, flowState.CodeVerifier, r.Form.Get("code_verifier"))
				
				// Return mock token response
				response := map[string]interface{}{
					"access_token":  "mock-access-token-interactive",
					"token_type":    "Bearer",
					"expires_in":    3600,
					"refresh_token": "mock-refresh-token",
					"scope":         strings.Join(config.DelegatedScopes, " "),
					"id_token":      "mock-id-token",
				}
				
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer mockTokenServer.Close()
		
		// Update config to use mock server
		originalConfig := *config
		config.AuthorityURL = mockTokenServer.URL
		defer func() { *config = originalConfig }()
		
		// Process callback
		result, err := flow.HandleCallback(ctx, callbackURL)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.NotNil(t, result.AccessToken)
		assert.NotNil(t, result.UserContext)
		assert.Equal(t, config.DelegatedScopes, result.GrantedScopes)
		
		// Verify stored token
		assert.Equal(t, "mock-access-token-interactive", result.AccessToken.Token)
		assert.True(t, result.AccessToken.IsDelegated)
		assert.Equal(t, config.TenantID, result.AccessToken.TenantID)
		
		t.Logf("Successfully processed callback and obtained delegated token")
	})

	t.Run("TestErrorHandling", func(t *testing.T) {
		// Test error callback (user denied consent)
		errorCallbackURL := fmt.Sprintf("%s?error=access_denied&error_description=User%%20denied%%20consent&state=test-state", 
			config.RedirectURI)
		
		result, err := flow.HandleCallback(ctx, errorCallbackURL)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Equal(t, "access_denied", result.Error)
		assert.Contains(t, result.ErrorDetails, "User denied consent")
		
		// Test invalid state
		invalidStateURL := fmt.Sprintf("%s?code=test-code&state=invalid-state", config.RedirectURI)
		result, err = flow.HandleCallback(ctx, invalidStateURL)
		require.NoError(t, err)
		assert.False(t, result.Success)
		assert.Equal(t, "INVALID_STATE", result.Error)
	})
}

// TestCallbackHandlerServer tests the HTTP callback server
func TestCallbackHandlerServer(t *testing.T) {
	handler := NewCallbackHandler()
	ctx := context.Background()
	
	// Start callback server
	err := handler.StartCallbackServer(ctx, "0") // Use random port
	require.NoError(t, err)
	defer handler.StopCallbackServer(ctx)
	
	t.Run("TestHealthEndpoint", func(t *testing.T) {
		resp, err := http.Get("http://localhost:" + handler.serverPort + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		
		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, "healthy", response["status"])
	})
	
	t.Run("TestSuccessfulCallback", func(t *testing.T) {
		// Simulate successful OAuth callback
		callbackURL := fmt.Sprintf("http://localhost:%s/auth/callback?code=test-code&state=test-state", 
			handler.serverPort)
		
		resp, err := http.Get(callbackURL)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/html", resp.Header.Get("Content-Type"))
		
		// Verify HTML contains success indicators
		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		html := string(body[:n])
		assert.Contains(t, html, "✅")
		assert.Contains(t, html, "Authorization successful")
		assert.Contains(t, html, "success")
	})
	
	t.Run("TestErrorCallback", func(t *testing.T) {
		// Simulate error OAuth callback
		callbackURL := fmt.Sprintf("http://localhost:%s/auth/callback?error=access_denied&error_description=User%%20denied", 
			handler.serverPort)
		
		resp, err := http.Get(callbackURL)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		// Verify HTML contains error indicators
		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		html := string(body[:n])
		assert.Contains(t, html, "❌")
		assert.Contains(t, html, "access_denied")
		assert.Contains(t, html, "error")
	})
	
	t.Run("TestJSONResponse", func(t *testing.T) {
		// Test JSON response for API clients
		client := &http.Client{}
		req, err := http.NewRequest("GET", 
			fmt.Sprintf("http://localhost:%s/auth/callback?code=test-code&state=test-state", handler.serverPort), 
			nil)
		require.NoError(t, err)
		req.Header.Set("Accept", "application/json")
		
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		
		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)
		assert.True(t, response["success"].(bool))
		assert.Equal(t, "test-code", response["code"])
		assert.Equal(t, "test-state", response["state"])
	})
}

// TestCapabilityTesting tests the post-consent capability validation
func TestCapabilityTesting(t *testing.T) {
	// Create mock Graph API server
	mockGraphServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify authentication header
		authHeader := r.Header.Get("Authorization")
		assert.True(t, strings.HasPrefix(authHeader, "Bearer "))
		
		w.Header().Set("Content-Type", "application/json")
		
		switch r.URL.Path {
		case "/me":
			// User profile endpoint
			response := map[string]interface{}{
				"id":                "user-123",
				"userPrincipalName": "testuser@example.com",
				"displayName":       "Test User",
			}
			json.NewEncoder(w).Encode(response)
			
		case "/users":
			// Directory users endpoint
			response := map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "user-1", "userPrincipalName": "user1@example.com"},
					{"id": "user-2", "userPrincipalName": "user2@example.com"},
				},
			}
			json.NewEncoder(w).Encode(response)
			
		case "/groups":
			// Groups endpoint
			response := map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "group-1", "displayName": "Test Group 1"},
					{"id": "group-2", "displayName": "Test Group 2"},
				},
			}
			json.NewEncoder(w).Encode(response)
			
		case "/identity/conditionalAccess/policies":
			// Conditional Access endpoint
			response := map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "policy-1", "displayName": "Test CA Policy", "state": "enabled"},
				},
			}
			json.NewEncoder(w).Encode(response)
			
		case "/deviceManagement/deviceConfigurations":
			// Intune endpoint
			response := map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "config-1", "displayName": "Test Device Config"},
				},
			}
			json.NewEncoder(w).Encode(response)
			
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockGraphServer.Close()
	
	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "capability-test-passphrase")
	require.NoError(t, err)
	
	config := &OAuth2Config{
		ClientID:        "capability-test-client",
		TenantID:        "capability-test-tenant",
		DelegatedScopes: []string{
			"User.Read", "Directory.Read.All", "Group.ReadWrite.All",
			"Policy.ReadWrite.ConditionalAccess", "DeviceManagementConfiguration.ReadWrite.All",
		},
	}
	
	provider := NewOAuth2Provider(credStore, config)
	flow := NewInteractiveAuthFlow(provider, config)
	
	// Note: GraphBaseURL is a const, so we use HTTP transport override instead
	
	// Create test access token with all scopes
	accessToken := &AccessToken{
		Token:         "test-capability-token",
		TokenType:     "Bearer",
		TenantID:      config.TenantID,
		IsDelegated:   true,
		ExpiresAt:     time.Now().Add(time.Hour),
		GrantedScopes: config.DelegatedScopes,
	}
	
	// Override HTTP client to use mock server
	flow.httpClient = &http.Client{
		Transport: &mockTransport{
			baseURL: mockGraphServer.URL,
		},
	}
	
	ctx := context.Background()
	
	t.Run("TestIndividualCapabilities", func(t *testing.T) {
		// Test user profile capability
		userTest := flow.testUserProfileAccess(ctx, accessToken)
		assert.True(t, userTest.Success, "User profile test should succeed")
		assert.Contains(t, userTest.Details, "Successfully retrieved user profile")
		
		// Test directory read capability
		dirTest := flow.testDirectoryReadAccess(ctx, accessToken)
		assert.True(t, dirTest.Success, "Directory read test should succeed")
		assert.Contains(t, dirTest.Details, "users from directory")
		
		// Test group management capability
		groupTest := flow.testGroupManagementAccess(ctx, accessToken)
		assert.True(t, groupTest.Success, "Group management test should succeed")
		assert.Contains(t, groupTest.Details, "groups")
		
		// Test conditional access capability
		caTest := flow.testConditionalAccessAccess(ctx, accessToken)
		assert.True(t, caTest.Success, "Conditional Access test should succeed")
		assert.Contains(t, caTest.Details, "conditional access policies")
		
		// Test Intune capability
		intuneTest := flow.testIntuneManagementAccess(ctx, accessToken)
		assert.True(t, intuneTest.Success, "Intune test should succeed")
		assert.Contains(t, intuneTest.Details, "device configurations")
	})
	
	t.Run("TestFullCapabilityReport", func(t *testing.T) {
		report, err := flow.TestFullCapabilities(ctx, config.TenantID, accessToken)
		require.NoError(t, err)
		assert.NotNil(t, report)
		
		// Verify report structure
		assert.Equal(t, config.TenantID, report.TenantID)
		assert.True(t, report.OverallSuccess)
		assert.Equal(t, 1.0, report.SuccessRate) // 100% success
		
		// Verify all capabilities are available
		expectedCapabilities := []string{
			"user_profile", "directory_read", "group_management",
			"conditional_access", "intune_management",
		}
		
		for _, capability := range expectedCapabilities {
			assert.True(t, report.Capabilities[capability], 
				"Capability %s should be available", capability)
			assert.True(t, report.Tests[capability].Success,
				"Test for %s should succeed", capability)
		}
		
		// Test summary
		summary := report.GetCapabilitySummary()
		assert.Contains(t, summary, "100.0%")
		assert.Contains(t, summary, "✅")
		
		t.Logf("Capability Summary:\n%s", summary)
	})
	
	t.Run("TestInsufficientPermissions", func(t *testing.T) {
		// Test with limited scopes
		limitedToken := &AccessToken{
			Token:         "limited-token",
			TokenType:     "Bearer",
			TenantID:      config.TenantID,
			IsDelegated:   true,
			ExpiresAt:     time.Now().Add(time.Hour),
			GrantedScopes: []string{"User.Read"}, // Only basic scope
		}
		
		report, err := flow.TestFullCapabilities(ctx, config.TenantID, limitedToken)
		require.NoError(t, err)
		
		// Should have some missing capabilities
		assert.False(t, report.OverallSuccess)
		assert.Less(t, report.SuccessRate, 1.0)
		assert.True(t, report.Capabilities["user_profile"])   // Should work
		assert.False(t, report.Capabilities["group_management"]) // Should fail
		
		// Should have recommendations
		assert.NotEmpty(t, report.Recommendations)
		
		summary := report.GetCapabilitySummary()
		assert.Contains(t, summary, "❌")
		assert.Contains(t, summary, "Recommendations:")
	})
}

// TestRealM365Integration tests with real Microsoft 365 if credentials are available
func TestRealM365InteractiveIntegration(t *testing.T) {
	// Skip if running without real M365 credentials
	clientID := os.Getenv("M365_CLIENT_ID")
	clientSecret := os.Getenv("M365_CLIENT_SECRET")
	tenantID := os.Getenv("M365_TENANT_ID")
	
	if clientID == "" || clientSecret == "" || tenantID == "" {
		t.Skip("Skipping real M365 interactive integration test - credentials not available")
	}
	
	tempDir := t.TempDir()
	credStore, err := NewFileCredentialStore(filepath.Join(tempDir, "creds"), "real-integration-passphrase")
	require.NoError(t, err)
	
	config := &OAuth2Config{
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		TenantID:        tenantID,
		RedirectURI:     "http://localhost:8080/auth/callback",
		SupportDelegatedAuth: true,
		DelegatedScopes: []string{
			"User.Read",
			"Directory.Read.All",
			"Group.Read.All",
		},
	}
	
	provider := NewOAuth2Provider(credStore, config)
	flow := NewInteractiveAuthFlow(provider, config)
	ctx := context.Background()
	
	t.Run("TestRealAuthURLGeneration", func(t *testing.T) {
		// Generate real auth URL
		flowState, authURL, err := flow.StartAuthFlow(ctx, tenantID, config.DelegatedScopes)
		require.NoError(t, err)
		assert.NotNil(t, flowState)
		assert.NotEmpty(t, authURL)
		
		// Verify URL points to real Microsoft endpoint
		assert.Contains(t, authURL, "login.microsoftonline.com")
		assert.Contains(t, authURL, tenantID)
		assert.Contains(t, authURL, clientID)
		
		t.Logf("Real M365 auth URL (manual testing): %s", authURL)
		t.Logf("To test manually:")
		t.Logf("1. Open the URL above in a browser")
		t.Logf("2. Sign in and consent to permissions")
		t.Logf("3. Copy the callback URL")
		t.Logf("4. Use it to test HandleCallback function")
	})
	
	// Note: Real callback testing would require manual interaction
	// or browser automation (which is beyond scope of this test)
}

// Helper type for mocking HTTP transport
type mockTransport struct {
	baseURL string
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite URL to use mock server
	originalURL := req.URL.String()
	newURL := strings.Replace(originalURL, GraphBaseURL, t.baseURL+"/v1.0", 1)
	
	newReq := req.Clone(req.Context())
	parsedURL, _ := url.Parse(newURL)
	newReq.URL = parsedURL
	
	return http.DefaultTransport.RoundTrip(newReq)
}