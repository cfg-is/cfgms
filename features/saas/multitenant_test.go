// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package saas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test-only implementations

// stubTenantDiscoverer is a test-only TenantDiscoverer that returns a fixed set of
// deterministic tenants without making any HTTP calls. Configure tenants at construction
// time; pass err to simulate discovery failures.
type stubTenantDiscoverer struct {
	tenants []TenantInfo
	err     error
}

func (s *stubTenantDiscoverer) DiscoverTenants(_ context.Context, _ *TokenSet) (*TenantDiscoveryResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &TenantDiscoveryResult{
		Tenants:      s.tenants,
		DiscoveredAt: time.Now(),
		Success:      true,
	}, nil
}

// newStubTenantDiscoverer returns a stub that returns the given tenants on every call.
func newStubTenantDiscoverer(tenants ...TenantInfo) *stubTenantDiscoverer {
	return &stubTenantDiscoverer{tenants: tenants}
}

// Mock implementations for testing

// MockCredentialStore implements CredentialStore for testing token and client-secret
// operations. It must NOT be used for consent state — use InMemoryConsentStore instead.
type MockCredentialStore struct {
	tokens  map[string]*TokenSet
	secrets map[string]string
}

func NewMockCredentialStore() *MockCredentialStore {
	return &MockCredentialStore{
		tokens:  make(map[string]*TokenSet),
		secrets: make(map[string]string),
	}
}

func (m *MockCredentialStore) StoreTokenSet(provider string, tokens *TokenSet) error {
	m.tokens[provider] = tokens
	return nil
}

func (m *MockCredentialStore) GetTokenSet(provider string) (*TokenSet, error) {
	if tokens, exists := m.tokens[provider]; exists {
		return tokens, nil
	}
	return nil, fmt.Errorf("token set not found for provider: %s", provider)
}

func (m *MockCredentialStore) DeleteTokenSet(provider string) error {
	delete(m.tokens, provider)
	return nil
}

func (m *MockCredentialStore) StoreClientSecret(provider, clientSecret string) error {
	m.secrets[provider] = clientSecret
	return nil
}

func (m *MockCredentialStore) GetClientSecret(provider string) (string, error) {
	if secret, exists := m.secrets[provider]; exists {
		return secret, nil
	}
	return "", fmt.Errorf("client secret not found for provider: %s", provider)
}

func (m *MockCredentialStore) IsAvailable() bool {
	return true
}

// Test MultiTenantManager

func TestMultiTenantManager_StartAdminConsent(t *testing.T) {
	tests := []struct {
		name     string
		config   *MultiTenantConfig
		wantErr  bool
		errMsg   string
		validate func(t *testing.T, url string)
	}{
		{
			name: "successful consent flow start",
			config: &MultiTenantConfig{
				OAuth2Config: OAuth2Config{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
					AuthURL:      "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
					TokenURL:     "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
					RedirectURL:  "https://your-app.com/callback",
					Scopes:       []string{"https://graph.microsoft.com/.default"},
				},
				IsMultiTenant:      true,
				AdminConsentScopes: []string{"https://graph.microsoft.com/.default"},
				ConsentPrompt:      "admin_consent",
			},
			wantErr: false,
			validate: func(t *testing.T, url string) {
				assert.Contains(t, url, "prompt=admin_consent")
				assert.Contains(t, url, "common/oauth2/v2.0/authorize")
			},
		},
		{
			name: "non-multitenant config",
			config: &MultiTenantConfig{
				OAuth2Config: OAuth2Config{
					ClientID: "test-client-id",
				},
				IsMultiTenant: false,
			},
			wantErr: true,
			errMsg:  "configuration is not marked as multi-tenant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credStore := NewMockCredentialStore()
			consentStore := NewInMemoryConsentStore()
			httpClient := NewGraphHTTPClient(100, 1000)
			mtm := NewMultiTenantManager(credStore, consentStore, httpClient, newStubTenantDiscoverer())

			ctx := context.Background()
			url, err := mtm.StartAdminConsent(ctx, "microsoft", tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Empty(t, url)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, url)
				if tt.validate != nil {
					tt.validate(t, url)
				}
			}
		})
	}
}

func TestMultiTenantManager_CompleteAdminConsent(t *testing.T) {
	// Deterministic tenants returned by the stub discoverer for success-path assertions.
	stubTenants := []TenantInfo{
		{TenantID: "stub-tenant-alpha", DisplayName: "Stub Alpha Corp", Domain: "alpha.example.com", HasAccess: true},
		{TenantID: "stub-tenant-beta", DisplayName: "Stub Beta Corp", Domain: "beta.example.com", HasAccess: true},
	}

	tests := []struct {
		name         string
		authCode     string
		serverResp   map[string]interface{}
		serverStatus int
		wantErr      bool
	}{
		{
			name:     "successful consent completion",
			authCode: "test-auth-code",
			serverResp: map[string]interface{}{
				"access_token":  "real-access-token",
				"refresh_token": "real-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "https://graph.microsoft.com/.default",
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
		},
		{
			name:         "token endpoint returns error",
			authCode:     "bad-code",
			serverResp:   map[string]interface{}{"error": "invalid_grant"},
			serverStatus: http.StatusBadRequest,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Token exchange server verifies form fields and returns configured response.
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
				assert.Equal(t, tt.authCode, r.FormValue("code"))
				assert.Equal(t, "test-client-id", r.FormValue("client_id"))
				assert.NotEmpty(t, r.FormValue("redirect_uri"))

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				if err := json.NewEncoder(w).Encode(tt.serverResp); err != nil {
					http.Error(w, "encode error", http.StatusInternalServerError)
				}
			}))
			defer tokenServer.Close()

			credStore := NewMockCredentialStore()
			consentStore := NewInMemoryConsentStore()
			// Use the real DefaultOAuth2Client so ExchangeCode hits the httptest server.
			// Wire a stub discoverer so discoverTenants returns stubTenants without HTTP calls.
			mtm := NewMultiTenantManager(credStore, consentStore, NewGraphHTTPClient(100, 1000), newStubTenantDiscoverer(stubTenants...))

			ctx := context.Background()
			provider := "microsoft"

			// Directly inject a ConsentStatus whose flow points at the test token server.
			// This is equivalent to what StartAdminConsent stores after calling StartFlow.
			flow := &OAuth2Flow{
				TokenURL:     tokenServer.URL,
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURI:  "https://app.example.com/callback",
				State:        "test-state",
				Created:      time.Now(),
				ExpiresAt:    time.Now().Add(10 * time.Minute),
			}
			require.NoError(t, consentStore.StoreConsent(provider, &ConsentStatus{
				Provider:    provider,
				ConsentFlow: flow,
			}))

			err := mtm.CompleteAdminConsent(ctx, provider, tt.authCode)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			updatedStatus, err := mtm.GetConsentStatus(ctx, provider)
			require.NoError(t, err)
			assert.True(t, updatedStatus.HasAdminConsent)

			// Confirm stored token came from the httptest server, not hardcoded literals.
			storedTokens, err := credStore.GetTokenSet(provider)
			require.NoError(t, err)
			assert.Equal(t, "real-access-token", storedTokens.AccessToken)
			assert.Equal(t, "real-refresh-token", storedTokens.RefreshToken)

			// Confirm the tenants returned by the stub discoverer were persisted
			// unchanged — no fabrication occurs between discovery and storage.
			require.Len(t, updatedStatus.AccessibleTenants, len(stubTenants))
			for i, want := range stubTenants {
				assert.Equal(t, want.TenantID, updatedStatus.AccessibleTenants[i].TenantID)
				assert.Equal(t, want.DisplayName, updatedStatus.AccessibleTenants[i].DisplayName)
				assert.Equal(t, want.Domain, updatedStatus.AccessibleTenants[i].Domain)
				assert.Equal(t, want.HasAccess, updatedStatus.AccessibleTenants[i].HasAccess)
			}
		})
	}
}

// TestMultiTenantManager_DiscoverTenantsErrors exercises the two new conditional
// branches in discoverTenants: a nil discoverer and a discoverer that returns an error.
// Both cases should cause CompleteAdminConsent to fail after a successful token exchange.
func TestMultiTenantManager_DiscoverTenantsErrors(t *testing.T) {
	// A token server that always returns a valid token so completeOAuth2Flow succeeds.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "ok-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer tokenServer.Close()

	flow := &OAuth2Flow{
		TokenURL:     tokenServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://app.example.com/callback",
		State:        "state",
		Created:      time.Now(),
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	tests := []struct {
		name       string
		discoverer TenantDiscoverer
		wantErrMsg string
	}{
		{
			name:       "nil discoverer returns error",
			discoverer: nil,
			wantErrMsg: "no tenant discoverer configured",
		},
		{
			name:       "discoverer returns error propagates",
			discoverer: &stubTenantDiscoverer{err: errors.New("graph unavailable")},
			wantErrMsg: "graph unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credStore := NewMockCredentialStore()
			consentStore := NewInMemoryConsentStore()
			mtm := NewMultiTenantManager(credStore, consentStore, NewGraphHTTPClient(100, 1000), tt.discoverer)

			require.NoError(t, consentStore.StoreConsent("microsoft", &ConsentStatus{
				Provider:    "microsoft",
				ConsentFlow: flow,
			}))

			err := mtm.CompleteAdminConsent(context.Background(), "microsoft", "any-code")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

func TestDefaultOAuth2Client_ExchangeCode(t *testing.T) {
	tests := []struct {
		name         string
		flow         *OAuth2Flow
		authCode     string
		serverResp   map[string]interface{}
		serverStatus int
		wantErr      bool
		validate     func(t *testing.T, ts *TokenSet)
	}{
		{
			name:     "successful exchange with all fields",
			authCode: "auth-code-abc",
			flow: &OAuth2Flow{
				ClientID:     "client-123",
				ClientSecret: "secret-xyz",
				RedirectURI:  "https://app.example.com/callback",
				CodeVerifier: "verifier-pkce",
			},
			serverResp: map[string]interface{}{
				"access_token":  "exchanged-access-token",
				"refresh_token": "exchanged-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    7200,
				"scope":         "openid profile email",
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			validate: func(t *testing.T, ts *TokenSet) {
				assert.Equal(t, "exchanged-access-token", ts.AccessToken)
				assert.Equal(t, "exchanged-refresh-token", ts.RefreshToken)
				assert.Equal(t, "Bearer", ts.TokenType)
				assert.ElementsMatch(t, []string{"openid", "profile", "email"}, ts.Scopes)
				assert.True(t, ts.ExpiresAt.After(time.Now()))
			},
		},
		{
			name:     "exchange without PKCE code_verifier",
			authCode: "auth-code-nopkce",
			flow: &OAuth2Flow{
				ClientID:     "client-123",
				ClientSecret: "secret-xyz",
				RedirectURI:  "https://app.example.com/callback",
				CodeVerifier: "",
			},
			serverResp: map[string]interface{}{
				"access_token": "access-nopkce",
				"token_type":   "Bearer",
				"expires_in":   3600,
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			validate: func(t *testing.T, ts *TokenSet) {
				assert.Equal(t, "access-nopkce", ts.AccessToken)
			},
		},
		{
			name:     "token endpoint returns 400",
			authCode: "bad-code",
			flow: &OAuth2Flow{
				ClientID:     "client-123",
				ClientSecret: "secret-xyz",
				RedirectURI:  "https://app.example.com/callback",
			},
			serverResp:   map[string]interface{}{"error": "invalid_grant", "error_description": "code expired"},
			serverStatus: http.StatusBadRequest,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
				assert.Equal(t, tt.authCode, r.FormValue("code"))
				assert.Equal(t, tt.flow.RedirectURI, r.FormValue("redirect_uri"))
				assert.Equal(t, tt.flow.ClientID, r.FormValue("client_id"))
				assert.Equal(t, tt.flow.ClientSecret, r.FormValue("client_secret"))
				if tt.flow.CodeVerifier != "" {
					assert.Equal(t, tt.flow.CodeVerifier, r.FormValue("code_verifier"))
				} else {
					assert.Empty(t, r.FormValue("code_verifier"))
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				if err := json.NewEncoder(w).Encode(tt.serverResp); err != nil {
					http.Error(w, "encode error", http.StatusInternalServerError)
				}
			}))
			defer tokenServer.Close()

			tt.flow.TokenURL = tokenServer.URL
			client := &DefaultOAuth2Client{httpClient: NewGraphHTTPClient(100, 1000)}

			ts, err := client.ExchangeCode(context.Background(), tt.flow, tt.authCode)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, ts)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, ts)
			if tt.validate != nil {
				tt.validate(t, ts)
			}
		})
	}
}

func TestMultiTenantManager_GetTenantToken(t *testing.T) {
	credStore := NewMockCredentialStore()
	consentStore := NewInMemoryConsentStore()
	httpClient := NewGraphHTTPClient(100, 1000)
	mtm := NewMultiTenantManager(credStore, consentStore, httpClient, newStubTenantDiscoverer())

	ctx := context.Background()
	provider := "microsoft"
	tenantID := "tenant-1"

	// Store real consent status with explicit accessible tenants.
	err := consentStore.StoreConsent(provider, &ConsentStatus{
		Provider:         provider,
		HasAdminConsent:  true,
		ConsentGrantedAt: time.Now(),
		AccessibleTenants: []TenantInfo{
			{TenantID: tenantID, HasAccess: true},
		},
	})
	require.NoError(t, err)

	// Store a valid token for the tenant
	tenantKey := mtm.getTenantKey(provider, tenantID)
	validToken := &TokenSet{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	err = credStore.StoreTokenSet(tenantKey, validToken)
	require.NoError(t, err)

	// Test getting the tenant token
	token, err := mtm.GetTenantToken(ctx, provider, tenantID)
	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "valid-token", token.AccessToken)
}

func TestMultiTenantManager_GetTenantToken_NoAccess(t *testing.T) {
	credStore := NewMockCredentialStore()
	consentStore := NewInMemoryConsentStore()
	httpClient := NewGraphHTTPClient(100, 1000)
	mtm := NewMultiTenantManager(credStore, consentStore, httpClient, newStubTenantDiscoverer())

	ctx := context.Background()
	provider := "microsoft"
	tenantID := "inaccessible-tenant"

	// Set up consent status without the requested tenant
	status := &ConsentStatus{
		Provider:         provider,
		HasAdminConsent:  true,
		ConsentGrantedAt: time.Now(),
		AccessibleTenants: []TenantInfo{
			{
				TenantID:    "different-tenant",
				DisplayName: "Different Tenant",
				HasAccess:   true,
			},
		},
	}

	err := consentStore.StoreConsent(provider, status)
	require.NoError(t, err)

	// Test getting token for inaccessible tenant
	token, err := mtm.GetTenantToken(ctx, provider, tenantID)
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "tenant inaccessible-tenant is not accessible")
}

func TestMultiTenantManager_GetTenantToken_ExpiredToken_RefreshNotImplemented(t *testing.T) {
	credStore := NewMockCredentialStore()
	consentStore := NewInMemoryConsentStore()
	mtm := NewMultiTenantManager(credStore, consentStore, NewGraphHTTPClient(100, 1000), newStubTenantDiscoverer())

	ctx := context.Background()
	provider := "microsoft"
	tenantID := "tenant-1"

	require.NoError(t, consentStore.StoreConsent(provider, &ConsentStatus{
		Provider:        provider,
		HasAdminConsent: true,
		AccessibleTenants: []TenantInfo{
			{TenantID: tenantID, HasAccess: true},
		},
	}))

	// Store an expired token; refreshTenantToken is called and must return an error.
	tenantKey := mtm.getTenantKey(provider, tenantID)
	require.NoError(t, credStore.StoreTokenSet(tenantKey, &TokenSet{
		AccessToken: "expired-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}))

	token, err := mtm.GetTenantToken(ctx, provider, tenantID)
	assert.Nil(t, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to refresh tenant token")
}

func TestMultiTenantManager_ListAccessibleTenants(t *testing.T) {
	credStore := NewMockCredentialStore()
	consentStore := NewInMemoryConsentStore()
	httpClient := NewGraphHTTPClient(100, 1000)
	mtm := NewMultiTenantManager(credStore, consentStore, httpClient, newStubTenantDiscoverer())

	ctx := context.Background()
	provider := "microsoft"

	// Store explicit consent status with known tenants.
	// LastTenantDiscovery is set to now so the cache-expiry check does not
	// trigger a RefreshTenantDiscovery call, keeping the test self-contained.
	expectedTenants := []TenantInfo{
		{
			TenantID:    "explicit-tenant-alpha",
			DisplayName: "Alpha Tenant",
			Domain:      "alpha.example.com",
			HasAccess:   true,
		},
	}
	err := consentStore.StoreConsent(provider, &ConsentStatus{
		Provider:            provider,
		HasAdminConsent:     true,
		ConsentGrantedAt:    time.Now(),
		LastTenantDiscovery: time.Now(),
		AccessibleTenants:   expectedTenants,
	})
	require.NoError(t, err)

	tenants, err := mtm.ListAccessibleTenants(ctx, provider)
	assert.NoError(t, err)
	require.Len(t, tenants, 1)

	assert.Equal(t, expectedTenants[0].TenantID, tenants[0].TenantID)
	assert.Equal(t, expectedTenants[0].DisplayName, tenants[0].DisplayName)
	assert.Equal(t, expectedTenants[0].Domain, tenants[0].Domain)
	assert.Equal(t, expectedTenants[0].HasAccess, tenants[0].HasAccess)
}

func TestMultiTenantManager_RevokeConsent(t *testing.T) {
	credStore := NewMockCredentialStore()
	consentStore := NewInMemoryConsentStore()
	httpClient := NewGraphHTTPClient(100, 1000)
	mtm := NewMultiTenantManager(credStore, consentStore, httpClient, newStubTenantDiscoverer())

	ctx := context.Background()
	provider := "microsoft"

	// Set up consent status and tenant tokens
	status := &ConsentStatus{
		Provider:         provider,
		HasAdminConsent:  true,
		ConsentGrantedAt: time.Now(),
		AccessibleTenants: []TenantInfo{
			{
				TenantID:  "tenant-1",
				HasAccess: true,
			},
		},
	}

	err := consentStore.StoreConsent(provider, status)
	require.NoError(t, err)

	// Store some tenant tokens
	tenantKey := mtm.getTenantKey(provider, "tenant-1")
	err = credStore.StoreTokenSet(tenantKey, &TokenSet{
		AccessToken: "tenant-token",
	})
	require.NoError(t, err)

	// Store base provider token
	err = credStore.StoreTokenSet(provider, &TokenSet{
		AccessToken: "base-token",
	})
	require.NoError(t, err)

	// Test revoking consent
	err = mtm.RevokeConsent(ctx, provider)
	assert.NoError(t, err)

	// Verify consent status was reset (GetConsentStatus returns default when deleted)
	newStatus, err := mtm.GetConsentStatus(ctx, provider)
	assert.NoError(t, err)
	assert.False(t, newStatus.HasAdminConsent)
	assert.Empty(t, newStatus.AccessibleTenants)

	// Verify tokens were cleaned up
	_, err = credStore.GetTokenSet(tenantKey)
	assert.Error(t, err)

	_, err = credStore.GetTokenSet(provider)
	assert.Error(t, err)
}

// Test MicrosoftMultiTenantProvider

func TestMicrosoftMultiTenantProvider_Creation(t *testing.T) {
	credStore := NewMockCredentialStore()
	httpClient := NewGraphHTTPClient(100, 1000)

	provider := NewMicrosoftMultiTenantProvider(credStore, httpClient)

	assert.NotNil(t, provider)
	assert.Equal(t, "microsoft-multitenant", provider.GetInfo().Name)
	assert.Contains(t, provider.GetInfo().SupportedAuthTypes, "oauth2-multitenant")
}

func TestMicrosoftMultiTenantProvider_StartAdminConsent(t *testing.T) {
	credStore := NewMockCredentialStore()
	httpClient := NewGraphHTTPClient(100, 1000)
	provider := NewMicrosoftMultiTenantProvider(credStore, httpClient)

	config := &MicrosoftMultiTenantConfig{
		ClientID:           "test-client-id",
		ClientSecret:       "test-secret",
		RedirectURI:        "https://test.com/callback",
		Scopes:             []string{"https://graph.microsoft.com/.default"},
		AdminConsentScopes: []string{"https://graph.microsoft.com/.default"},
	}

	ctx := context.Background()

	url, err := provider.StartAdminConsent(ctx, config)

	assert.NoError(t, err)
	assert.NotEmpty(t, url)
	assert.Contains(t, url, "common/oauth2/v2.0/authorize")
}

func TestMicrosoftMultiTenantProvider_CreateInTenant(t *testing.T) {
	tests := []struct {
		name           string
		serverStatus   int
		serverBody     string
		wantSuccess    bool
		wantStatusCode int
		wantDataKey    string
		wantDataValue  string
	}{
		{
			name:           "successful creation returns parsed response",
			serverStatus:   http.StatusCreated,
			serverBody:     `{"id":"new-user-id","displayName":"John Doe","userPrincipalName":"john@test.com"}`,
			wantSuccess:    true,
			wantStatusCode: http.StatusCreated,
			wantDataKey:    "id",
			wantDataValue:  "new-user-id",
		},
		{
			name:           "server error propagates as failed result",
			serverStatus:   http.StatusUnprocessableEntity,
			serverBody:     `{"error":{"code":"Request_BadRequest","message":"Invalid user data"}}`,
			wantSuccess:    false,
			wantStatusCode: http.StatusUnprocessableEntity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverBody))
			}))
			defer server.Close()

			credStore := NewMockCredentialStore()
			provider := NewMicrosoftMultiTenantProvider(credStore, server.Client())
			provider.baseURL = server.URL

			ctx := context.Background()
			tenantID := "tenant-1"

			err := provider.multiTenantManager.consentStore.StoreConsent(
				provider.GetInfo().Name,
				&ConsentStatus{
					Provider:         provider.GetInfo().Name,
					HasAdminConsent:  true,
					ConsentGrantedAt: time.Now(),
					AccessibleTenants: []TenantInfo{
						{TenantID: tenantID, HasAccess: true},
					},
				})
			require.NoError(t, err)

			tenantKey := provider.multiTenantManager.getTenantKey(provider.GetInfo().Name, tenantID)
			err = credStore.StoreTokenSet(tenantKey, &TokenSet{
				AccessToken: "test-token",
				TokenType:   "Bearer",
				ExpiresAt:   time.Now().Add(1 * time.Hour),
			})
			require.NoError(t, err)

			result, err := provider.CreateInTenant(ctx, tenantID, "users", map[string]interface{}{
				"displayName":       "John Doe",
				"userPrincipalName": "john@test.com",
			})

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantSuccess, result.Success)
			assert.Equal(t, tt.wantStatusCode, result.StatusCode)
			assert.Equal(t, tenantID, result.Metadata["tenant"])

			if tt.wantDataKey != "" {
				data, ok := result.Data.(map[string]interface{})
				require.True(t, ok, "expected map response data")
				assert.Equal(t, tt.wantDataValue, data[tt.wantDataKey])
			}
		})
	}
}

// Test TenantOnboardingWorkflow

func TestTenantOnboardingWorkflow_StartTenantOnboarding(t *testing.T) {
	credStore := NewMockCredentialStore()
	httpClient := NewGraphHTTPClient(100, 1000)
	provider := NewMicrosoftMultiTenantProvider(credStore, httpClient)
	workflow := NewTenantOnboardingWorkflow(provider)

	request := &OnboardingRequest{
		ProviderName: "microsoft-multitenant",
		MSPInfo: MSPInfo{
			MSPName:      "Test MSP",
			MSPTenantID:  "msp-tenant-123",
			ContactEmail: "admin@msp.com",
		},
		ClientInfo: ClientInfo{
			ClientName:    "Test Client",
			PrimaryDomain: "testclient.com",
		},
		ConsentConfig: ConsentConfiguration{
			RequiredScopes: []string{"https://graph.microsoft.com/.default"},
			ConsentTimeout: 30 * time.Minute,
		},
		AutomationSettings: AutomationSettings{
			EnableUserDiscovery:  true,
			EnableGroupDiscovery: true,
		},
	}

	ctx := context.Background()

	result, err := workflow.StartTenantOnboarding(ctx, request)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.OnboardingID)
	assert.NotEmpty(t, result.ConsentURL)
	assert.Contains(t, result.NextSteps, "Visit the consent URL to grant admin consent")
}

func TestTenantOnboardingWorkflow_ValidateRequest(t *testing.T) {
	workflow := &TenantOnboardingWorkflow{}

	tests := []struct {
		name    string
		request *OnboardingRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			request: &OnboardingRequest{
				ProviderName: "microsoft",
				MSPInfo: MSPInfo{
					MSPName: "Test MSP",
				},
				ClientInfo: ClientInfo{
					ClientName: "Test Client",
				},
				ConsentConfig: ConsentConfiguration{
					RequiredScopes: []string{"test.scope"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing provider name",
			request: &OnboardingRequest{
				MSPInfo: MSPInfo{
					MSPName: "Test MSP",
				},
			},
			wantErr: true,
			errMsg:  "provider_name is required",
		},
		{
			name: "missing MSP name",
			request: &OnboardingRequest{
				ProviderName: "microsoft",
				MSPInfo:      MSPInfo{},
			},
			wantErr: true,
			errMsg:  "msp_info.msp_name is required",
		},
		{
			name: "missing client name",
			request: &OnboardingRequest{
				ProviderName: "microsoft",
				MSPInfo: MSPInfo{
					MSPName: "Test MSP",
				},
				ClientInfo: ClientInfo{},
			},
			wantErr: true,
			errMsg:  "client_info.client_name is required",
		},
		{
			name: "empty scopes",
			request: &OnboardingRequest{
				ProviderName: "microsoft",
				MSPInfo: MSPInfo{
					MSPName: "Test MSP",
				},
				ClientInfo: ClientInfo{
					ClientName: "Test Client",
				},
				ConsentConfig: ConsentConfiguration{
					RequiredScopes: []string{},
				},
			},
			wantErr: true,
			errMsg:  "consent_config.required_scopes cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := workflow.validateOnboardingRequest(tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestMultiTenantManager_TenantCacheConcurrency verifies that concurrent writes
// to tenantCache (from RefreshTenantDiscovery triggered directly and via
// ListAccessibleTenants) do not cause data races under go test -race.
// tenantCache has no direct read paths in the current code, so this test exercises
// write-write safety. The RWMutex is chosen to be forward-compatible with future reads.
func TestMultiTenantManager_TenantCacheConcurrency(t *testing.T) {
	credStore := NewMockCredentialStore()
	consentStore := NewInMemoryConsentStore()
	httpClient := NewGraphHTTPClient(100, 1000)
	// Stub returns one deterministic tenant so RefreshTenantDiscovery writes a
	// non-empty AccessibleTenants slice to the consent store on each call.
	stub := newStubTenantDiscoverer(TenantInfo{TenantID: "stub-concurrent-tenant", HasAccess: true})
	mtm := NewMultiTenantManager(credStore, consentStore, httpClient, stub)

	ctx := context.Background()
	provider := "microsoft"

	// Pre-populate the base token. Only reads occur on this key during concurrent
	// execution — concurrent map reads in Go are safe without a mutex.
	err := credStore.StoreTokenSet(provider, &TokenSet{
		AccessToken:  "base-token",
		RefreshToken: "base-refresh-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	// Set LastTenantDiscovery in the past so ListAccessibleTenants triggers a
	// RefreshTenantDiscovery call, maximising concurrent write contention on tenantCache.
	err = consentStore.StoreConsent(provider, &ConsentStatus{
		Provider:            provider,
		HasAdminConsent:     true,
		ConsentGrantedAt:    time.Now(),
		LastTenantDiscovery: time.Now().Add(-30 * time.Minute),
		AccessibleTenants: []TenantInfo{
			{TenantID: "tenant-1", HasAccess: true},
		},
	})
	require.NoError(t, err)

	const goroutines = 10
	errs := make([]error, goroutines)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			<-start // block until all goroutines are released simultaneously
			if i%2 == 0 {
				_, errs[i] = mtm.ListAccessibleTenants(ctx, provider)
			} else {
				errs[i] = mtm.RefreshTenantDiscovery(ctx, provider)
			}
		}(i)
	}

	close(start) // release all goroutines at once to maximise contention
	wg.Wait()    // establishes happens-before for errs reads below

	for i, goroutineErr := range errs {
		assert.NoError(t, goroutineErr, "goroutine %d returned unexpected error", i)
	}

	// Verify that at least one refresh updated the consent store's accessible tenants.
	status, err := mtm.GetConsentStatus(ctx, provider)
	require.NoError(t, err)
	assert.True(t, status.HasAdminConsent)
	assert.NotEmpty(t, status.AccessibleTenants)
}

// TestMicrosoftMultiTenantProvider_TenantlessCRUD verifies that the five
// non-tenant-aware CRUD methods return ErrNoTenantSelected with a nil result.
// Callers that need to act on a specific tenant must use the *InTenant variants.
func TestMicrosoftMultiTenantProvider_TenantlessCRUD(t *testing.T) {
	credStore := NewMockCredentialStore()
	httpClient := NewGraphHTTPClient(100, 1000)
	provider := NewMicrosoftMultiTenantProvider(credStore, httpClient)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() (*ProviderResult, error)
	}{
		{
			name: "Create returns ErrNoTenantSelected",
			call: func() (*ProviderResult, error) {
				return provider.Create(ctx, "users", map[string]interface{}{"displayName": "Test"})
			},
		},
		{
			name: "Read returns ErrNoTenantSelected",
			call: func() (*ProviderResult, error) {
				return provider.Read(ctx, "users", "some-id")
			},
		},
		{
			name: "Update returns ErrNoTenantSelected",
			call: func() (*ProviderResult, error) {
				return provider.Update(ctx, "users", "some-id", map[string]interface{}{"displayName": "Updated"})
			},
		},
		{
			name: "Delete returns ErrNoTenantSelected",
			call: func() (*ProviderResult, error) {
				return provider.Delete(ctx, "users", "some-id")
			},
		},
		{
			name: "RawAPI returns ErrNoTenantSelected",
			call: func() (*ProviderResult, error) {
				return provider.RawAPI(ctx, "GET", "/users", nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.call()
			assert.Nil(t, result, "result must be nil — no side effects should occur")
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrNoTenantSelected),
				"expected ErrNoTenantSelected, got: %v", err)
		})
	}
}

// Benchmarks

func BenchmarkMultiTenantManager_GetTenantToken(b *testing.B) {
	credStore := NewMockCredentialStore()
	consentStore := NewInMemoryConsentStore()
	httpClient := NewGraphHTTPClient(100, 1000)
	mtm := NewMultiTenantManager(credStore, consentStore, httpClient, newStubTenantDiscoverer())

	ctx := context.Background()
	provider := "microsoft"
	tenantID := "benchmark-tenant"

	// Set up test data
	status := &ConsentStatus{
		Provider:        provider,
		HasAdminConsent: true,
		AccessibleTenants: []TenantInfo{
			{
				TenantID:  tenantID,
				HasAccess: true,
			},
		},
	}

	if err := consentStore.StoreConsent(provider, status); err != nil {
		b.Fatal(err)
	}

	tenantKey := mtm.getTenantKey(provider, tenantID)
	validToken := &TokenSet{
		AccessToken: "benchmark-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if err := credStore.StoreTokenSet(tenantKey, validToken); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := mtm.GetTenantToken(ctx, provider, tenantID); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMicrosoftMultiTenantProvider_CreateInTenant(b *testing.B) {
	credStore := NewMockCredentialStore()
	httpClient := NewGraphHTTPClient(100, 1000)
	provider := NewMicrosoftMultiTenantProvider(credStore, httpClient)

	ctx := context.Background()
	tenantID := "benchmark-tenant"
	resourceType := "users"
	data := map[string]interface{}{
		"displayName": "Benchmark User",
	}

	// Set up test data
	status := &ConsentStatus{
		Provider:        provider.GetInfo().Name,
		HasAdminConsent: true,
		AccessibleTenants: []TenantInfo{
			{
				TenantID:  tenantID,
				HasAccess: true,
			},
		},
	}

	if err := provider.multiTenantManager.consentStore.StoreConsent(provider.GetInfo().Name, status); err != nil {
		b.Fatal(err)
	}

	tenantKey := provider.multiTenantManager.getTenantKey(provider.GetInfo().Name, tenantID)
	validToken := &TokenSet{
		AccessToken: "benchmark-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if err := credStore.StoreTokenSet(tenantKey, validToken); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := provider.CreateInTenant(ctx, tenantID, resourceType, data); err != nil {
			b.Fatal(err)
		}
	}
}
