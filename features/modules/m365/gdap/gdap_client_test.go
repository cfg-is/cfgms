// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package gdap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCredentialStore is a minimal in-memory CredentialStore for use in GDAPClient tests.
// It stores a single OAuth2Config (for client credentials) and a single token.
// It is safe for concurrent use via an embedded mutex.
type testCredentialStore struct {
	mu     sync.Mutex
	config *auth.OAuth2Config
	token  *auth.AccessToken
}

func (s *testCredentialStore) StoreToken(_ string, token *auth.AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
	return nil
}

func (s *testCredentialStore) GetToken(_ string) (*auth.AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == nil {
		return nil, fmt.Errorf("no token stored")
	}
	return s.token, nil
}

func (s *testCredentialStore) DeleteToken(_ string) error { return nil }

func (s *testCredentialStore) StoreDelegatedToken(_, _ string, _ *auth.AccessToken) error {
	return nil
}

func (s *testCredentialStore) GetDelegatedToken(_, _ string) (*auth.AccessToken, error) {
	return nil, fmt.Errorf("no delegated token")
}

func (s *testCredentialStore) DeleteDelegatedToken(_, _ string) error { return nil }

func (s *testCredentialStore) StoreUserContext(_, _ string, _ *auth.UserContext) error { return nil }

func (s *testCredentialStore) GetUserContext(_, _ string) (*auth.UserContext, error) {
	return nil, fmt.Errorf("no user context")
}

func (s *testCredentialStore) DeleteUserContext(_, _ string) error { return nil }

func (s *testCredentialStore) StoreConfig(_ string, cfg *auth.OAuth2Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
	return nil
}

func (s *testCredentialStore) GetConfig(_ string) (*auth.OAuth2Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config == nil {
		return nil, fmt.Errorf("no config stored")
	}
	return s.config, nil
}

func (s *testCredentialStore) IsAvailable() bool { return true }

// tokenResponse builds a JSON token response for test token servers.
func tokenResponse(accessToken string, expiresIn int) map[string]interface{} {
	return map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	}
}

// TestGDAPClient_getPartnerCenterToken_happyPath verifies that getPartnerCenterToken
// performs a real OAuth2 client-credentials request to the configured token endpoint
// and returns a valid token.
func TestGDAPClient_getPartnerCenterToken_happyPath(t *testing.T) {
	var requestCount int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		require.Equal(t, "POST", r.Method)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "client_credentials", r.FormValue("grant_type"))
		assert.Equal(t, "test-client-id", r.FormValue("client_id"))
		assert.Equal(t, "test-client-secret", r.FormValue("client_secret"))
		assert.Equal(t, "https://api.partnercenter.microsoft.com/.default", r.FormValue("scope"))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResponse("partner-center-token", 3600)); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer tokenServer.Close()

	credStore := &testCredentialStore{
		config: &auth.OAuth2Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
	}
	client := NewGDAPClient(tokenServer.Client(), "partner-tenant-id")
	client.tokenBaseURL = tokenServer.URL
	client.SetCredentialStore(credStore)

	token, err := client.getPartnerCenterToken(context.Background())
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "partner-center-token", token.Token)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.True(t, token.ExpiresAt.After(time.Now()))
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))
}

// TestGDAPClient_getPartnerCenterToken_caching verifies that a valid token is served
// from the in-memory cache on subsequent calls without hitting the token endpoint again.
func TestGDAPClient_getPartnerCenterToken_caching(t *testing.T) {
	var requestCount int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResponse("cached-token", 3600)); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer tokenServer.Close()

	credStore := &testCredentialStore{
		config: &auth.OAuth2Config{
			ClientID:     "cid",
			ClientSecret: "csecret",
		},
	}
	client := NewGDAPClient(tokenServer.Client(), "partner-tenant-id")
	client.tokenBaseURL = tokenServer.URL
	client.SetCredentialStore(credStore)

	// First call fetches the token.
	tok1, err := client.getPartnerCenterToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "cached-token", tok1.Token)

	// Second call must return the cached token without hitting the server.
	tok2, err := client.getPartnerCenterToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, tok1.Token, tok2.Token)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount), "server must be hit exactly once")
}

// TestGDAPClient_getPartnerCenterToken_expiredCacheRefetch verifies that an expired
// in-memory token triggers a new request to the token endpoint.
func TestGDAPClient_getPartnerCenterToken_expiredCacheRefetch(t *testing.T) {
	var requestCount int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResponse("fresh-token", 3600)); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer tokenServer.Close()

	credStore := &testCredentialStore{
		config: &auth.OAuth2Config{ClientID: "cid", ClientSecret: "csecret"},
	}
	client := NewGDAPClient(tokenServer.Client(), "partner-tenant-id")
	client.tokenBaseURL = tokenServer.URL
	client.SetCredentialStore(credStore)

	// Seed an already-expired token in the in-memory cache.
	client.cachedToken = &auth.AccessToken{
		Token:     "expired-token",
		ExpiresAt: time.Now().Add(-time.Hour),
	}

	tok, err := client.getPartnerCenterToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "fresh-token", tok.Token)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount), "expired cache must trigger a fetch")
}

// TestGDAPClient_getPartnerCenterToken_missingCredentials verifies that missing
// OAuth2 configuration returns a descriptive error.
func TestGDAPClient_getPartnerCenterToken_missingCredentials(t *testing.T) {
	credStore := &testCredentialStore{} // no config stored
	client := NewGDAPClient(nil, "partner-tenant-id")
	client.SetCredentialStore(credStore)

	_, err := client.getPartnerCenterToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "partner Center credentials not found")
	assert.Contains(t, err.Error(), "partner-tenant-id")
}

// TestGDAPClient_getPartnerCenterToken_emptyClientID verifies that a config with
// an empty client_id returns a descriptive error.
func TestGDAPClient_getPartnerCenterToken_emptyClientID(t *testing.T) {
	credStore := &testCredentialStore{
		config: &auth.OAuth2Config{ClientID: "", ClientSecret: "secret"},
	}
	client := NewGDAPClient(nil, "partner-tenant-id")
	client.SetCredentialStore(credStore)

	_, err := client.getPartnerCenterToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id")
}

// TestGDAPClient_getPartnerCenterToken_emptyClientSecret verifies that a config
// with an empty client_secret returns a descriptive error.
func TestGDAPClient_getPartnerCenterToken_emptyClientSecret(t *testing.T) {
	credStore := &testCredentialStore{
		config: &auth.OAuth2Config{ClientID: "cid", ClientSecret: ""},
	}
	client := NewGDAPClient(nil, "partner-tenant-id")
	client.SetCredentialStore(credStore)

	_, err := client.getPartnerCenterToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_secret")
}

// TestGDAPClient_getPartnerCenterToken_noCredentialStore verifies that calling
// getPartnerCenterToken without a configured credential store returns an error.
func TestGDAPClient_getPartnerCenterToken_noCredentialStore(t *testing.T) {
	client := NewGDAPClient(nil, "partner-tenant-id")
	// credStore is nil by default

	_, err := client.getPartnerCenterToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential store not configured")
}

// TestGDAPClient_getPartnerCenterToken_oauthErrorResponse verifies that an OAuth2
// error response from the token endpoint is surfaced as a descriptive error.
func TestGDAPClient_getPartnerCenterToken_oauthErrorResponse(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		resp := map[string]interface{}{
			"error":             "invalid_client",
			"error_description": "AADSTS70011: The provided client secret is invalid.",
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer tokenServer.Close()

	credStore := &testCredentialStore{
		config: &auth.OAuth2Config{ClientID: "bad-cid", ClientSecret: "bad-secret"},
	}
	client := NewGDAPClient(tokenServer.Client(), "partner-tenant-id")
	client.tokenBaseURL = tokenServer.URL
	client.SetCredentialStore(credStore)

	_, err := client.getPartnerCenterToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_client")
}

// TestGDAPClient_getPartnerCenterToken_persistedTokenReused verifies that a valid
// persisted token from a previous run is served without hitting the token endpoint.
func TestGDAPClient_getPartnerCenterToken_persistedTokenReused(t *testing.T) {
	var requestCount int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResponse("new-token", 3600)); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer tokenServer.Close()

	persistedToken := &auth.AccessToken{
		Token:     "persisted-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	credStore := &testCredentialStore{
		config: &auth.OAuth2Config{ClientID: "cid", ClientSecret: "csecret"},
		token:  persistedToken,
	}
	client := NewGDAPClient(tokenServer.Client(), "partner-tenant-id")
	client.tokenBaseURL = tokenServer.URL
	client.SetCredentialStore(credStore)

	tok, err := client.getPartnerCenterToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "persisted-token", tok.Token)
	assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount), "valid persisted token must not trigger a fetch")
}

// TestGDAPClient_getPartnerCenterToken_tokenStoredAfterFetch verifies that a freshly
// fetched token is written back to the credential store for future process reuse.
func TestGDAPClient_getPartnerCenterToken_tokenStoredAfterFetch(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResponse("stored-token", 3600)); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer tokenServer.Close()

	credStore := &testCredentialStore{
		config: &auth.OAuth2Config{ClientID: "cid", ClientSecret: "csecret"},
	}
	client := NewGDAPClient(tokenServer.Client(), "partner-tenant-id")
	client.tokenBaseURL = tokenServer.URL
	client.SetCredentialStore(credStore)

	_, err := client.getPartnerCenterToken(context.Background())
	require.NoError(t, err)

	require.NotNil(t, credStore.token, "token must be persisted to the credential store")
	assert.Equal(t, "stored-token", credStore.token.Token)
}

// TestGDAPClient_getPartnerCenterToken_concurrentCallsNoraceCondition verifies that
// concurrent callers receive valid tokens and that the shared cachedToken field has
// no data races under the -race detector.
func TestGDAPClient_getPartnerCenterToken_concurrentCallsNoraceCondition(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResponse("concurrent-token", 3600)); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer tokenServer.Close()

	credStore := &testCredentialStore{
		config: &auth.OAuth2Config{ClientID: "cid", ClientSecret: "csecret"},
	}
	client := NewGDAPClient(tokenServer.Client(), "partner-tenant-id")
	client.tokenBaseURL = tokenServer.URL
	client.SetCredentialStore(credStore)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errors := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			tok, err := client.getPartnerCenterToken(context.Background())
			if err != nil {
				errors[i] = err
				return
			}
			if tok == nil || tok.Token == "" {
				errors[i] = fmt.Errorf("goroutine %d: got nil or empty token", i)
			}
		}()
	}
	wg.Wait()

	for i, err := range errors {
		assert.NoError(t, err, "goroutine %d must not error", i)
	}
}
