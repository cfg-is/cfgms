// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cache"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// failingCredentialStore is a test implementation of CredentialStore that returns
// errors on store operations to verify logging of those failures.
type failingCredentialStore struct {
	getConfigErr  error
	storeTokenErr error
}

func (s *failingCredentialStore) StoreToken(_ string, _ *AccessToken) error {
	return s.storeTokenErr
}

func (s *failingCredentialStore) GetToken(_ string) (*AccessToken, error) {
	return nil, errors.New("no token")
}

func (s *failingCredentialStore) DeleteToken(_ string) error { return nil }

func (s *failingCredentialStore) StoreDelegatedToken(_, _ string, _ *AccessToken) error {
	return s.storeTokenErr
}

func (s *failingCredentialStore) GetDelegatedToken(_, _ string) (*AccessToken, error) {
	return nil, errors.New("no token")
}

func (s *failingCredentialStore) DeleteDelegatedToken(_, _ string) error { return nil }

func (s *failingCredentialStore) StoreUserContext(_, _ string, _ *UserContext) error {
	return s.storeTokenErr
}

func (s *failingCredentialStore) GetUserContext(_, _ string) (*UserContext, error) {
	return nil, errors.New("no context")
}

func (s *failingCredentialStore) DeleteUserContext(_, _ string) error { return nil }

func (s *failingCredentialStore) StoreConfig(_ string, _ *OAuth2Config) error { return nil }

func (s *failingCredentialStore) GetConfig(_ string) (*OAuth2Config, error) {
	if s.getConfigErr != nil {
		return nil, s.getConfigErr
	}
	return nil, errors.New("no config")
}

func (s *failingCredentialStore) IsAvailable() bool { return true }

// TestOAuth2Provider_tokenStoreFailure_logsError verifies that token store failures
// are routed through the injected logger rather than written directly to stdout.
func TestOAuth2Provider_tokenStoreFailure_logsError(t *testing.T) {
	// Mock token endpoint that returns a valid token
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode failed", http.StatusInternalServerError)
		}
	}))
	defer mockServer.Close()

	mockLog := pkgtesting.NewMockLogger(false)
	credStore := &failingCredentialStore{
		storeTokenErr: errors.New("storage unavailable"),
	}
	config := &OAuth2Config{
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		TenantID:             "test-tenant",
		UseClientCredentials: true,
		AuthorityURL:         mockServer.URL,
	}

	provider := NewOAuth2Provider(credStore, config, mockLog)
	provider.SetHTTPClient(mockServer.Client())

	token, err := provider.GetAccessToken(context.Background(), config.TenantID)
	require.NoError(t, err)
	assert.NotNil(t, token)

	warnLogs := mockLog.GetLogs("warn")
	require.NotEmpty(t, warnLogs, "expected a warn log for token store failure")
	assert.Equal(t, "failed to store token", warnLogs[0].Message)
}

// TestOAuth2Provider_nilLogger_usesNoopLogger verifies that passing nil as logger
// falls back to the no-op logger instead of panicking.
func TestOAuth2Provider_nilLogger_usesNoopLogger(t *testing.T) {
	credStore := &failingCredentialStore{storeTokenErr: errors.New("store failed")}
	config := &OAuth2Config{TenantID: "t1", UseClientCredentials: true}

	provider := NewOAuth2Provider(credStore, config, nil)
	assert.NotNil(t, provider.logger, "logger must never be nil after construction")
}

// TestOAuth2Provider_exchangeCode_tokenStoreFailure_logsWarning verifies that
// ExchangeCodeForDelegatedToken logs a warning when StoreToken fails for an
// application token (nil userContext path).
func TestOAuth2Provider_exchangeCode_tokenStoreFailure_logsWarning(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"access_token": "exchange-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode failed", http.StatusInternalServerError)
		}
	}))
	defer mockServer.Close()

	mockLog := pkgtesting.NewMockLogger(false)
	credStore := &failingCredentialStore{storeTokenErr: errors.New("store failed")}
	config := &OAuth2Config{
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		TenantID:             "test-tenant",
		UseClientCredentials: true,
		AuthorityURL:         mockServer.URL,
	}

	provider := NewOAuth2Provider(credStore, config, mockLog)
	provider.SetHTTPClient(mockServer.Client())

	// nil userContext → application token path → calls StoreToken
	token, err := provider.ExchangeCodeForDelegatedToken(
		context.Background(), config.TenantID, "auth-code", "", nil,
	)
	require.NoError(t, err)
	assert.NotNil(t, token)

	warnLogs := mockLog.GetLogs("warn")
	require.NotEmpty(t, warnLogs, "expected warn log for token store failure")
	assert.Equal(t, "failed to store token", warnLogs[0].Message)
}

// testClock is a fake clock for controlling cache time in tests.
type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time { return c.now }

// TestOAuth2Provider_TokenCacheExpiry verifies that tokens are absent from the
// cache after the configured TTL elapses, using a fake clock to avoid real waits.
func TestOAuth2Provider_TokenCacheExpiry(t *testing.T) {
	startTime := time.Now()
	clk := &testClock{now: startTime}

	credStore := &failingCredentialStore{}
	provider := NewOAuth2Provider(credStore, nil, nil)
	defer provider.Close()

	// Replace production caches with fake-clock caches (no background cleanup).
	provider.tokenCache.Close()
	provider.tokenCache = cache.NewCache(cache.CacheConfig{
		Name:            "m365-token-test",
		DefaultTTL:      55 * time.Minute,
		CleanupInterval: 0,
		Clock:           clk,
	})
	provider.delegatedTokenCache.Close()
	provider.delegatedTokenCache = cache.NewCache(cache.CacheConfig{
		Name:            "m365-delegated-token-test",
		DefaultTTL:      55 * time.Minute,
		CleanupInterval: 0,
		Clock:           clk,
	})

	// Token expires 60 minutes from startTime; cache TTL = 60min - 5min = 55min.
	token := &AccessToken{
		Token:     "test-access-token",
		TokenType: "Bearer",
		ExpiresAt: startTime.Add(60 * time.Minute),
	}
	provider.setCachedToken("tenant1", token)

	// At T0 the token must be present.
	clk.now = startTime
	got := provider.getCachedToken("tenant1")
	require.NotNil(t, got, "token must be cached at T0")
	assert.Equal(t, "test-access-token", got.Token)

	// At T0+54min the token must still be present (within the 55-min window).
	clk.now = startTime.Add(54 * time.Minute)
	got = provider.getCachedToken("tenant1")
	assert.NotNil(t, got, "token must still be cached at T0+54min")

	// At T0+56min the TTL has elapsed; the cache must return nothing.
	clk.now = startTime.Add(56 * time.Minute)
	got = provider.getCachedToken("tenant1")
	assert.Nil(t, got, "token must be absent from cache at T0+56min (TTL=55min)")
}

// TestOAuth2Provider_DelegatedTokenCacheExpiry mirrors TestOAuth2Provider_TokenCacheExpiry
// for the delegated token cache.
func TestOAuth2Provider_DelegatedTokenCacheExpiry(t *testing.T) {
	startTime := time.Now()
	clk := &testClock{now: startTime}

	provider := NewOAuth2Provider(&failingCredentialStore{}, nil, nil)
	defer provider.Close()

	provider.tokenCache.Close()
	provider.tokenCache = cache.NewCache(cache.CacheConfig{
		Name:            "m365-token-test",
		DefaultTTL:      55 * time.Minute,
		CleanupInterval: 0,
		Clock:           clk,
	})
	provider.delegatedTokenCache.Close()
	provider.delegatedTokenCache = cache.NewCache(cache.CacheConfig{
		Name:            "m365-delegated-token-test",
		DefaultTTL:      55 * time.Minute,
		CleanupInterval: 0,
		Clock:           clk,
	})

	token := &AccessToken{
		Token:     "delegated-token",
		TokenType: "Bearer",
		ExpiresAt: startTime.Add(60 * time.Minute),
	}
	cacheKey := "tenant1:user1"
	provider.setDelegatedCachedToken(cacheKey, token)

	clk.now = startTime
	got := provider.getDelegatedCachedToken(cacheKey)
	require.NotNil(t, got, "delegated token must be cached at T0")
	assert.Equal(t, "delegated-token", got.Token)

	clk.now = startTime.Add(56 * time.Minute)
	got = provider.getDelegatedCachedToken(cacheKey)
	assert.Nil(t, got, "delegated token must be absent after TTL elapses")
}

// TestOAuth2Provider_setCachedToken_skipsTTLTooShort verifies that tokens
// already within the 5-minute buffer window are not stored in the cache.
func TestOAuth2Provider_setCachedToken_skipsTTLTooShort(t *testing.T) {
	provider := NewOAuth2Provider(&failingCredentialStore{}, nil, nil)
	defer provider.Close()

	// Token expires in 3 minutes — within the 5-minute buffer, TTL would be negative.
	token := &AccessToken{
		Token:     "almost-expired-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(3 * time.Minute),
	}
	provider.setCachedToken("tenant1", token)
	assert.Nil(t, provider.getCachedToken("tenant1"), "token near expiry must not be cached")
}

// TestOAuth2Provider_setCachedToken_evictsStaleEntry verifies that calling setCachedToken
// with an expired token evicts any pre-existing valid entry for that key.
func TestOAuth2Provider_setCachedToken_evictsStaleEntry(t *testing.T) {
	provider := NewOAuth2Provider(&failingCredentialStore{}, nil, nil)
	defer provider.Close()

	validToken := &AccessToken{
		Token:     "valid-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(60 * time.Minute),
	}
	provider.setCachedToken("tenant1", validToken)
	require.NotNil(t, provider.getCachedToken("tenant1"), "valid token must be cached initially")

	expiredToken := &AccessToken{
		Token:     "expired-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	provider.setCachedToken("tenant1", expiredToken)

	assert.Nil(t, provider.getCachedToken("tenant1"), "stale entry must be evicted when setCachedToken is called with an expired token")
}

// TestOAuth2Provider_setDelegatedCachedToken_evictsStaleEntry verifies that calling
// setDelegatedCachedToken with an expired token evicts any pre-existing valid entry.
func TestOAuth2Provider_setDelegatedCachedToken_evictsStaleEntry(t *testing.T) {
	provider := NewOAuth2Provider(&failingCredentialStore{}, nil, nil)
	defer provider.Close()

	cacheKey := "tenant1:user1"

	validToken := &AccessToken{
		Token:     "valid-delegated-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(60 * time.Minute),
	}
	provider.setDelegatedCachedToken(cacheKey, validToken)
	require.NotNil(t, provider.getDelegatedCachedToken(cacheKey), "valid token must be cached initially")

	expiredToken := &AccessToken{
		Token:     "expired-delegated-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	provider.setDelegatedCachedToken(cacheKey, expiredToken)

	assert.Nil(t, provider.getDelegatedCachedToken(cacheKey), "stale entry must be evicted when setDelegatedCachedToken is called with an expired token")
}

// TestOAuth2Provider_ClearMethods verifies all five Clear* methods delegate
// correctly to pkg/cache without panicking.
func TestOAuth2Provider_ClearMethods(t *testing.T) {
	provider := NewOAuth2Provider(&failingCredentialStore{}, nil, nil)
	defer provider.Close()

	token := &AccessToken{Token: "tok", ExpiresAt: time.Now().Add(60 * time.Minute)}
	provider.setCachedToken("t1", token)
	provider.setCachedToken("t2", token)
	provider.setDelegatedCachedToken("t1:u1", token)
	provider.setDelegatedCachedToken("t1:u2", token)
	provider.setDelegatedCachedToken("t2:u1", token)

	// ClearCacheForTenant removes only the targeted tenant.
	provider.ClearCacheForTenant("t1")
	assert.Nil(t, provider.getCachedToken("t1"))
	assert.NotNil(t, provider.getCachedToken("t2"))

	// ClearDelegatedCacheForUser removes only the targeted user.
	provider.ClearDelegatedCacheForUser("t1", "u1")
	assert.Nil(t, provider.getDelegatedCachedToken("t1:u1"))
	assert.NotNil(t, provider.getDelegatedCachedToken("t1:u2"))

	// ClearDelegatedCacheForTenant removes all users for the tenant.
	provider.ClearDelegatedCacheForTenant("t1")
	assert.Nil(t, provider.getDelegatedCachedToken("t1:u2"))
	assert.NotNil(t, provider.getDelegatedCachedToken("t2:u1"))

	// ClearCache wipes all application tokens.
	provider.ClearCache()
	assert.Nil(t, provider.getCachedToken("t2"))

	// ClearDelegatedCache wipes all delegated tokens.
	provider.ClearDelegatedCache()
	assert.Nil(t, provider.getDelegatedCachedToken("t2:u1"))
}

// TestOAuth2Provider_refreshDelegated_storeFailure_logsWarning verifies that
// RefreshDelegatedToken logs warnings when delegated token and user context
// storage fail.
func TestOAuth2Provider_refreshDelegated_storeFailure_logsWarning(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"access_token":  "refreshed-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "new-refresh",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode failed", http.StatusInternalServerError)
		}
	}))
	defer mockServer.Close()

	mockLog := pkgtesting.NewMockLogger(false)
	credStore := &failingCredentialStore{storeTokenErr: errors.New("store failed")}
	config := &OAuth2Config{
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		TenantID:             "uid-as-tenant",
		UseClientCredentials: false,
		AuthorityURL:         mockServer.URL,
	}

	provider := NewOAuth2Provider(credStore, config, mockLog)
	provider.SetHTTPClient(mockServer.Client())

	userCtx := &UserContext{
		UserID:            "uid-as-tenant",
		UserPrincipalName: "user@example.com",
		LastAuthenticated: time.Now(),
	}

	token, err := provider.RefreshDelegatedToken(context.Background(), "refresh-token", userCtx)
	require.NoError(t, err)
	assert.NotNil(t, token)

	warnLogs := mockLog.GetLogs("warn")
	require.GreaterOrEqual(t, len(warnLogs), 2, "expected warn logs for delegated token and user context store failures")

	messages := make([]string, len(warnLogs))
	for i, l := range warnLogs {
		messages[i] = l.Message
	}
	assert.Contains(t, messages, "failed to store delegated token")
	assert.Contains(t, messages, "failed to store user context")
}

// TestOAuth2Provider_GetAccessToken_configError verifies that GetAccessToken returns
// a CONFIG_ERROR when no OAuth2 configuration can be resolved for the tenant.
func TestOAuth2Provider_GetAccessToken_configError(t *testing.T) {
	// getConfigErr causes the credential store to return an error; nil defaultConfig
	// removes the fallback so getOAuth2Config has no configuration to return.
	credStore := &failingCredentialStore{getConfigErr: errors.New("config unavailable")}
	provider := NewOAuth2Provider(credStore, nil, nil)
	defer provider.Close()

	_, err := provider.GetAccessToken(context.Background(), "unknown-tenant")
	require.Error(t, err)
	authErr, ok := err.(*AuthenticationError)
	require.True(t, ok, "expected *AuthenticationError")
	assert.Equal(t, "CONFIG_ERROR", authErr.Code)
}

// rewriteTransport sends every request to target, preserving path and body, so
// the provider's hard-coded login host reaches an httptest server.
type rewriteTransport struct {
	target *url.URL
}

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = r.target.Scheme
	clone.URL.Host = r.target.Host
	clone.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(clone)
}

// [REQUIRED TEST] Issue #4891: MintAccessToken reads the connection on file on
// every call and serves no cached or stored token.
func TestMintAccessToken_RereadsConfigNoCacheNoStoredToken(t *testing.T) {
	var mu sync.Mutex
	var seen []url.Values
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		mu.Lock()
		seen = append(seen, r.PostForm)
		paths = append(paths, r.URL.Path)
		n := len(seen)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("minted-%d", n), "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	store := newKeyedCredentialStore()
	p := NewOAuth2Provider(store, nil, nil)
	p.SetHTTPClient(&http.Client{Transport: rewriteTransport{target: u}})
	ctx := context.Background()

	_, err = p.MintAccessToken(ctx, "client-1")
	require.Error(t, err, "no connection on file must fail")
	assert.Contains(t, err.Error(), "client-1")

	require.NoError(t, store.StoreConfig("client-1", &OAuth2Config{
		ClientID: "id-one", ClientSecret: "secret-one", TenantID: "m365-one", UseClientCredentials: true,
	}))
	// A stored token and a cached token must both be ignored.
	require.NoError(t, store.StoreToken("client-1", &AccessToken{Token: "stored", ExpiresAt: time.Now().Add(time.Hour)}))
	p.setCachedToken("client-1", &AccessToken{Token: "cached", ExpiresAt: time.Now().Add(time.Hour)})

	tok1, err := p.MintAccessToken(ctx, "client-1")
	require.NoError(t, err)
	assert.Equal(t, "minted-1", tok1.Token)
	tok2, err := p.MintAccessToken(ctx, "client-1")
	require.NoError(t, err)
	assert.Equal(t, "minted-2", tok2.Token, "every call mints anew")

	stored, _ := store.GetToken("client-1")
	assert.Equal(t, "stored", stored.Token, "minting must not persist a token")

	// Replace the connection.
	require.NoError(t, store.StoreConfig("client-1", &OAuth2Config{
		ClientID: "id-two", ClientSecret: "secret-two", TenantID: "m365-two", UseClientCredentials: true,
	}))
	_, err = p.MintAccessToken(ctx, "client-1")
	require.NoError(t, err)
	mu.Lock()
	last := seen[len(seen)-1]
	lastPath := paths[len(paths)-1]
	mu.Unlock()
	assert.Equal(t, "id-two", last.Get("client_id"))
	if last.Get("client_secret") != "secret-two" {
		t.Fatal("token endpoint did not receive the replaced client secret")
	}
	assert.Contains(t, lastPath, "m365-two")

	// Delete the connection.
	store.mu.Lock()
	delete(store.configs, "client-1")
	store.mu.Unlock()
	_, err = p.MintAccessToken(ctx, "client-1")
	require.Error(t, err)
}

func TestMintAccessToken_UnsupportedConnectionAndStoreError(t *testing.T) {
	store := newKeyedCredentialStore()
	require.NoError(t, store.StoreConfig("t1", &OAuth2Config{ClientID: "a", ClientSecret: "b", TenantID: "m"}))
	p := NewOAuth2Provider(store, &OAuth2Config{ClientID: "default", ClientSecret: "default", UseClientCredentials: true}, nil)
	_, err := p.MintAccessToken(context.Background(), "t1")
	require.Error(t, err)

	// defaultConfig must never be used for a tenant without a connection.
	_, err = p.MintAccessToken(context.Background(), "t2")
	require.Error(t, err)

	p2 := NewOAuth2Provider(&failingCredentialStore{getConfigErr: errors.New("store closed")}, nil, nil)
	_, err = p2.MintAccessToken(context.Background(), "t1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "t1")
}
