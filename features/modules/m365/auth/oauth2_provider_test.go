// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		_ = json.NewEncoder(w).Encode(resp)
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
		_ = json.NewEncoder(w).Encode(resp)
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
	require.GreaterOrEqual(t, len(warnLogs), 1, "expected at least one warn log")
}
