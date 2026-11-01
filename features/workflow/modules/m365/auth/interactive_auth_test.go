// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestInteractiveAuthenticator_CallbackEscapesProviderError(t *testing.T) {
	ia := &InteractiveAuthenticator{callbackAddr: ":0"}
	results := make(chan authResult, 1)
	ia.setupCallbackHandler("expected-state", "verifier", "tenant", results)

	req := httptest.NewRequest(http.MethodGet,
		"/callback?error=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&error_description=%3Cimg+src%3Dx+onerror%3Dalert%282%29%3E",
		nil)
	rec := httptest.NewRecorder()
	ia.server.Handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	body := rec.Body.String()
	require.NotContains(t, body, "<script>")
	require.NotContains(t, body, "<img")
	require.True(t, strings.Contains(body, "&lt;script&gt;") && strings.Contains(body, "&lt;img"),
		"provider-controlled HTML must be escaped in the callback response")
	require.Error(t, (<-results).err)
}

// TestInteractiveAuthenticator_warning_logsToLogger verifies that a failure to
// retrieve user roles is routed through the injected logger (not written to
// stdout directly).
func TestInteractiveAuthenticator_warning_logsToLogger(t *testing.T) {
	// Mock Graph server: /me succeeds, /me/memberOf returns 500 to force an error
	mockGraph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/me":
			resp := map[string]interface{}{
				"id":                "user-id-1",
				"userPrincipalName": "testuser@example.com",
				"displayName":       "Test User",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			// All other paths (including /me/memberOf) return 500
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer mockGraph.Close()

	mockLog := pkgtesting.NewMockLogger(false)

	credStore := &failingCredentialStore{}
	config := &OAuth2Config{
		TenantID:             "test-tenant",
		UseClientCredentials: true,
	}

	provider := NewOAuth2Provider(credStore, config, logging.NewNoopLogger())
	// Override HTTP client so requests hit our mock server instead of graph.microsoft.com
	provider.SetHTTPClient(&http.Client{
		Transport: &graphURLRewriteTransport{baseURL: mockGraph.URL},
	})

	ia := NewInteractiveAuthenticator(provider, ":0", mockLog)

	token := &AccessToken{
		Token:     "test-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	userCtx, err := ia.getUserInfo(context.Background(), token)
	require.NoError(t, err, "getUserInfo should succeed even when roles fail")
	assert.NotNil(t, userCtx)

	warnLogs := mockLog.GetLogs("warn")
	require.NotEmpty(t, warnLogs, "expected warn log for role retrieval failure")
	assert.Equal(t, "could not retrieve user roles", warnLogs[0].Message)
}

// graphURLRewriteTransport rewrites graph.microsoft.com requests to a test server.
type graphURLRewriteTransport struct {
	baseURL string
}

func (t *graphURLRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = "http"
	cloned.URL.Host = t.baseURL[len("http://"):]
	return http.DefaultTransport.RoundTrip(cloned)
}

// TestInteractiveAuthenticator_nilLogger_usesNoopLogger verifies that a nil logger
// is replaced with the no-op logger at construction time.
func TestInteractiveAuthenticator_nilLogger_usesNoopLogger(t *testing.T) {
	credStore := &failingCredentialStore{}
	config := &OAuth2Config{TenantID: "t1"}
	provider := NewOAuth2Provider(credStore, config, logging.NewNoopLogger())

	ia := NewInteractiveAuthenticator(provider, ":0", nil)
	assert.NotNil(t, ia.logger, "logger must never be nil after construction")
}
