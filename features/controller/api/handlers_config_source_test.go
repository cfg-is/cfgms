// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	cfgpkg "github.com/cfgis/cfgms/pkg/config"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// alwaysSucceedValidator is a real test double (not a mock) that always reports success.
// It records whether ValidateMountPoint was called so tests can assert on RBAC ordering.
type alwaysSucceedValidator struct {
	called int
}

func (v *alwaysSucceedValidator) ValidateMountPoint(_ context.Context, _ *cfgpkg.ConfigSourceInfo, _ secretsiface.SecretStore) error {
	v.called++
	return nil
}

// alwaysFailValidator is a real test double that always returns a connection error.
type alwaysFailValidator struct{}

func (v *alwaysFailValidator) ValidateMountPoint(_ context.Context, _ *cfgpkg.ConfigSourceInfo, _ secretsiface.SecretStore) error {
	return fmt.Errorf("mount point connection test failed: connection refused")
}

// setupConfigSourceTestServer creates a test server and a tenant with a git config source.
func setupConfigSourceTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	server := setupTestServer(t)

	ctx := context.Background()
	td, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		Name: "TestConfigSourceTenant",
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType:   "git",
			cfgpkg.MetaKeyConfigSourceURL:    "https://github.com/example/configs.git",
			cfgpkg.MetaKeyConfigSourceBranch: "main",
		},
	})
	require.NoError(t, err)
	return server, td.ID
}

// TestConnectionTest_RBACGateFiresBeforeOutbound verifies that when the caller does
// not have the tenant.manage permission, the handler returns HTTP 403 and the
// MountPointValidator is never called (no outbound connection is made).
func TestConnectionTest_RBACGateFiresBeforeOutbound(t *testing.T) {
	server := setupTestServer(t)

	validator := &alwaysSucceedValidator{}
	server.SetMountPointValidator(validator, nil)

	// API key lacks tenant.manage permission.
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/some-tenant/config-source/test",
		bytes.NewBufferString("{}"))
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"expected 403 when caller lacks tenant.manage permission")
	assert.Equal(t, 0, validator.called,
		"validator must not be called when RBAC denies access (no outbound connection)")
}

// TestConnectionTest_RateLimitReturns429 verifies that after configTestMaxPerTenant
// requests within the window, subsequent requests return HTTP 429.
func TestConnectionTest_RateLimitReturns429(t *testing.T) {
	server, tenantID := setupConfigSourceTestServer(t)

	server.SetMountPointValidator(&alwaysSucceedValidator{}, nil)

	apiKey := NewTestKey(t, server, []string{"tenant:manage"})
	url := fmt.Sprintf("/api/v1/tenants/%s/config-source/test", tenantID)

	// Exhaust the per-tenant rate limit.
	for i := 0; i < configTestMaxPerTenant; i++ {
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("{}"))
		req.Header.Set("X-API-Key", apiKey)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		code := w.Code
		require.True(t, code == http.StatusOK,
			"request %d should succeed before limit, got %d", i+1, code)
	}

	// The next request must be rate-limited.
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("{}"))
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code,
		"expected 429 after exhausting per-tenant rate limit")
}

// TestConnectionTest_ActorFromContextOnly verifies that the handler extracts the actor
// identity from the authenticated request context, not from the request body or query.
func TestConnectionTest_ActorFromContextOnly(t *testing.T) {
	server, tenantID := setupConfigSourceTestServer(t)
	server.SetMountPointValidator(&alwaysSucceedValidator{}, nil)

	apiKey := NewTestKey(t, server, []string{"tenant:manage"})

	// Attempt to inject a fake actor via the request body (must be ignored).
	body := `{"actor": "injected-actor", "user": "attacker"}`
	url := fmt.Sprintf("/api/v1/tenants/%s/config-source/test", tenantID)
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	require.NotEqual(t, http.StatusInternalServerError, w.Code,
		"handler must not crash when request body contains actor field")
	assert.Equal(t, http.StatusOK, w.Code)

	// The response body must NOT reflect the injected actor string.
	responseBody := w.Body.String()
	assert.NotContains(t, responseBody, "injected-actor",
		"response must not reflect request body actor field")
}

// TestConnectionTest_Returns200WhenReachable verifies the response shape when reachable.
func TestConnectionTest_Returns200WhenReachable(t *testing.T) {
	server, tenantID := setupConfigSourceTestServer(t)
	server.SetMountPointValidator(&alwaysSucceedValidator{}, nil)

	apiKey := NewTestKey(t, server, []string{"tenant:manage"})
	url := fmt.Sprintf("/api/v1/tenants/%s/config-source/test", tenantID)

	req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("{}"))
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data      configSourceTestResponse `json:"data"`
		Timestamp time.Time                `json:"timestamp"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Data.Reachable, "expected reachable=true when validator succeeds")
	assert.Empty(t, resp.Data.Error, "expected no error when reachable")
}

// TestConnectionTest_Returns200WhenUnreachable verifies the response shape when unreachable.
func TestConnectionTest_Returns200WhenUnreachable(t *testing.T) {
	server, tenantID := setupConfigSourceTestServer(t)
	server.SetMountPointValidator(&alwaysFailValidator{}, nil)

	apiKey := NewTestKey(t, server, []string{"tenant:manage"})
	url := fmt.Sprintf("/api/v1/tenants/%s/config-source/test", tenantID)

	req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("{}"))
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data configSourceTestResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.False(t, resp.Data.Reachable, "expected reachable=false when validator fails")
	assert.NotEmpty(t, resp.Data.Error, "expected error message in response")
}
