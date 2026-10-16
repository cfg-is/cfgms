// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// Issue #5022: API error responses are JSON, 403 bodies carry no decision
// internals, and the unauthenticated health probes disclose nothing but status.

func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, status int) ErrorResponse {
	t.Helper()
	require.Equal(t, status, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
	var er ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &er), "body must be a JSON ErrorResponse: %q", rec.Body.String())
	require.NotNil(t, er.Error)
	return er
}

func TestAuthorizationErrorBodyIsTrimmed(t *testing.T) {
	server := setupTestServer(t)
	key := NewTestKey(t, server, []string{"steward:list"})

	handler := wrapWithAuth(server, "steward", "write-config",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/test", nil)
	req.Header.Set("X-API-Key", key)
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "test-tenant"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	er := assertJSONError(t, rec, http.StatusForbidden)
	assert.Equal(t, "INSUFFICIENT_PERMISSIONS", er.Error.Code)
	assert.Equal(t, map[string]interface{}{"permission_id": "steward:write-config"}, er.Error.Details)
	body := rec.Body.String()
	for _, leaked := range []string{"subject_id", "tenant_id", "duration_ms", "conditional_vars", "authorization_decision", "reason"} {
		assert.NotContains(t, body, leaked)
	}
}

func TestPublicHealthProbesDiscloseOnlyStatus(t *testing.T) {
	server := setupTestServer(t)
	for _, path := range []string{"/api/v1/health", "/api/v1/ready"} {
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw), path)
		data, ok := raw["data"].(map[string]interface{})
		require.True(t, ok, path)
		assert.Contains(t, data, "status", path)
		assert.NotContains(t, data, "version", path)
		assert.NotContains(t, data, "services", path)
		assert.NotContains(t, data, "checks", path)
	}
}

func TestAPIRouterErrorsAreJSON(t *testing.T) {
	withEmbeddedSPA(t, testEmbeddedAssetsPlaceholderOnly())
	server := setupTestServer(t)

	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/api/v1/doesnotexist", http.StatusNotFound},
		{http.MethodPatch, "/api/v1/health", http.StatusMethodNotAllowed},
		{http.MethodPatch, "/api/v1/stewards", http.StatusMethodNotAllowed},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("X-API-Key", NewTestKey(t, server, []string{"steward:list"}))
			server.router.ServeHTTP(rec, req)
			assertJSONError(t, rec, tc.status)
			assert.NotEmpty(t, rec.Header().Get("Strict-Transport-Security"))
			assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		})
	}
}

func TestConvertedHandlerErrorPathIsJSON(t *testing.T) {
	server := setupTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/x/acknowledge", strings.NewReader("{"))
	server.handleAcknowledgeAlert(rec, req)
	assertJSONError(t, rec, http.StatusBadRequest)
}
