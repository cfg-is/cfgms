// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
)

// storeTestConfig stores a minimal valid StewardConfig for the given tenant and steward.
func storeTestConfig(t *testing.T, server *Server, tenantID, stewardID string) {
	t.Helper()
	cfg := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   stewardID,
			Mode: stewardconfig.ModeController,
			Logging: stewardconfig.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
			ErrorHandling: stewardconfig.ErrorHandlingConfig{
				ModuleLoadFailure:  stewardconfig.ActionContinue,
				ResourceFailure:    stewardconfig.ActionWarn,
				ConfigurationError: stewardconfig.ActionFail,
			},
		},
		Modules:   map[string]string{"file": "file"},
		Resources: []stewardconfig.ResourceConfig{},
	}
	err := server.configService.SetConfiguration(context.Background(), tenantID, stewardID, cfg)
	require.NoError(t, err)
}

func TestHandleListConfigs(t *testing.T) {
	t.Run("200 with empty list when no configs stored", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"config:list"})

		req := httptest.NewRequest("GET", "/api/v1/configs", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var resp APIResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.NotNil(t, resp.Data)
		list, ok := resp.Data.([]interface{})
		require.True(t, ok, "data should be a JSON array, got %T", resp.Data)
		assert.Len(t, list, 0)
	})

	t.Run("200 with configs list when configs are stored", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"config:list"}, "test-tenant", 5*time.Minute)

		storeTestConfig(t, server, "test-tenant", "steward-alpha")
		storeTestConfig(t, server, "test-tenant", "steward-beta")

		req := httptest.NewRequest("GET", "/api/v1/configs", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var resp APIResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		list, ok := resp.Data.([]interface{})
		require.True(t, ok, "data should be a JSON array")
		assert.Len(t, list, 2)
	})

	t.Run("tenant filter applied via tenant_id query param — same tenant allowed", func(t *testing.T) {
		server := setupTestServer(t)
		// API key scoped to acme-corp; query param also says acme-corp — allowed
		apiKey := NewEphemeralTestKey(t, server, []string{"config:list"}, "acme-corp", 5*time.Minute)

		storeTestConfig(t, server, "acme-corp", "steward-1")

		req := httptest.NewRequest("GET", "/api/v1/configs?tenant_id=acme-corp", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var resp APIResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		list, ok := resp.Data.([]interface{})
		require.True(t, ok, "data should be a JSON array")
		assert.Len(t, list, 1)

		item, ok := list[0].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "steward-1", item["steward_id"])
	})

	t.Run("cross-tenant query param returns 403", func(t *testing.T) {
		server := setupTestServer(t)
		// API key scoped to acme-corp; query param asks for other-tenant — forbidden
		apiKey := NewEphemeralTestKey(t, server, []string{"config:list"}, "acme-corp", 5*time.Minute)

		req := httptest.NewRequest("GET", "/api/v1/configs?tenant_id=other-tenant", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		var errResp ErrorResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
		assert.Equal(t, "TENANT_MISMATCH", errResp.Error.Code)
	})

	t.Run("missing permission returns 403", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:list"})

		req := httptest.NewRequest("GET", "/api/v1/configs", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}
