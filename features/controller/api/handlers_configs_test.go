// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

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

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
	storageifaces "github.com/cfgis/cfgms/pkg/storage/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// failingConfigStore is a real ConfigStore implementation whose ListConfigs and
// DeleteConfig operations always fail. All other operations delegate to the
// embedded real store. It exercises the 500 INTERNAL_ERROR handler branches
// without mocking CFGMS components.
type failingConfigStore struct {
	cfgconfig.ConfigStore
}

func (f *failingConfigStore) ListConfigs(context.Context, *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	return nil, errors.New("storage backend unavailable")
}

func (f *failingConfigStore) DeleteConfig(context.Context, *cfgconfig.ConfigKey) error {
	return errors.New("storage backend unavailable")
}

// useFailingConfigService swaps the server's configuration service for one
// backed by a config store that fails list/delete operations, so handler tests
// can exercise the internal-error (500) branch with real components.
func useFailingConfigService(t *testing.T, server *Server) {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	composite := storageifaces.NewStorageManagerFromStores(
		&failingConfigStore{ConfigStore: sm.GetConfigStore()},
		sm.GetAuditStore(),
		sm.GetRBACStore(),
		sm.GetTenantStore(),
		sm.GetClientTenantStore(),
		sm.GetRegistrationTokenStore(),
		sm.GetSessionStore(),
		sm.GetStewardStore(),
		sm.GetCommandStore(),
		sm.GetTriggerStore(),
		sm.GetPushStore(),
	)
	logger := logging.NewNoopLogger()
	server.configService = service.NewConfigurationServiceV2(logger, composite, service.NewControllerService(logger))
}

// storeTestConfig stores a minimal valid StewardConfig for the given tenant and steward.
func storeTestConfig(t *testing.T, server *Server, tenantID, stewardID string) {
	t.Helper()
	cfg := &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{
			ID:   stewardID,
			Mode: stewardtypes.ModeController,
			Logging: stewardtypes.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
			ErrorHandling: stewardtypes.ErrorHandlingConfig{
				ModuleLoadFailure:  stewardtypes.ActionContinue,
				ResourceFailure:    stewardtypes.ActionWarn,
				ConfigurationError: stewardtypes.ActionFail,
			},
		},
		Modules:   map[string]string{"file": "file"},
		Resources: []stewardtypes.ResourceConfig{},
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

	t.Run("500 INTERNAL_ERROR when storage backend fails", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"config:list"})
		useFailingConfigService(t, server)

		req := httptest.NewRequest("GET", "/api/v1/configs", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusInternalServerError, rec.Code)
		var errResp ErrorResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
		assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
	})
}
