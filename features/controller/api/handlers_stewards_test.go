// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// ---- buildFleetFilter unit tests (no server required) ----

func TestBuildFleetFilter_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	filter, err := buildFleetFilter(req, "")
	require.NoError(t, err)
	assert.True(t, isEmptyFilter(filter))
}

func TestBuildFleetFilter_OS(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux", nil)
	filter, err := buildFleetFilter(req, "")
	require.NoError(t, err)
	assert.Equal(t, "linux", filter.OS)
	assert.False(t, isEmptyFilter(filter))
}

func TestBuildFleetFilter_AllParams(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/stewards?os=windows&platform=server&arch=amd64&status=online&hostname=web&tag=prod&tag=web", nil)
	filter, err := buildFleetFilter(req, "tenant-a")
	require.NoError(t, err)

	assert.Equal(t, "windows", filter.OS)
	assert.Equal(t, "server", filter.Platform)
	assert.Equal(t, "amd64", filter.Architecture)
	assert.Equal(t, "online", filter.Status)
	assert.Equal(t, "web", filter.Hostname)
	assert.Equal(t, "tenant-a", filter.TenantID) // comes from context, not query param
	assert.Equal(t, []string{"prod", "web"}, filter.Tags)
	assert.False(t, isEmptyFilter(filter))
}

func TestBuildFleetFilter_Tags_MultiValue(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/stewards?tag=production&tag=web&tag=db", nil)
	filter, err := buildFleetFilter(req, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"production", "web", "db"}, filter.Tags)
}

func TestBuildFleetFilter_TenantID_FromContext_NotQueryParam(t *testing.T) {
	// tenant_id in query param must be ignored; it comes from context only
	req := httptest.NewRequest("GET", "/api/v1/stewards?tenant_id=injected-tenant", nil)
	filter, err := buildFleetFilter(req, "real-tenant-from-context")
	require.NoError(t, err)
	assert.Equal(t, "real-tenant-from-context", filter.TenantID)
}

func TestBuildFleetFilter_InvalidStatus_ReturnsError(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/stewards?status=invalid", nil)
	_, err := buildFleetFilter(req, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid status")
}

func TestBuildFleetFilter_FieldTooLong_ReturnsError(t *testing.T) {
	longVal := strings.Repeat("a", 300)
	req := httptest.NewRequest("GET", "/api/v1/stewards?hostname="+longVal, nil)
	_, err := buildFleetFilter(req, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum length")
}

// ---- isEmptyFilter unit tests ----

func TestIsEmptyFilter_AllEmpty(t *testing.T) {
	assert.True(t, isEmptyFilter(fleet.Filter{}))
}

func TestIsEmptyFilter_WithTags(t *testing.T) {
	assert.False(t, isEmptyFilter(fleet.Filter{Tags: []string{"production"}}))
}

func TestIsEmptyFilter_WithDNAAttributes(t *testing.T) {
	assert.False(t, isEmptyFilter(fleet.Filter{DNAAttributes: map[string]string{"env": "prod"}}))
}

// ---- Error path tests: handleListStewards with failing fleet query ----

// failingFleetQuery is a real implementation of fleet.FleetQuery that always returns an error.
// It is not a mock — it satisfies the interface with deterministic error behavior for error-path testing.
type failingFleetQuery struct{}

func (f *failingFleetQuery) Search(_ context.Context, _ fleet.Filter) ([]fleet.StewardResult, error) {
	return nil, errors.New("forced fleet query failure")
}

func (f *failingFleetQuery) Count(_ context.Context, _ fleet.Filter) (int, error) {
	return 0, errors.New("forced fleet query failure")
}

func TestHandleListStewards_FleetQueryError_Returns500(t *testing.T) {
	server := setupTestServer(t)
	// Replace the fleet query with one that always fails.
	server.fleetQuery = &failingFleetQuery{}
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	// Any filter triggers the fleet query code path.
	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---- Integration tests: handleListStewards with fleet filtering ----

// registerTestSteward adds a steward to the controller service via AcceptRegistration.
// It uses the "test-tenant" tenant ID (same as NewTestKey) so fleet filter scoping works.
func registerTestSteward(t *testing.T, svc interface {
	AcceptRegistration(context.Context, *controller.RegisterRequest) (*controller.RegisterResponse, error)
}, attrs map[string]string) string {
	t.Helper()
	req := &controller.RegisterRequest{
		Version: "v1.0",
		InitialDna: &common.DNA{
			Id:         "dna-" + attrs["hostname"],
			Attributes: attrs,
		},
	}
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "test-tenant")
	resp, err := svc.AcceptRegistration(ctx, req)
	require.NoError(t, err)
	return resp.StewardId
}

func TestHandleListStewards_NoFilter_ReturnsAll(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	// Register two stewards
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-linux-1", "os": "linux", "arch": "amd64",
	})
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-windows-1", "os": "windows", "arch": "amd64",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 2)
}

func TestHandleListStewards_FilterByOS_ReturnsSubset(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-linux-1", "os": "linux", "arch": "amd64",
	})
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-windows-1", "os": "windows", "arch": "amd64",
	})
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-linux-2", "os": "linux", "arch": "arm64",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 2)
	for _, s := range resp.Data {
		require.NotNil(t, s.DNA)
		assert.Equal(t, "linux", s.DNA.OS)
	}
}

func TestHandleListStewards_FilterByStatus_ReturnsOnlineOnly(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-1", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?status=online", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// Registered stewards have status "registered", not "online", so filter returns none
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	// No stewards with status=online; empty result is correct behavior
	assert.NotNil(t, resp.Data)
	assert.Empty(t, resp.Data)
}

func TestHandleListStewards_FilterByHostname_SubstringMatch(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "web-server-01", "os": "linux",
	})
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "db-server-01", "os": "linux",
	})
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "web-server-02", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?hostname=web-server", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 2)
	for _, s := range resp.Data {
		require.NotNil(t, s.DNA)
		assert.Contains(t, s.DNA.Hostname, "web-server")
	}
}

func TestHandleListStewards_CombinedFilter_AND(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	// linux + amd64
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-1", "os": "linux", "arch": "amd64",
	})
	// linux + arm64 (should not match amd64 filter)
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-2", "os": "linux", "arch": "arm64",
	})
	// windows + amd64 (should not match linux filter)
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-3", "os": "windows", "arch": "amd64",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux&arch=amd64", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 1)
	assert.Equal(t, "amd64", resp.Data[0].DNA.Architecture)
}

func TestHandleListStewards_NoMatch_ReturnsEmptyArray(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-1", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?os=windows", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotNil(t, resp.Data)
	assert.Empty(t, resp.Data)
}

// TestHandleListStewards_HTTPRegisteredSteward_AppearsInList verifies that a steward
// registered via the HTTP path (RegisterSteward on ControllerService) appears in the
// list response.
func TestHandleListStewards_HTTPRegisteredSteward_AppearsInList(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	// Simulate HTTP registration writing into the single authoritative registry
	require.NoError(t, server.controllerService.RegisterSteward("http-steward-1", "test-tenant", "addr-1", "registered"))

	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, "http-steward-1", resp.Data[0].ID)
	assert.Equal(t, "registered", resp.Data[0].Status)
}

// TestHandleListStewards_HTTPRegistration_NoDuplicates verifies that registering the same
// steward ID twice produces exactly one entry in the list.
func TestHandleListStewards_HTTPRegistration_NoDuplicates(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	require.NoError(t, server.controllerService.RegisterSteward("dup-steward", "test-tenant", "addr-1", "registered"))
	require.NoError(t, server.controllerService.RegisterSteward("dup-steward", "test-tenant", "addr-2", "quarantined"))

	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 1, "duplicate steward ID should produce exactly one entry")
	assert.Equal(t, "quarantined", resp.Data[0].Status)
}

// noopSender is a minimal transport stub that satisfies registry.MessageSender
// so that registry.Register's nil-Sender guard passes in tests. It is not a
// mock of a CFGMS business component — MessageSender is a low-level transport
// interface whose production implementation is a gRPC stream that cannot be
// instantiated in unit tests without a live gRPC server. Tests here validate
// registry lookup behavior, not message delivery.
type noopSender struct{}

func (n *noopSender) SendMsg(_ interface{}) error { return nil }

// TestHandleGetSteward_ConnectedSteward verifies that active_sessions == 1 and
// connection_state == "connected" when the steward has an entry in the registry.
func TestHandleGetSteward_ConnectedSteward(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	// Register the steward in the controller service so GetStewardInfo can find it.
	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "connected-host", "os": "linux",
	})

	// Wire a real InMemoryRegistry with the steward registered.
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(&registry.StewardConnection{
		StewardID:   stewardID,
		Sender:      &noopSender{},
		ConnectedAt: time.Now(),
	}))
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.ID)
	assert.NotEmpty(t, resp.Data.Status)
	assert.Equal(t, 1, resp.Data.ActiveSessions)
	assert.Equal(t, "connected", resp.Data.ConnectionState)
}

// TestHandleGetSteward_DisconnectedSteward verifies that active_sessions == 0 and
// connection_state == "disconnected" when the steward is not in the registry.
func TestHandleGetSteward_DisconnectedSteward(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	// Register the steward in the controller service but not in the connection registry.
	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "disconnected-host", "os": "linux",
	})

	// Wire a real InMemoryRegistry with no entry for this steward.
	reg := registry.NewRegistry()
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.ID)
	assert.NotEmpty(t, resp.Data.Status)
	assert.Equal(t, 0, resp.Data.ActiveSessions)
	assert.Equal(t, "disconnected", resp.Data.ConnectionState)
}

// TestHandleGetSteward_NilRegistry verifies that active_sessions == 0 and
// connection_state == "disconnected" when no registry is wired (OSS single-node).
func TestHandleGetSteward_NilRegistry(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "no-registry-host", "os": "linux",
	})
	// registry is nil by default in setupTestServer — no SetRegistry call.

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.ID)
	assert.NotEmpty(t, resp.Data.Status)
	assert.Equal(t, 0, resp.Data.ActiveSessions)
	assert.Equal(t, "disconnected", resp.Data.ConnectionState)
}

// TestHandleStewardAuthRefresh_UnknownSteward_Returns404 verifies that POSTing to
// /api/v1/stewards/{id}/auth/refresh with an unregistered steward ID returns 404.
func TestHandleStewardAuthRefresh_UnknownSteward_Returns404(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:auth-refresh"})

	req := httptest.NewRequest("POST", "/api/v1/stewards/nonexistent-steward-id/auth/refresh", strings.NewReader("{}"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleStewardAuthRefresh_KnownSteward_Returns200 verifies that POSTing to
// /api/v1/stewards/{id}/auth/refresh with a registered steward returns 200 with
// {"steward_id":"...","status":"refresh_requested"}.
func TestHandleStewardAuthRefresh_KnownSteward_Returns200(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:auth-refresh"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "auth-refresh-host", "os": "linux",
	})

	req := httptest.NewRequest("POST", "/api/v1/stewards/"+stewardID+"/auth/refresh", strings.NewReader("{}"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, stewardID, body["steward_id"])
	assert.Equal(t, "refresh_requested", body["status"])
}

// TestServer_ConfigStatusRouteDeregistered verifies that GET /api/v1/stewards/{id}/config/status
// is no longer registered and returns 404 or 405, never 200 with hardcoded "unknown" data.
func TestServer_ConfigStatusRouteDeregistered(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-config"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/any-steward-id/config/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusOK, rec.Code, "config/status route must not return 200 after deregistration")
	assert.True(t, rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed,
		"expected 404 or 405, got %d", rec.Code)
}

func TestHandleDeleteStewardConfig(t *testing.T) {
	t.Run("success 204 when config exists", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:delete-config"}, "test-tenant", 5*time.Minute)

		storeTestConfig(t, server, "test-tenant", "steward-to-delete")

		req := httptest.NewRequest("DELETE", "/api/v1/stewards/steward-to-delete/config", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("not-found 404 when config does not exist", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:delete-config"}, "test-tenant", 5*time.Minute)

		req := httptest.NewRequest("DELETE", "/api/v1/stewards/nonexistent-steward/config", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
		var errResp ErrorResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
		assert.Equal(t, "CONFIG_NOT_FOUND", errResp.Error.Code)
	})

	t.Run("bad steward ID 400", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:delete-config"}, "test-tenant", 5*time.Minute)

		// Dots and colons are URL-safe but fail identifierRegex (^[a-zA-Z0-9_-]+$)
		req := httptest.NewRequest("DELETE", "/api/v1/stewards/steward.invalid:id/config", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing permission returns 403", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-config"})

		req := httptest.NewRequest("DELETE", "/api/v1/stewards/some-steward/config", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("internal error 500 when storage backend fails", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:delete-config"}, "test-tenant", 5*time.Minute)
		useFailingConfigService(t, server)

		req := httptest.NewRequest("DELETE", "/api/v1/stewards/steward-x/config", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusInternalServerError, rec.Code)
		var errResp ErrorResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
		assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
	})
}

// TestHandleGetStewardConfig_HappyPath exercises the stewardtypes.FromProto conversion
// path inside handleGetStewardConfig: register a steward, store a config, then GET it.
func TestHandleGetStewardConfig_HappyPath(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-config"})

	// Register a steward so GetConfiguration can look up its tenant.
	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "cfg-test-host", "os": "linux",
	})

	// Store a config — uses the same "test-tenant" that registerTestSteward injects
	// via context. The inheritance resolver will fall back to device-level config since
	// "test-tenant" has no full TenantData record in this in-memory test setup.
	storeTestConfig(t, server, "test-tenant", stewardID)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/config", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "response data must be a map, got %T", resp.Data)
	assert.Equal(t, stewardID, data["steward_id"])
	assert.Contains(t, data, "config")
}

// TestHandleGetStewardConfig_StewardNotRegistered verifies that requesting config for
// an unknown steward returns 400 CONFIG_ERROR (configService returns NOT_FOUND).
func TestHandleGetStewardConfig_StewardNotRegistered(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-config"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/nonexistent-steward/config", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "CONFIG_ERROR", errResp.Error.Code)
}

// TestHandleGetStewardConfig_InsufficientPermission verifies 403 when the API key
// lacks steward:read-config permission.
func TestHandleGetStewardConfig_InsufficientPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/any-steward/config", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---- handleGetStewardDNA attribute tests ----

// registerTestStewardWithDNA adds a steward with the given DNA attributes and returns its ID.
// The optional tenantID parameter overrides the default "test-tenant".
func registerTestStewardWithDNA(t *testing.T, server *Server, attrs map[string]string, tenantID string) string {
	t.Helper()
	if tenantID == "" {
		tenantID = "test-tenant"
	}
	req := &controller.RegisterRequest{
		Version: "v1.0",
		InitialDna: &common.DNA{
			Id:         "dna-" + attrs["hostname"],
			Attributes: attrs,
		},
	}
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, tenantID)
	resp, err := server.controllerService.AcceptRegistration(ctx, req)
	require.NoError(t, err)
	return resp.StewardId
}

// TestHandleGetStewardDNA_Attribute verifies that the handler returns {"value":"<val>"}
// when ?attribute=<key> is present, the key exists in the DNA, and the key is not denylisted.
func TestHandleGetStewardDNA_Attribute(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-dna"})

	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "attr-host", "os": "linux", "custom.key": "myvalue",
	}, "test-tenant")

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna?attribute=custom.key", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "myvalue", resp["value"])
}

// TestHandleGetStewardDNA_AttributeNotFound verifies 404 with DNA_ATTRIBUTE_NOT_FOUND
// when the key is not present in the DNA attributes.
func TestHandleGetStewardDNA_AttributeNotFound(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-dna"})

	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "notfound-host", "os": "linux",
	}, "test-tenant")

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna?attribute=nonexistent.key", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "DNA_ATTRIBUTE_NOT_FOUND", errResp.Error.Code)
}

// TestHandleGetStewardDNA_AttributeDenylistRedaction verifies that attribute keys matching
// sensitive patterns (*token*, *secret*, *password*, *credential*, *api_key*) return HTTP 404
// with code DNA_ATTRIBUTE_REDACTED, even when the key exists in the DNA.
func TestHandleGetStewardDNA_AttributeDenylistRedaction(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-dna"})

	// Register a steward with sensitive attributes present in DNA.
	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname":        "denylist-host",
		"os":              "linux",
		"auth_token":      "supersecret",
		"api_secret":      "topsecret",
		"user_password":   "hunter2",
		"user_credential": "cred123",
		"service_api_key": "key456",
	}, "test-tenant")

	denylisted := []string{
		"auth_token",      // matches *token*
		"api_secret",      // matches *secret*
		"user_password",   // matches *password*
		"user_credential", // matches *credential*
		"service_api_key", // matches *api_key*
	}

	for _, key := range denylisted {
		t.Run(key, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna?attribute="+key, nil)
			req.Header.Set("X-API-Key", apiKey)
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusNotFound, rec.Code, "expected 404 for denylisted key %q", key)
			var errResp ErrorResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
			assert.Equal(t, "DNA_ATTRIBUTE_REDACTED", errResp.Error.Code,
				"expected DNA_ATTRIBUTE_REDACTED for key %q", key)
		})
	}
}

// TestHandleGetStewardDNA_RejectsCrossTenant verifies that an API key scoped to tenant-a
// cannot read DNA for a steward registered in tenant-b. The response must be HTTP 404
// (not 403) to avoid disclosing steward existence across tenants.
func TestHandleGetStewardDNA_RejectsCrossTenant(t *testing.T) {
	server := setupTestServer(t)

	// Steward registered in tenant-b.
	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "cross-tenant-host", "os": "linux",
	}, "tenant-b")

	// API key scoped to tenant-a (cannot read tenant-b stewards).
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-dna"}, "tenant-a", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant DNA read must return 404, not 403")
}

// TestHandleGetStewardDNA_RejectsPrefixCollision verifies that "tenant-a" cannot access
// a steward in "tenant-abc" despite the raw string prefix matching. The "/" separator
// boundary must be checked so "tenant-a" only grants access to "tenant-a" or "tenant-a/*".
func TestHandleGetStewardDNA_RejectsPrefixCollision(t *testing.T) {
	server := setupTestServer(t)

	// Steward in "tenant-abc" — must NOT be visible to "tenant-a" caller.
	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "collision-host", "os": "linux",
	}, "tenant-abc")

	apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-dna"}, "tenant-a", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "prefix-collision tenant must return 404")
}

// TestHandleGetStewardDNA_InternalError verifies that a GetStewardDNA service error
// returns HTTP 500 with code INTERNAL_ERROR. The handler is called directly (bypassing
// auth middleware) with an empty TenantID so the cross-tenant guard is skipped, and
// the steward ID does not exist in the service - causing GetStewardDNA to return an error.
func TestHandleGetStewardDNA_InternalError(t *testing.T) {
	server := setupTestServer(t)

	// Call handler directly: empty TenantID skips cross-tenant check; non-existent steward
	// causes GetStewardDNA to return an error, exercising the INTERNAL_ERROR path.
	req := httptest.NewRequest("GET", "/api/v1/stewards/ghost-steward/dna", nil)
	req = withTenant(req, "")
	req = withVars(req, map[string]string{"id": "ghost-steward"})
	rec := httptest.NewRecorder()

	server.handleGetStewardDNA(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
}

// TestHandleGetStewardDNA_DNANotFound verifies HTTP 404 with code DNA_NOT_FOUND when
// the steward is registered but its DNA field is nil. GetStewardInfo returns a pointer
// to the live StewardInfo struct, so setting DNA = nil directly produces the condition.
func TestHandleGetStewardDNA_DNANotFound(t *testing.T) {
	server := setupTestServer(t)

	require.NoError(t, server.controllerService.RegisterSteward("no-dna-steward", "test-tenant", "addr-1", "registered"))

	// Null out the DNA via the pointer returned by GetStewardInfo so GetStewardDNA
	// returns nil,nil — exercising the DNA_NOT_FOUND response path.
	info, ok := server.controllerService.GetStewardInfo("no-dna-steward")
	require.True(t, ok)
	info.DNA = nil

	req := httptest.NewRequest("GET", "/api/v1/stewards/no-dna-steward/dna", nil)
	req = withTenant(req, "test-tenant")
	req = withVars(req, map[string]string{"id": "no-dna-steward"})
	rec := httptest.NewRecorder()

	server.handleGetStewardDNA(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "DNA_NOT_FOUND", errResp.Error.Code)
}

// TestHandleGetStewardDNA_AttributeKeyTooLong verifies HTTP 400 with code
// ATTRIBUTE_KEY_TOO_LONG when ?attribute= exceeds 128 characters.
func TestHandleGetStewardDNA_AttributeKeyTooLong(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-dna"})

	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "toolong-host", "os": "linux",
	}, "test-tenant")

	longKey := strings.Repeat("a", 129)
	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna?attribute="+longKey, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "ATTRIBUTE_KEY_TOO_LONG", errResp.Error.Code)
}

// ---- handleGetStewardModules tests (from develop) ----

// TestHandleGetStewardModules_StewardNotFound verifies 404 for an unknown steward ID.
func TestHandleGetStewardModules_StewardNotFound(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-modules"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/nonexistent-steward/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// TestHandleGetStewardModules_ReturnsNotImplemented verifies 501 + MODULES_UNAVAILABLE
// for a known steward with no module DNA and a tenant-authorized admin.
func TestHandleGetStewardModules_ReturnsNotImplemented(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-modules"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "no-modules-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotImplemented, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "MODULES_UNAVAILABLE", errResp.Error.Code)
	assert.Contains(t, errResp.Error.Message, "steward does not report loaded modules")
}

// TestHandleGetStewardModules_Returns200WithModules verifies that a steward with a
// modules.loaded DNA attribute returns 200 with the parsed module list.
func TestHandleGetStewardModules_Returns200WithModules(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-modules"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "modules-host", "os": "linux",
		"modules.loaded": "file, service, package",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data struct {
			Modules []struct {
				Name string `json:"name"`
			} `json:"modules"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data.Modules, 3)
	assert.Equal(t, "file", resp.Data.Modules[0].Name)
	assert.Equal(t, "service", resp.Data.Modules[1].Name)
	assert.Equal(t, "package", resp.Data.Modules[2].Name)
}

// TestHandleGetStewardModules_InvalidStewardID verifies 400 for a malformed steward ID.
// Dots and colons fail identifierRegex (^[a-zA-Z0-9_-]+$) and are caught by
// the validation middleware, which returns VALIDATION_ERROR.
func TestHandleGetStewardModules_InvalidStewardID(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-modules"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/steward.invalid:id/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleGetStewardModules_InsufficientPermission verifies 403 when the caller
// lacks steward:read-modules permission.
func TestHandleGetStewardModules_InsufficientPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/any-steward/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestHandleGetStewardModules_RejectsCrossTenant verifies HTTP 404 (not 403) when
// the caller's tenant_path is NOT a prefix of the steward's tenant_path.
func TestHandleGetStewardModules_RejectsCrossTenant(t *testing.T) {
	server := setupTestServer(t)
	// Caller is in "other-tenant"; the steward is in "test-tenant".
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-modules"}, "other-tenant", 5*time.Minute)

	// Register a steward under "test-tenant" (the default for registerTestSteward).
	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "cross-tenant-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// Must be 404, not 403, to avoid existence disclosure across tenant boundaries.
	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// ---- handleGetStewardLogs tests (from develop) ----

// TestHandleGetStewardLogs_ReturnsNotImplemented verifies that GET /api/v1/stewards/{id}/logs
// returns 501 with LOGS_UNAVAILABLE error code for a valid steward ID.
func TestHandleGetStewardLogs_ReturnsNotImplemented(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-test-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "LOGS_UNAVAILABLE", body["code"])
}

// TestHandleGetStewardLogs_StewardNotFound verifies that GET /api/v1/stewards/{id}/logs
// returns 404 when the steward ID is not found.
func TestHandleGetStewardLogs_StewardNotFound(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/nonexistent-steward/logs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleGetStewardLogs_InsufficientPermission verifies 403 when the caller
// lacks steward:read-logs permission.
func TestHandleGetStewardLogs_InsufficientPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/any-steward/logs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestHandleGetStewardLogs_InvalidTailParameter verifies 400 for out-of-range tail value.
func TestHandleGetStewardLogs_InvalidTailParameter(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-validation-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?tail=9999", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_PARAMETER", errResp.Error.Code)
}

// TestHandleGetStewardLogs_InvalidSinceParameter verifies 400 for non-parseable duration.
func TestHandleGetStewardLogs_InvalidSinceParameter(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-validation-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?since=notaduration", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_PARAMETER", errResp.Error.Code)
}

// TestHandleGetStewardLogs_InvalidLevelParameter verifies 400 for unknown log level.
func TestHandleGetStewardLogs_InvalidLevelParameter(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-validation-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?level=TRACE", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_PARAMETER", errResp.Error.Code)
}

// TestHandleGetStewardLogs_InvalidModuleParameter verifies 400 for module name exceeding 128 chars.
func TestHandleGetStewardLogs_InvalidModuleParameter(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-validation-host", "os": "linux",
	})

	longModule := strings.Repeat("x", 129)
	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?module="+longModule, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_PARAMETER", errResp.Error.Code)
}

// ---- GET /api/v1/stewards pagination tests (Issue #2489) ----

// listStewardsPage mirrors the paginated envelope returned when limit/offset
// query parameters are present on GET /api/v1/stewards.
type listStewardsPage struct {
	Stewards []StewardInfo `json:"stewards"`
	Total    int           `json:"total"`
	Limit    int           `json:"limit"`
	Offset   int           `json:"offset"`
}

// getStewardsRaw performs GET /api/v1/stewards<query> through the router and
// returns the HTTP status code and raw response body.
func getStewardsRaw(t *testing.T, server *Server, apiKey, query string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/stewards"+query, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// getStewardsPage performs GET /api/v1/stewards<query> and decodes the
// paginated envelope. Fails the test unless the response is HTTP 200.
func getStewardsPage(t *testing.T, server *Server, apiKey, query string) listStewardsPage {
	t.Helper()
	code, body := getStewardsRaw(t, server, apiKey, query)
	require.Equal(t, http.StatusOK, code, "body: %s", body)
	var resp struct {
		Data listStewardsPage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Data
}

// pageIDs extracts the steward IDs from a page in response order.
func pageIDs(page listStewardsPage) []string {
	ids := make([]string, 0, len(page.Stewards))
	for _, s := range page.Stewards {
		ids = append(ids, s.ID)
	}
	return ids
}

// registerNStewards registers n stewards with the given os attribute and
// returns their IDs sorted ascending (the deterministic pagination order).
func registerNStewards(t *testing.T, server *Server, n int, osName string) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := registerTestSteward(t, server.controllerService, map[string]string{
			"hostname": fmt.Sprintf("page-host-%s-%d", osName, i), "os": osName,
		})
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ---- parseStewardPagination unit tests (no server required) ----

func TestParseStewardPagination(t *testing.T) {
	cases := []struct {
		name       string
		query      string
		wantErr    bool
		wantPaged  bool
		wantLimit  int
		wantOffset int
	}{
		{name: "no params", query: "", wantPaged: false},
		{name: "limit and offset", query: "limit=10&offset=5", wantPaged: true, wantLimit: 10, wantOffset: 5},
		{name: "limit without offset implies offset 0", query: "limit=10", wantPaged: true, wantLimit: 10, wantOffset: 0},
		{name: "offset without limit rejected", query: "offset=5", wantErr: true},
		{name: "limit lower boundary", query: "limit=1", wantPaged: true, wantLimit: 1, wantOffset: 0},
		{name: "limit upper boundary", query: "limit=500", wantPaged: true, wantLimit: 500, wantOffset: 0},
		{name: "limit zero rejected", query: "limit=0", wantErr: true},
		{name: "limit above cap rejected", query: "limit=501", wantErr: true},
		{name: "limit non-integer rejected", query: "limit=abc", wantErr: true},
		{name: "offset negative rejected", query: "limit=10&offset=-1", wantErr: true},
		{name: "offset non-integer rejected", query: "limit=10&offset=xyz", wantErr: true},
		{name: "offset zero accepted", query: "limit=10&offset=0", wantPaged: true, wantLimit: 10, wantOffset: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, err := url.ParseQuery(tc.query)
			require.NoError(t, err)
			limit, offset, paginated, perr := parseStewardPagination(q)
			if tc.wantErr {
				require.Error(t, perr)
				return
			}
			require.NoError(t, perr)
			assert.Equal(t, tc.wantPaged, paginated)
			assert.Equal(t, tc.wantLimit, limit)
			assert.Equal(t, tc.wantOffset, offset)
		})
	}
}

// TestParseStewardPagination_ErrorNamesParamNotValue verifies that validation
// error messages reference the parameter name only and never echo the raw
// client-supplied value (no information disclosure).
func TestParseStewardPagination_ErrorNamesParamNotValue(t *testing.T) {
	cases := map[string]string{
		"limit=EVILVALUE1":           "limit",
		"limit=10&offset=EVILVALUE2": "offset",
		"offset=EVILVALUE3":          "offset",
	}
	for query, param := range cases {
		q, err := url.ParseQuery(query)
		require.NoError(t, err)
		_, _, _, perr := parseStewardPagination(q)
		require.Error(t, perr, "query %q must fail validation", query)
		assert.Contains(t, perr.Error(), param, "error must name the offending param for query %q", query)
		assert.NotContains(t, perr.Error(), "EVILVALUE", "error must not echo the raw client value for query %q", query)
	}
}

// ---- HTTP-level pagination tests (filtered path: API-key tenant scope) ----

// TestHandleListStewards_Pagination_PageBoundaries covers first page, mid page,
// last partial page, and offset beyond total, asserting stable ID-sorted order
// and post-filter pre-slice total on every page.
func TestHandleListStewards_Pagination_PageBoundaries(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	sortedIDs := registerNStewards(t, server, 5, "linux")

	t.Run("first page", func(t *testing.T) {
		page := getStewardsPage(t, server, apiKey, "?limit=2&offset=0")
		assert.Equal(t, sortedIDs[0:2], pageIDs(page))
		assert.Equal(t, 5, page.Total)
		assert.Equal(t, 2, page.Limit)
		assert.Equal(t, 0, page.Offset)
	})

	t.Run("mid page", func(t *testing.T) {
		page := getStewardsPage(t, server, apiKey, "?limit=2&offset=2")
		assert.Equal(t, sortedIDs[2:4], pageIDs(page))
		assert.Equal(t, 5, page.Total)
		assert.Equal(t, 2, page.Limit)
		assert.Equal(t, 2, page.Offset)
	})

	t.Run("last partial page", func(t *testing.T) {
		page := getStewardsPage(t, server, apiKey, "?limit=2&offset=4")
		assert.Equal(t, sortedIDs[4:5], pageIDs(page))
		assert.Equal(t, 5, page.Total)
	})

	t.Run("offset beyond total returns empty page with correct total", func(t *testing.T) {
		page := getStewardsPage(t, server, apiKey, "?limit=2&offset=10")
		assert.NotNil(t, page.Stewards)
		assert.Empty(t, page.Stewards)
		assert.Equal(t, 5, page.Total)
		assert.Equal(t, 10, page.Offset)
	})
}

// TestHandleListStewards_Pagination_Deterministic verifies two identical
// requests return identical pages (stable ID sort before slicing).
func TestHandleListStewards_Pagination_Deterministic(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	registerNStewards(t, server, 6, "linux")

	first := getStewardsPage(t, server, apiKey, "?limit=3&offset=2")
	second := getStewardsPage(t, server, apiKey, "?limit=3&offset=2")
	assert.Equal(t, pageIDs(first), pageIDs(second), "identical requests must return identical pages")
	assert.Equal(t, first.Total, second.Total)
}

// TestHandleListStewards_Pagination_WithFilter verifies pagination combined
// with an existing filter param: total reflects the post-filter count
// regardless of page size, and pages contain only matching stewards.
func TestHandleListStewards_Pagination_WithFilter(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	linuxIDs := registerNStewards(t, server, 3, "linux")
	registerNStewards(t, server, 2, "windows")

	pageSmall := getStewardsPage(t, server, apiKey, "?os=linux&limit=1&offset=0")
	require.Len(t, pageSmall.Stewards, 1)
	assert.Equal(t, 3, pageSmall.Total, "total must be the post-filter count")
	assert.Equal(t, linuxIDs[0], pageSmall.Stewards[0].ID)
	assert.Equal(t, "linux", pageSmall.Stewards[0].DNA.OS)

	pageLarge := getStewardsPage(t, server, apiKey, "?os=linux&limit=500&offset=0")
	assert.Equal(t, 3, pageLarge.Total, "total must not vary with page size")
	assert.Equal(t, linuxIDs, pageIDs(pageLarge))
}

// TestHandleListStewards_Pagination_LimitWithoutOffset verifies that limit
// without offset defaults offset to 0 (identical to an explicit offset=0).
func TestHandleListStewards_Pagination_LimitWithoutOffset(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	sortedIDs := registerNStewards(t, server, 4, "linux")

	implicit := getStewardsPage(t, server, apiKey, "?limit=2")
	explicit := getStewardsPage(t, server, apiKey, "?limit=2&offset=0")
	assert.Equal(t, 0, implicit.Offset)
	assert.Equal(t, sortedIDs[0:2], pageIDs(implicit))
	assert.Equal(t, pageIDs(explicit), pageIDs(implicit))
}

// TestHandleListStewards_Pagination_OffsetWithoutLimit_Returns400 verifies
// offset without limit is rejected (ambiguous page size) with a specific
// error code and no steward data in the body.
func TestHandleListStewards_Pagination_OffsetWithoutLimit_Returns400(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	registerNStewards(t, server, 2, "linux")

	code, body := getStewardsRaw(t, server, apiKey, "?offset=1")
	require.Equal(t, http.StatusBadRequest, code)
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(body, &errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "INVALID_PAGINATION", errResp.Error.Code)
	assert.NotContains(t, string(body), "stewards", "error response must carry no data")
}

// TestHandleListStewards_Pagination_InvalidParams_Return400 verifies each
// invalid limit/offset value is rejected with HTTP 400, a specific error
// code, and no steward data. Non-integer and negative values are caught by
// the shared request-validation middleware (pre-existing behavior for all
// endpoints, code VALIDATION_ERROR); values that pass the middleware but
// violate the pinned pagination rules (limit<1, limit>500) are rejected by
// the handler with INVALID_PAGINATION.
func TestHandleListStewards_Pagination_InvalidParams_Return400(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	registerNStewards(t, server, 2, "linux")

	cases := []struct {
		name     string
		query    string
		wantCode string
	}{
		{name: "non-integer limit", query: "?limit=zzevilzz", wantCode: "VALIDATION_ERROR"},
		{name: "limit below minimum", query: "?limit=0", wantCode: "INVALID_PAGINATION"},
		{name: "limit above cap", query: "?limit=501", wantCode: "INVALID_PAGINATION"},
		{name: "negative offset", query: "?limit=10&offset=-1", wantCode: "VALIDATION_ERROR"},
		{name: "non-integer offset", query: "?limit=10&offset=zzevilzz", wantCode: "VALIDATION_ERROR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := getStewardsRaw(t, server, apiKey, tc.query)
			require.Equal(t, http.StatusBadRequest, code)
			var errResp ErrorResponse
			require.NoError(t, json.Unmarshal(body, &errResp))
			require.NotNil(t, errResp.Error)
			assert.Equal(t, tc.wantCode, errResp.Error.Code)
			assert.NotContains(t, string(body), `"stewards"`, "error response must carry no data")
		})
	}
}

// TestHandleListStewards_Pagination_HandlerRejectsInvalidParams exercises the
// handler's own validation directly (bypassing the router middleware, as on
// the unfiltered path): every invalid value returns 400 INVALID_PAGINATION,
// no data, and the error body names the offending param without echoing the
// raw client-supplied value.
func TestHandleListStewards_Pagination_HandlerRejectsInvalidParams(t *testing.T) {
	server := setupTestServer(t)
	require.NoError(t, server.controllerService.RegisterSteward("inv-1", "test-tenant", "addr-1", "registered"))

	cases := []struct {
		name     string
		query    string
		rawValue string // must not appear in the response body
	}{
		{name: "non-integer limit", query: "?limit=zzevilzz", rawValue: "zzevilzz"},
		{name: "limit below minimum", query: "?limit=0", rawValue: ""},
		{name: "limit above cap", query: "?limit=501", rawValue: ""},
		{name: "negative offset", query: "?limit=10&offset=-1", rawValue: ""},
		{name: "non-integer offset", query: "?limit=10&offset=zzevilzz", rawValue: "zzevilzz"},
		{name: "offset without limit", query: "?offset=3", rawValue: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := listStewardsDirect(t, server, tc.query)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			body := rec.Body.String()
			var errResp ErrorResponse
			require.NoError(t, json.Unmarshal([]byte(body), &errResp))
			require.NotNil(t, errResp.Error)
			assert.Equal(t, "INVALID_PAGINATION", errResp.Error.Code)
			assert.NotContains(t, body, `"stewards"`, "error response must carry no data")
			if tc.rawValue != "" {
				assert.NotContains(t, body, tc.rawValue, "error body must not echo the raw client value")
			}
		})
	}
}

// TestHandleListStewards_NoParams_BackwardCompatiblePlainList asserts the
// no-params response keeps the existing shape: data is a plain JSON array of
// stewards (not a pagination envelope) so cfg and existing clients cannot break.
func TestHandleListStewards_NoParams_BackwardCompatiblePlainList(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	sortedIDs := registerNStewards(t, server, 3, "linux")

	code, body := getStewardsRaw(t, server, apiKey, "")
	require.Equal(t, http.StatusOK, code)

	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	trimmed := strings.TrimSpace(string(resp.Data))
	require.True(t, strings.HasPrefix(trimmed, "["), "data must be a plain JSON array, got: %s", trimmed)

	var list []StewardInfo
	require.NoError(t, json.Unmarshal(resp.Data, &list))
	got := make([]string, 0, len(list))
	for _, s := range list {
		got = append(got, s.ID)
	}
	sort.Strings(got)
	assert.Equal(t, sortedIDs, got, "full list must contain every registered steward")
	assert.NotContains(t, string(body), `"total"`, "no-params response must not grow pagination fields")
}

// ---- Unfiltered code path (empty tenant context -> GetAllStewards) ----

// listStewardsDirect invokes handleListStewards directly with an empty tenant
// context so the unfiltered GetAllStewards code path is exercised.
func listStewardsDirect(t *testing.T, server *Server, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/stewards"+query, nil)
	req = withTenant(req, "")
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)
	return rec
}

// TestHandleListStewards_Pagination_UnfilteredPath verifies pagination is
// applied on the unfiltered GetAllStewards path with deterministic ID order
// and post-slice total.
func TestHandleListStewards_Pagination_UnfilteredPath(t *testing.T) {
	server := setupTestServer(t)
	for _, id := range []string{"pg-c", "pg-a", "pg-b"} {
		require.NoError(t, server.controllerService.RegisterSteward(id, "test-tenant", "addr-"+id, "registered"))
	}

	rec := listStewardsDirect(t, server, "?limit=2&offset=1")
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data listStewardsPage `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, []string{"pg-b", "pg-c"}, pageIDs(resp.Data), "page must be ID-sorted before slicing")
	assert.Equal(t, 3, resp.Data.Total)
	assert.Equal(t, 2, resp.Data.Limit)
	assert.Equal(t, 1, resp.Data.Offset)
}

// TestHandleListStewards_UnfilteredPath_NoParams_PlainList verifies the
// unfiltered path keeps the plain-array payload when no pagination params
// are supplied.
func TestHandleListStewards_UnfilteredPath_NoParams_PlainList(t *testing.T) {
	server := setupTestServer(t)
	require.NoError(t, server.controllerService.RegisterSteward("plain-1", "test-tenant", "addr-1", "registered"))

	rec := listStewardsDirect(t, server, "")
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	trimmed := strings.TrimSpace(string(resp.Data))
	assert.True(t, strings.HasPrefix(trimmed, "["), "unfiltered no-params data must be a plain JSON array, got: %s", trimmed)
}

// TestHandleCreateAPIKey_AcceptsStewardReadLogs verifies that steward:read-logs is a
// registered permission and can be granted via handleCreateAPIKey. Without this entry in
// knownPermissions, operators cannot mint keys that reach the logs endpoint.
func TestHandleCreateAPIKey_AcceptsStewardReadLogs(t *testing.T) {
	server := setupTestServer(t)

	// Call handleCreateAPIKey directly with the steward:read-logs permission.
	body := []byte(`{"name":"logs-key","permissions":["steward:read-logs"]}`)
	req := httptest.NewRequest("POST", "/api/v1/api-keys", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := req.Context()
	ctx = context.WithValue(ctx, ctxkeys.TenantID, "test-tenant")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleCreateAPIKey(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code, "steward:read-logs must be a known permission")
}
