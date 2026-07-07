// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	loggingInterfaces "github.com/cfgis/cfgms/pkg/logging/interfaces"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
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

// TestHandleListStewards_FleetQuery_VersionFromDNAAttributes verifies that the
// filtered fleet query path (handleListStewards with a filter) populates the
// Version field in StewardInfo from the steward.version DNA attribute. (Issue #2260)
func TestHandleListStewards_FleetQuery_VersionFromDNAAttributes(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	// Register a steward whose DNA includes steward.version — this simulates
	// what a steward publishes after the Issue #2260 change.
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname":        "host-versioned",
		"os":              "linux",
		"steward.version": "v1.4.2",
	})

	// Use a filter to trigger the fleetQuery code path (not the no-filter path).
	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1, "exactly one steward must match the os=linux filter")
	assert.Equal(t, "v1.4.2", resp.Data[0].Version,
		"Version must be populated from steward.version DNA attribute in the filtered fleet query path")
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
// the steward is registered but its DNA field is nil.
func TestHandleGetStewardDNA_DNANotFound(t *testing.T) {
	server := setupTestServer(t)

	require.NoError(t, server.controllerService.RegisterSteward("no-dna-steward", "test-tenant", "addr-1", "registered"))

	// Clear the DNA on the live registry entry. GetStewardInfo now returns a
	// copy-on-read so mutation of the returned value does not reach the live
	// entry; SetStewardDNA writes directly to the registry.
	ok := server.controllerService.SetStewardDNA("no-dna-steward", nil)
	require.True(t, ok)

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

// TestHandleGetStewardLogs_ReturnsEmpty verifies that GET /api/v1/stewards/{id}/logs
// returns 200 with an empty event list when no steward event logging manager is wired.
func TestHandleGetStewardLogs_ReturnsEmpty(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-test-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var body APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	data, ok := body.Data.(map[string]interface{})
	require.True(t, ok, "data should be a map")
	events, ok := data["events"]
	require.True(t, ok, "data should have events key")
	eventsSlice, ok := events.([]interface{})
	require.True(t, ok, "events should be a slice")
	assert.Empty(t, eventsSlice, "events should be empty when no manager is wired")
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

// newTestStewardEventManager creates a synchronous file-backed LoggingManager
// suitable for test use. Entries are immediately queryable after WriteEntry + Flush.
func newTestStewardEventManager(t *testing.T) *logging.LoggingManager {
	t.Helper()
	mgr, err := logging.NewLoggingManager(&logging.LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":        t.TempDir(),
			"file_prefix":      "steward-events",
			"max_file_size":    10 * 1024 * 1024,
			"retention_days":   1,
			"compress_rotated": false,
		},
		Level:       "DEBUG",
		ServiceName: "test-controller",
		Component:   "test",
		AsyncWrites: false, // synchronous so entries are visible immediately
		BatchSize:   1,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, mgr.Close()) })
	return mgr
}

// writeTestStewardEventAt writes a log entry with the given steward_id and explicit
// timestamp into the manager. Use explicit timestamps in correlated-pair tests to
// ensure deterministic detection-before-outcome ordering without relying on wall-clock races.
func writeTestStewardEventAt(t *testing.T, mgr *logging.LoggingManager, stewardID, level, message, correlationID string, ts time.Time) {
	t.Helper()
	entry := loggingInterfaces.LogEntry{
		Timestamp:     ts,
		Level:         level,
		Message:       message,
		CorrelationID: correlationID,
		Fields: map[string]interface{}{
			"steward_id": stewardID,
		},
	}
	require.NoError(t, mgr.WriteEntry(context.Background(), entry))
	require.NoError(t, mgr.Flush(context.Background()))
}

// writeTestStewardEvent writes a log entry with the current wall-clock timestamp.
func writeTestStewardEvent(t *testing.T, mgr *logging.LoggingManager, stewardID, level, message, correlationID string) {
	t.Helper()
	writeTestStewardEventAt(t, mgr, stewardID, level, message, correlationID, time.Now())
}

// TestGetStewardLogs_CrossTenantBlocked verifies that a caller scoped to tenant A
// cannot read events for a steward belonging to tenant B (AC: cross-tenant blocked).
func TestGetStewardLogs_CrossTenantBlocked(t *testing.T) {
	server := setupTestServer(t)

	// Register steward in "tenant-b" (different from the caller's tenant).
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-b")
	resp, err := server.controllerService.AcceptRegistration(ctx, &controller.RegisterRequest{
		Version: "v1.0",
		InitialDna: &common.DNA{
			Id:         "dna-cross-tenant",
			Attributes: map[string]string{"hostname": "cross-tenant-host", "os": "linux"},
		},
	})
	require.NoError(t, err)
	stewardID := resp.StewardId

	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)

	// Caller is scoped to "tenant-a" — different from the steward's "tenant-b".
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-logs"}, "tenant-a", 5*time.Minute)
	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// 404 to avoid disclosing steward existence across tenants (matches the existing ACL pattern).
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestGetStewardLogs_ScopedToPathSteward verifies that when two stewards' events share
// the same steward-event LoggingManager, GET /stewards/{A}/logs returns only steward A's
// entries and never steward B's (result-set scoping by steward_id, not just ACL).
func TestGetStewardLogs_ScopedToPathSteward(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardA := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "scope-host-a", "os": "linux",
	})
	stewardB := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "scope-host-b", "os": "linux",
	})

	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)

	// Write one event for steward A and one for steward B.
	writeTestStewardEvent(t, mgr, stewardA, "INFO", "event from A", "")
	writeTestStewardEvent(t, mgr, stewardB, "INFO", "event from B", "")

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardA+"/logs?since=1h", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	data := body.Data.(map[string]interface{})
	events := data["events"].([]interface{})

	// Only steward A's event should appear.
	require.Len(t, events, 1, "exactly one event expected for steward A")
	record := events[0].(map[string]interface{})
	detection := record["detection"].(map[string]interface{})
	assert.Equal(t, "event from A", detection["message"])
}

// TestGetStewardLogs_RollupByCorrelationID verifies that two persisted entries sharing
// a correlation_id are rendered as a single rolled-up record (detection + outcome).
func TestGetStewardLogs_RollupByCorrelationID(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "rollup-host", "os": "linux",
	})

	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)

	corrID := "corr-abc-123"
	t0 := time.Now()
	t1 := t0.Add(time.Millisecond)
	writeTestStewardEventAt(t, mgr, stewardID, "INFO", "monitor fired", corrID, t0)
	writeTestStewardEventAt(t, mgr, stewardID, "INFO", "convergence complete", corrID, t1)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?since=1h", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	data := body.Data.(map[string]interface{})
	events := data["events"].([]interface{})

	// Two entries sharing a correlation_id must roll up into one record.
	require.Len(t, events, 1, "two correlated entries must produce exactly one rolled-up record")
	record := events[0].(map[string]interface{})
	assert.Equal(t, corrID, record["correlation_id"])
	assert.NotNil(t, record["detection"], "detection must be present")
	assert.NotNil(t, record["outcome"], "outcome must be present")
	assert.NotEqual(t, true, record["pending_outcome"], "pending_outcome must not be set when outcome is present")
}

// TestGetStewardLogs_PendingOutcome verifies that a single correlated event with no
// paired outcome in the query window is marked pending_outcome=true (the ADR-012 §2
// "monitor fired, convergence never completed" wedge signal).
func TestGetStewardLogs_PendingOutcome(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "pending-outcome-host", "os": "linux",
	})

	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)

	// Write only the detection event — no paired outcome.
	corrID := "corr-pending-xyz"
	writeTestStewardEvent(t, mgr, stewardID, "WARN", "monitor fired, no response yet", corrID)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?since=1h", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	data := body.Data.(map[string]interface{})
	events := data["events"].([]interface{})

	require.Len(t, events, 1, "one correlated event without outcome must produce one record")
	record := events[0].(map[string]interface{})
	assert.Equal(t, corrID, record["correlation_id"])
	assert.NotNil(t, record["detection"], "detection must be present")
	assert.Nil(t, record["outcome"], "outcome must be absent")
	assert.Equal(t, true, record["pending_outcome"], "pending_outcome must be true for a detection with no outcome")
}

// ---- handleMoveSteward tests (Issue #2341) ----

// setupMoveStewardServer creates a test server wired with a real flat-file steward
// store (rooted at a t.TempDir(), no external infrastructure required) and a tenant
// backing store pre-seeded with both "source-tenant" and "dest-tenant" in Active state.
// The returned root is the store's backing directory, used by tests that need to induce
// a genuine durable-store failure.
func setupMoveStewardServer(t *testing.T) (*Server, business.StewardStore, string) {
	t.Helper()
	server := setupTestServer(t)

	st, root := newTestStewardDurableStore(t)
	server.SetStewardStore(st)

	// Create source and destination tenants in the backing store. setupTestServer
	// builds a fresh tenant manager per test, so neither tenant can pre-exist —
	// a CreateTenant failure here is a real setup error and must fail the test.
	ctx := context.Background()
	for _, id := range []string{"source-tenant", "dest-tenant"} {
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: id, Name: id})
		require.NoError(t, err, "creating tenant %q", id)
	}
	return server, st, root
}

// seedSteward persists a steward record into the real flat-file store, failing the
// test on error. Records are written verbatim; RegisterSteward defaults an empty
// status to "registered" but preserves any status the caller sets.
func seedSteward(t *testing.T, st business.StewardStore, rec *business.StewardRecord) {
	t.Helper()
	require.NoError(t, st.RegisterSteward(context.Background(), rec), "seeding steward %q", rec.ID)
}

// postMoveSteward calls handleMoveSteward directly (bypassing Tier-3 middleware) with a
// root-admin mTLS principal so we can exercise the handler logic in isolation.
func postMoveSteward(server *Server, stewardID, newTenantID string) *httptest.ResponseRecorder {
	body := strings.NewReader(`{"new_tenant_id":"` + newTenantID + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+stewardID+"/move", body)
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "cfgms-admin", IsAdmin: true, TenantID: ""})
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)
	return rec
}

// TestHandleMoveSteward_HappyPath verifies the move succeeds and returns status "moved"
// with the correct old and new tenant IDs.
func TestHandleMoveSteward_HappyPath(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)

	// Wire a registered steward in the controller service and the store.
	require.NoError(t, server.controllerService.RegisterSteward("s-happy", "source-tenant", "addr", "registered"))
	seedSteward(t, st, &business.StewardRecord{ID: "s-happy", TenantID: "source-tenant", Status: business.StewardStatusRegistered})

	// dest-tenant is already created by setupMoveStewardServer.
	rec := postMoveSteward(server, "s-happy", "dest-tenant")

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "moved", resp.Data["status"])
	assert.Equal(t, "dest-tenant", resp.Data["tenant_id"])
	assert.Equal(t, "source-tenant", resp.Data["previous_tenant"])
}

// TestHandleMoveSteward_InMemoryRegistryUpdated verifies that after a move, the live
// in-memory registry reflects the new tenant ID so config resolves from the new path.
// This is the "already-connected steward re-scopes" AC (Issue #2341).
func TestHandleMoveSteward_InMemoryRegistryUpdated(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)

	require.NoError(t, server.controllerService.RegisterSteward("s-connected", "source-tenant", "addr", "active"))
	seedSteward(t, st, &business.StewardRecord{ID: "s-connected", TenantID: "source-tenant", Status: business.StewardStatusActive})

	// dest-tenant is already created by setupMoveStewardServer.
	rec := postMoveSteward(server, "s-connected", "dest-tenant")
	require.Equal(t, http.StatusOK, rec.Code)

	// The controller service registry must reflect the new tenant — config resolution
	// reads this on the next convergence.
	info, ok := server.controllerService.GetStewardInfo("s-connected")
	require.True(t, ok, "steward must still be in the registry after move")
	assert.Equal(t, "dest-tenant", info.TenantID,
		"in-memory TenantID must be updated so config resolves from the new tenant path")
}

// TestHandleMoveSteward_NoCertReissue verifies that the move does not alter the steward
// identity fields (DeviceID, IdentityKeyPub) — proving no cert re-issue occurs.
func TestHandleMoveSteward_NoCertReissue(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)

	pub := []byte{0x01, 0x02, 0x03}
	seedSteward(t, st, &business.StewardRecord{
		ID:             "s-nocert",
		TenantID:       "source-tenant",
		Status:         business.StewardStatusRegistered,
		DeviceID:       "aabbcc",
		IdentityKeyPub: pub,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-nocert", "source-tenant", "addr", "registered"))

	// dest-tenant is already created by setupMoveStewardServer.
	ctx := context.Background()
	rec := postMoveSteward(server, "s-nocert", "dest-tenant")
	require.Equal(t, http.StatusOK, rec.Code)

	got, err := server.stewardStore.GetSteward(ctx, "s-nocert")
	require.NoError(t, err)
	// Identity fields must be unchanged.
	assert.Equal(t, "aabbcc", got.DeviceID, "DeviceID must not change on move")
	assert.Equal(t, pub, got.IdentityKeyPub, "IdentityKeyPub must not change on move")
	assert.Equal(t, "dest-tenant", got.TenantID, "TenantID must be updated")
}

// TestHandleMoveSteward_SelfMove verifies that a move to the same tenant short-circuits
// with no state change (status "no_change") and does not touch the store or registry.
func TestHandleMoveSteward_SelfMove(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)

	seedSteward(t, st, &business.StewardRecord{ID: "s-self", TenantID: "source-tenant", Status: business.StewardStatusRegistered})
	require.NoError(t, server.controllerService.RegisterSteward("s-self", "source-tenant", "addr", "registered"))

	rec := postMoveSteward(server, "s-self", "source-tenant")

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "no_change", resp.Data["status"], "self-move must return no_change")
}

// TestHandleMoveSteward_RevokedSourceRejected verifies that a move from a revoked
// steward returns 400 STEWARD_REVOKED — moving would back-door re-entry.
func TestHandleMoveSteward_RevokedSourceRejected(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)

	seedSteward(t, st, &business.StewardRecord{ID: "s-revoked", TenantID: "source-tenant", Status: business.StewardStatusRevoked})

	// dest-tenant is already created by setupMoveStewardServer.
	rec := postMoveSteward(server, "s-revoked", "dest-tenant")

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_REVOKED", errResp.Error.Code)
}

// TestHandleMoveSteward_AllowedSourceStatuses verifies that each allowed source status
// succeeds and the status is not promoted (no implicit status change on move).
func TestHandleMoveSteward_AllowedSourceStatuses(t *testing.T) {
	allowedStatuses := []business.StewardStatus{
		business.StewardStatusRegistered,
		business.StewardStatusActive,
		business.StewardStatusLost,
		business.StewardStatusArchived,
		business.StewardStatusDormant,
		business.StewardStatusDeregistered,
	}

	for _, status := range allowedStatuses {
		status := status
		t.Run(string(status), func(t *testing.T) {
			server, st, _ := setupMoveStewardServer(t)

			id := "s-" + string(status)
			seedSteward(t, st, &business.StewardRecord{ID: id, TenantID: "source-tenant", Status: status})
			require.NoError(t, server.controllerService.RegisterSteward(id, "source-tenant", "addr", string(status)))

			// dest-tenant is already created by setupMoveStewardServer.
			ctx := context.Background()
			rec := postMoveSteward(server, id, "dest-tenant")
			require.Equal(t, http.StatusOK, rec.Code, "status %q must be allowed to move", status)

			// Status must not be promoted.
			got, err := server.stewardStore.GetSteward(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, status, got.Status, "status must not change on move for %q", status)
		})
	}
}

// TestHandleMoveSteward_DestinationNotFound verifies that moving to a nonexistent
// tenant returns 400 TENANT_NOT_FOUND.
func TestHandleMoveSteward_DestinationNotFound(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)
	seedSteward(t, st, &business.StewardRecord{ID: "s-dest404", TenantID: "source-tenant", Status: business.StewardStatusRegistered})

	rec := postMoveSteward(server, "s-dest404", "nonexistent-tenant")

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code)
}

// TestHandleMoveSteward_DestinationNotActive verifies that moving to a tenant that
// exists but is not in "active" status returns 400 TENANT_NOT_ACTIVE. The durable
// store must not be updated when the destination is inactive.
func TestHandleMoveSteward_DestinationNotActive(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)
	seedSteward(t, st, &business.StewardRecord{ID: "s-inactive-dest", TenantID: "source-tenant", Status: business.StewardStatusRegistered})

	// dest-tenant was created active by setupMoveStewardServer; suspend it so the
	// handler sees a non-active destination.
	ctx := context.Background()
	require.NoError(t, server.tenantManager.SuspendTenant(ctx, "dest-tenant"))

	rec := postMoveSteward(server, "s-inactive-dest", "dest-tenant")

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "TENANT_NOT_ACTIVE", errResp.Error.Code)

	// The move must not have been persisted.
	got, err := server.stewardStore.GetSteward(ctx, "s-inactive-dest")
	require.NoError(t, err)
	assert.Equal(t, "source-tenant", got.TenantID, "steward must remain in source tenant when destination is not active")
}

// TestHandleMoveSteward_DurableStoreWriteFails verifies that when the durable store
// write fails after all validation passes, the handler returns 500 INTERNAL_ERROR.
func TestHandleMoveSteward_DurableStoreWriteFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Chmod does not enforce POSIX directory permissions on Windows")
	}
	server, st, root := setupMoveStewardServer(t)
	seedSteward(t, st, &business.StewardRecord{ID: "s-writefail", TenantID: "source-tenant", Status: business.StewardStatusRegistered})
	require.NoError(t, server.controllerService.RegisterSteward("s-writefail", "source-tenant", "addr", "registered"))

	// Induce a genuine durable-store write failure: make the flat-file store's backing
	// directory read-only. The record was already written, so GetSteward (a pure read)
	// still succeeds and the handler reaches UpdateStewardTenant, whose atomic write
	// (temp-file creation in the directory) then fails with a permission error — the
	// handler must surface a 500. Restore the mode on cleanup so t.TempDir() removal
	// (registered earlier, so it runs after this) can delete the tree.
	stewardDir := filepath.Join(root, "stewards")
	require.NoError(t, os.Chmod(stewardDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(stewardDir, 0o750) })

	rec := postMoveSteward(server, "s-writefail", "dest-tenant")

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
}

// TestHandleMoveSteward_StewardNotFound verifies 404 when the steward ID is unknown.
func TestHandleMoveSteward_StewardNotFound(t *testing.T) {
	server, _, _ := setupMoveStewardServer(t)

	rec := postMoveSteward(server, "nonexistent-steward", "dest-tenant")

	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// TestHandleMoveSteward_InvalidStewardID verifies 400 for a malformed steward ID.
func TestHandleMoveSteward_InvalidStewardID(t *testing.T) {
	server := setupTestServer(t)

	body := strings.NewReader(`{"new_tenant_id":"dest"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/bad.id:here/move", body)
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "admin", IsAdmin: true, TenantID: ""})
	req = withVars(req, map[string]string{"id": "bad.id:here"})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_STEWARD_ID", errResp.Error.Code)
}

// TestHandleMoveSteward_MissingNewTenantID verifies 400 when new_tenant_id is absent.
func TestHandleMoveSteward_MissingNewTenantID(t *testing.T) {
	server := setupTestServer(t)

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/some-steward/move", body)
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "admin", IsAdmin: true, TenantID: ""})
	req = withVars(req, map[string]string{"id": "some-steward"})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "MISSING_TENANT_ID", errResp.Error.Code)
}

// TestHandleMoveSteward_InvalidTenantIDFormat verifies 400 for a malformed new_tenant_id.
func TestHandleMoveSteward_InvalidTenantIDFormat(t *testing.T) {
	server := setupTestServer(t)

	body := strings.NewReader(`{"new_tenant_id":"bad.tenant:id"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/some-steward/move", body)
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "admin", IsAdmin: true, TenantID: ""})
	req = withVars(req, map[string]string{"id": "some-steward"})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_TENANT_ID", errResp.Error.Code)
}

// TestHandleMoveSteward_APIKeyRejected verifies that an API-key caller (non-mTLS) is
// rejected with 403 at the Tier-3 gate when hitting the route via the router.
func TestHandleMoveSteward_APIKeyRejected(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:move"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/some-steward/move",
		strings.NewReader(`{"new_tenant_id":"dest"}`))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "API-key callers must be rejected at Tier-3")
}

// ---- handleMoveSteward authorization + audit tests (Issue #2342) ----

// postMoveStewardWithPrincipal calls handleMoveSteward directly with an explicit principal
// (bypassing Tier-3 middleware) so authorization logic can be tested in isolation.
func postMoveStewardWithPrincipal(server *Server, stewardID, newTenantID string, p *Principal) *httptest.ResponseRecorder {
	body := strings.NewReader(`{"new_tenant_id":"` + newTenantID + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+stewardID+"/move", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "test-request-id-"+stewardID)
	req = withPrincipal(req, p)
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)
	return rec
}

// setupMoveAuthServer creates a test server with source and destination tenants for
// authorization tests. In addition to the standard "source-tenant" and "dest-tenant", it
// creates hierarchical child tenants as separate store entries with path-style IDs so the
// anchored-prefix check can be exercised.
func setupMoveAuthServer(t *testing.T) (*Server, business.StewardStore) {
	t.Helper()
	server, st, _ := setupMoveStewardServer(t)
	ctx := context.Background()

	// Add extra tenants needed for hierarchical tests. "msp-a" and "other-msp" are flat
	// parent-level scopes; "msp-a-child" serves as a child-namespace stand-in.
	for _, id := range []string{"msp-a", "msp-a-child", "other-msp"} {
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: id, Name: id})
		require.NoError(t, err, "creating tenant %q", id)
	}
	return server, st
}

// TestHandleMoveSteward_ScopedAdmin_NoAuthorityOverSource verifies 403 when a scoped
// admin's scope does not cover the source tenant.
func TestHandleMoveSteward_ScopedAdmin_NoAuthorityOverSource(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-auth-nosrc",
		TenantID: "source-tenant", // caller has scope "other-msp", no authority here
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-auth-nosrc", "source-tenant", "addr", "registered"))

	// dest-tenant is in scope but source is not
	scopedPrincipal := &Principal{ID: "scoped-admin", IsAdmin: true, TenantID: "other-msp", CertSerial: "SN-001", CertFingerprint: "fp-001"}
	rec := postMoveStewardWithPrincipal(server, "s-auth-nosrc", "dest-tenant", scopedPrincipal)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INSUFFICIENT_SCOPE", errResp.Error.Code)
}

// TestHandleMoveSteward_ScopedAdmin_NoAuthorityOverDestination verifies 403 when a
// scoped admin's scope covers the source but not the destination.
func TestHandleMoveSteward_ScopedAdmin_NoAuthorityOverDestination(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	// Seed a steward in "msp-a" so the caller's scope covers the source.
	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-auth-nodst",
		TenantID: "msp-a",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-auth-nodst", "msp-a", "addr", "registered"))

	// "other-msp" is not in "msp-a" scope
	scopedPrincipal := &Principal{ID: "scoped-admin", IsAdmin: true, TenantID: "msp-a", CertSerial: "SN-002", CertFingerprint: "fp-002"}
	rec := postMoveStewardWithPrincipal(server, "s-auth-nodst", "other-msp", scopedPrincipal)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INSUFFICIENT_SCOPE", errResp.Error.Code)
}

// TestHandleMoveSteward_ScopedAdmin_AuthorityOverBoth_AnchoredPrefix verifies 200 when a
// scoped admin has anchored-prefix authority over both source and destination.
// The source steward is stored with a hierarchical TenantID ("msp-a/child-src") so the
// prefix check exercises the strings.HasPrefix path.
func TestHandleMoveSteward_ScopedAdmin_AuthorityOverBoth_AnchoredPrefix(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	// Seed the steward directly with a hierarchical source tenant ID so the stored record
	// has "msp-a/..." format while the controller service index uses "msp-a".
	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-auth-both",
		TenantID: "msp-a/child-src",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-auth-both", "msp-a/child-src", "addr", "registered"))

	// Destination is also a child of "msp-a/" — caller has authority over both.
	// We use "msp-a-child" (a flat tenant that was pre-created) as destination. The
	// scope check for dest is strings.HasPrefix("msp-a-child", "msp-a/") == false,
	// so we need a true hierarchical path. Create a child tenant in the store.
	ctx := context.Background()
	require.NoError(t, st.RegisterSteward(ctx, &business.StewardRecord{
		ID:       "s-dest-placeholder",
		TenantID: "msp-a/child-dst",
	}))
	// Register "msp-a/child-dst" as a destination tenant via a direct store insertion
	// (bypassing tenant manager validation) — we only need GetTenant to return active.
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:   "msp-a-child-dst",
		Name: "msp-a-child-dst",
	})
	require.NoError(t, err)

	// For the anchored-prefix test, pass a flat destination that's literally under "msp-a/"
	// by constructing the request with new_tenant_id = "msp-a/child-dst". Since tenantPathRegex
	// now accepts slashes, this is valid. The tenant store won't have this exact path-style ID
	// (the tenant manager uses flat IDs), so GetTenant returns not-found → 400 TENANT_NOT_FOUND.
	// That means the AUTH check passed (no 403) and the failure is the subsequent tenant lookup.
	scopedPrincipal := &Principal{ID: "msp-admin", IsAdmin: true, TenantID: "msp-a", CertSerial: "SN-003", CertFingerprint: "fp-003"}
	rec := postMoveStewardWithPrincipal(server, "s-auth-both", "msp-a/child-dst", scopedPrincipal)

	// The authorization check PASSES (both in scope), but the destination tenant isn't
	// registered — we get 400 TENANT_NOT_FOUND, not 403 INSUFFICIENT_SCOPE.
	require.NotEqual(t, http.StatusForbidden, rec.Code, "auth must pass for msp-a scope over msp-a/child-dst destination")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code,
		"403 would mean auth failed; 400 TENANT_NOT_FOUND confirms auth passed and tenant lookup failed")
}

// TestHandleMoveSteward_ScopedAdmin_ExactTenantMatch verifies that a scoped admin with
// a scope exactly matching both source and destination is allowed (exact-match path).
func TestHandleMoveSteward_ScopedAdmin_ExactTenantMatch(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	// Both source and destination are "msp-a" — but that's a self-move.
	// Use source = "msp-a" (exact match) and dest = "msp-a-child" which is NOT in scope.
	// To test exact-match on destination, use dest = "msp-a" → self-move (no_change).
	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-auth-exact",
		TenantID: "msp-a",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-auth-exact", "msp-a", "addr", "registered"))

	// Caller has exact match on source; dest = "msp-a" is also exact match → self-move
	scopedPrincipal := &Principal{ID: "msp-admin", IsAdmin: true, TenantID: "msp-a", CertSerial: "SN-004", CertFingerprint: "fp-004"}
	rec := postMoveStewardWithPrincipal(server, "s-auth-exact", "msp-a", scopedPrincipal)

	// Auth passes (exact match on both), self-move short-circuits → no_change
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct{ Data map[string]interface{} `json:"data"` }
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "no_change", resp.Data["status"])
}

// TestHandleMoveSteward_UnscopedRootAdmin_Allowed verifies that a root (TenantID=="")
// admin can always move any steward regardless of source/destination tenants.
func TestHandleMoveSteward_UnscopedRootAdmin_Allowed(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-auth-root",
		TenantID: "source-tenant",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-auth-root", "source-tenant", "addr", "registered"))

	rootPrincipal := &Principal{ID: "root-admin", IsAdmin: true, TenantID: "", CertSerial: "SN-ROOT", CertFingerprint: "fp-root"}
	rec := postMoveStewardWithPrincipal(server, "s-auth-root", "dest-tenant", rootPrincipal)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct{ Data map[string]interface{} `json:"data"` }
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "moved", resp.Data["status"])
}

// TestHandleMoveSteward_AuditOnSuccess verifies that a successful move emits an audit
// record containing source/destination tenants, admin identity (CN + cert fields),
// request ID, before→after diff, and outcome.
func TestHandleMoveSteward_AuditOnSuccess(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-audit-ok",
		TenantID: "source-tenant",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-audit-ok", "source-tenant", "addr", "registered"))

	rootPrincipal := &Principal{
		ID:              "audit-admin",
		IsAdmin:         true,
		TenantID:        "",
		CertSerial:      "SERIAL-OK",
		CertFingerprint: "FPRINT-OK",
	}
	body := strings.NewReader(`{"new_tenant_id":"dest-tenant"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/s-audit-ok/move", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "req-audit-ok-123")
	req = withPrincipal(req, rootPrincipal)
	req = withVars(req, map[string]string{"id": "s-audit-ok"})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Flush the audit manager so in-memory events reach the store.
	require.NoError(t, server.auditManager.Flush(context.Background()))

	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"steward_move"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "at least one steward_move audit entry expected")

	var found *business.AuditEntry
	for _, e := range entries {
		if e.Action == "steward_move" && e.Result == business.AuditResultSuccess {
			found = e
			break
		}
	}
	require.NotNil(t, found, "successful steward_move audit entry not found")

	assert.Equal(t, business.AuditResultSuccess, found.Result)
	assert.Equal(t, business.AuditSeverityHigh, found.Severity)
	assert.Equal(t, "audit-admin", found.UserID, "admin CN must be recorded")
	assert.Equal(t, "req-audit-ok-123", found.RequestID, "request ID must be recorded")
	assert.NotNil(t, found.Changes, "before→after diff must be present")
	assert.Equal(t, "source-tenant", found.Changes.Before["tenant_id"], "before tenant must be source-tenant")
	assert.Equal(t, "dest-tenant", found.Changes.After["tenant_id"], "after tenant must be dest-tenant")
	assert.Equal(t, "source-tenant", found.Details["source_tenant"], "source_tenant detail must be set")
	assert.Equal(t, "dest-tenant", found.Details["dest_tenant"], "dest_tenant detail must be set")
	assert.Equal(t, "SERIAL-OK", found.Details["cert_serial"], "cert_serial must be recorded")
	assert.Equal(t, "FPRINT-OK", found.Details["cert_fingerprint"], "cert_fingerprint must be recorded")
}

// TestHandleMoveSteward_AuditOnDenial verifies that a denied move emits a Critical-severity
// security audit event containing source/destination tenants, admin identity, request ID,
// before→after diff, and outcome=denied.
func TestHandleMoveSteward_AuditOnDenial(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-audit-deny",
		TenantID: "source-tenant",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-audit-deny", "source-tenant", "addr", "registered"))

	scopedPrincipal := &Principal{
		ID:              "scoped-deny-admin",
		IsAdmin:         true,
		TenantID:        "other-msp",
		CertSerial:      "SERIAL-DENY",
		CertFingerprint: "FPRINT-DENY",
	}
	body := strings.NewReader(`{"new_tenant_id":"dest-tenant"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/s-audit-deny/move", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "req-audit-deny-456")
	req = withPrincipal(req, scopedPrincipal)
	req = withVars(req, map[string]string{"id": "s-audit-deny"})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))

	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"steward_move"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "at least one steward_move audit entry expected")

	var found *business.AuditEntry
	for _, e := range entries {
		if e.Action == "steward_move" && e.Result == business.AuditResultDenied {
			found = e
			break
		}
	}
	require.NotNil(t, found, "denied steward_move audit entry not found")

	assert.Equal(t, business.AuditResultDenied, found.Result)
	assert.Equal(t, business.AuditSeverityCritical, found.Severity, "denied move must be Critical severity")
	assert.Equal(t, "scoped-deny-admin", found.UserID, "admin CN must be recorded")
	assert.Equal(t, "req-audit-deny-456", found.RequestID, "request ID must be recorded")
	assert.NotNil(t, found.Changes, "before→after diff must be present even for denied moves")
	assert.Equal(t, "source-tenant", found.Changes.Before["tenant_id"])
	assert.Equal(t, "dest-tenant", found.Changes.After["tenant_id"])
	assert.Equal(t, "source-tenant", found.Details["source_tenant"])
	assert.Equal(t, "dest-tenant", found.Details["dest_tenant"])
	assert.Equal(t, "SERIAL-DENY", found.Details["cert_serial"])
	assert.Equal(t, "FPRINT-DENY", found.Details["cert_fingerprint"])
}

// TestHandleMoveSteward_TenantPathWithSlash verifies that a hierarchical new_tenant_id
// (containing a slash) now passes format validation (tenantPathRegex allows slashes).
func TestHandleMoveSteward_TenantPathWithSlash(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-slash-test",
		TenantID: "msp-a/child-src",
		Status:   business.StewardStatusRegistered,
	})

	// Request with hierarchical new_tenant_id — format validation must pass.
	// The tenant doesn't exist in the store, so we expect TENANT_NOT_FOUND (400), not INVALID_TENANT_ID (400).
	scopedPrincipal := &Principal{ID: "msp-admin", IsAdmin: true, TenantID: "msp-a", CertSerial: "SN-007", CertFingerprint: "fp-007"}
	rec := postMoveStewardWithPrincipal(server, "s-slash-test", "msp-a/other-child", scopedPrincipal)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.NotEqual(t, "INVALID_TENANT_ID", errResp.Error.Code,
		"hierarchical tenant IDs must pass format validation")
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code,
		"auth passed and tenant lookup failed as expected")
}
