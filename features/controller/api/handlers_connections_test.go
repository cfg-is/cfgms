// SPDX-License-Identifier: AGPL-3.0-only
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

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// registerTestConnection registers a live StewardConnection in reg for the given steward ID.
// ConnectedAt and RemoteAddr are populated so response fields can be asserted.
func registerTestConnection(t *testing.T, reg *registry.InMemoryRegistry, stewardID string) {
	t.Helper()
	require.NoError(t, reg.Register(&registry.StewardConnection{
		StewardID:   stewardID,
		Sender:      &noopSender{},
		ConnectedAt: time.Now().UTC().Truncate(time.Second),
		RemoteAddr:  "10.0.0.1:12345",
	}))
}

// registerStewardUnderTenant registers a steward in the controller service scoped
// to a specific tenant. Mirrors registerTestSteward but accepts an explicit tenantID.
func registerStewardUnderTenant(t *testing.T, server *Server, tenantID, hostname string) string {
	t.Helper()
	req := &controller.RegisterRequest{
		Version: "v1.0",
		InitialDna: &common.DNA{
			Id:         "dna-" + hostname,
			Attributes: map[string]string{"hostname": hostname, "os": "linux"},
		},
	}
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, tenantID)
	resp, err := server.controllerService.AcceptRegistration(ctx, req)
	require.NoError(t, err)
	return resp.StewardId
}

// ---- handleGetStewardConnection tests ----

func TestHandleGetStewardConnection_Connected(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "connected-host", "os": "linux",
	})

	reg := registry.NewRegistry()
	registerTestConnection(t, reg, stewardID)
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/connection", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardConnectionDetail `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.StewardID)
	assert.True(t, resp.Data.Connected)
	require.NotNil(t, resp.Data.ConnectedAt)
	assert.False(t, resp.Data.ConnectedAt.IsZero())
	assert.Equal(t, "10.0.0.1:12345", resp.Data.RemoteAddr)
	require.NotNil(t, resp.Data.LastActivity)
}

func TestHandleGetStewardConnection_KnownButDisconnected(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "disconnected-host", "os": "linux",
	})

	// Registry is wired but steward has no live connection entry.
	reg := registry.NewRegistry()
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/connection", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardConnectionDetail `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.StewardID)
	assert.False(t, resp.Data.Connected)
	assert.Nil(t, resp.Data.ConnectedAt)
	assert.Empty(t, resp.Data.RemoteAddr)
	assert.Nil(t, resp.Data.LastActivity)
}

func TestHandleGetStewardConnection_UnknownSteward_Returns404(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	reg := registry.NewRegistry()
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/does-not-exist/connection", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleGetStewardConnection_WrongTenant_Returns404 is a REQUIRED acceptance-criteria test.
// It verifies that the handler enforces tenant isolation explicitly: requirePermission's
// path-var check does not apply to a steward-ID path variable (only "tenant" resourceType
// qualifies), so the handler must compare TenantIDs itself. A caller from one tenant must
// receive 404 (not the connection record) when the steward belongs to a different tenant.
func TestHandleGetStewardConnection_WrongTenant_Returns404(t *testing.T) {
	server := setupTestServer(t)

	// Register steward under "test-tenant" (the default for registerTestSteward).
	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "tenant-a-host", "os": "linux",
	})

	reg := registry.NewRegistry()
	registerTestConnection(t, reg, stewardID)
	server.SetRegistry(reg)

	// Caller is scoped to "other-tenant" — must not see this steward.
	wrongTenantKey := NewEphemeralTestKey(t, server, []string{"steward:read"}, "other-tenant", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/connection", nil)
	req.Header.Set("X-API-Key", wrongTenantKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// Must be 404, not 200 with connection data — avoids cross-tenant steward existence disclosure.
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleGetStewardConnection_NilRegistry_Returns503(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	// registry is nil by default in setupTestServer — no SetRegistry call.

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-no-registry", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/connection", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ---- handleListAllConnections tests ----

// TestHandleListAllConnections_Reachable verifies that GET /api/v1/stewards/connections/all
// is actually served by handleListAllConnections and not captured by the earlier /{id} pattern.
// A 404 with STEWARD_NOT_FOUND would indicate the /{id} route captured the request.
func TestHandleListAllConnections_Reachable(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	reg := registry.NewRegistry()
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/connections/all", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// Must be 200 with a connections list, NOT a STEWARD_NOT_FOUND error.
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data struct {
			Connections []StewardConnectionItem `json:"connections"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotNil(t, resp.Data.Connections)
}

func TestHandleListAllConnections_ReturnsConnectedStewards(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	stewardID1 := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-1", "os": "linux",
	})
	stewardID2 := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-2", "os": "linux",
	})

	reg := registry.NewRegistry()
	registerTestConnection(t, reg, stewardID1)
	registerTestConnection(t, reg, stewardID2)
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/connections/all", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data struct {
			Connections []StewardConnectionItem `json:"connections"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data.Connections, 2)
	seen := make(map[string]bool)
	for _, item := range resp.Data.Connections {
		seen[item.StewardID] = true
		assert.False(t, item.ConnectedAt.IsZero())
		assert.Equal(t, "10.0.0.1:12345", item.RemoteAddr)
	}
	assert.True(t, seen[stewardID1])
	assert.True(t, seen[stewardID2])
}

// TestHandleListAllConnections_ReturnsOnlyCallerTenant is a REQUIRED acceptance-criteria test.
// It verifies that a connected steward belonging to a different tenant never appears in the
// caller's list response, even when that steward is currently connected and in the registry.
func TestHandleListAllConnections_ReturnsOnlyCallerTenant(t *testing.T) {
	server := setupTestServer(t)

	// Register one steward under "test-tenant" (default for registerTestSteward).
	ownStewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "own-host", "os": "linux",
	})
	// Register a steward under a different tenant.
	otherStewardID := registerStewardUnderTenant(t, server, "other-tenant", "other-host")

	reg := registry.NewRegistry()
	registerTestConnection(t, reg, ownStewardID)
	registerTestConnection(t, reg, otherStewardID)
	server.SetRegistry(reg)

	// API key scoped to "test-tenant" must not reveal "other-tenant" steward.
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/connections/all", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data struct {
			Connections []StewardConnectionItem `json:"connections"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	// Only the steward belonging to "test-tenant" must appear.
	require.Len(t, resp.Data.Connections, 1)
	assert.Equal(t, ownStewardID, resp.Data.Connections[0].StewardID)
}

func TestHandleListAllConnections_NilRegistry_Returns503(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	// registry is nil by default in setupTestServer — no SetRegistry call.

	req := httptest.NewRequest("GET", "/api/v1/stewards/connections/all", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleListAllConnections_EmptyWhenNoConnections(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	reg := registry.NewRegistry()
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/connections/all", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data struct {
			Connections []StewardConnectionItem `json:"connections"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Empty(t, resp.Data.Connections)
}

// TestHandleListAllConnections_DisconnectedStewardNotIncluded verifies that a steward
// known to the controller service but with no live registry entry is absent from the list.
func TestHandleListAllConnections_DisconnectedStewardNotIncluded(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	// Steward is registered in the controller service but not in the live registry.
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "offline-host", "os": "linux",
	})

	reg := registry.NewRegistry()
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/connections/all", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data struct {
			Connections []StewardConnectionItem `json:"connections"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Empty(t, resp.Data.Connections)
}
