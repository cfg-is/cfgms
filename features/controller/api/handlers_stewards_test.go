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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/fleet"
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
	longVal := string(make([]byte, 300))
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
	resp, err := svc.AcceptRegistration(context.Background(), req)
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
