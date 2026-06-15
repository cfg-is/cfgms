// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestReadyEndpoint_503WhenNoStorage: the readiness endpoint reports not-ready
// (503) when the controller cannot serve from durable storage. setupTestServer
// wires a storage-less controller service, which is exactly the degraded state
// a cutover candidate must not be promoted in (Issue #2012).
func TestReadyEndpoint_503WhenNoStorage(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/ready", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var response APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	data, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "not_ready", data["status"])
}

// TestReadyEndpoint_200WhenStorageReady: with a storage-backed controller
// service whose durable round-trip succeeds, /api/v1/ready returns 200 "ready".
func TestReadyEndpoint_200WhenStorageReady(t *testing.T) {
	server := setupTestServer(t)

	cfg := fleetStorage.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.EnableDeduplication = false
	mgr, err := fleetStorage.NewManager(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })
	// handleReady reads s.controllerService at call time, so swapping in a
	// storage-backed service after construction is sufficient.
	server.controllerService = service.NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr)

	req := httptest.NewRequest("GET", "/api/v1/ready", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	data, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "ready", data["status"])
}
