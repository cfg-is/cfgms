// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Tests for handleUpdateStewardConfig validation-vs-storage error routing (Issue #2482).
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleUpdateStewardConfig_InvalidResourceName_Returns400 verifies that a config
// upload with an invalid resource name (dot in name, e.g. "docker.io") returns HTTP 400
// with code VALIDATION_ERROR and the specific failed-field detail in the message, not
// 500 STORAGE_ERROR (Issue #2482).
func TestHandleUpdateStewardConfig_InvalidResourceName_Returns400(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:write-config"}, "test-tenant", 5*time.Minute)

	body := []byte(`
steward:
  id: test-steward-invalid-rsrc
  mode: controller
  logging:
    level: info
    format: text
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail
modules:
  file: file
resources:
  - name: docker.io
    module: file
    config:
      path: /tmp/test
      content: x
`)

	req := httptest.NewRequest("PUT", "/api/v1/stewards/test-steward-invalid-rsrc/config", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"validation failure must return 400, not 5xx; body: %s", rec.Body.String())
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "VALIDATION_ERROR", resp.Error.Code,
		"code must be VALIDATION_ERROR, not STORAGE_ERROR")
	assert.Contains(t, resp.Error.Message, "docker.io",
		"message must name the invalid resource so the client can diagnose without server logs")
}

// TestHandleUpdateStewardConfig_ValidConfig_Returns200 verifies that a well-formed
// config upload succeeds (Issue #2482 — regression guard that the fix does not
// accidentally block valid uploads).
func TestHandleUpdateStewardConfig_ValidConfig_Returns200(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:write-config"}, "test-tenant", 5*time.Minute)

	body := []byte(`
steward:
  id: test-steward-valid
  mode: controller
  logging:
    level: info
    format: text
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail
modules:
  file: file
resources:
  - name: my-managed-file
    module: file
    config:
      path: /tmp/managed
      content: hello
`)

	req := httptest.NewRequest("PUT", "/api/v1/stewards/test-steward-valid/config", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"valid config must be accepted; body: %s", rec.Body.String())
}
