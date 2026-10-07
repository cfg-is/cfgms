//go:build cfgms_test_endpoints

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTaggedTestConfigRouteRequiresRuntimeOptIn(t *testing.T) {
	server := setupTestServer(t)
	const path = "/api/v1/test/stewards/tagged-test-steward/config"
	body := []byte(`
steward:
  id: tagged-test-steward
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
  - name: tagged-test-resource
    module: file
    config:
      path: /tmp/tagged-test
      content: enabled
`)

	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Code,
		"a specially built test binary must still fail closed without runtime opt-in")

	t.Setenv("CFGMS_ENABLE_TEST_ENDPOINTS", "true")
	req = httptest.NewRequest(http.MethodPut, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code,
		"tagged test binary with explicit runtime opt-in should expose the integration-test route: %s", rec.Body.String())
}
