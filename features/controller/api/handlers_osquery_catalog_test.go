// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveOsqueryQuery(t *testing.T, server *Server, body osqueryQueryRequest) *httptest.ResponseRecorder {
	t.Helper()
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()
	server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery)).ServeHTTP(rec, req)
	return rec
}

func TestOsqueryQuery_UnknownCatalogID_Returns400BeforeFanOut(t *testing.T) {
	disp := &stubOsqueryDispatcher{}
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithStewardIDs("steward-1")

	rec := serveOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "no_such_query", Selector: "all"})

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "INVALID_CATALOG_ID", errorCode(t, rec))
	assert.Empty(t, disp.calls, "no dispatch may happen for an unknown catalog id")
}

func TestOsqueryQuery_InvalidParams_Returns400(t *testing.T) {
	disp := &stubOsqueryDispatcher{}
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithStewardIDs("steward-1")

	rec := serveOsqueryQuery(t, server, osqueryQueryRequest{
		CatalogID: "file_info",
		Params:    map[string]string{"path": "/etc/x'; DROP TABLE users;--"},
		Selector:  "all",
	})

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "INVALID_PARAMS", errorCode(t, rec))
	assert.NotContains(t, rec.Body.String(), "DROP TABLE", "raw value must not be echoed")
	assert.Empty(t, disp.calls)
}

func TestOsqueryCatalogRoute_ReturnsList(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"osquery:list-catalog"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/osquery/catalog", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"host_info"`)
	assert.False(t, strings.Contains(strings.ToUpper(rec.Body.String()), "SELECT"))
}

func TestOsqueryCatalogRoute_RequiresPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/osquery/catalog", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
