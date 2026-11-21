// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	grantWiringTenant = "test-tenant-integration"
	grantWiringPath   = "/api/v1/automation/grants"
)

// grantWiringServer builds the real controller through New, the construction path
// the binary uses, with a seeded API key that holds automation-grant:read. The grant
// store is never set by the test: only controller startup can have wired it.
func grantWiringServer(t *testing.T) (*Server, string) {
	t.Helper()
	keyBytes := make([]byte, 16)
	_, err := rand.Read(keyBytes)
	require.NoError(t, err)
	key := "grant-wiring-" + hex.EncodeToString(keyBytes)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())
	t.Setenv("CFGMS_SEED_TEST_API_KEYS", "1")
	t.Setenv("CFGMS_API_KEY_GRANT_READER", key)
	t.Setenv("CFGMS_API_KEY_GRANT_READER_TENANT", grantWiringTenant)

	srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())
	require.NotNil(t, srv.httpServer)
	mustCreateTenantForWiring(t, srv.storageManager.GetTenantStore(), grantWiringTenant, grantWiringTenant, "")
	return srv, key
}

func serveGrantRequest(srv *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.httpServer.GetRouter().ServeHTTP(rec, req)
	return rec
}

type grantListBody struct {
	Data struct {
		Grants []struct {
			ID       string `json:"id"`
			TenantID string `json:"tenant_id"`
			Name     string `json:"name"`
		} `json:"grants"`
		Count int `json:"count"`
	} `json:"data"`
}

// TestServer_New_WiresAutomationGrantStore is the [REQUIRED TEST] for Issue #6394: the
// controller built through New answers the grant routes per contract instead of 503,
// lists a grant created in the wired store, and authenticates its cfgag_ credential.
func TestServer_New_WiresAutomationGrantStore(t *testing.T) {
	srv, key := grantWiringServer(t)
	require.NotNil(t, srv.httpServer.AutomationGrantStore(),
		"controller startup must wire the automation grant store (else every grant route 503s)")
	apiKey := map[string]string{"X-API-Key": key}

	t.Run("list answers 200 with an empty list, not 503", func(t *testing.T) {
		rec := serveGrantRequest(srv, http.MethodGet, grantWiringPath, "", apiKey)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var got grantListBody
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got), rec.Body.String())
		assert.Equal(t, 0, got.Data.Count)
		assert.Contains(t, rec.Body.String(), `"grants":[]`)
	})

	t.Run("create route is live and refuses an API key by contract, not 503", func(t *testing.T) {
		// automation-grant:create requires Strong assurance with a presence tap, which
		// no API key can hold; the answer must be a permission refusal, never a 503.
		body := `{"name":"ci","tenant_id":"` + grantWiringTenant + `","expires_at":"` +
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
		rec := serveGrantRequest(srv, http.MethodPost, grantWiringPath, body, apiKey)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), "Automation grants not available")
	})

	t.Run("a created grant is listed and its credential authenticates", func(t *testing.T) {
		grant, credential, err := srv.httpServer.AutomationGrantStore().Create(
			t.Context(), grantWiringTenant, "wired-grant", "operator-1", time.Now().Add(time.Hour))
		require.NoError(t, err)

		rec := serveGrantRequest(srv, http.MethodGet, grantWiringPath, "", apiKey)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var got grantListBody
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got), rec.Body.String())
		require.Len(t, got.Data.Grants, 1)
		assert.Equal(t, grant.ID, got.Data.Grants[0].ID)
		assert.Equal(t, grantWiringTenant, got.Data.Grants[0].TenantID)

		// A route outside the grant allowlist is refused only after the credential
		// authenticated; an unknown credential never gets that far.
		bearer := map[string]string{"Authorization": "Bearer " + credential}
		denied := serveGrantRequest(srv, http.MethodGet, grantWiringPath, "", bearer)
		assert.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
		assert.Contains(t, denied.Body.String(), "AUTOMATION_ROUTE_DENIED")

		// A route the grant scope allows: the run begin handler runs for the
		// authenticated grant (an empty body is a request error, not an auth error).
		begin := serveGrantRequest(srv, http.MethodPost, "/api/v1/automation/runs", "{}", bearer)
		assert.NotEqual(t, http.StatusUnauthorized, begin.Code, begin.Body.String())
		assert.NotEqual(t, http.StatusServiceUnavailable, begin.Code, begin.Body.String())
		assert.NotContains(t, begin.Body.String(), "INVALID_AUTOMATION_GRANT")

		bogus := map[string]string{"Authorization": "Bearer cfgag_" + strings.Repeat("x", 43)}
		refused := serveGrantRequest(srv, http.MethodPost, "/api/v1/automation/runs", "{}", bogus)
		assert.Equal(t, http.StatusUnauthorized, refused.Code, refused.Body.String())
		assert.Contains(t, refused.Body.String(), "INVALID_AUTOMATION_GRANT")
	})
}
