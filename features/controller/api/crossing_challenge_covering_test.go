// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func challengeEndpoint(t *testing.T, rec *httptest.ResponseRecorder) (string, bool) {
	t.Helper()
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	v, ok := body["break_glass_endpoint"].(string)
	return v, ok
}

func TestWriteTenantCrossingChallenge_NamesCoveringMSP(t *testing.T) {
	server := seedRootTenant(t, setupCrossingTestServer(t))
	for _, tn := range [][2]string{{"cov-msp", testRootTenantID}, {"cov-client", "cov-msp"}, {"cov-grandchild", "cov-client"}} {
		_, err := server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ID: tn[0], ParentID: tn[1]})
		require.NoError(t, err)
	}

	for _, owner := range []string{"cov-msp", "cov-client", "cov-grandchild"} {
		rec := httptest.NewRecorder()
		server.writeTenantCrossingChallenge(rec, owner)
		endpoint, ok := challengeEndpoint(t, rec)
		require.True(t, ok)
		assert.Equal(t, "/api/v1/tenants/cov-msp/break-glass", endpoint, "owner %s", owner)
		assert.NotContains(t, rec.Body.String(), "cov-client")
		assert.NotContains(t, rec.Body.String(), "cov-grandchild")
	}
}

func TestWriteTenantCrossingChallenge_FailsClosed(t *testing.T) {
	server := seedRootTenant(t, setupCrossingTestServer(t))
	for _, owner := range []string{"", "no-such-tenant", testRootTenantID} {
		rec := httptest.NewRecorder()
		server.writeTenantCrossingChallenge(rec, owner)
		endpoint, ok := challengeEndpoint(t, rec)
		assert.False(t, ok, "owner %q must not yield an endpoint, got %q", owner, endpoint)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
	}
	assert.Equal(t, "", server.crossingCoveringTenant(context.Background(), "no-such-tenant"))

	server.tenantManager = nil
	rec := httptest.NewRecorder()
	server.writeTenantCrossingChallenge(rec, "cov-client")
	_, ok := challengeEndpoint(t, rec)
	assert.False(t, ok)
}
