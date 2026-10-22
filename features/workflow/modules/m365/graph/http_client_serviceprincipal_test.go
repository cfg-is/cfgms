// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package graph

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
)

func newSPTestClient(t *testing.T, h http.HandlerFunc) *HTTPClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewHTTPClient(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
}

func spToken() *auth.AccessToken {
	return &auth.AccessToken{Token: "test-token", TenantID: "t"}
}

func TestHTTPClient_CreateServicePrincipal(t *testing.T) {
	var method, path string
	var body []byte
	c := newSPTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"sp-1","appId":"app-1"}`))
	})

	sp, err := c.CreateServicePrincipal(context.Background(), spToken(), &CreateServicePrincipalRequest{
		AppID: "app-1", AccountEnabled: true, Tags: []string{"x"}, ReplyUrls: []string{"https://r/cb"},
	})
	require.NoError(t, err)
	assert.Equal(t, "sp-1", sp.ID)
	assert.Equal(t, http.MethodPost, method)
	assert.Equal(t, "/servicePrincipals", path)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "app-1", got["appId"])
	assert.Equal(t, true, got["accountEnabled"])
	assert.Equal(t, []interface{}{"x"}, got["tags"])
	assert.Equal(t, []interface{}{"https://r/cb"}, got["replyUrls"])
}

func TestHTTPClient_ListServicePrincipalsSendsFilter(t *testing.T) {
	var filter, path string
	c := newSPTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		path, filter = r.URL.Path, r.URL.Query().Get("$filter")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"id":"sp-1","appId":"app-1"}]}`))
	})

	sps, err := c.ListServicePrincipals(context.Background(), spToken(), "appId eq 'app-1'")
	require.NoError(t, err)
	require.Len(t, sps, 1)
	assert.Equal(t, "app-1", sps[0].AppID)
	assert.Equal(t, "/servicePrincipals", path)
	assert.Equal(t, "appId eq 'app-1'", filter)
}

func TestHTTPClient_ServicePrincipalErrors(t *testing.T) {
	c := newSPTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Forbidden","message":"denied"}}`))
	})

	_, err := c.CreateServicePrincipal(context.Background(), spToken(), &CreateServicePrincipalRequest{AppID: "a"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create service principal")

	_, err = c.ListServicePrincipals(context.Background(), spToken(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list service principals")
}
