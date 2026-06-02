// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTenantServer creates an httptest server that serves canned tenant API responses.
func newTenantServer(t *testing.T) *httptest.Server {
	t.Helper()

	tenant := APITenantResponse{
		ID:     "team-root",
		Name:   "team-root",
		Status: "active",
	}

	envelope := map[string]interface{}{
		"data": tenant,
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tenants":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(envelope)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tenants/team-root":
			_ = json.NewEncoder(w).Encode(envelope)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// newTenantConflictServer returns a server that always responds 409 to POST /api/v1/tenants.
func newTenantConflictServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"TENANT_EXISTS","message":"tenant already exists"}}`))
	}))
}

func TestCreateTenantCommand_HappyPath(t *testing.T) {
	server := newTenantServer(t)
	defer server.Close()

	origAPIURL := tenantAPIURL
	origTLSInsecure := tenantTLSInsecure
	origID := tenantCreateID
	origParent := tenantCreateParent
	t.Cleanup(func() {
		tenantAPIURL = origAPIURL
		tenantTLSInsecure = origTLSInsecure
		tenantCreateID = origID
		tenantCreateParent = origParent
	})

	tenantAPIURL = server.URL
	tenantTLSInsecure = true
	tenantCreateID = "team-root"
	tenantCreateParent = ""

	output := captureStdout(t, func() {
		err := runTenantCreate(tenantCreateCmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "team-root", "success output must include the tenant ID")
}

func TestCreateTenantCommand_AlreadyExists(t *testing.T) {
	server := newTenantConflictServer(t)
	defer server.Close()

	origAPIURL := tenantAPIURL
	origTLSInsecure := tenantTLSInsecure
	origID := tenantCreateID
	origParent := tenantCreateParent
	t.Cleanup(func() {
		tenantAPIURL = origAPIURL
		tenantTLSInsecure = origTLSInsecure
		tenantCreateID = origID
		tenantCreateParent = origParent
	})

	tenantAPIURL = server.URL
	tenantTLSInsecure = true
	tenantCreateID = "team-root"
	tenantCreateParent = ""

	output := captureStdout(t, func() {
		// Must exit 0 (no error) when tenant already exists
		err := runTenantCreate(tenantCreateCmd, nil)
		require.NoError(t, err, "idempotent: already-existing tenant must exit 0")
	})

	assert.Contains(t, output, "tenant already exists")
}

func TestCreateTenantCommand_WithParent(t *testing.T) {
	// bodyErrCh carries any read error from the server goroutine to the test goroutine.
	bodyErrCh := make(chan error, 1)
	bodyCh := make(chan []byte, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/tenants" {
			body, err := io.ReadAll(r.Body)
			bodyErrCh <- err
			bodyCh <- body
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"id":        "agent-test",
					"name":      "agent-test",
					"parent_id": "team-root",
					"status":    "active",
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	origAPIURL := tenantAPIURL
	origTLSInsecure := tenantTLSInsecure
	origID := tenantCreateID
	origParent := tenantCreateParent
	t.Cleanup(func() {
		tenantAPIURL = origAPIURL
		tenantTLSInsecure = origTLSInsecure
		tenantCreateID = origID
		tenantCreateParent = origParent
	})

	tenantAPIURL = server.URL
	tenantTLSInsecure = true
	tenantCreateID = "agent-test"
	tenantCreateParent = "team-root"

	output := captureStdout(t, func() {
		err := runTenantCreate(tenantCreateCmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "agent-test")

	// Verify the request body contained the parent_id (read from the server goroutine via channels)
	require.NoError(t, <-bodyErrCh, "server must be able to read the request body")
	capturedBody := <-bodyCh
	var reqBody APITenantCreateRequest
	require.NoError(t, json.Unmarshal(capturedBody, &reqBody), "request body must be valid JSON")
	assert.Equal(t, "team-root", reqBody.ParentID, "--parent flag must set parent_id in the request")
}

func TestCreateTenantCommand_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	origAPIURL := tenantAPIURL
	origTLSInsecure := tenantTLSInsecure
	origID := tenantCreateID
	t.Cleanup(func() {
		tenantAPIURL = origAPIURL
		tenantTLSInsecure = origTLSInsecure
		tenantCreateID = origID
	})

	tenantAPIURL = server.URL
	tenantTLSInsecure = true
	tenantCreateID = "some-tenant"

	err := runTenantCreate(tenantCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create tenant")
}

func TestGetTenantViaAPI_Exists(t *testing.T) {
	server := newTenantServer(t)
	defer server.Close()

	client, err := newClientFromFlags(server.URL, "", "", true)
	require.NoError(t, err)

	td, err := client.GetTenantViaAPI(t.Context(), "team-root")
	require.NoError(t, err)
	assert.Equal(t, "team-root", td.ID)
}

func TestGetTenantViaAPI_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"TENANT_NOT_FOUND","message":"tenant not found"}}`))
	}))
	defer server.Close()

	client, err := newClientFromFlags(server.URL, "", "", true)
	require.NoError(t, err)

	_, err = client.GetTenantViaAPI(t.Context(), "missing-tenant")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant not found")
}
