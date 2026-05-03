// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout replaces os.Stdout with a pipe, calls fn, and returns the captured output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w

	fn()

	require.NoError(t, w.Close())
	os.Stdout = orig

	data, err := io.ReadAll(r)
	require.NoError(t, err)

	return string(data)
}

// newTokenServer creates an httptest server that serves canned token API responses.
func newTokenServer(t *testing.T) *httptest.Server {
	t.Helper()

	expiresAt := "2026-06-01T00:00:00Z"
	token := APITokenResponse{
		Token:         "abc123testtoken",
		TenantID:      "test-tenant",
		ControllerURL: "controller.example.com:4433",
		Group:         "production",
		CreatedAt:     "2026-05-01T00:00:00Z",
		ExpiresAt:     &expiresAt,
		SingleUse:     false,
		Revoked:       false,
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/registration/tokens":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(token)
		case r.Method == "GET" && r.URL.Path == "/api/v1/registration/tokens":
			resp := APITokenListResponse{
				Tokens: []APITokenResponse{token},
				Total:  1,
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v1/registration/tokens/"):
			_ = json.NewEncoder(w).Encode(token)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRunTokenCreate_JSONOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	// Save and restore package-level flag vars
	origAPIURL := tokenAPIURL
	origAPIKey := tokenAPIKey
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origControllerURL := tokenControllerURL
	origGroup := tokenGroup
	origExpiresIn := tokenExpiresIn
	origSingleUse := tokenSingleUse
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenAPIKey = origAPIKey
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenControllerURL = origControllerURL
		tokenGroup = origGroup
		tokenExpiresIn = origExpiresIn
		tokenSingleUse = origSingleUse
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = "test-tenant"
	tokenControllerURL = "controller.example.com:4433"
	tokenGroup = ""
	tokenExpiresIn = ""
	tokenSingleUse = false
	tokenJSONOutput = true

	output := captureStdout(t, func() {
		err := runTokenCreate(tokenCreateCmd, nil)
		require.NoError(t, err)
	})

	// Output must be valid JSON parseable as APITokenResponse
	var parsed APITokenResponse
	require.NoError(t, json.Unmarshal([]byte(output), &parsed), "output must be valid JSON")

	assert.Equal(t, "abc123testtoken", parsed.Token)
	assert.Equal(t, "test-tenant", parsed.TenantID)
	assert.Equal(t, "controller.example.com:4433", parsed.ControllerURL)

	// No human-readable text on stdout
	assert.NotContains(t, output, "Registration Token:")
	assert.NotContains(t, output, "Deployment Examples:")
}

func TestRunTokenCreate_TextOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	origAPIURL := tokenAPIURL
	origAPIKey := tokenAPIKey
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origControllerURL := tokenControllerURL
	origGroup := tokenGroup
	origExpiresIn := tokenExpiresIn
	origSingleUse := tokenSingleUse
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenAPIKey = origAPIKey
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenControllerURL = origControllerURL
		tokenGroup = origGroup
		tokenExpiresIn = origExpiresIn
		tokenSingleUse = origSingleUse
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = "test-tenant"
	tokenControllerURL = "controller.example.com:4433"
	tokenGroup = ""
	tokenExpiresIn = ""
	tokenSingleUse = false
	tokenJSONOutput = false

	output := captureStdout(t, func() {
		err := runTokenCreate(tokenCreateCmd, nil)
		require.NoError(t, err)
	})

	// Human-readable output must be present
	assert.Contains(t, output, "Registration Token:")
	assert.Contains(t, output, "abc123testtoken")
	assert.Contains(t, output, "Deployment Examples:")

	// Must not be bare JSON
	assert.False(t, json.Valid([]byte(strings.TrimSpace(output))), "text output must not be valid JSON")
}

func TestRunTokenCreate_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origControllerURL := tokenControllerURL
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenControllerURL = origControllerURL
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = "test-tenant"
	tokenControllerURL = "controller.example.com:4433"
	tokenJSONOutput = false

	err := runTokenCreate(tokenCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create token")
}

func TestRunTokenList_JSONOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = ""
	tokenJSONOutput = true

	output := captureStdout(t, func() {
		err := runTokenList(tokenListCmd, nil)
		require.NoError(t, err)
	})

	// Output must be valid JSON parseable as APITokenListResponse
	var parsed APITokenListResponse
	require.NoError(t, json.Unmarshal([]byte(output), &parsed), "output must be valid JSON")

	assert.Equal(t, 1, parsed.Total)
	require.Len(t, parsed.Tokens, 1)
	assert.Equal(t, "abc123testtoken", parsed.Tokens[0].Token)

	// No human-readable text on stdout
	assert.NotContains(t, output, "Found")
	assert.NotContains(t, output, "token(s):")
}

func TestRunTokenList_TextOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = ""
	tokenJSONOutput = false

	output := captureStdout(t, func() {
		err := runTokenList(tokenListCmd, nil)
		require.NoError(t, err)
	})

	// Human-readable output must be present
	assert.Contains(t, output, "Found 1 token(s):")
	assert.Contains(t, output, "abc123testtoken")
}

func TestRunTokenList_JSONOutput_EmptyList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := APITokenListResponse{Tokens: []APITokenResponse{}, Total: 0}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = ""
	tokenJSONOutput = true

	output := captureStdout(t, func() {
		err := runTokenList(tokenListCmd, nil)
		require.NoError(t, err)
	})

	// Even with zero tokens, JSON path must emit valid JSON
	var parsed APITokenListResponse
	require.NoError(t, json.Unmarshal([]byte(output), &parsed), "output must be valid JSON")
	assert.Equal(t, 0, parsed.Total)
}

func TestRunTokenList_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"service unavailable"}`))
	}))
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = ""
	tokenJSONOutput = false

	err := runTokenList(tokenListCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list tokens")
}

func TestRunTokenGet_TextOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenJSONOutput = false

	output := captureStdout(t, func() {
		err := runTokenGet(tokenGetCmd, []string{"abc123testtoken"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "Token: abc123testtoken")
	assert.Contains(t, output, "Tenant ID:")
	assert.Contains(t, output, "test-tenant")
	assert.Contains(t, output, "Controller URL:")
	assert.Contains(t, output, "controller.example.com:4433")
	assert.Contains(t, output, "Status:")

	// Must not be bare JSON
	assert.False(t, json.Valid([]byte(strings.TrimSpace(output))), "text output must not be valid JSON")
}

func TestRunTokenGet_JSONOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenJSONOutput = true

	output := captureStdout(t, func() {
		err := runTokenGet(tokenGetCmd, []string{"abc123testtoken"})
		require.NoError(t, err)
	})

	// Output must be valid JSON parseable as APITokenResponse
	var parsed APITokenResponse
	require.NoError(t, json.Unmarshal([]byte(output), &parsed), "output must be valid JSON")

	assert.Equal(t, "abc123testtoken", parsed.Token)
	assert.Equal(t, "test-tenant", parsed.TenantID)
	assert.Equal(t, "controller.example.com:4433", parsed.ControllerURL)

	// No human-readable text on stdout
	assert.NotContains(t, output, "Token:")
	assert.NotContains(t, output, "Tenant ID:")
}

func TestRunTokenGet_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"token not found"}`))
	}))
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenJSONOutput = false

	err := runTokenGet(tokenGetCmd, []string{"nonexistenttoken"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get token nonexistenttoken")
}

func TestRunTokenGet_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenJSONOutput = false

	err := runTokenGet(tokenGetCmd, []string{"sometesttoken"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get token sometesttoken")
	assert.Contains(t, err.Error(), "internal server error")
}
