// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setStewardTagFlags wires the module-level flags for a test run and returns a cleanup func.
func setStewardTagFlags(serverURL, apiKey string) func() {
	origURL := stewardTagURL
	origKey := stewardTagAPIKey
	origInsecure := stewardTagTLSInsecure
	stewardTagURL = serverURL
	stewardTagAPIKey = apiKey
	stewardTagTLSInsecure = true
	return func() {
		stewardTagURL = origURL
		stewardTagAPIKey = origKey
		stewardTagTLSInsecure = origInsecure
	}
}

// tagsAPIResponse mirrors the REST response envelope for tag endpoints.
type tagsAPIResponse struct {
	Data struct {
		Tags []string `json:"tags"`
	} `json:"data"`
}

// TestStewardTagAddCmd_HappyPath verifies that runStewardTagAdd sends the correct
// POST body and prints the resulting tag list.
func TestStewardTagAddCmd_HappyPath(t *testing.T) {
	var capturedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		assert.True(t, strings.HasSuffix(r.URL.Path, "/steward-abc/tags"), "path: %s", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedBody))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tagsAPIResponse{Data: struct {
			Tags []string `json:"tags"`
		}{Tags: []string{"prod", "web"}}})
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	var out bytes.Buffer
	stewardTagAddCmd.SetOut(&out)
	err := runStewardTagAdd(stewardTagAddCmd, []string{"steward-abc", "prod", "web"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "prod")
	assert.Contains(t, out.String(), "web")

	// Verify the request body contained the tags slice.
	tagsRaw, ok := capturedBody["tags"].([]interface{})
	require.True(t, ok)
	assert.Len(t, tagsRaw, 2)
}

// TestStewardTagAddCmd_NotFound verifies a 404 returns a descriptive error.
func TestStewardTagAddCmd_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	err := runStewardTagAdd(stewardTagAddCmd, []string{"no-such", "prod"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestStewardTagAddCmd_Forbidden verifies a 403 returns a descriptive error.
func TestStewardTagAddCmd_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	err := runStewardTagAdd(stewardTagAddCmd, []string{"other-tenant-steward", "prod"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient permissions")
}

// TestStewardTagRmCmd_HappyPath verifies that runStewardTagRm sends the correct
// DELETE body and prints the remaining tag list.
func TestStewardTagRmCmd_HappyPath(t *testing.T) {
	var capturedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		assert.True(t, strings.HasSuffix(r.URL.Path, "/steward-abc/tags"), "path: %s", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedBody))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tagsAPIResponse{Data: struct {
			Tags []string `json:"tags"`
		}{Tags: []string{"prod"}}})
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	var out bytes.Buffer
	stewardTagRmCmd.SetOut(&out)
	err := runStewardTagRm(stewardTagRmCmd, []string{"steward-abc", "web"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "prod")

	tagsRaw, ok := capturedBody["tags"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, "web", tagsRaw[0])
}

// TestStewardTagRmCmd_AllRemoved verifies the "no tags remain" message when empty.
func TestStewardTagRmCmd_AllRemoved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tagsAPIResponse{Data: struct {
			Tags []string `json:"tags"`
		}{Tags: []string{}}})
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	var out bytes.Buffer
	stewardTagRmCmd.SetOut(&out)
	err := runStewardTagRm(stewardTagRmCmd, []string{"steward-abc", "prod"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "No tags remain")
}

// TestStewardTagRmCmd_NotFound verifies a 404 returns a descriptive error.
func TestStewardTagRmCmd_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	err := runStewardTagRm(stewardTagRmCmd, []string{"no-such", "prod"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestStewardTagLsCmd_HappyPath verifies that runStewardTagLs prints a table of tags.
func TestStewardTagLsCmd_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		assert.True(t, strings.HasSuffix(r.URL.Path, "/steward-abc/tags"), "path: %s", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tagsAPIResponse{Data: struct {
			Tags []string `json:"tags"`
		}{Tags: []string{"prod", "web"}}})
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	var out bytes.Buffer
	stewardTagLsCmd.SetOut(&out)
	err := runStewardTagLs(stewardTagLsCmd, []string{"steward-abc"})
	require.NoError(t, err)
	output := out.String()
	assert.Contains(t, output, "prod")
	assert.Contains(t, output, "web")
}

// TestStewardTagLsCmd_Empty verifies the "no tags" message when no tags are set.
func TestStewardTagLsCmd_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tagsAPIResponse{Data: struct {
			Tags []string `json:"tags"`
		}{Tags: []string{}}})
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	var out bytes.Buffer
	stewardTagLsCmd.SetOut(&out)
	err := runStewardTagLs(stewardTagLsCmd, []string{"steward-abc"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "No tags")
}

// TestStewardTagLsCmd_NotFound verifies a 404 returns a descriptive error.
func TestStewardTagLsCmd_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	err := runStewardTagLs(stewardTagLsCmd, []string{"no-such"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestStewardTagRmCmd_Forbidden verifies a 403 returns a descriptive error.
func TestStewardTagRmCmd_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	err := runStewardTagRm(stewardTagRmCmd, []string{"other-tenant-steward", "prod"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient permissions")
}

// TestStewardTagLsCmd_ServerError verifies that an unexpected server error is reported.
func TestStewardTagLsCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	cleanup := setStewardTagFlags(srv.URL, "test-key")
	defer cleanup()

	err := runStewardTagLs(stewardTagLsCmd, []string{"steward-abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list failed")
}

// TestStewardTagCmds_ServerNameFlagRegistered verifies that --server-name is
// registered on every steward tag subcommand alongside --tls-insecure (Issue #3174).
func TestStewardTagCmds_ServerNameFlagRegistered(t *testing.T) {
	for _, cmd := range []*cobra.Command{stewardTagAddCmd, stewardTagRmCmd, stewardTagLsCmd} {
		assert.NotNil(t, cmd.Flags().Lookup("server-name"), "--server-name flag must be registered on steward tag %s", cmd.Name())
	}
}
