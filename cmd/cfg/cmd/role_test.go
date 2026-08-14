// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setRoleFlags wires the module-level flags for a test run and returns a cleanup func.
func setRoleFlags(url, apiKey string) func() {
	origURL := roleURL
	origKey := roleAPIKey
	origInsecure := roleTLSInsecure
	roleURL = url
	roleAPIKey = apiKey
	roleTLSInsecure = true
	return func() {
		roleURL = origURL
		roleAPIKey = origKey
		roleTLSInsecure = origInsecure
	}
}

// TestRoleCreateCmd_HappyPath verifies that runRoleCreate sends the correct
// POST body and prints a success message.
func TestRoleCreateCmd_HappyPath(t *testing.T) {
	var capturedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/roles", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"name":     "github-runners",
				"selector": "os:windows tag:github-runner",
			},
		})
	}))
	defer srv.Close()

	cleanup := setRoleFlags(srv.URL, "test-key")
	defer cleanup()

	// Write a minimal fragment YAML file.
	tmpDir := t.TempDir()
	fragFile := filepath.Join(tmpDir, "frag.yaml")
	require.NoError(t, os.WriteFile(fragFile, []byte("steward:\n  logging:\n    level: debug\n"), 0600))

	// Restore flags changed by init() binding.
	origSelector := roleSelector
	origConfigFile := roleConfigFile
	roleSelector = "os:windows tag:github-runner"
	roleConfigFile = fragFile
	defer func() {
		roleSelector = origSelector
		roleConfigFile = origConfigFile
	}()

	var out bytes.Buffer
	roleCreateCmd.SetOut(&out)
	err := runRoleCreate(roleCreateCmd, []string{"github-runners"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "github-runners")

	// Verify the request body included name, selector, and fragment.
	assert.Equal(t, "github-runners", capturedBody["name"])
	assert.Equal(t, "os:windows tag:github-runner", capturedBody["selector"])
	assert.NotNil(t, capturedBody["fragment"])
}

// TestRoleCreateCmd_MissingFile verifies that a missing config file is reported.
func TestRoleCreateCmd_MissingFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach server when config file is missing")
	}))
	defer srv.Close()

	cleanup := setRoleFlags(srv.URL, "test-key")
	defer cleanup()

	origConfigFile := roleConfigFile
	roleConfigFile = "/nonexistent/path/frag.yaml"
	defer func() { roleConfigFile = origConfigFile }()

	err := runRoleCreate(roleCreateCmd, []string{"my-role"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

// TestRoleLsCmd_HappyPath verifies that runRoleLs prints a table with role names.
func TestRoleLsCmd_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/roles", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{"name": "role-a", "selector": "os:linux", "created_by": "admin"},
				{"name": "role-b", "selector": "tag:debug", "created_by": "admin"},
			},
		})
	}))
	defer srv.Close()

	cleanup := setRoleFlags(srv.URL, "test-key")
	defer cleanup()

	var out bytes.Buffer
	roleLsCmd.SetOut(&out)
	err := runRoleLs(roleLsCmd, nil)
	require.NoError(t, err)

	output := out.String()
	assert.Contains(t, output, "role-a")
	assert.Contains(t, output, "role-b")
	assert.Contains(t, output, "os:linux")
}

// TestRoleLsCmd_Empty verifies that runRoleLs prints a helpful message when empty.
func TestRoleLsCmd_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []interface{}{}})
	}))
	defer srv.Close()

	cleanup := setRoleFlags(srv.URL, "test-key")
	defer cleanup()

	var out bytes.Buffer
	roleLsCmd.SetOut(&out)
	err := runRoleLs(roleLsCmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "No role configs found")
}

// TestRoleShowCmd_HappyPath verifies that runRoleShow prints role details.
func TestRoleShowCmd_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		assert.True(t, strings.HasSuffix(r.URL.Path, "/github-runners"), "path: %s", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"name":       "github-runners",
				"selector":   "os:windows",
				"created_by": "ops-team",
				"fragment":   map[string]interface{}{},
			},
		})
	}))
	defer srv.Close()

	cleanup := setRoleFlags(srv.URL, "test-key")
	defer cleanup()

	var out bytes.Buffer
	roleShowCmd.SetOut(&out)
	err := runRoleShow(roleShowCmd, []string{"github-runners"})
	require.NoError(t, err)

	output := out.String()
	assert.Contains(t, output, "github-runners")
	assert.Contains(t, output, "os:windows")
}

// TestRoleShowCmd_NotFound verifies that runRoleShow returns an error on 404.
func TestRoleShowCmd_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cleanup := setRoleFlags(srv.URL, "test-key")
	defer cleanup()

	err := runRoleShow(roleShowCmd, []string{"missing"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestRoleDeleteCmd_HappyPath verifies that runRoleDelete sends DELETE and prints confirmation.
func TestRoleDeleteCmd_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		assert.True(t, strings.HasSuffix(r.URL.Path, "/github-runners"), "path: %s", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"deleted": "github-runners"}})
	}))
	defer srv.Close()

	cleanup := setRoleFlags(srv.URL, "test-key")
	defer cleanup()

	var out bytes.Buffer
	roleDeleteCmd.SetOut(&out)
	err := runRoleDelete(roleDeleteCmd, []string{"github-runners"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "github-runners")
}

// TestRoleDeleteCmd_NotFound verifies that runRoleDelete returns an error on 404.
func TestRoleDeleteCmd_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cleanup := setRoleFlags(srv.URL, "test-key")
	defer cleanup()

	err := runRoleDelete(roleDeleteCmd, []string{"missing"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestRoleCmds_ServerNameFlagRegistered verifies that --server-name is
// registered on every role subcommand alongside --tls-insecure (Issue #3174).
func TestRoleCmds_ServerNameFlagRegistered(t *testing.T) {
	for _, cmd := range []*cobra.Command{roleCreateCmd, roleLsCmd, roleShowCmd, roleDeleteCmd} {
		assert.NotNil(t, cmd.Flags().Lookup("server-name"), "--server-name flag must be registered on role %s", cmd.Name())
	}
}
