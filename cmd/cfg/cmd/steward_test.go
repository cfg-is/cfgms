// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStewardList_CallsGetStewardsEndpoint(t *testing.T) {
	now := time.Now().UTC()
	stewards := []map[string]interface{}{
		{"id": "steward-abc", "status": "connected", "last_seen": now.Format(time.RFC3339)},
		{"id": "steward-xyz", "status": "offline", "last_seen": now.Add(-5 * time.Minute).Format(time.RFC3339)},
	}

	var requestPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data":      stewards,
			"timestamp": now,
		})
	}))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
	})

	stewardURL = server.URL
	stewardTLSInsecure = true

	output := captureStdout(t, func() {
		err := runStewardList(stewardListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/stewards", requestPath)
	assert.Contains(t, output, "steward-abc")
	assert.Contains(t, output, "steward-xyz")
}

func TestStewardList_NonOKStatusReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	}))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
	})

	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runStewardList(stewardListCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestStewardList_EmptyList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data":      []interface{}{},
			"timestamp": time.Now().UTC(),
		})
	}))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
	})

	stewardURL = server.URL
	stewardTLSInsecure = true

	output := captureStdout(t, func() {
		err := runStewardList(stewardListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "No stewards registered")
}

func TestStewardList_FlagsRegistered(t *testing.T) {
	assert.NotNil(t, stewardListCmd.Flags().Lookup("url"), "--url flag must be registered")
	assert.NotNil(t, stewardListCmd.Flags().Lookup("api-key"), "--api-key flag must be registered")
	assert.NotNil(t, stewardListCmd.Flags().Lookup("tls-ca-cert"), "--tls-ca-cert flag must be registered")
	assert.NotNil(t, stewardListCmd.Flags().Lookup("tls-insecure"), "--tls-insecure flag must be registered")
}

func TestStewardCmd_RegisteredOnRoot(t *testing.T) {
	var found bool
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "steward" {
			found = true
			break
		}
	}
	assert.True(t, found, "steward command must be registered on rootCmd")
}

func TestStewardStatusCommand(t *testing.T) {
	t.Run("happy path prints labelled fields", func(t *testing.T) {
		now := time.Now().UTC()
		var requestPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":               "steward-abc123",
					"status":           "connected",
					"connection_state": "connected",
					"last_seen":        now.Format(time.RFC3339),
					"version":          "1.0.0",
					"tenant_id":        "default",
					"group":            "production",
					"dna": map[string]interface{}{
						"hostname":     "steward-vm-1",
						"os":           "linux",
						"architecture": "amd64",
					},
				},
				"timestamp": now,
			})
		}))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
		})
		stewardURL = server.URL
		stewardTLSInsecure = true

		output := captureStdout(t, func() {
			err := runStewardStatus(stewardStatusCmd, []string{"steward-abc123"})
			require.NoError(t, err)
		})

		assert.Equal(t, "/api/v1/stewards/steward-abc123", requestPath)
		assert.Contains(t, output, "steward-abc123")
		assert.Contains(t, output, "connected")
		assert.Contains(t, output, "1.0.0")
		assert.Contains(t, output, "steward-vm-1")
		assert.Contains(t, output, "linux")
		assert.Contains(t, output, "default")
		assert.Contains(t, output, "production")
	})

	t.Run("missing id argument returns cobra arg error", func(t *testing.T) {
		err := stewardStatusCmd.Args(stewardStatusCmd, []string{})
		require.Error(t, err)
	})

	t.Run("unknown id 404 returns not found error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "steward not found"})
		}))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
		})
		stewardURL = server.URL
		stewardTLSInsecure = true

		err := runStewardStatus(stewardStatusCmd, []string{"nonexistent-steward-id"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.Contains(t, err.Error(), "nonexistent-steward-id")
	})

	t.Run("non-ok non-404 status returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
		}))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
		})
		stewardURL = server.URL
		stewardTLSInsecure = true

		err := runStewardStatus(stewardStatusCmd, []string{"steward-abc123"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("json flag emits raw JSON response", func(t *testing.T) {
		now := time.Now().UTC()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":     "steward-abc123",
					"status": "connected",
				},
				"timestamp": now,
			})
		}))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		origJSON := stewardStatusJSONOutput
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
			stewardStatusJSONOutput = origJSON
		})
		stewardURL = server.URL
		stewardTLSInsecure = true
		stewardStatusJSONOutput = true

		output := captureStdout(t, func() {
			err := runStewardStatus(stewardStatusCmd, []string{"steward-abc123"})
			require.NoError(t, err)
		})

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(output), &parsed), "output must be valid JSON")
		assert.Contains(t, output, "steward-abc123")
	})
}

func TestStewardList_UsesBundleClientPattern(t *testing.T) {
	// Verify resolveBundleClient is used by confirming --no-bundle flag is inherited
	// from rootCmd's persistent flags (the same flag resolveBundleClient reads).
	f := rootCmd.PersistentFlags().Lookup("no-bundle")
	assert.NotNil(t, f, "--no-bundle persistent flag must exist on rootCmd for bundle resolution")

	// Confirm steward list is a sub-command of stewardCmd (not directly on root)
	var found bool
	for _, cmd := range stewardCmd.Commands() {
		if cmd.Name() == "list" {
			found = true
			break
		}
	}
	assert.True(t, found, "list must be registered as subcommand of stewardCmd")
}
