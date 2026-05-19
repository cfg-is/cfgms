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
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigUploadCommand(t *testing.T) {
	t.Run("happy path sends PUT with yaml content type", func(t *testing.T) {
		var (
			capturedMethod      string
			capturedPath        string
			capturedContentType string
			capturedBody        string
		)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedMethod = r.Method
			capturedPath = r.URL.Path
			capturedContentType = r.Header.Get("Content-Type")

			bodyBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			capturedBody = string(bodyBytes)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{
					"steward_id": "test-steward",
					"tenant_id":  "default",
					"status":     "stored",
					"message":    "Configuration stored successfully",
				},
				"timestamp": "2026-05-19T00:00:00Z",
			})
		}))
		defer server.Close()

		yamlContent := "resources:\n  - type: file\n    name: test\n"
		tmpFile := filepath.Join(t.TempDir(), "fleet-config.yaml")
		require.NoError(t, os.WriteFile(tmpFile, []byte(yamlContent), 0600))

		origURL := configUploadURL
		origInsecure := configUploadTLSInsecure
		origStewardID := configUploadStewardID
		origJSON := configUploadJSONOutput
		t.Cleanup(func() {
			configUploadURL = origURL
			configUploadTLSInsecure = origInsecure
			configUploadStewardID = origStewardID
			configUploadJSONOutput = origJSON
		})

		configUploadURL = server.URL
		configUploadTLSInsecure = true
		configUploadStewardID = "test-steward"
		configUploadJSONOutput = false

		output := captureStdout(t, func() {
			err := runConfigUpload(configUploadCmd, []string{tmpFile})
			require.NoError(t, err)
		})

		assert.Equal(t, "PUT", capturedMethod)
		assert.Equal(t, "/api/v1/stewards/test-steward/config", capturedPath)
		assert.Equal(t, "application/yaml", capturedContentType)
		assert.Equal(t, yamlContent, capturedBody)
		assert.Contains(t, output, "Configuration stored for steward test-steward (status: stored)")
	})

	t.Run("file not found returns error before HTTP call", func(t *testing.T) {
		httpCallCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpCallCount++
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		origURL := configUploadURL
		origStewardID := configUploadStewardID
		t.Cleanup(func() {
			configUploadURL = origURL
			configUploadStewardID = origStewardID
		})

		configUploadURL = server.URL
		configUploadStewardID = "test-steward"

		err := runConfigUpload(configUploadCmd, []string{"/nonexistent/path/config.yaml"})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "file not found")
		assert.Equal(t, 0, httpCallCount, "no HTTP call should be made when file not found")
	})

	t.Run("empty file returns error before HTTP call", func(t *testing.T) {
		httpCallCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpCallCount++
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tmpFile := filepath.Join(t.TempDir(), "empty-config.yaml")
		require.NoError(t, os.WriteFile(tmpFile, []byte{}, 0600))

		origURL := configUploadURL
		origStewardID := configUploadStewardID
		t.Cleanup(func() {
			configUploadURL = origURL
			configUploadStewardID = origStewardID
		})

		configUploadURL = server.URL
		configUploadStewardID = "test-steward"

		err := runConfigUpload(configUploadCmd, []string{tmpFile})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "file is empty")
		assert.Equal(t, 0, httpCallCount, "no HTTP call should be made when file is empty")
	})

	t.Run("missing steward flag returns error before HTTP call", func(t *testing.T) {
		httpCallCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpCallCount++
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		yamlContent := "resources: []\n"
		tmpFile := filepath.Join(t.TempDir(), "fleet-config.yaml")
		require.NoError(t, os.WriteFile(tmpFile, []byte(yamlContent), 0600))

		origURL := configUploadURL
		origStewardID := configUploadStewardID
		t.Cleanup(func() {
			configUploadURL = origURL
			configUploadStewardID = origStewardID
		})

		configUploadURL = server.URL
		configUploadStewardID = ""

		err := runConfigUpload(configUploadCmd, []string{tmpFile})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "--steward")
		assert.Equal(t, 0, httpCallCount, "no HTTP call should be made when steward ID is missing")
	})

	t.Run("HTTP 4xx error propagated", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "steward not found",
			})
		}))
		defer server.Close()

		yamlContent := "resources: []\n"
		tmpFile := filepath.Join(t.TempDir(), "fleet-config.yaml")
		require.NoError(t, os.WriteFile(tmpFile, []byte(yamlContent), 0600))

		origURL := configUploadURL
		origInsecure := configUploadTLSInsecure
		origStewardID := configUploadStewardID
		t.Cleanup(func() {
			configUploadURL = origURL
			configUploadTLSInsecure = origInsecure
			configUploadStewardID = origStewardID
		})

		configUploadURL = server.URL
		configUploadTLSInsecure = true
		configUploadStewardID = "nonexistent-steward"

		err := runConfigUpload(configUploadCmd, []string{tmpFile})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "steward not found")
	})

	t.Run("json flag emits raw API response JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{
					"steward_id": "test-steward",
					"tenant_id":  "default",
					"status":     "stored",
					"message":    "Configuration stored successfully",
				},
				"timestamp": "2026-05-19T00:00:00Z",
			})
		}))
		defer server.Close()

		yamlContent := "resources: []\n"
		tmpFile := filepath.Join(t.TempDir(), "fleet-config.yaml")
		require.NoError(t, os.WriteFile(tmpFile, []byte(yamlContent), 0600))

		origURL := configUploadURL
		origInsecure := configUploadTLSInsecure
		origStewardID := configUploadStewardID
		origJSON := configUploadJSONOutput
		t.Cleanup(func() {
			configUploadURL = origURL
			configUploadTLSInsecure = origInsecure
			configUploadStewardID = origStewardID
			configUploadJSONOutput = origJSON
		})

		configUploadURL = server.URL
		configUploadTLSInsecure = true
		configUploadStewardID = "test-steward"
		configUploadJSONOutput = true

		output := captureStdout(t, func() {
			err := runConfigUpload(configUploadCmd, []string{tmpFile})
			require.NoError(t, err)
		})

		assert.True(t, strings.Contains(output, "steward_id"), "JSON output should contain steward_id")
		assert.True(t, strings.Contains(output, "stored"), "JSON output should contain stored status")
		// Verify output is valid JSON
		var parsed interface{}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed), "output should be valid JSON")
	})
}
