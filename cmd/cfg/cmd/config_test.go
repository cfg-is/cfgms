// SPDX-License-Identifier: AGPL-3.0-only
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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigListCommand(t *testing.T) {
	t.Run("happy path prints table with configs", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "/api/v1/configs", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"steward_id": "steward-abc",
						"tenant_id":  "acme-corp",
						"version":    3,
						"updated_at": "2026-05-20T10:00:00Z",
						"updated_by": "admin",
					},
				},
				"timestamp": "2026-05-20T10:00:00Z",
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origJSON := configListJSON
		origTenant := configListTenantID
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configListJSON = origJSON
			configListTenantID = origTenant
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configListJSON = false
		configListTenantID = ""

		output := captureStdout(t, func() {
			err := runConfigList(configListCmd, []string{})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "steward-abc")
		assert.Contains(t, output, "acme-corp")
	})

	t.Run("empty list prints no configurations found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data":      []interface{}{},
				"timestamp": "2026-05-20T10:00:00Z",
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origJSON := configListJSON
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configListJSON = origJSON
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configListJSON = false

		output := captureStdout(t, func() {
			err := runConfigList(configListCmd, []string{})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "No configurations found")
	})

	t.Run("tenant flag appended as query param", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data":      []interface{}{},
				"timestamp": "2026-05-20T10:00:00Z",
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origTenant := configListTenantID
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configListTenantID = origTenant
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configListTenantID = "my-tenant"

		_ = captureStdout(t, func() {
			err := runConfigList(configListCmd, []string{})
			require.NoError(t, err)
		})

		assert.Equal(t, "tenant_id=my-tenant", capturedQuery)
	})

	t.Run("API error propagated", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
		})

		configAPIURL = server.URL
		configTLSInsecure = true

		err := runConfigList(configListCmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized")
	})
}

func TestConfigShowCommand(t *testing.T) {
	t.Run("happy path prints config for steward", func(t *testing.T) {
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			assert.Equal(t, "GET", r.Method)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"steward_id": "steward-xyz",
					"version":    2,
					"config": map[string]interface{}{
						"steward": map[string]interface{}{"id": "steward-xyz"},
					},
				},
				"timestamp": "2026-05-20T10:00:00Z",
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origJSON := configShowJSON
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configShowJSON = origJSON
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configShowJSON = false

		output := captureStdout(t, func() {
			err := runConfigShow(configShowCmd, []string{"steward-xyz"})
			require.NoError(t, err)
		})

		assert.Equal(t, "/api/v1/stewards/steward-xyz/config", capturedPath)
		assert.Contains(t, output, "steward-xyz")
	})

	t.Run("404 not found propagated as error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "config not found"})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
		})

		configAPIURL = server.URL
		configTLSInsecure = true

		err := runConfigShow(configShowCmd, []string{"missing-steward"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config not found")
	})

	t.Run("json flag emits raw response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data":      map[string]interface{}{"steward_id": "s1"},
				"timestamp": "2026-05-20T10:00:00Z",
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origJSON := configShowJSON
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configShowJSON = origJSON
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configShowJSON = true

		output := captureStdout(t, func() {
			err := runConfigShow(configShowCmd, []string{"s1"})
			require.NoError(t, err)
		})

		var parsed interface{}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed), "output should be valid JSON")
	})
}

func TestConfigDeleteCommand(t *testing.T) {
	t.Run("happy path prints confirmation on 204", func(t *testing.T) {
		var capturedMethod, capturedPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedMethod = r.Method
			capturedPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
		})

		configAPIURL = server.URL
		configTLSInsecure = true

		output := captureStdout(t, func() {
			err := runConfigDelete(configDeleteCmd, []string{"steward-del"})
			require.NoError(t, err)
		})

		assert.Equal(t, "DELETE", capturedMethod)
		assert.Equal(t, "/api/v1/stewards/steward-del/config", capturedPath)
		assert.Contains(t, output, "deleted")
	})

	t.Run("404 not found propagated as error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "config not found"})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
		})

		configAPIURL = server.URL
		configTLSInsecure = true

		err := runConfigDelete(configDeleteCmd, []string{"nonexistent"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config not found")
	})

	t.Run("API error propagated", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
		})

		configAPIURL = server.URL
		configTLSInsecure = true

		err := runConfigDelete(configDeleteCmd, []string{"some-steward"})
		require.Error(t, err)
	})
}

func TestConfigDeploymentsCommand(t *testing.T) {
	t.Run("happy path prints summary and steward table", func(t *testing.T) {
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			assert.Equal(t, "GET", r.Method)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"config_id": "cfg-prod",
					"summary": map[string]interface{}{
						"applied": 2,
						"pending": 1,
						"failed":  0,
						"halted":  0,
						"total":   3,
					},
					"stewards": []map[string]interface{}{
						{
							"steward_id":   "steward-001",
							"status":       "applied",
							"last_updated": time.Now().UTC().Format(time.RFC3339),
						},
					},
					"push_history": []map[string]interface{}{},
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origJSON := configDeploymentsJSON
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configDeploymentsJSON = origJSON
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configDeploymentsJSON = false

		output := captureStdout(t, func() {
			err := runConfigDeployments(configDeploymentsCmd, []string{"cfg-prod"})
			require.NoError(t, err)
		})

		assert.Equal(t, "/api/v1/configs/cfg-prod/deployments", capturedPath)
		assert.Contains(t, output, "cfg-prod")
		assert.Contains(t, output, "Applied:")
		assert.Contains(t, output, "2")
		assert.Contains(t, output, "steward-001")
		assert.Contains(t, output, "applied")
	})

	t.Run("config ID with special chars is path-escaped", func(t *testing.T) {
		var capturedRawPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// r.URL.RawPath preserves the original percent-encoded path;
			// r.URL.Path is the decoded form — use RawPath to verify encoding.
			capturedRawPath = r.URL.RawPath
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"config_id":    "cfg/prod env",
					"summary":      map[string]interface{}{"applied": 0, "pending": 0, "failed": 0, "halted": 0, "total": 0},
					"stewards":     []interface{}{},
					"push_history": []interface{}{},
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origJSON := configDeploymentsJSON
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configDeploymentsJSON = origJSON
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configDeploymentsJSON = false

		_ = captureStdout(t, func() {
			_ = runConfigDeployments(configDeploymentsCmd, []string{"cfg/prod env"})
		})

		assert.Equal(t, "/api/v1/configs/cfg%2Fprod%20env/deployments", capturedRawPath)
	})

	t.Run("empty stewards prints no stewards found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"config_id":    "cfg-empty",
					"summary":      map[string]interface{}{"applied": 0, "pending": 0, "failed": 0, "halted": 0, "total": 0},
					"stewards":     []interface{}{},
					"push_history": []interface{}{},
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origJSON := configDeploymentsJSON
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configDeploymentsJSON = origJSON
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configDeploymentsJSON = false

		output := captureStdout(t, func() {
			err := runConfigDeployments(configDeploymentsCmd, []string{"cfg-empty"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "No stewards found")
	})

	t.Run("json flag emits raw API response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"config_id":    "cfg-prod",
					"summary":      map[string]interface{}{"applied": 1, "pending": 0, "failed": 0, "halted": 0, "total": 1},
					"stewards":     []interface{}{},
					"push_history": []interface{}{},
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origJSON := configDeploymentsJSON
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configDeploymentsJSON = origJSON
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configDeploymentsJSON = true

		output := captureStdout(t, func() {
			err := runConfigDeployments(configDeploymentsCmd, []string{"cfg-prod"})
			require.NoError(t, err)
		})

		var parsed interface{}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed), "output should be valid JSON")
		assert.Contains(t, output, "config_id")
	})

	t.Run("API error propagated", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
		})

		configAPIURL = server.URL
		configTLSInsecure = true

		err := runConfigDeployments(configDeploymentsCmd, []string{"cfg-prod"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized")
	})
}

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
