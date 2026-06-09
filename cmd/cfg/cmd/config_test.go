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

func TestConfigDiff_ShowsDifferences(t *testing.T) {
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		assert.Equal(t, "GET", r.Method)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"steward_id": "steward-diff-test",
				"version":    1,
				"config": map[string]interface{}{
					"hostname": "old-host.example.com",
				},
				"updated_at": "2026-06-09T10:00:00Z",
			},
			"timestamp": "2026-06-09T10:00:00Z",
		})
	}))
	defer server.Close()

	localConfig := "hostname: new-host.example.com\n"
	tmpFile := filepath.Join(t.TempDir(), "new-config.yaml")
	require.NoError(t, os.WriteFile(tmpFile, []byte(localConfig), 0600))

	origURL := configAPIURL
	origInsecure := configTLSInsecure
	origDiffJSON := configDiffJSON
	origSecrets := configDiffIncludeSecrets
	t.Cleanup(func() {
		configAPIURL = origURL
		configTLSInsecure = origInsecure
		configDiffJSON = origDiffJSON
		configDiffIncludeSecrets = origSecrets
	})

	configAPIURL = server.URL
	configTLSInsecure = true
	configDiffJSON = false
	configDiffIncludeSecrets = false

	var returnedErr error
	diffOutput := captureStdout(t, func() {
		returnedErr = runConfigDiff(configDiffCmd, []string{"steward-diff-test", tmpFile})
	})

	assert.Equal(t, "/api/v1/stewards/steward-diff-test/config", capturedPath)
	assert.ErrorIs(t, returnedErr, errDifferencesFound, "non-zero exit expected when configs differ")
	assert.NotEmpty(t, diffOutput, "diff output should be printed")
}

func TestConfigDiff_SecretsRedactedByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"steward_id": "steward-sec-test",
				"version":    1,
				"config": map[string]interface{}{
					"api_key":    "supersecretapikey",
					"password":   "mysecretpassword",
					"token":      "bearer-token-xyz",
					"secret_key": "verysecretvalue",
					"credential": "mycredential",
					"hostname":   "old-host.example.com",
				},
				"updated_at": "2026-06-09T10:00:00Z",
			},
			"timestamp": "2026-06-09T10:00:00Z",
		})
	}))
	defer server.Close()

	// Local file has a different hostname so hostname appears in the diff;
	// the secret fields only exist in the server config and will be shown as
	// deleted — redacted to *** — not as their raw values.
	localConfig := "hostname: new-host.example.com\n"
	tmpFile := filepath.Join(t.TempDir(), "new-config.yaml")
	require.NoError(t, os.WriteFile(tmpFile, []byte(localConfig), 0600))

	origURL := configAPIURL
	origInsecure := configTLSInsecure
	origDiffJSON := configDiffJSON
	origSecrets := configDiffIncludeSecrets
	t.Cleanup(func() {
		configAPIURL = origURL
		configTLSInsecure = origInsecure
		configDiffJSON = origDiffJSON
		configDiffIncludeSecrets = origSecrets
	})

	configAPIURL = server.URL
	configTLSInsecure = true
	configDiffJSON = false
	configDiffIncludeSecrets = false

	var returnedErr error
	diffOutput := captureStdout(t, func() {
		returnedErr = runConfigDiff(configDiffCmd, []string{"steward-sec-test", tmpFile})
	})

	// Configs differ (hostname changed and secret keys deleted)
	assert.ErrorIs(t, returnedErr, errDifferencesFound)

	// Secret values must NOT appear in output — they are redacted to ***
	assert.NotContains(t, diffOutput, "supersecretapikey")
	assert.NotContains(t, diffOutput, "mysecretpassword")
	assert.NotContains(t, diffOutput, "bearer-token-xyz")
	assert.NotContains(t, diffOutput, "verysecretvalue")
	assert.NotContains(t, diffOutput, "mycredential")

	// Non-secret hostname change appears in the diff output
	assert.Contains(t, diffOutput, "example.com")
}

func TestConfigDiff_404NoConfigStored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "config not found"})
	}))
	defer server.Close()

	tmpFile := filepath.Join(t.TempDir(), "new-config.yaml")
	require.NoError(t, os.WriteFile(tmpFile, []byte("hostname: example.com\n"), 0600))

	origURL := configAPIURL
	origInsecure := configTLSInsecure
	t.Cleanup(func() {
		configAPIURL = origURL
		configTLSInsecure = origInsecure
	})

	configAPIURL = server.URL
	configTLSInsecure = true

	var returnedErr error
	output := captureStdout(t, func() {
		returnedErr = runConfigDiff(configDiffCmd, []string{"unknown-steward", tmpFile})
	})

	require.NoError(t, returnedErr, "404 should exit 0 with informational message")
	assert.Contains(t, output, "No config stored for steward unknown-steward")
}

func TestConfigDiff_LocalFileNotFound(t *testing.T) {
	origURL := configAPIURL
	origInsecure := configTLSInsecure
	t.Cleanup(func() {
		configAPIURL = origURL
		configTLSInsecure = origInsecure
	})

	configAPIURL = "http://localhost:19999"
	configTLSInsecure = true

	err := runConfigDiff(configDiffCmd, []string{"steward-abc", "/nonexistent/path/config.yaml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file not found")
}

func TestConfigDiff_IncludeSecretsFlag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"steward_id": "steward-sec2",
				"version":    1,
				"config": map[string]interface{}{
					"api_key":  "plaintextsecret",
					"hostname": "example.com",
				},
				"updated_at": "2026-06-09T10:00:00Z",
			},
			"timestamp": "2026-06-09T10:00:00Z",
		})
	}))
	defer server.Close()

	localConfig := "hostname: example.com\n"
	tmpFile := filepath.Join(t.TempDir(), "new-config.yaml")
	require.NoError(t, os.WriteFile(tmpFile, []byte(localConfig), 0600))

	origURL := configAPIURL
	origInsecure := configTLSInsecure
	origSecrets := configDiffIncludeSecrets
	t.Cleanup(func() {
		configAPIURL = origURL
		configTLSInsecure = origInsecure
		configDiffIncludeSecrets = origSecrets
	})

	configAPIURL = server.URL
	configTLSInsecure = true
	configDiffIncludeSecrets = true // bypass redaction

	var returnedErr error
	diffOutput := captureStdout(t, func() {
		returnedErr = runConfigDiff(configDiffCmd, []string{"steward-sec2", tmpFile})
	})

	assert.ErrorIs(t, returnedErr, errDifferencesFound)
	// With --include-secrets, the actual value must appear in the diff output
	assert.Contains(t, diffOutput, "plaintextsecret")
}

func TestConfigDiff_IdenticalConfigsExitZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"steward_id": "steward-same",
				"version":    1,
				"config": map[string]interface{}{
					"hostname": "example.com",
				},
				"updated_at": "2026-06-09T10:00:00Z",
			},
			"timestamp": "2026-06-09T10:00:00Z",
		})
	}))
	defer server.Close()

	// Local file has the same content as the server config
	localConfig := "hostname: example.com\n"
	tmpFile := filepath.Join(t.TempDir(), "same-config.yaml")
	require.NoError(t, os.WriteFile(tmpFile, []byte(localConfig), 0600))

	origURL := configAPIURL
	origInsecure := configTLSInsecure
	t.Cleanup(func() {
		configAPIURL = origURL
		configTLSInsecure = origInsecure
	})

	configAPIURL = server.URL
	configTLSInsecure = true

	err := runConfigDiff(configDiffCmd, []string{"steward-same", tmpFile})
	require.NoError(t, err, "identical configs should exit 0")
}

func TestConfigDiff_APIErrorPropagated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	}))
	defer server.Close()

	tmpFile := filepath.Join(t.TempDir(), "new-config.yaml")
	require.NoError(t, os.WriteFile(tmpFile, []byte("hostname: example.com\n"), 0600))

	origURL := configAPIURL
	origInsecure := configTLSInsecure
	t.Cleanup(func() {
		configAPIURL = origURL
		configTLSInsecure = origInsecure
	})

	configAPIURL = server.URL
	configTLSInsecure = true

	err := runConfigDiff(configDiffCmd, []string{"steward-abc", tmpFile})
	require.Error(t, err)
	assert.NotErrorIs(t, err, errDifferencesFound, "API error should not be mistaken for differences")
}

func TestConfigDiff_JSONFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"steward_id": "steward-json",
				"version":    1,
				"config": map[string]interface{}{
					"hostname": "old-host.example.com",
				},
				"updated_at": "2026-06-09T10:00:00Z",
			},
			"timestamp": "2026-06-09T10:00:00Z",
		})
	}))
	defer server.Close()

	localConfig := "hostname: new-host.example.com\n"
	tmpFile := filepath.Join(t.TempDir(), "new-config.yaml")
	require.NoError(t, os.WriteFile(tmpFile, []byte(localConfig), 0600))

	origURL := configAPIURL
	origInsecure := configTLSInsecure
	origDiffJSON := configDiffJSON
	t.Cleanup(func() {
		configAPIURL = origURL
		configTLSInsecure = origInsecure
		configDiffJSON = origDiffJSON
	})

	configAPIURL = server.URL
	configTLSInsecure = true
	configDiffJSON = true // request JSON output

	var returnedErr error
	diffOutput := captureStdout(t, func() {
		returnedErr = runConfigDiff(configDiffCmd, []string{"steward-json", tmpFile})
	})

	assert.ErrorIs(t, returnedErr, errDifferencesFound)
	// JSON output must be valid JSON
	var parsed interface{}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(diffOutput)), &parsed), "--json output should be valid JSON")
}

func TestRedactSecrets_NestedMap(t *testing.T) {
	config := map[string]interface{}{
		"hostname": "example.com",
		"database": map[string]interface{}{
			"password": "db-secret",
			"host":     "db.example.com",
		},
		"api_key": "top-level-key",
	}

	redactSecrets(config)

	assert.Equal(t, "example.com", config["hostname"], "non-secret key must be unchanged")
	assert.Equal(t, "***", config["api_key"], "top-level secret key must be redacted")

	db, ok := config["database"].(map[string]interface{})
	require.True(t, ok, "database value must remain a map")
	assert.Equal(t, "***", db["password"], "nested secret key must be redacted")
	assert.Equal(t, "db.example.com", db["host"], "nested non-secret key must be unchanged")
}

func TestRedactSecrets_ArrayNestedSecrets(t *testing.T) {
	// Mirrors the real CFGMS config shape: resources is a list of maps
	// each with a nested config map that may contain secret keys.
	config := map[string]interface{}{
		"resources": []interface{}{
			map[string]interface{}{
				"name": "db-module",
				"config": map[string]interface{}{
					"password": "hunter2",
					"api_key":  "AKIA1234",
					"host":     "db.example.com",
				},
			},
			map[string]interface{}{
				"name":  "web-module",
				"token": "bearer-xyz",
				"host":  "web.example.com",
			},
		},
	}

	redactSecrets(config)

	resources, ok := config["resources"].([]interface{})
	require.True(t, ok, "resources must remain a slice")
	require.Len(t, resources, 2)

	db := resources[0].(map[string]interface{})
	assert.Equal(t, "db-module", db["name"], "non-secret key in array element must be unchanged")
	dbCfg := db["config"].(map[string]interface{})
	assert.Equal(t, "***", dbCfg["password"], "array-nested password must be redacted")
	assert.Equal(t, "***", dbCfg["api_key"], "array-nested api_key must be redacted")
	assert.Equal(t, "db.example.com", dbCfg["host"], "array-nested non-secret key must be unchanged")

	web := resources[1].(map[string]interface{})
	assert.Equal(t, "***", web["token"], "array element top-level token must be redacted")
	assert.Equal(t, "web.example.com", web["host"], "array element non-secret key must be unchanged")
}

func TestConfigRollback_ExecutesRollback(t *testing.T) {
	t.Run("calls execute endpoint with correct body and polls status", func(t *testing.T) {
		var (
			executeMethod string
			executePath   string
			executeBody   string
			statusPath    string
		)

		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			switch {
			case r.Method == "POST" && r.URL.Path == "/api/v1/rollback/execute":
				executeMethod = r.Method
				executePath = r.URL.Path
				bodyBytes, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				executeBody = string(bodyBytes)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"rollback": map[string]interface{}{
						"id":     "rb-001",
						"status": "pending",
					},
				})
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v1/rollback/"):
				statusPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"rollback": map[string]interface{}{
						"id":     "rb-001",
						"status": "completed",
					},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origTo := configRollbackTo
		origDryRun := configRollbackDryRun
		origJSON := configRollbackJSON
		origPollInterval := rollbackPollInterval
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configRollbackTo = origTo
			configRollbackDryRun = origDryRun
			configRollbackJSON = origJSON
			rollbackPollInterval = origPollInterval
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configRollbackTo = "abc1234567890"
		configRollbackDryRun = false
		configRollbackJSON = false
		rollbackPollInterval = 0 // no sleep in tests

		output := captureStdout(t, func() {
			err := runConfigRollback(configRollbackCmd, []string{"steward-abc"})
			require.NoError(t, err)
		})

		assert.Equal(t, "POST", executeMethod)
		assert.Equal(t, "/api/v1/rollback/execute", executePath)
		assert.Equal(t, "/api/v1/rollback/rb-001/status", statusPath)
		assert.Contains(t, output, "completed")

		// Verify request body uses rollback_to field (not "version")
		var reqBody map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(executeBody), &reqBody))
		assert.Equal(t, "abc1234567890", reqBody["rollback_to"])
		assert.Equal(t, "steward", reqBody["target_type"])
		assert.Equal(t, "steward-abc", reqBody["target_id"])
		_, hasVersion := reqBody["version"]
		assert.False(t, hasVersion, "request body must use rollback_to not version")
	})

	t.Run("surfaces 412 approval required message", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionFailed)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "approval required"})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origTo := configRollbackTo
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configRollbackTo = origTo
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configRollbackTo = "abc123"

		err := runConfigRollback(configRollbackCmd, []string{"steward-abc"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "412")
	})

	t.Run("surfaces 409 in-progress message", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "rollback in progress"})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origTo := configRollbackTo
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configRollbackTo = origTo
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configRollbackTo = "abc123"

		err := runConfigRollback(configRollbackCmd, []string{"steward-abc"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "409")
	})

	t.Run("surfaces 403 permission denied as error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "permission denied"})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origTo := configRollbackTo
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configRollbackTo = origTo
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configRollbackTo = "abc123"

		err := runConfigRollback(configRollbackCmd, []string{"steward-abc"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "403")
	})

	t.Run("surfaces 422 validation failed as error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "validation failed"})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origTo := configRollbackTo
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configRollbackTo = origTo
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configRollbackTo = "abc123"

		err := runConfigRollback(configRollbackCmd, []string{"steward-abc"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "422")
	})
}

func TestConfigRollback_DryRun(t *testing.T) {
	t.Run("calls preview endpoint when --dry-run is set", func(t *testing.T) {
		var (
			capturedMethod string
			capturedPath   string
			capturedBody   string
		)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedMethod = r.Method
			capturedPath = r.URL.Path
			bodyBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			capturedBody = string(bodyBytes)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"preview": map[string]interface{}{
					"changes":           []interface{}{},
					"affected_modules":  []string{},
					"requires_approval": false,
				},
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origTo := configRollbackTo
		origDryRun := configRollbackDryRun
		origJSON := configRollbackJSON
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configRollbackTo = origTo
			configRollbackDryRun = origDryRun
			configRollbackJSON = origJSON
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configRollbackTo = "abc1234567890"
		configRollbackDryRun = true
		configRollbackJSON = false

		output := captureStdout(t, func() {
			err := runConfigRollback(configRollbackCmd, []string{"steward-abc"})
			require.NoError(t, err)
		})

		assert.Equal(t, "POST", capturedMethod)
		assert.Equal(t, "/api/v1/rollback/preview", capturedPath)
		assert.Contains(t, output, "preview")

		// Verify request body uses rollback_to field
		var reqBody map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(capturedBody), &reqBody))
		assert.Equal(t, "abc1234567890", reqBody["rollback_to"])
	})
}

func TestConfigRollback_ListsPointsWhenNoVersion(t *testing.T) {
	t.Run("lists rollback points when --to is omitted", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"rollback_points": []map[string]interface{}{
					{
						"commit_sha":   "abc1234567890",
						"timestamp":    "2026-06-01T10:00:00Z",
						"author":       "admin",
						"message":      "Update config",
						"risk_level":   "low",
						"can_rollback": true,
					},
				},
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origTo := configRollbackTo
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configRollbackTo = origTo
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configRollbackTo = "" // omitted

		output := captureStdout(t, func() {
			err := runConfigRollback(configRollbackCmd, []string{"steward-abc"})
			require.NoError(t, err)
		})

		assert.Contains(t, capturedQuery, "target_type=steward")
		assert.Contains(t, capturedQuery, "target_id=steward-abc")
		assert.Contains(t, output, "abc1234567890")
	})

	t.Run("prints empty message when no rollback points", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"rollback_points": []interface{}{},
			})
		}))
		defer server.Close()

		origURL := configAPIURL
		origInsecure := configTLSInsecure
		origTo := configRollbackTo
		t.Cleanup(func() {
			configAPIURL = origURL
			configTLSInsecure = origInsecure
			configRollbackTo = origTo
		})

		configAPIURL = server.URL
		configTLSInsecure = true
		configRollbackTo = ""

		output := captureStdout(t, func() {
			err := runConfigRollback(configRollbackCmd, []string{"steward-abc"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "No rollback points available")
	})
}
