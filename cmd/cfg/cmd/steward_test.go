// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrapWithResolve wraps an http.HandlerFunc so that POST /api/v1/fleet/resolve
// returns a single-element fleet containing the given stewardID (with no DNA).
// All other requests are delegated to the wrapped handler. This lets existing
// single-ID tests work correctly now that the commands call resolveOrFailFast
// before issuing per-steward requests.
func wrapWithResolve(t *testing.T, stewardID string, next http.HandlerFunc) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve" {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(struct {
				Data []StewardInfo `json:"data"`
			}{Data: []StewardInfo{{ID: stewardID}}}); err != nil {
				t.Errorf("encode resolve: %v", err)
			}
			return
		}
		next(w, r)
	}
}

func TestStewardList_CallsGetStewardsEndpoint(t *testing.T) {
	now := time.Now().UTC()
	stewards := []map[string]interface{}{
		{"id": "steward-abc", "status": "connected", "last_seen": now.Format(time.RFC3339)},
		{"id": "steward-xyz", "status": "offline", "last_seen": now.Add(-5 * time.Minute).Format(time.RFC3339)},
	}

	var requestPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/registration/pending" {
			_ = json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		requestPath = r.URL.Path
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
		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		})
		server := httptest.NewServer(wrapWithResolve(t, "steward-abc123", innerHandler))
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
		// Resolve returns the steward, then the status fetch returns 404.
		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "steward not found"})
		})
		server := httptest.NewServer(wrapWithResolve(t, "nonexistent-steward-id", innerHandler))
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
		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
		})
		server := httptest.NewServer(wrapWithResolve(t, "steward-abc123", innerHandler))
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

	t.Run("json flag emits keyed JSON response", func(t *testing.T) {
		now := time.Now().UTC()
		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":     "steward-abc123",
					"status": "connected",
				},
				"timestamp": now,
			})
		})
		server := httptest.NewServer(wrapWithResolve(t, "steward-abc123", innerHandler))
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

		// --json now emits a keyed-by-steward array (story 4 schema).
		var entries []KeyedOutputEntry
		require.NoError(t, json.Unmarshal([]byte(output), &entries), "output must be a valid JSON array")
		require.Len(t, entries, 1)
		assert.True(t, entries[0].Success)
		assert.Contains(t, output, "steward-abc123")
	})
}

// TestStewardModules_CallsEndpoint verifies that the modules command calls the correct
// API path and prints the 501 unavailability message without erroring.
func TestStewardModules_CallsEndpoint(t *testing.T) {
	var requestPath string
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]string{
				"code":    "MODULES_UNAVAILABLE",
				"message": "steward does not report loaded modules in DNA; ensure steward version supports module DNA attributes",
			},
		})
	})
	server := httptest.NewServer(wrapWithResolve(t, "steward-abc123", innerHandler))
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
		err := runStewardModules(stewardModulesCmd, []string{"steward-abc123"})
		require.NoError(t, err, "501 response must not error the command")
	})

	assert.Equal(t, "/api/v1/stewards/steward-abc123/modules", requestPath)
	assert.Contains(t, output, "Module list not available")
}

func TestStewardModules_NotFound(t *testing.T) {
	// Resolve returns the steward; then the modules fetch returns 404.
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]string{"code": "STEWARD_NOT_FOUND", "message": "Steward not found"},
		})
	})
	server := httptest.NewServer(wrapWithResolve(t, "nonexistent-steward", innerHandler))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
	})
	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runStewardModules(stewardModulesCmd, []string{"nonexistent-steward"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestStewardModules_NonOKStatusReturnsError(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
	})
	server := httptest.NewServer(wrapWithResolve(t, "steward-abc123", innerHandler))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
	})
	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runStewardModules(stewardModulesCmd, []string{"steward-abc123"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestStewardModules_JSONFlag(t *testing.T) {
	now := time.Now().UTC()
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data":      map[string]interface{}{"modules": []map[string]string{{"name": "file"}}},
			"timestamp": now,
		})
	})
	server := httptest.NewServer(wrapWithResolve(t, "steward-abc123", innerHandler))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origJSON := stewardModulesJSON
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardModulesJSON = origJSON
	})
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardModulesJSON = true

	output := captureStdout(t, func() {
		err := runStewardModules(stewardModulesCmd, []string{"steward-abc123"})
		require.NoError(t, err)
	})

	// --json now emits a keyed-by-steward array (story 4 schema).
	var entries []KeyedOutputEntry
	require.NoError(t, json.Unmarshal([]byte(output), &entries), "output must be a valid JSON array")
	require.Len(t, entries, 1)
	assert.True(t, entries[0].Success)
	assert.Contains(t, output, "file")
}

func TestStewardLogs_JSONFlag(t *testing.T) {
	now := time.Now().UTC()
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"lines": []map[string]string{
				{
					"timestamp": now.Format(time.RFC3339),
					"level":     "info",
					"module":    "file",
					"message":   "convergence-complete",
				},
			},
		})
	})
	server := httptest.NewServer(wrapWithResolve(t, "steward-abc123", innerHandler))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origJSON := stewardLogsJSON
	origTail := stewardLogsTail
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardLogsJSON = origJSON
		stewardLogsTail = origTail
	})
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardLogsJSON = true
	stewardLogsTail = 100

	output := captureStdout(t, func() {
		err := runStewardLogs(stewardLogsCmd, []string{"steward-abc123"})
		require.NoError(t, err)
	})

	// --json emits a keyed-by-steward array (story 4 schema).
	var entries []KeyedOutputEntry
	require.NoError(t, json.Unmarshal([]byte(output), &entries), "output must be a valid JSON array")
	require.Len(t, entries, 1)
	assert.True(t, entries[0].Success)
	assert.Contains(t, output, "convergence-complete")
}

func TestStewardModules_HappyPath(t *testing.T) {
	now := time.Now().UTC()
	var requestPath string
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"modules": []map[string]string{
					{"name": "file"},
					{"name": "service"},
					{"name": "package"},
				},
			},
			"timestamp": now,
		})
	})
	server := httptest.NewServer(wrapWithResolve(t, "steward-abc123", innerHandler))
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
		err := runStewardModules(stewardModulesCmd, []string{"steward-abc123"})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/stewards/steward-abc123/modules", requestPath)
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "file")
	assert.Contains(t, output, "service")
	assert.Contains(t, output, "package")
}

func TestStewardLogs_CallsEndpoint(t *testing.T) {
	var requestPath string
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"code":    "LOGS_UNAVAILABLE",
			"message": "steward log pull not yet supported; collect logs directly from the steward host",
		})
	})
	server := httptest.NewServer(wrapWithResolve(t, "steward-abc", innerHandler))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origTail := stewardLogsTail
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardLogsTail = origTail
	})
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardLogsTail = 100

	output := captureStdout(t, func() {
		err := runStewardLogs(stewardLogsCmd, []string{"steward-abc"})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/stewards/steward-abc/logs", requestPath)
	assert.Contains(t, output, "not yet available")
}

func TestStewardLogs_HandlesNotImplemented(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "LOGS_UNAVAILABLE"})
	})
	server := httptest.NewServer(wrapWithResolve(t, "steward-abc", innerHandler))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origTail := stewardLogsTail
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardLogsTail = origTail
	})
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardLogsTail = 100

	err := runStewardLogs(stewardLogsCmd, []string{"steward-abc"})
	assert.NoError(t, err, "501 response must not return an error")
}

func TestStewardLogs_NotFound(t *testing.T) {
	// Resolve returns the steward; then the logs fetch returns 404.
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]string{"code": "STEWARD_NOT_FOUND", "message": "Steward not found"},
		})
	})
	server := httptest.NewServer(wrapWithResolve(t, "nonexistent-steward", innerHandler))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origTail := stewardLogsTail
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardLogsTail = origTail
	})
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardLogsTail = 100

	err := runStewardLogs(stewardLogsCmd, []string{"nonexistent-steward"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestStewardLogs_NonOKStatusReturnsError(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
	})
	server := httptest.NewServer(wrapWithResolve(t, "steward-abc", innerHandler))
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origTail := stewardLogsTail
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardLogsTail = origTail
	})
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardLogsTail = 100

	err := runStewardLogs(stewardLogsCmd, []string{"steward-abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
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

// ---- steward dna tests ----

// TestStewardDNA_CallsEndpoint verifies that `cfg steward dna <id>` calls
// GET /api/v1/stewards/<id>/dna and that the tabular output contains "Hostname".
func TestStewardDNA_CallsEndpoint(t *testing.T) {
	var requestPath string
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"hostname":     "myhost",
				"os":           "linux",
				"architecture": "amd64",
				"collected_at": "2026-06-09T10:00:00Z",
				"attributes": map[string]string{
					"env": "prod",
				},
			},
			"timestamp": time.Now().UTC(),
		})
	})
	srv := httptest.NewServer(wrapWithResolve(t, "steward-abc", innerHandler))
	defer srv.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origAttr := stewardDNAAttribute
	origJSON := stewardDNAJSONOutput
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardDNAAttribute = origAttr
		stewardDNAJSONOutput = origJSON
	})

	stewardURL = srv.URL
	stewardTLSInsecure = true
	stewardDNAAttribute = ""
	stewardDNAJSONOutput = false

	output := captureStdout(t, func() {
		err := runStewardDNA(stewardDNACmd, []string{"steward-abc"})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/stewards/steward-abc/dna", requestPath)
	assert.Contains(t, output, "Hostname")
	assert.Contains(t, output, "myhost")
}

// TestStewardDNA_AttributeFlag verifies that --attribute appends the query parameter
// and prints only the raw value (no label) for a single-match selector.
func TestStewardDNA_AttributeFlag(t *testing.T) {
	var requestURL string
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "linux"})
	})
	srv := httptest.NewServer(wrapWithResolve(t, "steward-xyz", innerHandler))
	defer srv.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origAttr := stewardDNAAttribute
	origJSON := stewardDNAJSONOutput
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardDNAAttribute = origAttr
		stewardDNAJSONOutput = origJSON
	})

	stewardURL = srv.URL
	stewardTLSInsecure = true
	stewardDNAAttribute = "os"
	stewardDNAJSONOutput = false

	output := captureStdout(t, func() {
		err := runStewardDNA(stewardDNACmd, []string{"steward-xyz"})
		require.NoError(t, err)
	})

	assert.Contains(t, requestURL, "attribute=os")
	// Single match with --attribute: plain value (backward compatible).
	assert.Equal(t, "linux\n", output)
}

// TestStewardDNA_AttributeNotFound verifies non-zero exit (error) when the server returns 404.
func TestStewardDNA_AttributeNotFound(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]string{"code": "DNA_ATTRIBUTE_NOT_FOUND", "message": "attribute not found"},
		})
	})
	srv := httptest.NewServer(wrapWithResolve(t, "steward-abc", innerHandler))
	defer srv.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origAttr := stewardDNAAttribute
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardDNAAttribute = origAttr
	})

	stewardURL = srv.URL
	stewardTLSInsecure = true
	stewardDNAAttribute = "nonexistent"

	err := runStewardDNA(stewardDNACmd, []string{"steward-abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

// TestStewardDNA_JSONOutput verifies that --json emits a keyed-by-steward JSON array
// (story 4 schema) with the raw DNA payload embedded per entry.
func TestStewardDNA_JSONOutput(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"hostname": "myhost", "os": "linux"},
		})
	})
	srv := httptest.NewServer(wrapWithResolve(t, "steward-abc", innerHandler))
	defer srv.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origAttr := stewardDNAAttribute
	origJSON := stewardDNAJSONOutput
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardDNAAttribute = origAttr
		stewardDNAJSONOutput = origJSON
	})

	stewardURL = srv.URL
	stewardTLSInsecure = true
	stewardDNAAttribute = ""
	stewardDNAJSONOutput = true

	output := captureStdout(t, func() {
		err := runStewardDNA(stewardDNACmd, []string{"steward-abc"})
		require.NoError(t, err)
	})

	// --json now emits a keyed-by-steward array (story 4 schema).
	var entries []KeyedOutputEntry
	require.NoError(t, json.Unmarshal([]byte(output), &entries), "output must be a valid JSON array")
	require.Len(t, entries, 1)
	assert.True(t, entries[0].Success)
	assert.Contains(t, output, "myhost")
}

// ---- cfg steward move tests (Issue #2342, updated for selector in #2444) ----

// newSingleStewardMoveServer creates a test server serving fleet/resolve (returning
// singleID as the only match) and the move endpoint via the given moveHandler.
func newSingleStewardMoveServer(t *testing.T, singleID string, moveHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve" {
			_ = json.NewEncoder(w).Encode(struct {
				Data []StewardInfo `json:"data"`
			}{Data: []StewardInfo{{ID: singleID}}})
			return
		}
		moveHandler(w, r)
	}))
}

func TestStewardMove_Success(t *testing.T) {
	var requestPath string
	var requestMethod string
	var requestBody map[string]string

	server := newSingleStewardMoveServer(t, "steward-abc", func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		requestMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&requestBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"steward_id":      "steward-abc",
				"tenant_id":       "dest-tenant",
				"previous_tenant": "source-tenant",
				"status":          "moved",
			},
		})
	})
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origToTenant := stewardMoveToTenant
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardMoveToTenant = origToTenant
	})

	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardMoveToTenant = "dest-tenant"

	output := captureStdout(t, func() {
		err := runStewardMove(stewardMoveCmd, []string{"steward-abc"})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/stewards/steward-abc/move", requestPath)
	assert.Equal(t, http.MethodPost, requestMethod)
	assert.Equal(t, "dest-tenant", requestBody["new_tenant_id"])
	assert.Contains(t, output, "moved")
	assert.Contains(t, output, "dest-tenant")
}

func TestStewardMove_NoChange(t *testing.T) {
	server := newSingleStewardMoveServer(t, "steward-abc", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"steward_id":      "steward-abc",
				"tenant_id":       "same-tenant",
				"previous_tenant": "same-tenant",
				"status":          "no_change",
			},
		})
	})
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origToTenant := stewardMoveToTenant
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardMoveToTenant = origToTenant
	})

	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardMoveToTenant = "same-tenant"

	output := captureStdout(t, func() {
		err := runStewardMove(stewardMoveCmd, []string{"steward-abc"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "no change")
}

func TestStewardMove_Forbidden_ReturnsClearError(t *testing.T) {
	server := newSingleStewardMoveServer(t, "steward-abc", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "INSUFFICIENT_SCOPE",
				"message": "Insufficient scope to move steward between these tenants",
			},
		})
	})
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origToTenant := stewardMoveToTenant
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardMoveToTenant = origToTenant
	})

	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardMoveToTenant = "other-tenant"

	err := runStewardMove(stewardMoveCmd, []string{"steward-abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "move denied")
	assert.Contains(t, err.Error(), "steward-abc")
}

func TestStewardMove_StewardNotFound_Returns404Error(t *testing.T) {
	server := newSingleStewardMoveServer(t, "unknown-steward", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "STEWARD_NOT_FOUND",
				"message": "Steward not found",
			},
		})
	})
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origToTenant := stewardMoveToTenant
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardMoveToTenant = origToTenant
	})

	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardMoveToTenant = "dest-tenant"

	err := runStewardMove(stewardMoveCmd, []string{"unknown-steward"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestStewardMove_FlagsRegistered(t *testing.T) {
	assert.NotNil(t, stewardMoveCmd.Flags().Lookup("url"), "--url flag must be registered")
	assert.NotNil(t, stewardMoveCmd.Flags().Lookup("tls-ca-cert"), "--tls-ca-cert flag must be registered")
	assert.NotNil(t, stewardMoveCmd.Flags().Lookup("tls-insecure"), "--tls-insecure flag must be registered")
	assert.NotNil(t, stewardMoveCmd.Flags().Lookup("to-tenant"), "--to-tenant flag must be registered")
	assert.NotNil(t, stewardMoveCmd.Flags().Lookup("json"), "--json flag must be registered")
}

// ---- cfg steward decommission tests (Issue #2408, updated for selector in #2444) ----

// newSingleStewardDecommissionServer creates a test server serving fleet/resolve (returning
// singleID as the only match) and DELETE /api/v1/stewards/{id} via decommHandler.
func newSingleStewardDecommissionServer(t *testing.T, singleID string, decommHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve" {
			_ = json.NewEncoder(w).Encode(struct {
				Data []StewardInfo `json:"data"`
			}{Data: []StewardInfo{{ID: singleID}}})
			return
		}
		decommHandler(w, r)
	}))
}

// TestStewardDecommission_CallsDeleteEndpoint verifies that decommission issues an
// HTTP DELETE to /api/v1/stewards/{id} and reports success on 200.
func TestStewardDecommission_CallsDeleteEndpoint(t *testing.T) {
	var requestPath string
	var requestMethod string

	server := newSingleStewardDecommissionServer(t, "steward-abc123", func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		requestMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":     "steward-abc123",
				"status": "deregistered",
			},
		})
	})
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
		err := runStewardDecommission(stewardDecommissionCmd, []string{"steward-abc123"})
		require.NoError(t, err)
	})

	assert.Equal(t, http.MethodDelete, requestMethod)
	assert.Equal(t, "/api/v1/stewards/steward-abc123", requestPath)
	assert.Contains(t, output, "steward-abc123")
	assert.Contains(t, output, "decommissioned")
}

// TestStewardDecommission_NotFound_ReturnsError verifies a 404 surfaces a clear error.
func TestStewardDecommission_NotFound_ReturnsError(t *testing.T) {
	server := newSingleStewardDecommissionServer(t, "unknown-steward", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "STEWARD_NOT_FOUND",
				"message": "Steward not found",
			},
		})
	})
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
	})

	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runStewardDecommission(stewardDecommissionCmd, []string{"unknown-steward"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	assert.Contains(t, err.Error(), "unknown-steward")
}

// TestStewardDecommission_Forbidden_ReturnsMTLSError verifies that a 403 (API-key caller
// rejected at the Tier-3 gate) surfaces an mTLS-specific error.
func TestStewardDecommission_Forbidden_ReturnsMTLSError(t *testing.T) {
	server := newSingleStewardDecommissionServer(t, "steward-abc123", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "MTLS_REQUIRED",
				"message": "mTLS admin certificate required for this endpoint",
			},
		})
	})
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
	})

	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runStewardDecommission(stewardDecommissionCmd, []string{"steward-abc123"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mTLS")
}

// TestStewardDecommission_ServiceUnavailable_ReturnsRetryError verifies that a 503
// (fleet store unavailable) surfaces a retry-later error.
func TestStewardDecommission_ServiceUnavailable_ReturnsRetryError(t *testing.T) {
	server := newSingleStewardDecommissionServer(t, "steward-abc123", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "SERVICE_UNAVAILABLE",
				"message": "Fleet store unavailable",
			},
		})
	})
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
	})

	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runStewardDecommission(stewardDecommissionCmd, []string{"steward-abc123"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retry")
}

// TestStewardDecommission_OtherHTTPError_ReturnsStatusAndBody verifies that an unexpected
// status returns the status and response body.
func TestStewardDecommission_OtherHTTPError_ReturnsStatusAndBody(t *testing.T) {
	server := newSingleStewardDecommissionServer(t, "steward-abc123", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	})
	defer server.Close()

	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
	})

	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runStewardDecommission(stewardDecommissionCmd, []string{"steward-abc123"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "internal server error")
}

func TestStewardDecommission_FlagsRegistered(t *testing.T) {
	assert.NotNil(t, stewardDecommissionCmd.Flags().Lookup("url"), "--url flag must be registered")
	assert.NotNil(t, stewardDecommissionCmd.Flags().Lookup("tls-ca-cert"), "--tls-ca-cert flag must be registered")
	assert.NotNil(t, stewardDecommissionCmd.Flags().Lookup("tls-insecure"), "--tls-insecure flag must be registered")
	assert.NotNil(t, stewardDecommissionCmd.Flags().Lookup("json"), "--json flag must be registered")
}

// ---- multi-match selector fan-out tests (Issue #2445) ----

// wrapWithMultiResolve wraps an http.HandlerFunc so that POST /api/v1/fleet/resolve
// returns all provided stewards. All other requests are delegated to next.
func wrapWithMultiResolve(t *testing.T, stewards []StewardInfo, next http.HandlerFunc) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve" {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(struct {
				Data []StewardInfo `json:"data"`
			}{Data: stewards}); err != nil {
				t.Errorf("encode resolve: %v", err)
			}
			return
		}
		next(w, r)
	}
}

// stewardIDFromPath extracts the steward ID from URLs of the form
// /api/v1/stewards/{id}[/suffix].
func stewardIDFromPath(path string) string {
	parts := strings.SplitN(path, "/", 6)
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// TestStewardStatus_MultiMatchFanOut verifies that the status command fans out
// over all stewards matched by a selector and aggregates results.
func TestStewardStatus_MultiMatchFanOut(t *testing.T) {
	twoStewards := []StewardInfo{
		{ID: "sw-aaa", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "sw-bbb", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	t.Run("human output is host-prefixed for two-steward match", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := stewardIDFromPath(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"id": id, "status": "connected"},
			})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
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
			err := runStewardStatus(stewardStatusCmd, []string{"os:linux"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "=== host-a#sw-aaa ===")
		assert.Contains(t, output, "=== host-b#sw-bbb ===")
		assert.Contains(t, output, "sw-aaa")
		assert.Contains(t, output, "sw-bbb")
	})

	t.Run("json output has keyed entry for each matched steward", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := stewardIDFromPath(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"id": id, "status": "connected"},
			})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
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
			err := runStewardStatus(stewardStatusCmd, []string{"os:linux"})
			require.NoError(t, err)
		})

		var entries []KeyedOutputEntry
		require.NoError(t, json.Unmarshal([]byte(output), &entries))
		require.Len(t, entries, 2)
		assert.True(t, entries[0].Success)
		assert.True(t, entries[1].Success)
		keys := []string{entries[0].Key, entries[1].Key}
		assert.Contains(t, keys, "host-a#sw-aaa")
		assert.Contains(t, keys, "host-b#sw-bbb")
	})

	t.Run("partial failure is reported per-steward and exits non-zero", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := stewardIDFromPath(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			if id == "sw-bbb" {
				// Simulate steward going offline between resolve and fetch.
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"id": id, "status": "connected"},
			})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
		})
		stewardURL = server.URL
		stewardTLSInsecure = true

		var err error
		output := captureStdout(t, func() {
			err = runStewardStatus(stewardStatusCmd, []string{"os:linux"})
		})

		require.Error(t, err, "command must exit non-zero when any steward fetch fails")
		// The successful steward's output is still printed.
		assert.Contains(t, output, "sw-aaa")
	})
}

// TestStewardDNA_MultiMatchFanOut verifies that the dna command fans out over
// all matched stewards and aggregates results.
func TestStewardDNA_MultiMatchFanOut(t *testing.T) {
	twoStewards := []StewardInfo{
		{ID: "sw-aaa", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "sw-bbb", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	t.Run("human output is host-prefixed for two-steward match", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := stewardIDFromPath(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"hostname": id + "-host", "os": "linux"},
			})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		origAttr := stewardDNAAttribute
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
			stewardDNAAttribute = origAttr
		})
		stewardURL = server.URL
		stewardTLSInsecure = true
		stewardDNAAttribute = ""

		output := captureStdout(t, func() {
			err := runStewardDNA(stewardDNACmd, []string{"os:linux"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "=== host-a#sw-aaa ===")
		assert.Contains(t, output, "=== host-b#sw-bbb ===")
	})

	t.Run("json output has keyed entry for each matched steward", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := stewardIDFromPath(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"hostname": id + "-host", "os": "linux"},
			})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		origJSON := stewardDNAJSONOutput
		origAttr := stewardDNAAttribute
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
			stewardDNAJSONOutput = origJSON
			stewardDNAAttribute = origAttr
		})
		stewardURL = server.URL
		stewardTLSInsecure = true
		stewardDNAJSONOutput = true
		stewardDNAAttribute = ""

		output := captureStdout(t, func() {
			err := runStewardDNA(stewardDNACmd, []string{"os:linux"})
			require.NoError(t, err)
		})

		var entries []KeyedOutputEntry
		require.NoError(t, json.Unmarshal([]byte(output), &entries))
		require.Len(t, entries, 2)
		keys := []string{entries[0].Key, entries[1].Key}
		assert.Contains(t, keys, "host-a#sw-aaa")
		assert.Contains(t, keys, "host-b#sw-bbb")
	})

	t.Run("attribute mode returns one keyed value per matched steward", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := stewardIDFromPath(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Both return different attribute values for distinctiveness.
			val := "linux"
			if id == "sw-bbb" {
				val = "windows"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"value": val})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		origAttr := stewardDNAAttribute
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
			stewardDNAAttribute = origAttr
		})
		stewardURL = server.URL
		stewardTLSInsecure = true
		stewardDNAAttribute = "os"

		output := captureStdout(t, func() {
			err := runStewardDNA(stewardDNACmd, []string{"all"})
			require.NoError(t, err)
		})

		// Multi-match --attribute must prefix each value with the steward key.
		assert.Contains(t, output, "host-a#sw-aaa: linux")
		assert.Contains(t, output, "host-b#sw-bbb: windows")
	})

	t.Run("partial failure exits non-zero", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := stewardIDFromPath(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			if id == "sw-bbb" {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"hostname": "host-a", "os": "linux"},
			})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		origAttr := stewardDNAAttribute
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
			stewardDNAAttribute = origAttr
		})
		stewardURL = server.URL
		stewardTLSInsecure = true
		stewardDNAAttribute = ""

		err := runStewardDNA(stewardDNACmd, []string{"all"})
		require.Error(t, err, "command must exit non-zero when any steward fetch fails")
	})
}

// TestStewardLogs_MultiMatchFanOut verifies that the logs command fans out over
// all stewards matched by a selector.
func TestStewardLogs_MultiMatchFanOut(t *testing.T) {
	twoStewards := []StewardInfo{
		{ID: "sw-aaa", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "sw-bbb", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	t.Run("two stewards fan out and produce host-prefixed output", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"lines": []map[string]string{
					{"timestamp": "2026-01-01T00:00:00Z", "level": "INFO", "module": "core", "message": "ok"},
				},
			})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		origTail := stewardLogsTail
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
			stewardLogsTail = origTail
		})
		stewardURL = server.URL
		stewardTLSInsecure = true
		stewardLogsTail = 10

		output := captureStdout(t, func() {
			err := runStewardLogs(stewardLogsCmd, []string{"os:linux"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "=== host-a#sw-aaa ===")
		assert.Contains(t, output, "=== host-b#sw-bbb ===")
	})

	t.Run("partial failure exits non-zero", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := stewardIDFromPath(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			if id == "sw-bbb" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"lines": []interface{}{}})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		origTail := stewardLogsTail
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
			stewardLogsTail = origTail
		})
		stewardURL = server.URL
		stewardTLSInsecure = true
		stewardLogsTail = 10

		err := runStewardLogs(stewardLogsCmd, []string{"os:linux"})
		require.Error(t, err, "command must exit non-zero when any steward fetch fails")
	})
}

// TestStewardModules_MultiMatchFanOut verifies that the modules command fans out
// over all stewards matched by a selector.
func TestStewardModules_MultiMatchFanOut(t *testing.T) {
	twoStewards := []StewardInfo{
		{ID: "sw-aaa", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "sw-bbb", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	t.Run("two stewards fan out and produce host-prefixed output", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"modules": []map[string]string{{"name": "file", "version": "1.0"}},
				},
			})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
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
			err := runStewardModules(stewardModulesCmd, []string{"os:linux"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "=== host-a#sw-aaa ===")
		assert.Contains(t, output, "=== host-b#sw-bbb ===")
		assert.Contains(t, output, "file")
	})

	t.Run("partial failure exits non-zero", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := stewardIDFromPath(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			if id == "sw-bbb" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"modules": []interface{}{}},
			})
		})
		server := httptest.NewServer(wrapWithMultiResolve(t, twoStewards, inner))
		defer server.Close()

		origURL := stewardURL
		origInsecure := stewardTLSInsecure
		t.Cleanup(func() {
			stewardURL = origURL
			stewardTLSInsecure = origInsecure
		})
		stewardURL = server.URL
		stewardTLSInsecure = true

		err := runStewardModules(stewardModulesCmd, []string{"os:linux"})
		require.Error(t, err, "command must exit non-zero when any steward fetch fails")
	})
}
