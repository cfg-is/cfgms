// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetControllerClient_TLSCACertFlagWired(t *testing.T) {
	certPEM := generateTestCACert(t)

	tmpFile, err := os.CreateTemp(t.TempDir(), "ca-cert-*.pem")
	require.NoError(t, err)
	_, err = tmpFile.Write(certPEM)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	origURL := healthURL
	origCACert := controllerTLSCACert
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSCACert = origCACert
		controllerTLSInsecure = origInsecure
	})

	healthURL = "https://controller.example.com"
	controllerTLSCACert = tmpFile.Name()
	controllerTLSInsecure = false

	client, err := getControllerClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestGetControllerClient_TLSInsecureFlagWired(t *testing.T) {
	origURL := healthURL
	origCACert := controllerTLSCACert
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSCACert = origCACert
		controllerTLSInsecure = origInsecure
	})

	healthURL = "https://controller.example.com"
	controllerTLSCACert = ""
	controllerTLSInsecure = true

	client, err := getControllerClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestGetControllerClient_TLSCACertEnvWired(t *testing.T) {
	certPEM := generateTestCACert(t)

	tmpFile, err := os.CreateTemp(t.TempDir(), "ca-cert-*.pem")
	require.NoError(t, err)
	_, err = tmpFile.Write(certPEM)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	origURL := healthURL
	origCACert := controllerTLSCACert
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSCACert = origCACert
		controllerTLSInsecure = origInsecure
	})
	t.Setenv("CFGMS_TLS_CA_CERT", tmpFile.Name())
	t.Setenv("CFGMS_TLS_INSECURE", "")

	healthURL = "https://controller.example.com"
	controllerTLSCACert = ""
	controllerTLSInsecure = false

	client, err := getControllerClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestGetControllerClient_TLSInsecureEnvWired(t *testing.T) {
	origURL := healthURL
	origCACert := controllerTLSCACert
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSCACert = origCACert
		controllerTLSInsecure = origInsecure
	})
	t.Setenv("CFGMS_TLS_INSECURE", "true")

	healthURL = "https://controller.example.com"
	controllerTLSCACert = ""
	controllerTLSInsecure = false

	client, err := getControllerClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestControllerCmd_TLSFlagsRegistered(t *testing.T) {
	assert.NotNil(t, controllerCmd.PersistentFlags().Lookup("tls-ca-cert"), "--tls-ca-cert flag must be registered on controllerCmd")
	assert.NotNil(t, controllerCmd.PersistentFlags().Lookup("tls-insecure"), "--tls-insecure flag must be registered on controllerCmd")
}

func TestGetControllerClient_BundleFound_UsesMTLS(t *testing.T) {
	tmpDir := t.TempDir()
	bundleFilePath := filepath.Join(tmpDir, "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://bundle-controller.local:9443")

	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	origBundlePath := bundlePath
	origNoBundle := noBundle
	origHealthURL := healthURL
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
		bundlePath = origBundlePath
		noBundle = origNoBundle
		healthURL = origHealthURL
	})
	userConfigDirFn = func() (string, error) { return filepath.Join(tmpDir, "no-userconfig"), nil }
	systemBundlePathFn = func() string { return filepath.Join(tmpDir, "no-system.bundle.yaml") }

	// Ensure env var is not set
	origEnv, wasSet := os.LookupEnv("CFGMS_ADMIN_BUNDLE")
	require.NoError(t, os.Unsetenv("CFGMS_ADMIN_BUNDLE"))
	t.Cleanup(func() {
		if wasSet {
			require.NoError(t, os.Setenv("CFGMS_ADMIN_BUNDLE", origEnv))
		} else {
			require.NoError(t, os.Unsetenv("CFGMS_ADMIN_BUNDLE"))
		}
	})

	bundlePath = bundleFilePath
	noBundle = false
	healthURL = "https://flag-url.local:9443" // --url flag takes precedence over bundle URL

	client, err := getControllerClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	// Bundle was used: client must have mTLS certificates loaded
	transport := client.httpClient.Transport.(*http.Transport)
	assert.NotEmpty(t, transport.TLSClientConfig.Certificates)
	// URL comes from the flag (not the bundle), since healthURL was set
	assert.Equal(t, "https://flag-url.local:9443", client.baseURL)
}

func TestGetControllerClient_NoBundleFlag_FallsBackToAPIKey(t *testing.T) {
	tmpDir := t.TempDir()
	bundleFilePath := filepath.Join(tmpDir, "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://bundle-controller.local:9443")

	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	origBundlePath := bundlePath
	origNoBundle := noBundle
	origHealthURL := healthURL
	origHealthAPIKey := healthAPIKey
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
		bundlePath = origBundlePath
		noBundle = origNoBundle
		healthURL = origHealthURL
		healthAPIKey = origHealthAPIKey
	})
	userConfigDirFn = func() (string, error) { return filepath.Join(tmpDir, "no-userconfig"), nil }
	systemBundlePathFn = func() string { return filepath.Join(tmpDir, "no-system.bundle.yaml") }
	t.Setenv("CFGMS_ADMIN_BUNDLE", bundleFilePath)

	bundlePath = bundleFilePath
	noBundle = true // explicit opt-out
	healthURL = "https://api-key-controller.local:9080"
	healthAPIKey = "ctrl-test-key"

	client, err := getControllerClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	// --no-bundle means API key path; no mTLS certificates
	assert.Equal(t, "https://api-key-controller.local:9080", client.baseURL)
	assert.Equal(t, "ctrl-test-key", client.apiKey)
	transport := client.httpClient.Transport.(*http.Transport)
	assert.Empty(t, transport.TLSClientConfig.Certificates)
}

func newControllerHealthServer(t *testing.T) *httptest.Server {
	t.Helper()

	now := time.Now().UTC()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/health/detailed":
			resp := map[string]interface{}{
				"status":         "healthy",
				"timestamp":      now.Format(time.RFC3339),
				"uptime_seconds": int64(3600),
				"components":     map[string]interface{}{},
				"alerts":         []interface{}{},
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "/api/v1/health/metrics":
			resp := map[string]interface{}{
				"timestamp": now.Format(time.RFC3339),
				"transport": map[string]interface{}{
					"connected_stewards": 5,
					"stream_errors":      int64(0),
					"messages_sent":      int64(100),
					"messages_received":  int64(100),
					"avg_latency_ns":     int64(1000),
					"collected_at":       now.Format(time.RFC3339),
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRunControllerStatus_TextOutput(t *testing.T) {
	server := newControllerHealthServer(t)
	defer server.Close()

	origURL := healthURL
	origFormat := healthFormat
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		healthFormat = origFormat
		controllerTLSInsecure = origInsecure
	})

	healthURL = server.URL
	healthFormat = "text"
	controllerTLSInsecure = true

	output := captureStdout(t, func() {
		err := runControllerStatus(controllerStatusCmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "Controller Health Status")
	assert.Contains(t, output, "HEALTHY")
}

func TestRunControllerStatus_JSONOutput(t *testing.T) {
	server := newControllerHealthServer(t)
	defer server.Close()

	origURL := healthURL
	origFormat := healthFormat
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		healthFormat = origFormat
		controllerTLSInsecure = origInsecure
	})

	healthURL = server.URL
	healthFormat = "json"
	controllerTLSInsecure = true

	output := captureStdout(t, func() {
		err := runControllerStatus(controllerStatusCmd, nil)
		require.NoError(t, err)
	})

	assert.True(t, json.Valid([]byte(output)), "output must be valid JSON")
}

func TestRunControllerStatus_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	origURL := healthURL
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSInsecure = origInsecure
	})

	healthURL = server.URL
	controllerTLSInsecure = true

	err := runControllerStatus(controllerStatusCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API request failed")
}

func TestRunControllerMetrics_TextOutput(t *testing.T) {
	server := newControllerHealthServer(t)
	defer server.Close()

	origURL := healthURL
	origFormat := healthFormat
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		healthFormat = origFormat
		controllerTLSInsecure = origInsecure
	})

	healthURL = server.URL
	healthFormat = "text"
	controllerTLSInsecure = true

	output := captureStdout(t, func() {
		err := runControllerMetrics(controllerMetricsCmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "Controller Metrics")
	assert.Contains(t, output, "Transport")
}

func TestRunControllerMetrics_JSONOutput(t *testing.T) {
	server := newControllerHealthServer(t)
	defer server.Close()

	origURL := healthURL
	origFormat := healthFormat
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		healthFormat = origFormat
		controllerTLSInsecure = origInsecure
	})

	healthURL = server.URL
	healthFormat = "json"
	controllerTLSInsecure = true

	output := captureStdout(t, func() {
		err := runControllerMetrics(controllerMetricsCmd, nil)
		require.NoError(t, err)
	})

	assert.True(t, json.Valid([]byte(output)), "output must be valid JSON")
}

func TestRunControllerMetrics_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	origURL := healthURL
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSInsecure = origInsecure
	})

	healthURL = server.URL
	controllerTLSInsecure = true

	err := runControllerMetrics(controllerMetricsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API request failed")
}

func newSigningCertRotateServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/certificates/signing/rotate" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req struct {
			OverlapDays int `json:"overlap_days"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"old_serial":        "abc123",
				"new_serial":        "def456",
				"overlap_days":      req.OverlapDays,
				"stewards_notified": 2,
			},
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestRunSigningCertRotate_Success(t *testing.T) {
	server := newSigningCertRotateServer(t)
	defer server.Close()

	origURL := healthURL
	origInsecure := controllerTLSInsecure
	origOverlap := signingCertOverlapDays
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSInsecure = origInsecure
		signingCertOverlapDays = origOverlap
	})

	healthURL = server.URL
	controllerTLSInsecure = true
	signingCertOverlapDays = 30

	output := captureStdout(t, func() {
		err := runSigningCertRotate(signingCertRotateCmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "rotated successfully")
	assert.Contains(t, output, "abc123")
	assert.Contains(t, output, "def456")
	assert.Contains(t, output, "30")
	assert.Contains(t, output, "2")
}

func TestRunSigningCertRotate_OverlapDaysFlag(t *testing.T) {
	var receivedOverlap int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/certificates/signing/rotate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			OverlapDays int `json:"overlap_days"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedOverlap = req.OverlapDays
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"old_serial":        "old",
				"new_serial":        "new",
				"overlap_days":      req.OverlapDays,
				"stewards_notified": 0,
			},
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	capServer := httptest.NewServer(mux)
	defer capServer.Close()

	origURL := healthURL
	origInsecure := controllerTLSInsecure
	origOverlap := signingCertOverlapDays
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSInsecure = origInsecure
		signingCertOverlapDays = origOverlap
	})

	healthURL = capServer.URL
	controllerTLSInsecure = true
	signingCertOverlapDays = 14

	err := runSigningCertRotate(signingCertRotateCmd, nil)
	require.NoError(t, err)
	assert.Equal(t, 14, receivedOverlap, "--overlap-days value must be sent in request body")
}

func TestRunSigningCertRotate_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"INTERNAL","message":"rotation failed"}}`))
	}))
	defer server.Close()

	origURL := healthURL
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSInsecure = origInsecure
	})

	healthURL = server.URL
	controllerTLSInsecure = true

	err := runSigningCertRotate(signingCertRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation failed")
}

func TestRunSigningCertRotate_MalformedResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-valid-json{{"))
	}))
	defer server.Close()

	origURL := healthURL
	origInsecure := controllerTLSInsecure
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSInsecure = origInsecure
	})

	healthURL = server.URL
	controllerTLSInsecure = true

	err := runSigningCertRotate(signingCertRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse rotation response")
}

func TestRunSigningCertRotate_NegativeOverlapDaysRejected(t *testing.T) {
	origOverlap := signingCertOverlapDays
	t.Cleanup(func() { signingCertOverlapDays = origOverlap })
	signingCertOverlapDays = -1

	// We set no server URL so getControllerClient would fail, but the bounds
	// check should fire first.
	origURL := healthURL
	t.Cleanup(func() { healthURL = origURL })
	healthURL = "https://controller.example.com"

	err := runSigningCertRotate(signingCertRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "overlap-days")
}

func TestSigningCertCmd_SubcommandsRegistered(t *testing.T) {
	var found bool
	for _, sub := range controllerCmd.Commands() {
		if sub.Use == "signing-cert" {
			found = true
			var rotateFound bool
			for _, rsub := range sub.Commands() {
				if rsub.Use == "rotate" {
					rotateFound = true
				}
			}
			assert.True(t, rotateFound, "signing-cert must have a rotate subcommand")
		}
	}
	assert.True(t, found, "controllerCmd must have a signing-cert subcommand")
}

func TestSigningCertRotateCmd_OverlapDaysFlagRegistered(t *testing.T) {
	f := signingCertRotateCmd.Flags().Lookup("overlap-days")
	require.NotNil(t, f, "--overlap-days flag must be registered on signing-cert rotate")
	assert.Equal(t, "30", f.DefValue, "--overlap-days default must be 30")
}
