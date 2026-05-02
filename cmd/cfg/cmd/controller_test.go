// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
