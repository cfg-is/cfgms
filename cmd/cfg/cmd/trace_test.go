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

func TestGetTraceClient_TLSCACertFlagWired(t *testing.T) {
	certPEM := generateTestCACert(t)

	tmpFile, err := os.CreateTemp(t.TempDir(), "ca-cert-*.pem")
	require.NoError(t, err)
	_, err = tmpFile.Write(certPEM)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	origURL := traceURL
	origCACert := traceTLSCACert
	origInsecure := traceTLSInsecure
	t.Cleanup(func() {
		traceURL = origURL
		traceTLSCACert = origCACert
		traceTLSInsecure = origInsecure
	})

	traceURL = "https://controller.example.com"
	traceTLSCACert = tmpFile.Name()
	traceTLSInsecure = false

	client, err := getTraceClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestGetTraceClient_TLSInsecureFlagWired(t *testing.T) {
	origURL := traceURL
	origCACert := traceTLSCACert
	origInsecure := traceTLSInsecure
	t.Cleanup(func() {
		traceURL = origURL
		traceTLSCACert = origCACert
		traceTLSInsecure = origInsecure
	})

	traceURL = "https://controller.example.com"
	traceTLSCACert = ""
	traceTLSInsecure = true

	client, err := getTraceClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestGetTraceClient_TLSCACertEnvWired(t *testing.T) {
	certPEM := generateTestCACert(t)

	tmpFile, err := os.CreateTemp(t.TempDir(), "ca-cert-*.pem")
	require.NoError(t, err)
	_, err = tmpFile.Write(certPEM)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	origURL := traceURL
	origCACert := traceTLSCACert
	origInsecure := traceTLSInsecure
	t.Cleanup(func() {
		traceURL = origURL
		traceTLSCACert = origCACert
		traceTLSInsecure = origInsecure
	})
	t.Setenv("CFGMS_TLS_CA_CERT", tmpFile.Name())
	t.Setenv("CFGMS_TLS_INSECURE", "")

	traceURL = "https://controller.example.com"
	traceTLSCACert = ""
	traceTLSInsecure = false

	client, err := getTraceClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestGetTraceClient_TLSInsecureEnvWired(t *testing.T) {
	origURL := traceURL
	origCACert := traceTLSCACert
	origInsecure := traceTLSInsecure
	t.Cleanup(func() {
		traceURL = origURL
		traceTLSCACert = origCACert
		traceTLSInsecure = origInsecure
	})
	t.Setenv("CFGMS_TLS_INSECURE", "true")

	traceURL = "https://controller.example.com"
	traceTLSCACert = ""
	traceTLSInsecure = false

	client, err := getTraceClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestTraceCmd_TLSFlagsRegistered(t *testing.T) {
	assert.NotNil(t, traceCmd.Flags().Lookup("tls-ca-cert"), "--tls-ca-cert flag must be registered on traceCmd")
	assert.NotNil(t, traceCmd.Flags().Lookup("tls-insecure"), "--tls-insecure flag must be registered on traceCmd")
}

func newTraceServer(t *testing.T, requestID string) *httptest.Server {
	t.Helper()

	now := time.Now().UTC()
	endTime := now.Add(50 * time.Millisecond)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/health/trace/" + requestID:
			resp := map[string]interface{}{
				"request_id":  requestID,
				"trace_id":    "trace-abc",
				"start_time":  now.Format(time.RFC3339Nano),
				"end_time":    endTime.Format(time.RFC3339Nano),
				"duration_ms": 50.0,
				"operation":   "test-op",
				"component":   "test",
				"status":      "success",
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRunTrace_TextOutput(t *testing.T) {
	const reqID = "req123abc"
	server := newTraceServer(t, reqID)
	defer server.Close()

	origURL := traceURL
	origFormat := traceFormat
	origInsecure := traceTLSInsecure
	t.Cleanup(func() {
		traceURL = origURL
		traceFormat = origFormat
		traceTLSInsecure = origInsecure
	})

	traceURL = server.URL
	traceFormat = "text"
	traceTLSInsecure = true

	output := captureStdout(t, func() {
		err := runTrace(traceCmd, []string{reqID})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "Request Trace:")
	assert.Contains(t, output, reqID)
	assert.Contains(t, output, "SUCCESS")
}

func TestRunTrace_JSONOutput(t *testing.T) {
	const reqID = "req123abc"
	server := newTraceServer(t, reqID)
	defer server.Close()

	origURL := traceURL
	origFormat := traceFormat
	origInsecure := traceTLSInsecure
	t.Cleanup(func() {
		traceURL = origURL
		traceFormat = origFormat
		traceTLSInsecure = origInsecure
	})

	traceURL = server.URL
	traceFormat = "json"
	traceTLSInsecure = true

	output := captureStdout(t, func() {
		err := runTrace(traceCmd, []string{reqID})
		require.NoError(t, err)
	})

	assert.True(t, json.Valid([]byte(output)), "output must be valid JSON")
}

func TestRunTrace_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	origURL := traceURL
	origInsecure := traceTLSInsecure
	t.Cleanup(func() {
		traceURL = origURL
		traceTLSInsecure = origInsecure
	})

	traceURL = server.URL
	traceTLSInsecure = true

	err := runTrace(traceCmd, []string{"nonexistent-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trace not found")
	assert.Contains(t, err.Error(), "nonexistent-id")
}

func TestRunTrace_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	origURL := traceURL
	origInsecure := traceTLSInsecure
	t.Cleanup(func() {
		traceURL = origURL
		traceTLSInsecure = origInsecure
	})

	traceURL = server.URL
	traceTLSInsecure = true

	err := runTrace(traceCmd, []string{"some-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API request failed")
}
