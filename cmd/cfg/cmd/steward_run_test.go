// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	certbundle "github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeRunAPIResponse encodes a standard { "data": ..., "timestamp": ... } response.
func writeRunAPIResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data":      data,
		"timestamp": time.Now().UTC(),
	})
}

// generateTestBundleWithRSA writes an admin bundle file containing a fresh RSA
// private key and a self-signed certificate to dir, then returns the file path.
func generateTestBundleWithRSA(t *testing.T, dir string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-operator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	b := &certbundle.Bundle{
		KeyPEM:  keyPEM,
		CertPEM: certPEM,
		CAPEM:   certPEM,
	}
	p := dir + "/admin.bundle.yaml"
	require.NoError(t, certbundle.Write(p, b))
	return p
}

// generateTestSigningCredential creates a payload-signing ECDSA keypair and
// self-signed certificate, stores the private key in the credential store under
// signingCredentialName, and writes the certificate PEM to CFGMS_SIGNING_CERT — all
// under a fresh t.TempDir() so nothing touches the real user config directory. This is
// signCommandContent's credential source since Issue #3696 switched client-side
// payload signing from the admin bundle to the zero-custody CSR-issued credential; the
// steward-side dispatch tests only exercise transport/business logic and don't care
// about chain-of-trust, so a self-signed cert (unlike sigTestOperatorCert in
// features/steward/commands) is sufficient here.
func generateTestSigningCredential(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	overrideCredentialsDir(t, dir)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-signing-credential"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	credStore, err := newCredentialStore()
	require.NoError(t, err)
	require.NoError(t, credStore.Store(context.Background(), signingCredentialName, keyPEM))

	certPath := filepath.Join(dir, "signing-cert.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	t.Setenv("CFGMS_SIGNING_CERT", certPath)
}

// saveStewardRunGlobals captures the current values of all run-command flag variables
// and all global function variables that affect bundle resolution, then restores them
// via t.Cleanup so tests cannot pollute each other's state. It also provisions a test
// payload-signing credential (Issue #3696) so run-command/exec tests that reach
// signCommandContent find one — harmless for tests (e.g. run-script) that never sign.
func saveStewardRunGlobals(t *testing.T) {
	t.Helper()
	generateTestSigningCredential(t)
	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origTarget := stewardRunTarget
	origScript := stewardRunScript
	origVersion := stewardRunVersion
	origParams := stewardRunParams
	origWait := stewardRunWait
	origSkipOffline := stewardRunSkipOffline
	origWaitTimeout := stewardRunWaitTimeout
	origShell := stewardRunShell
	origDevice := stewardRunResultDevice
	origPollInterval := runWaitPollInterval
	origBP := bundlePath
	origNoBundle := noBundle
	origUserConfigDir := userConfigDirFn
	origSystemBundle := systemBundlePathFn
	// exec vars
	origExecCmd := stewardExecCommand
	origExecShell := stewardExecShell
	origExecTimeout := stewardExecTimeout
	origExecJSON := stewardExecJSONOutput
	// confirm gate and JSON output vars
	origYes := stewardYes
	origScriptJSON := stewardRunScriptJSONOutput
	origCommandJSON := stewardRunCommandJSONOutput
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardRunTarget = origTarget
		stewardRunScript = origScript
		stewardRunVersion = origVersion
		stewardRunParams = origParams
		stewardRunWait = origWait
		stewardRunSkipOffline = origSkipOffline
		stewardRunWaitTimeout = origWaitTimeout
		stewardRunShell = origShell
		stewardRunResultDevice = origDevice
		runWaitPollInterval = origPollInterval
		bundlePath = origBP
		noBundle = origNoBundle
		userConfigDirFn = origUserConfigDir
		systemBundlePathFn = origSystemBundle
		stewardExecCommand = origExecCmd
		stewardExecShell = origExecShell
		stewardExecTimeout = origExecTimeout
		stewardExecJSONOutput = origExecJSON
		stewardYes = origYes
		stewardRunScriptJSONOutput = origScriptJSON
		stewardRunCommandJSONOutput = origCommandJSON
	})
}

// ---------------------------------------------------------------------------
// run-script tests
// ---------------------------------------------------------------------------

func TestStewardRunScript_AsyncReturnsRunID(t *testing.T) {
	var requestPath, requestMethod string
	var requestBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve":
			// Single match — confirm gate is a no-op.
			writeRunAPIResponse(w, []map[string]interface{}{{"id": "s1", "status": "online"}})
		default:
			requestPath = r.URL.Path
			requestMethod = r.Method
			requestBody, _ = io.ReadAll(r.Body)
			writeRunAPIResponse(w, map[string]string{"run_id": "run-abc123"})
		}
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardRunScript = "my-script"
	stewardRunTarget = "os:linux"
	stewardRunVersion = "v2"
	stewardRunWait = false

	output := captureStdout(t, func() {
		err := runRunScript(stewardRunScriptCmd, []string{})
		require.NoError(t, err)
	})

	assert.Equal(t, http.MethodPost, requestMethod)
	assert.Equal(t, "/api/v1/runs/script", requestPath)
	assert.Contains(t, output, "run-abc123")

	// Verify request body fields
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(requestBody, &body))
	assert.Equal(t, "my-script", body["script_id"])
	assert.Equal(t, "os:linux", body["target"])
	assert.Equal(t, "v2", body["script_version"])
}

func TestStewardRunScript_NonOKStatusReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid selector"})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardRunScript = "my-script"

	err := runRunScript(stewardRunScriptCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
}

func TestStewardRunScript_SkipOfflineIncludedInBody(t *testing.T) {
	var requestBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, _ = io.ReadAll(r.Body)
		writeRunAPIResponse(w, map[string]string{"run_id": "run-skip-offline"})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardRunScript = "my-script"
	stewardRunSkipOffline = true

	_ = captureStdout(t, func() {
		require.NoError(t, runRunScript(stewardRunScriptCmd, []string{}))
	})

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(requestBody, &body))
	assert.Equal(t, true, body["skip_offline"])
}

func TestStewardRunScript_ParamsIncludedInBody(t *testing.T) {
	var requestBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, _ = io.ReadAll(r.Body)
		writeRunAPIResponse(w, map[string]string{"run_id": "run-params"})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardRunScript = "my-script"
	stewardRunParams = []string{"env=prod", "region=us-east-1"}

	_ = captureStdout(t, func() {
		require.NoError(t, runRunScript(stewardRunScriptCmd, []string{}))
	})

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(requestBody, &body))
	params, ok := body["params"].(map[string]interface{})
	require.True(t, ok, "params must be a JSON object")
	assert.Equal(t, "prod", params["env"])
	assert.Equal(t, "us-east-1", params["region"])
}

func TestStewardRunScript_InvalidParamReturnsError(t *testing.T) {
	saveStewardRunGlobals(t)
	stewardRunParams = []string{"no-equals-sign"}

	err := runRunScript(stewardRunScriptCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no-equals-sign")
}

// ---------------------------------------------------------------------------
// [REQUIRED TEST] run-command — base64-encodes content + includes signature block
// ---------------------------------------------------------------------------

func TestStewardRunCommand_SignsAndBase64Encodes(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	var capturedBody []byte
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve":
			// Single match — confirm gate is a no-op.
			writeRunAPIResponse(w, []map[string]interface{}{{"id": "s1", "status": "online"}})
		default:
			capturedPath = r.URL.Path
			capturedBody, _ = io.ReadAll(r.Body)
			writeRunAPIResponse(w, map[string]string{"run_id": "cmd-run-id"})
		}
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardRunShell = "bash"
	stewardRunTarget = "os:linux"

	output := captureStdout(t, func() {
		err := runRunCommand(stewardRunCommandCmd, []string{"echo hello"})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/runs/command", capturedPath)
	assert.Contains(t, output, "cmd-run-id")

	// Parse the captured request body and verify it
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))

	// content must be base64-encoded
	contentB64, ok := body["content"].(string)
	require.True(t, ok, "content field must be present and a string")
	decoded, err := base64.StdEncoding.DecodeString(contentB64)
	require.NoError(t, err, "content must be valid base64")
	assert.Equal(t, "echo hello", string(decoded))

	// signature block must be present with all required fields. The signature comes
	// from the payload-signing credential (Issue #3696) generateTestSigningCredential
	// provisions inside saveStewardRunGlobals — an ECDSA key — not from the RSA admin
	// bundle above, which now authenticates only the API connection.
	sigRaw, ok := body["signature"]
	require.True(t, ok, "signature block must be present in request body")
	sigMap, ok := sigRaw.(map[string]interface{})
	require.True(t, ok, "signature must be a JSON object")
	assert.Equal(t, "ecdsa-sha256", sigMap["algorithm"], "algorithm must be ecdsa-sha256 for the payload-signing credential's ECDSA key")
	assert.NotEmpty(t, sigMap["value"], "signature value must not be empty")
	assert.NotEmpty(t, sigMap["public_key"], "public_key must not be empty")

	// signature value must be valid base64
	sigVal, _ := sigMap["value"].(string)
	_, err = base64.StdEncoding.DecodeString(sigVal)
	require.NoError(t, err, "signature value must be valid base64")
}

func TestStewardRunCommand_FailsWithoutBundleKey(t *testing.T) {
	saveStewardRunGlobals(t)

	// Redirect bundle lookup to an empty temp dir (no bundle file)
	emptyDir := t.TempDir()
	bundlePath = ""
	userConfigDirFn = func() (string, error) { return emptyDir, nil }
	systemBundlePathFn = func() string { return emptyDir + "/nonexistent.bundle.yaml" }
	noBundle = false
	stewardRunShell = "bash"

	err := runRunCommand(stewardRunCommandCmd, []string{"echo hello"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bundle")
}

// TestStewardRunCommand_FailsWhenBundleHasNoKey verifies that a bundle without a
// private key fails run-command. Since Issue #3694, target resolution (a real API
// call requiring a working mTLS client) happens before signing, so the bundle's
// missing key now surfaces as a client-construction failure (X509 key pair load)
// rather than the deeper "no private key" signing error the pre-#3694 ordering
// produced — both are the same underlying defect (no usable signing key in the
// bundle), just detected at a different layer.
func TestStewardRunCommand_FailsWhenBundleHasNoKey(t *testing.T) {
	dir := t.TempDir()

	// Write bundle without a private key
	b := &certbundle.Bundle{
		CertPEM: "cert-placeholder",
		CAPEM:   "ca-placeholder",
		// KeyPEM intentionally empty
	}
	bundleFile := dir + "/admin.bundle.yaml"
	require.NoError(t, certbundle.Write(bundleFile, b))

	saveStewardRunGlobals(t)
	bundlePath = bundleFile
	stewardRunShell = "bash"

	err := runRunCommand(stewardRunCommandCmd, []string{"echo hello"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate", "must fail cleanly on a bundle with no usable key material")
}

func TestStewardRunCommand_ReadsFileWhenArgIsFilePath(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	scriptFile := dir + "/script.sh"
	require.NoError(t, writeFileContent(scriptFile, "#!/bin/bash\necho from-file"))

	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve" {
			// Broadcast (no --target) resolves "all" for the operator envelope's
			// target list (Issue #3694).
			writeRunAPIResponse(w, []map[string]interface{}{{"id": "s1", "status": "online"}})
			return
		}
		capturedBody, _ = io.ReadAll(r.Body)
		writeRunAPIResponse(w, map[string]string{"run_id": "file-run-id"})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardRunShell = "bash"

	_ = captureStdout(t, func() {
		require.NoError(t, runRunCommand(stewardRunCommandCmd, []string{scriptFile}))
	})

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))
	contentB64, _ := body["content"].(string)
	decoded, err := base64.StdEncoding.DecodeString(contentB64)
	require.NoError(t, err)
	assert.Equal(t, "#!/bin/bash\necho from-file", string(decoded))
}

// writeFileContent is a test helper that writes content to path.
func writeFileContent(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}

// ---------------------------------------------------------------------------
// run-status tests
// ---------------------------------------------------------------------------

func TestStewardRunStatus_PrintsStatusAndCounts(t *testing.T) {
	var requestPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		writeRunAPIResponse(w, map[string]interface{}{
			"run_id":         "run-status-id",
			"status":         "running",
			"job_count":      3,
			"completed_jobs": 1,
			"failed_jobs":    0,
		})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true

	output := captureStdout(t, func() {
		err := runRunStatus(stewardRunStatusCmd, []string{"run-status-id"})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/runs/run-status-id", requestPath)
	assert.Contains(t, output, "running")
	assert.Contains(t, output, "3")
	assert.Contains(t, output, "1")
}

func TestStewardRunStatus_NotFoundReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runRunStatus(stewardRunStatusCmd, []string{"nonexistent-run"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-run")
}

func TestStewardRunStatus_NonOKStatusReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runRunStatus(stewardRunStatusCmd, []string{"some-run-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// ---------------------------------------------------------------------------
// run-result tests
// ---------------------------------------------------------------------------

func TestStewardRunResult_PrintsJobInfo(t *testing.T) {
	var requestPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		writeRunAPIResponse(w, []map[string]interface{}{
			{
				"job_id":       "job-001",
				"run_id":       "run-result-id",
				"device_id":    "device-alpha",
				"execution_id": "exec-111",
				"status":       "completed",
			},
			{
				"job_id":    "job-002",
				"run_id":    "run-result-id",
				"device_id": "device-beta",
				"status":    "pending",
			},
		})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardRunResultDevice = ""

	output := captureStdout(t, func() {
		err := runRunResult(stewardRunResultCmd, []string{"run-result-id"})
		require.NoError(t, err)
	})

	assert.Equal(t, "/api/v1/runs/run-result-id/jobs", requestPath)
	assert.Contains(t, output, "device-alpha")
	assert.Contains(t, output, "device-beta")
	assert.Contains(t, output, "completed")
	assert.Contains(t, output, "pending")
}

func TestStewardRunResult_DeviceFilterShowsOnlyMatchingJobs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeRunAPIResponse(w, []map[string]interface{}{
			{"job_id": "job-001", "device_id": "device-alpha", "status": "completed"},
			{"job_id": "job-002", "device_id": "device-beta", "status": "running"},
		})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardRunResultDevice = "device-alpha"

	output := captureStdout(t, func() {
		err := runRunResult(stewardRunResultCmd, []string{"run-result-id"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "device-alpha")
	assert.NotContains(t, output, "device-beta")
}

func TestStewardRunResult_NotFoundReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runRunResult(stewardRunResultCmd, []string{"missing-run"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing-run")
}

// ---------------------------------------------------------------------------
// run-cancel tests
// ---------------------------------------------------------------------------

func TestStewardRunCancel_CallsDeleteAndPrintsConfirmation(t *testing.T) {
	var requestPath, requestMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		requestMethod = r.Method
		writeRunAPIResponse(w, map[string]bool{"cancelled": true})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true

	output := captureStdout(t, func() {
		err := runRunCancel(stewardRunCancelCmd, []string{"cancel-run-id"})
		require.NoError(t, err)
	})

	assert.Equal(t, http.MethodDelete, requestMethod)
	assert.Equal(t, "/api/v1/runs/cancel-run-id", requestPath)
	assert.Contains(t, output, "cancel-run-id")
}

func TestStewardRunCancel_NotFoundReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runRunCancel(stewardRunCancelCmd, []string{"ghost-run"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ghost-run")
}

func TestStewardRunCancel_AlreadyTerminalReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "already terminal"})
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true

	err := runRunCancel(stewardRunCancelCmd, []string{"done-run"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "done-run")
}

// ---------------------------------------------------------------------------
// [REQUIRED TEST] --wait — exits 0 and prints completion summary on second poll
// ---------------------------------------------------------------------------

func TestStewardRunWait_CompletesOnSecondPoll(t *testing.T) {
	var pollCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runs/script":
			writeRunAPIResponse(w, map[string]string{"run_id": "wait-run-id"})
		case r.Method == http.MethodGet:
			n := atomic.AddInt32(&pollCount, 1)
			status := "running"
			completed := 0
			if n >= 2 {
				status = "completed"
				completed = 2
			}
			writeRunAPIResponse(w, map[string]interface{}{
				"run_id":         "wait-run-id",
				"status":         status,
				"job_count":      2,
				"completed_jobs": completed,
				"failed_jobs":    0,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardRunScript = "my-script"
	stewardRunWait = true
	stewardRunWaitTimeout = 30 * time.Second
	runWaitPollInterval = time.Millisecond // fast for testing

	output := captureStdout(t, func() {
		err := runRunScript(stewardRunScriptCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "completed", "output must contain completion status")
	assert.GreaterOrEqual(t, atomic.LoadInt32(&pollCount), int32(2), "must poll at least twice")
}

func TestStewardRunWait_TimesOutAndReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			writeRunAPIResponse(w, map[string]string{"run_id": "timeout-run"})
		default:
			writeRunAPIResponse(w, map[string]interface{}{
				"run_id":         "timeout-run",
				"status":         "running",
				"job_count":      1,
				"completed_jobs": 0,
				"failed_jobs":    0,
			})
		}
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	stewardRunScript = "my-script"
	stewardRunWait = true
	stewardRunWaitTimeout = 10 * time.Millisecond
	runWaitPollInterval = time.Millisecond

	_ = captureStdout(t, func() {
		err := runRunScript(stewardRunScriptCmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
	})
}

// ---------------------------------------------------------------------------
// Flag registration tests
// ---------------------------------------------------------------------------

func TestStewardRunCommandsRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, cmd := range stewardCmd.Commands() {
		names[cmd.Name()] = true
	}
	for _, want := range []string{"run-script", "run-command", "run-status", "run-result", "run-cancel"} {
		assert.True(t, names[want], "stewardCmd must have %q subcommand", want)
	}
}

func TestStewardRunScript_FlagsRegistered(t *testing.T) {
	for _, flag := range []string{"target", "script", "version", "param", "wait", "skip-offline", "wait-timeout", "json"} {
		assert.NotNil(t, stewardRunScriptCmd.Flags().Lookup(flag), "run-script must have --%s flag", flag)
	}
}

func TestStewardRunCommand_FlagsRegistered(t *testing.T) {
	for _, flag := range []string{"target", "shell", "param", "wait", "skip-offline", "wait-timeout", "json"} {
		assert.NotNil(t, stewardRunCommandCmd.Flags().Lookup(flag), "run-command must have --%s flag", flag)
	}
}

func TestStewardRunResult_FlagsRegistered(t *testing.T) {
	assert.NotNil(t, stewardRunResultCmd.Flags().Lookup("device"), "run-result must have --device flag")
}

// ---------------------------------------------------------------------------
// [REQUIRED TEST] exec — single-steward dispatch and output display
// ---------------------------------------------------------------------------

// TestRunCommandSingle_SubmitsCommandAndDisplaysOutput verifies that:
//   - POST /api/v1/runs/command is called with the raw selector (no id: prepend)
//   - The job output is printed after the run reaches terminal state.
func TestRunCommandSingle_SubmitsCommandAndDisplaysOutput(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve":
			writeRunAPIResponse(w, []map[string]interface{}{
				{"id": "target-steward-id", "status": "online"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runs/command":
			capturedBody, _ = io.ReadAll(r.Body)
			writeRunAPIResponse(w, map[string]string{"run_id": "exec-run-id"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runs/exec-run-id":
			writeRunAPIResponse(w, map[string]interface{}{
				"run_id":         "exec-run-id",
				"status":         "completed",
				"job_count":      1,
				"completed_jobs": 1,
				"failed_jobs":    0,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runs/exec-run-id/jobs":
			writeRunAPIResponse(w, []map[string]interface{}{
				{
					"job_id":    "job-001",
					"run_id":    "exec-run-id",
					"device_id": "target-steward-id",
					"status":    "completed",
					"output":    "hello from steward\n",
					"exit_code": 0,
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardExecCommand = "echo hello"
	stewardExecShell = "bash"
	stewardExecTimeout = 30 * time.Second
	runWaitPollInterval = time.Millisecond

	output := captureStdout(t, func() {
		err := runRunCommandSingle(stewardExecCmd, []string{"target-steward-id"})
		require.NoError(t, err)
	})

	// target must be the raw selector — no id: prepend (regression: issue #2257).
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))
	assert.Equal(t, "target-steward-id", body["target"], "target must be the raw selector, not id:<steward-id>")

	// Verify output is displayed
	assert.Contains(t, output, "exec-run-id")
	assert.Contains(t, output, "hello from steward")
}

// TestRunCommandSingle_TimeoutError verifies that exec returns an error when the
// wait timeout elapses before the run reaches a terminal state.
func TestRunCommandSingle_TimeoutError(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve":
			writeRunAPIResponse(w, []map[string]interface{}{
				{"id": "some-steward-id", "status": "online"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runs/command":
			writeRunAPIResponse(w, map[string]string{"run_id": "timeout-exec-run"})
		default:
			// Always return running status for the wait-poll loop.
			writeRunAPIResponse(w, map[string]interface{}{
				"run_id":         "timeout-exec-run",
				"status":         "running",
				"job_count":      1,
				"completed_jobs": 0,
				"failed_jobs":    0,
			})
		}
	}))
	defer server.Close()

	saveStewardRunGlobals(t)
	stewardURL = server.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardExecCommand = "sleep 999"
	stewardExecShell = "bash"
	stewardExecTimeout = 10 * time.Millisecond
	runWaitPollInterval = time.Millisecond

	_ = captureStdout(t, func() {
		err := runRunCommandSingle(stewardExecCmd, []string{"some-steward-id"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
	})
}

func TestStewardExecCommandRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, cmd := range stewardCmd.Commands() {
		names[cmd.Name()] = true
	}
	assert.True(t, names["exec"], "stewardCmd must have 'exec' subcommand")
}

func TestStewardExecFlagsRegistered(t *testing.T) {
	for _, flag := range []string{"command", "shell", "timeout", "json"} {
		assert.NotNil(t, stewardExecCmd.Flags().Lookup(flag), "exec must have --%s flag", flag)
	}
}

// ---------------------------------------------------------------------------
// [REQUIRED TEST] confirm-gate wiring — run-script
// ---------------------------------------------------------------------------

// newRunScriptResolveServer creates a minimal test server that handles
// POST /api/v1/fleet/resolve → resolveMatches and POST /api/v1/runs/script →
// {"run_id": runID}. Requests to other paths return 404.
func newRunScriptResolveServer(t *testing.T, runID string, resolveMatches []map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve":
			writeRunAPIResponse(w, resolveMatches)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runs/script":
			writeRunAPIResponse(w, map[string]string{"run_id": runID})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestRunScript_ConfirmGate_SingleMatchNoPrompt verifies that a selector
// resolving to exactly one steward proceeds without requiring --yes.
func TestRunScript_ConfirmGate_SingleMatchNoPrompt(t *testing.T) {
	srv := newRunScriptResolveServer(t, "run-single",
		[]map[string]interface{}{{"id": "s1", "status": "online"}},
	)
	defer srv.Close()

	saveStewardRunGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	stewardRunScript = "my-script"
	stewardRunTarget = "id:s1"
	stewardYes = false // single match → no prompt required

	_ = captureStdout(t, func() {
		err := runRunScript(stewardRunScriptCmd, []string{})
		require.NoError(t, err)
	})
}

// TestRunScript_ConfirmGate_MultiMatchNonTTYRequiresYes verifies that a selector
// resolving to more than one steward is blocked when --yes is not set and stdin
// is not an interactive TTY (which is always true in test environments).
func TestRunScript_ConfirmGate_MultiMatchNonTTYRequiresYes(t *testing.T) {
	srv := newRunScriptResolveServer(t, "run-multi",
		[]map[string]interface{}{
			{"id": "s1", "status": "online"},
			{"id": "s2", "status": "online"},
		},
	)
	defer srv.Close()

	saveStewardRunGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	stewardRunScript = "my-script"
	stewardRunTarget = "os:linux"
	stewardYes = false

	err := runRunScript(stewardRunScriptCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "yes")
}

// TestRunScript_JSONOutput_KeyedBySteward verifies that --json produces a
// keyed-by-steward array (story 4 schema) with the run_id in each payload.
func TestRunScript_JSONOutput_KeyedBySteward(t *testing.T) {
	srv := newRunScriptResolveServer(t, "run-json-id",
		[]map[string]interface{}{
			{"id": "s1", "dna": map[string]interface{}{"hostname": "host-one"}},
			{"id": "s2", "dna": map[string]interface{}{"hostname": "host-two"}},
		},
	)
	defer srv.Close()

	saveStewardRunGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	stewardRunScript = "my-script"
	stewardRunTarget = "os:linux"
	stewardYes = true
	stewardRunScriptJSONOutput = true

	output := captureStdout(t, func() {
		err := runRunScript(stewardRunScriptCmd, []string{})
		require.NoError(t, err)
	})

	var entries []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(output), &entries), "output must be valid JSON")
	require.Len(t, entries, 2, "must have one entry per resolved steward")

	keys := make(map[string]bool)
	for _, e := range entries {
		key, ok := e["key"].(string)
		require.True(t, ok, "each entry must have a string 'key' field")
		keys[key] = true
		assert.True(t, e["success"].(bool), "each entry must be success=true")
		payload, ok := e["payload"].(map[string]interface{})
		require.True(t, ok, "each entry must have a payload object")
		assert.Equal(t, "run-json-id", payload["run_id"], "payload must contain run_id")
	}
	assert.True(t, keys["host-one#s1"], "output must contain key 'host-one#s1'")
	assert.True(t, keys["host-two#s2"], "output must contain key 'host-two#s2'")
}

// ---------------------------------------------------------------------------
// [REQUIRED TEST] confirm-gate wiring — run-command
// ---------------------------------------------------------------------------

// newRunCommandResolveServer creates a minimal test server for run-command confirm-gate tests.
func newRunCommandResolveServer(t *testing.T, runID string, resolveMatches []map[string]interface{}, capturedBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve":
			writeRunAPIResponse(w, resolveMatches)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runs/command":
			if capturedBody != nil {
				*capturedBody, _ = io.ReadAll(r.Body)
			}
			writeRunAPIResponse(w, map[string]string{"run_id": runID})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestRunCommand_ConfirmGate_SingleMatchNoPrompt verifies that a single-match
// target proceeds without --yes.
func TestRunCommand_ConfirmGate_SingleMatchNoPrompt(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	srv := newRunCommandResolveServer(t, "cmd-single",
		[]map[string]interface{}{{"id": "s1", "status": "online"}},
		nil,
	)
	defer srv.Close()

	saveStewardRunGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardRunShell = "bash"
	stewardRunTarget = "id:s1"
	stewardYes = false

	_ = captureStdout(t, func() {
		err := runRunCommand(stewardRunCommandCmd, []string{"echo hello"})
		require.NoError(t, err)
	})
}

// TestRunCommand_ConfirmGate_MultiMatchNonTTYRequiresYes verifies that a multi-
// match target is blocked without --yes in a non-interactive context.
func TestRunCommand_ConfirmGate_MultiMatchNonTTYRequiresYes(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	srv := newRunCommandResolveServer(t, "cmd-multi",
		[]map[string]interface{}{
			{"id": "s1", "status": "online"},
			{"id": "s2", "status": "online"},
		},
		nil,
	)
	defer srv.Close()

	saveStewardRunGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardRunShell = "bash"
	stewardRunTarget = "os:linux"
	stewardYes = false

	err := runRunCommand(stewardRunCommandCmd, []string{"echo hello"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "yes")
}

// TestRunCommand_JSONOutput_KeyedBySteward verifies that --json output from
// run-command is a keyed-by-steward array with the run_id in each payload.
// ---------------------------------------------------------------------------
// Issue #3694 — operator envelope nonce generation.
// ---------------------------------------------------------------------------

// funcSourceText returns the exact source text of the top-level function funcName
// declared in filename, via AST parse rather than string search — used to assert
// directly against the implementation (Issue #3694 AC) rather than only against
// observed output.
func funcSourceText(t *testing.T, filename, funcName string) string {
	t.Helper()
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	require.NoError(t, err)
	src, err := os.ReadFile(filename)
	require.NoError(t, err)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != funcName {
			continue
		}
		start := fset.Position(fd.Pos()).Offset
		end := fset.Position(fd.End()).Offset
		return string(src[start:end])
	}
	t.Fatalf("function %s not found in %s", funcName, filename)
	return ""
}

// TestGenerateOperatorNonce_UsesCryptoRandDirectly is a required test (Issue #3694
// AC): the nonce-generation call site uses crypto/rand — not math/rand, a counter,
// or a timestamp — and produces at least 16 bytes. Verified directly against the
// implementation (AST-extracted source of generateOperatorNonce, plus a
// package-wide scan for a stray math/rand import), not just observed output
// variance across calls, per the AC's own wording.
func TestGenerateOperatorNonce_UsesCryptoRandDirectly(t *testing.T) {
	fn := funcSourceText(t, "steward.go", "generateOperatorNonce")
	assert.Contains(t, fn, "rand.Read", "must generate the nonce via crypto/rand.Read")
	assert.NotContains(t, fn, "math/rand", "must not use math/rand")
	assert.NotContains(t, fn, "time.Now", "must not derive the nonce from a timestamp")
	assert.NotContains(t, fn, "uuid", "must not derive the nonce from a UUID")
	assert.NotContains(t, fn, "counter", "must not derive the nonce from a counter")

	// Confirm "rand" resolves to crypto/rand in this file, not a package-wide
	// math/rand import that could shadow it. Only non-test files are scanned: this
	// very test's source legitimately contains the literal string being searched
	// for (in this comment and assertion), which would otherwise self-match.
	pkgFiles, err := filepath.Glob("*.go")
	require.NoError(t, err)
	mathRandImport := `"math/rand"`
	for _, f := range pkgFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		content, err := os.ReadFile(f)
		require.NoError(t, err)
		assert.NotContains(t, string(content), mathRandImport,
			"non-test package file must not import math/rand (file %s)", f)
	}

	require.GreaterOrEqual(t, operatorNonceBytes, 16,
		"the nonce byte length constant must meet the AC's 16-byte floor")

	nonce, err := generateOperatorNonce()
	require.NoError(t, err)
	decoded, err := hex.DecodeString(nonce)
	require.NoError(t, err, "nonce must be valid hex")
	assert.GreaterOrEqual(t, len(decoded), 16, "generated nonce must be at least 16 bytes")
}

// TestGenerateOperatorNonce_UniqueAcrossCalls is a sanity companion to the
// implementation-level check above: many consecutive calls never collide.
func TestGenerateOperatorNonce_UniqueAcrossCalls(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce, err := generateOperatorNonce()
		require.NoError(t, err)
		require.False(t, seen[nonce], "nonce %q repeated", nonce)
		seen[nonce] = true
	}
}

func TestRunCommand_JSONOutput_KeyedBySteward(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	srv := newRunCommandResolveServer(t, "cmd-json-id",
		[]map[string]interface{}{
			{"id": "s1", "dna": map[string]interface{}{"hostname": "host-one"}},
			{"id": "s2", "dna": map[string]interface{}{"hostname": "host-two"}},
		},
		nil,
	)
	defer srv.Close()

	saveStewardRunGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardRunShell = "bash"
	stewardRunTarget = "os:linux"
	stewardYes = true
	stewardRunCommandJSONOutput = true

	output := captureStdout(t, func() {
		err := runRunCommand(stewardRunCommandCmd, []string{"echo hello"})
		require.NoError(t, err)
	})

	var entries []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(output), &entries), "output must be valid JSON")
	require.Len(t, entries, 2, "must have one entry per resolved steward")

	keys := make(map[string]bool)
	for _, e := range entries {
		key, ok := e["key"].(string)
		require.True(t, ok, "each entry must have a string 'key' field")
		keys[key] = true
		assert.True(t, e["success"].(bool), "each entry must be success=true")
		payload, ok := e["payload"].(map[string]interface{})
		require.True(t, ok, "each entry must have a payload object")
		assert.Equal(t, "cmd-json-id", payload["run_id"], "payload must contain run_id")
	}
	assert.True(t, keys["host-one#s1"], "output must contain key 'host-one#s1'")
	assert.True(t, keys["host-two#s2"], "output must contain key 'host-two#s2'")
}
