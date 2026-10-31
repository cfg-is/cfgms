// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	credCLIID       = "3f2a9c0e1b7d4e58a6c1d2e3f4a5b6c7"
	credCLIPassword = "Hx9!-one-time-pw"
	credCLIToken    = "presence-token-5559"
)

// setupDirectoryCredentialTest points the directory flags at srvURL with a test bundle
// and an interactive terminal whose presence relay yields credCLIToken.
func setupDirectoryCredentialTest(t *testing.T, srvURL string) (relayedPermission *string) {
	t.Helper()
	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://placeholder.local:9443")
	origURL, origInsecure, origBundle, origNoBundle := directoryURL, directoryTLSInsecure, bundlePath, noBundle
	directoryURL, directoryTLSInsecure, bundlePath, noBundle = srvURL, true, bundleFilePath, false
	origTerminal, origFlow := isTerminalFn, presenceBrowserFlowFn
	t.Cleanup(func() {
		directoryURL, directoryTLSInsecure, bundlePath, noBundle = origURL, origInsecure, origBundle, origNoBundle
		isTerminalFn, presenceBrowserFlowFn = origTerminal, origFlow
	})
	isTerminalFn = func() bool { return true }
	relayed := ""
	presenceBrowserFlowFn = func(_ *APIClient, _, _ string, _ []byte, permission string) (string, error) {
		relayed = permission
		return credCLIToken, nil
	}
	return &relayed
}

func TestCfgCredentialReveal_StepUpRoundTripAndPrintsOnce(t *testing.T) {
	var challenged, revealed int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/directory/credentials/"+credCLIID+"/reveal", r.URL.Path)
		w.Header().Set("Cache-Control", "no-store")
		if r.Header.Get("X-Presence-Token") != credCLIToken {
			challenged++
			w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="directory:credential-reveal"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		revealed++
		w.Header().Set("Content-Type", "application/json")
		if revealed > 1 {
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"error":{"code":"CREDENTIAL_GONE","message":"credential is no longer available"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": credCLIID, "resource_id": "user-jdoe", "password": credCLIPassword})
	}))
	defer srv.Close()
	relayed := setupDirectoryCredentialTest(t, srv.URL)

	client, err := getDirectoryClient()
	require.NoError(t, err)

	var out, errOut bytes.Buffer
	require.NoError(t, runDirectoryCredentialReveal(context.Background(), &out, &errOut, client, credCLIID))
	assert.Equal(t, "directory:credential-reveal", *relayed, "the real step-up handler relays the challenged permission")
	assert.Equal(t, 1, challenged)
	assert.Equal(t, credCLIPassword+"\n", out.String(), "the password is the only thing on stdout")
	assert.Contains(t, errOut.String(), "shown once")
	assert.NotContains(t, errOut.String(), credCLIPassword, "the password must not reach stderr")

	// A second reveal prints nothing and says the password is gone.
	out.Reset()
	errOut.Reset()
	err = runDirectoryCredentialReveal(context.Background(), &out, &errOut, client, credCLIID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer available")
	assert.NotContains(t, err.Error(), credCLIPassword)
	assert.Empty(t, out.String())
	assert.NotContains(t, errOut.String(), credCLIPassword)
}

func TestCfgCredentialReveal_RejectsMalformedIDWithoutRequest(t *testing.T) {
	var hits int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	setupDirectoryCredentialTest(t, srv.URL)
	client, err := getDirectoryClient()
	require.NoError(t, err)

	for _, id := range []string{"", "short", "../../etc/passwd", credCLIID + "0", "3F2A9C0E1B7D4E58A6C1D2E3F4A5B6C7"} {
		var out, errOut bytes.Buffer
		require.Error(t, runDirectoryCredentialReveal(context.Background(), &out, &errOut, client, id), id)
		assert.Empty(t, out.String())
	}
	assert.Zero(t, hits)
}

func TestCfgCredentialReveal_RefusesUnprintablePassword(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"resource_id": "u", "password": "pw\x1b[2J"})
	}))
	defer srv.Close()
	setupDirectoryCredentialTest(t, srv.URL)
	client, err := getDirectoryClient()
	require.NoError(t, err)

	var out, errOut bytes.Buffer
	require.Error(t, runDirectoryCredentialReveal(context.Background(), &out, &errOut, client, credCLIID))
	assert.Empty(t, out.String())
}

func TestCfgCredentialList_PrintsRecordsWithoutValues(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/directory/credentials", r.URL.Path)
		_, _ = w.Write([]byte(`{"items":[{"id":"` + credCLIID + `","resource_id":"user-jdoe","created_at":"2026-10-01T12:00:00Z","expires_at":"2026-10-04T12:00:00Z"}]}`))
	}))
	defer srv.Close()
	setupDirectoryCredentialTest(t, srv.URL)
	client, err := getDirectoryClient()
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, runDirectoryCredentialList(context.Background(), &out, client, directoryOutputTable))
	assert.Contains(t, out.String(), credCLIID)
	assert.Contains(t, out.String(), "user-jdoe")
	assert.Contains(t, out.String(), "EXPIRES")

	out.Reset()
	require.NoError(t, runDirectoryCredentialList(context.Background(), &out, client, directoryOutputJSON))
	assert.Contains(t, out.String(), `"resource_id": "user-jdoe"`)
	require.Error(t, runDirectoryCredentialList(context.Background(), &out, client, "yaml"))
}
