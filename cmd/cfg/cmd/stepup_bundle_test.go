// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certbundle "github.com/cfgis/cfgms/pkg/cert/bundle"
)

// TestNewClientFromBundle_RunsPresenceRelayOnStepUp guards Issue #4508: a client
// built from the admin mTLS bundle must run the CLI presence relay when the
// controller answers a presence-gated 401, exactly as a session client does. The
// bundle is the only CLI credential that carries AssuranceStrong, so without this
// no CLI path can satisfy a Strong + presence route such as signing-credential:request.
func TestNewClientFromBundle_RunsPresenceRelayOnStepUp(t *testing.T) {
	const presenceToken = "presence-token-4508"

	var requests, retriedWithToken int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("X-Presence-Token") == presenceToken {
			retriedWithToken++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
			return
		}
		w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="signing-credential:request"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	b, err := buildTestAdminBundle(server.URL)
	require.NoError(t, err)
	bundleFile := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	require.NoError(t, certbundle.Write(bundleFile, b))

	origTerminal, origFlow := isTerminalFn, presenceBrowserFlowFn
	t.Cleanup(func() { isTerminalFn, presenceBrowserFlowFn = origTerminal, origFlow })
	isTerminalFn = func() bool { return true }
	var relayedPermission string
	presenceBrowserFlowFn = func(_ *APIClient, _, _ string, _ []byte, permission string) (string, error) {
		relayedPermission = permission
		return presenceToken, nil
	}

	client, err := newClientFromBundle(bundleFile, server.URL, true, "")
	require.NoError(t, err)

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/signing-credential/request", nil)
	require.NoError(t, err, "a presence-gated 401 must be resolved by the relay, not returned to the caller")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "signing-credential:request", relayedPermission, "the relay must be bound to the challenged permission")
	assert.Equal(t, 1, retriedWithToken, "the request must be retried once with the collected presence token")
	assert.Equal(t, 2, requests)
}
