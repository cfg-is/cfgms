// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6142: tests for cfg account software-authenticator.
//
// Tests drive the real root command through Execute() against a real HTTP test
// server, with real admin bundle material (see account_test.go for the plain-HTTP
// rationale). Coverage:
//   - request shape: PUT /api/v1/accounts/<username>/software-authenticator with
//     body {"enabled":true|false}
//   - output: stored state in text and --json modes
//   - server refusals (400, 403, 404, 503) give a non-zero exit with the server message
//   - --enabled is required; the username argument is required
//   - the username is path-escaped
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// softwareAuthenticatorCapture records what the test server received.
type softwareAuthenticatorCapture struct {
	method  string
	rawPath string
	body    []byte
	calls   int
}

// newSoftwareAuthenticatorServer serves the PUT route. When status is 200 it echoes
// the requested flag back in the success envelope; otherwise it answers with the
// controller's {"error":{"code","message"}} body.
func newSoftwareAuthenticatorServer(t *testing.T, status int, code, message string, capture *softwareAuthenticatorCapture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capture.calls++
		capture.method = r.Method
		capture.rawPath = r.URL.EscapedPath()
		capture.body = body

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{"code": code, "message": message},
			})
			return
		}
		var req struct {
			Enabled bool `json:"enabled"`
		}
		_ = json.Unmarshal(body, &req)
		writeEnvelope(w, apiSoftwareAuthenticatorResponse{
			Username:                   "agent-admin",
			TenantID:                   "acme-corp",
			AllowSoftwareAuthenticator: req.Enabled,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setupSoftwareAuthenticatorTest(t *testing.T, status int, code, message string) (*httptest.Server, *softwareAuthenticatorCapture) {
	t.Helper()
	capture := &softwareAuthenticatorCapture{}
	srv := newSoftwareAuthenticatorServer(t, status, code, message, capture)
	restore := saveAccountFlags(t)
	t.Cleanup(restore)
	bundlePath = writeBundleFile(t, generateWebAuthnBundle(t), srv.URL)
	return srv, capture
}

func TestAccountSoftwareAuthenticatorSendsPUTWithBody(t *testing.T) {
	for _, tc := range []struct {
		flag string
		want string
	}{
		{"--enabled=true", `{"enabled":true}`},
		{"--enabled=false", `{"enabled":false}`},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			srv, capture := setupSoftwareAuthenticatorTest(t, http.StatusOK, "", "")

			_, err := executeAccountCommand(t, "",
				"account", "software-authenticator", "agent-admin", tc.flag, "--url", srv.URL)
			require.NoError(t, err)

			assert.Equal(t, 1, capture.calls)
			assert.Equal(t, http.MethodPut, capture.method)
			assert.Equal(t, "/api/v1/accounts/agent-admin/software-authenticator", capture.rawPath)
			assert.JSONEq(t, tc.want, string(capture.body))
		})
	}
}

func TestAccountSoftwareAuthenticatorPrintsStoredState(t *testing.T) {
	srv, _ := setupSoftwareAuthenticatorTest(t, http.StatusOK, "", "")

	out, err := executeAccountCommand(t, "",
		"account", "software-authenticator", "agent-admin", "--enabled=true", "--url", srv.URL)
	require.NoError(t, err)
	assert.Contains(t, out, "Software authenticator enabled for account: agent-admin")
	assert.Contains(t, out, "acme-corp")
	assert.Contains(t, out, "true")

	out, err = executeAccountCommand(t, "",
		"account", "software-authenticator", "agent-admin", "--enabled=false", "--url", srv.URL)
	require.NoError(t, err)
	assert.Contains(t, out, "Software authenticator disabled for account: agent-admin")
}

func TestAccountSoftwareAuthenticatorJSONOutput(t *testing.T) {
	srv, _ := setupSoftwareAuthenticatorTest(t, http.StatusOK, "", "")

	out, err := executeAccountCommand(t, "",
		"account", "software-authenticator", "agent-admin", "--enabled=true", "--json", "--url", srv.URL)
	require.NoError(t, err)

	var got apiSoftwareAuthenticatorResponse
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "agent-admin", got.Username)
	assert.Equal(t, "acme-corp", got.TenantID)
	assert.True(t, got.AllowSoftwareAuthenticator)
}

func TestAccountSoftwareAuthenticatorServerRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		code    string
		message string
	}{
		{"400 root shape", http.StatusBadRequest, "INVALID_ACCOUNT_SHAPE", "Account has root scope; the software authenticator cannot be enabled"},
		{"403 tap missing", http.StatusForbidden, "PRESENCE_REQUIRED", "A fresh presence tap is required"},
		{"403 tenant scope", http.StatusForbidden, "FORBIDDEN", "Enabling needs a root-scope caller"},
		{"404 not found", http.StatusNotFound, "ACCOUNT_NOT_FOUND", "Account not found"},
		{"503 audit unavailable", http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Audit trail unavailable; flag not changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, capture := setupSoftwareAuthenticatorTest(t, tc.status, tc.code, tc.message)

			out, err := executeAccountCommand(t, "",
				"account", "software-authenticator", "agent-admin", "--enabled=true", "--url", srv.URL)
			require.Error(t, err, "a server refusal must be a non-zero exit")
			assert.Contains(t, err.Error(), tc.message, "the server message must reach the operator")
			assert.Contains(t, err.Error(), tc.code)
			assert.NotContains(t, out, "Software authenticator enabled", "no success output on refusal")
			assert.Equal(t, 1, capture.calls)
		})
	}
}

func TestAccountSoftwareAuthenticatorEnabledIsRequired(t *testing.T) {
	srv, capture := setupSoftwareAuthenticatorTest(t, http.StatusOK, "", "")

	_, err := executeAccountCommand(t, "",
		"account", "software-authenticator", "agent-admin", "--url", srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enabled")
	assert.Zero(t, capture.calls, "no request may be sent without --enabled")
}

func TestAccountSoftwareAuthenticatorRejectsNonBoolEnabled(t *testing.T) {
	srv, capture := setupSoftwareAuthenticatorTest(t, http.StatusOK, "", "")

	_, err := executeAccountCommand(t, "",
		"account", "software-authenticator", "agent-admin", "--enabled=maybe", "--url", srv.URL)
	require.Error(t, err)
	assert.Zero(t, capture.calls)
}

func TestAccountSoftwareAuthenticatorRequiresUsername(t *testing.T) {
	srv, capture := setupSoftwareAuthenticatorTest(t, http.StatusOK, "", "")

	_, err := executeAccountCommand(t, "",
		"account", "software-authenticator", "--enabled=true", "--url", srv.URL)
	require.Error(t, err)
	assert.Zero(t, capture.calls)
}

func TestAccountSoftwareAuthenticatorEscapesUsername(t *testing.T) {
	srv, capture := setupSoftwareAuthenticatorTest(t, http.StatusOK, "", "")

	_, err := executeAccountCommand(t, "",
		"account", "software-authenticator", "a/b c", "--enabled=false", "--url", srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/accounts/a%2Fb%20c/software-authenticator", capture.rawPath)
}

func TestAccountSoftwareAuthenticatorRegistered(t *testing.T) {
	var found bool
	for _, sub := range accountCmd.Commands() {
		if sub.Name() != "software-authenticator" {
			continue
		}
		found = true
		require.NotNil(t, sub.Flags().Lookup("enabled"))
		require.NotNil(t, sub.Flags().Lookup("json"))
		assert.Equal(t, []string{"true"}, sub.Flags().Lookup("enabled").Annotations["cobra_annotation_bash_completion_one_required_flag"])
	}
	assert.True(t, found, "cfg account software-authenticator must be registered on accountCmd")
}
