// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3725: tests for cfg credential revoke-by-token / cancel-request /
// list-orphaned / revoke-orphaned.
//
// All tests use real HTTP test servers (no mocks) and a real admin bundle,
// mirroring account_test.go's established shape for this package.
package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// credentialContainmentServerConfig controls which responses the test server emits.
type credentialContainmentServerConfig struct {
	revokeByTokenResults []apiCredentialRequestContainmentOutcome
	revokeByTokenStatus  int // defaults to 200 when zero
	cancelStatus         int // defaults to 200 when zero
	orphaned             []apiOrphanedCredentialInfo
	revokeOrphanedStatus int // defaults to 200 when zero
}

func newCredentialContainmentTestServer(t *testing.T, cfg credentialContainmentServerConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case r.Method == http.MethodPost && strings.Contains(path, "/revoke-issued-credentials"):
			status := cfg.revokeByTokenStatus
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			if status == http.StatusOK {
				writeEnvelope(w, apiRevokeByEnrolmentTokenResponse{
					TokenID: "et-test",
					Results: cfg.revokeByTokenResults,
				})
			} else {
				_, _ = w.Write([]byte(`{"error":{"code":"TOKEN_NOT_FOUND","message":"enrolment token not found"}}`))
			}

		case r.Method == http.MethodPost && strings.Contains(path, "/credential-requests/") && strings.HasSuffix(path, "/cancel"):
			status := cfg.cancelStatus
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			if status == http.StatusOK {
				_, _ = w.Write([]byte(`{"data":{"id":"cr-test","status":"denied"}}`))
			} else {
				_, _ = w.Write([]byte(`{"error":{"code":"REQUEST_NOT_APPROVED","message":"credential request is pending, not yet approved"}}`))
			}

		case r.Method == http.MethodGet && strings.HasSuffix(path, "/credential-requests/orphaned"):
			writeEnvelope(w, cfg.orphaned)

		case r.Method == http.MethodPost && strings.Contains(path, "/credential-requests/orphaned/") && strings.HasSuffix(path, "/revoke"):
			status := cfg.revokeOrphanedStatus
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			if status == http.StatusOK {
				_, _ = w.Write([]byte(`{"data":{"revoked":true}}`))
			} else {
				_, _ = w.Write([]byte(`{"error":{"code":"NOT_ORPHANED","message":"certificate is bound to an account"}}`))
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// saveCredentialContainmentFlags snapshots and restores the package-level flag vars
// touched by these tests, mirroring saveAccountFlags.
func saveCredentialContainmentFlags(t *testing.T) func() {
	t.Helper()
	origAPIURL := credentialContainmentAPIURL
	origForce := credentialContainmentForce
	origJSON := credentialListOrphanedJSONOut
	origBundlePath := bundlePath
	origNoBundle := noBundle
	return func() {
		credentialContainmentAPIURL = origAPIURL
		credentialContainmentForce = origForce
		credentialListOrphanedJSONOut = origJSON
		bundlePath = origBundlePath
		noBundle = origNoBundle
	}
}

// setupCredentialContainmentTest creates the test server, generates a bundle, wires
// bundlePath, and returns a restore function — mirrors setupAccountTest.
func setupCredentialContainmentTest(t *testing.T, cfg credentialContainmentServerConfig) (*httptest.Server, func()) {
	t.Helper()
	srv := newCredentialContainmentTestServer(t, cfg)
	restore := saveCredentialContainmentFlags(t)
	b := generateWebAuthnBundle(t)
	bundlePath = writeBundleFile(t, b, srv.URL)
	return srv, restore
}

// ---- revoke-by-token ----------------------------------------------------------------

func TestCredentialRevokeByToken_HappyPath(t *testing.T) {
	cfg := credentialContainmentServerConfig{
		revokeByTokenResults: []apiCredentialRequestContainmentOutcome{
			{RequestID: "cr-1", Outcome: "contained"},
			{RequestID: "cr-2", Outcome: "already_contained"},
		},
	}
	_, restore := setupCredentialContainmentTest(t, cfg)
	defer restore()
	credentialContainmentForce = true

	var out bytes.Buffer
	credentialRevokeByTokenCmd.SetOut(&out)
	t.Cleanup(func() { credentialRevokeByTokenCmd.SetOut(nil) })

	err := runCredentialRevokeByToken(credentialRevokeByTokenCmd, []string{"et-1234"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "cr-1: contained")
	assert.Contains(t, out.String(), "cr-2: already_contained")
}

func TestCredentialRevokeByToken_RequiresForce(t *testing.T) {
	_, restore := setupCredentialContainmentTest(t, credentialContainmentServerConfig{})
	defer restore()
	credentialContainmentForce = false

	credentialRevokeByTokenCmd.SetIn(strings.NewReader("n\n"))
	t.Cleanup(func() { credentialRevokeByTokenCmd.SetIn(nil) })

	err := runCredentialRevokeByToken(credentialRevokeByTokenCmd, []string{"et-1234"})
	require.Error(t, err, "revoke-by-token without --force must fail when confirmation is not given")
	assert.Contains(t, err.Error(), "aborted")
}

// TestCredentialRevokeByToken_ZeroMatchFailsFast covers the AC: a zero-match
// token/request selection fails fast with a non-zero exit rather than silently
// succeeding.
func TestCredentialRevokeByToken_ZeroMatchFailsFast(t *testing.T) {
	cfg := credentialContainmentServerConfig{revokeByTokenResults: []apiCredentialRequestContainmentOutcome{}}
	_, restore := setupCredentialContainmentTest(t, cfg)
	defer restore()
	credentialContainmentForce = true

	err := runCredentialRevokeByToken(credentialRevokeByTokenCmd, []string{"et-empty"})
	require.Error(t, err, "zero results must be treated as a failure, not silent success")
	assert.Contains(t, err.Error(), "no credential requests found")
}

func TestCredentialRevokeByToken_UnknownToken_Errors(t *testing.T) {
	cfg := credentialContainmentServerConfig{revokeByTokenStatus: http.StatusNotFound}
	_, restore := setupCredentialContainmentTest(t, cfg)
	defer restore()
	credentialContainmentForce = true

	err := runCredentialRevokeByToken(credentialRevokeByTokenCmd, []string{"et-does-not-exist"})
	require.Error(t, err)
}

// ---- cancel-request -------------------------------------------------------------------

func TestCredentialCancelRequest_HappyPath(t *testing.T) {
	_, restore := setupCredentialContainmentTest(t, credentialContainmentServerConfig{})
	defer restore()
	credentialContainmentForce = true

	var out bytes.Buffer
	credentialCancelRequestCmd.SetOut(&out)
	t.Cleanup(func() { credentialCancelRequestCmd.SetOut(nil) })

	err := runCredentialCancelRequest(credentialCancelRequestCmd, []string{"cr-1234"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "cr-1234")
}

func TestCredentialCancelRequest_RequiresForce(t *testing.T) {
	_, restore := setupCredentialContainmentTest(t, credentialContainmentServerConfig{})
	defer restore()
	credentialContainmentForce = false

	credentialCancelRequestCmd.SetIn(strings.NewReader("n\n"))
	t.Cleanup(func() { credentialCancelRequestCmd.SetIn(nil) })

	err := runCredentialCancelRequest(credentialCancelRequestCmd, []string{"cr-1234"})
	require.Error(t, err, "cancel-request without --force must fail when confirmation is not given")
	assert.Contains(t, err.Error(), "aborted")
}

func TestCredentialCancelRequest_RefusedByServer_Errors(t *testing.T) {
	cfg := credentialContainmentServerConfig{cancelStatus: http.StatusConflict}
	_, restore := setupCredentialContainmentTest(t, cfg)
	defer restore()
	credentialContainmentForce = true

	err := runCredentialCancelRequest(credentialCancelRequestCmd, []string{"cr-pending"})
	require.Error(t, err)
}

// ---- list-orphaned --------------------------------------------------------------------

func TestCredentialListOrphaned_HappyPath(t *testing.T) {
	cfg := credentialContainmentServerConfig{
		orphaned: []apiOrphanedCredentialInfo{
			{RequestID: "cr-1", Serial: "abc123", TenantID: "acme-corp", AccountID: "acc-1", CollectedAt: "2026-08-01T00:00:00Z"},
		},
	}
	_, restore := setupCredentialContainmentTest(t, cfg)
	defer restore()

	var out bytes.Buffer
	credentialListOrphanedCmd.SetOut(&out)
	t.Cleanup(func() { credentialListOrphanedCmd.SetOut(nil) })

	err := runCredentialListOrphaned(credentialListOrphanedCmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "abc123")
	assert.Contains(t, out.String(), "cr-1")
}

func TestCredentialListOrphaned_Empty(t *testing.T) {
	_, restore := setupCredentialContainmentTest(t, credentialContainmentServerConfig{orphaned: []apiOrphanedCredentialInfo{}})
	defer restore()

	var out bytes.Buffer
	credentialListOrphanedCmd.SetOut(&out)
	t.Cleanup(func() { credentialListOrphanedCmd.SetOut(nil) })

	err := runCredentialListOrphaned(credentialListOrphanedCmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "No orphaned")
}

func TestCredentialListOrphaned_JSONOutput(t *testing.T) {
	cfg := credentialContainmentServerConfig{
		orphaned: []apiOrphanedCredentialInfo{
			{RequestID: "cr-1", Serial: "abc123"},
		},
	}
	_, restore := setupCredentialContainmentTest(t, cfg)
	defer restore()
	credentialListOrphanedJSONOut = true

	var out bytes.Buffer
	credentialListOrphanedCmd.SetOut(&out)
	t.Cleanup(func() {
		credentialListOrphanedCmd.SetOut(nil)
		credentialListOrphanedJSONOut = false
	})

	err := runCredentialListOrphaned(credentialListOrphanedCmd, nil)
	require.NoError(t, err)

	var got []apiOrphanedCredentialInfo
	require.NoError(t, json.NewDecoder(&out).Decode(&got))
	require.Len(t, got, 1)
	assert.Equal(t, "abc123", got[0].Serial)
}

// ---- revoke-orphaned ------------------------------------------------------------------

func TestCredentialRevokeOrphaned_HappyPath(t *testing.T) {
	_, restore := setupCredentialContainmentTest(t, credentialContainmentServerConfig{})
	defer restore()
	credentialContainmentForce = true

	var out bytes.Buffer
	credentialRevokeOrphanedCmd.SetOut(&out)
	t.Cleanup(func() { credentialRevokeOrphanedCmd.SetOut(nil) })

	err := runCredentialRevokeOrphaned(credentialRevokeOrphanedCmd, []string{"abc123"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "abc123")
}

func TestCredentialRevokeOrphaned_RequiresForce(t *testing.T) {
	_, restore := setupCredentialContainmentTest(t, credentialContainmentServerConfig{})
	defer restore()
	credentialContainmentForce = false

	credentialRevokeOrphanedCmd.SetIn(strings.NewReader("n\n"))
	t.Cleanup(func() { credentialRevokeOrphanedCmd.SetIn(nil) })

	err := runCredentialRevokeOrphaned(credentialRevokeOrphanedCmd, []string{"abc123"})
	require.Error(t, err, "revoke-orphaned without --force must fail when confirmation is not given")
	assert.Contains(t, err.Error(), "aborted")
}

func TestCredentialRevokeOrphaned_RefusedByServer_Errors(t *testing.T) {
	cfg := credentialContainmentServerConfig{revokeOrphanedStatus: http.StatusConflict}
	_, restore := setupCredentialContainmentTest(t, cfg)
	defer restore()
	credentialContainmentForce = true

	err := runCredentialRevokeOrphaned(credentialRevokeOrphanedCmd, []string{"abc123"})
	require.Error(t, err)
}

// ---- flag wiring ------------------------------------------------------------------

func TestCredentialContainmentSubcommandsRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, c := range credentialCmd.Commands() {
		names[strings.Fields(c.Use)[0]] = true
	}
	for _, want := range []string{"revoke-by-token", "cancel-request", "list-orphaned", "revoke-orphaned"} {
		assert.True(t, names[want], "credential command %q must be registered under credentialCmd", want)
	}

	assert.NotNil(t, credentialRevokeByTokenCmd.Flags().Lookup("force"))
	assert.NotNil(t, credentialCancelRequestCmd.Flags().Lookup("force"))
	assert.NotNil(t, credentialRevokeOrphanedCmd.Flags().Lookup("force"))
	assert.NotNil(t, credentialListOrphanedCmd.Flags().Lookup("json"))
}
