// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #4287: tests for the CLI presence-relay lodge/read/collect handlers.
//
// Coverage:
//   - lodge: success, no principal, machine principal (ADR-021 Amendment 7 Decision 2), invalid
//     permission, invalid body hash, non-standard method, deceptive/oversized path,
//     and the absence of any caller-supplied consent text
//   - read: success (returns the four bound values), unknown id, different account
//     (existence-oracle safe)
//   - collect: pending, unknown id, different account (Desired State 3), single-use
//     (second collect after the first succeeds gets 410 Gone)
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// validLodgeBody returns a well-formed LodgeCliPresenceRequestBody for module:approve.
func validLodgeBody() LodgeCliPresenceRequestBody {
	return LodgeCliPresenceRequestBody{
		Method:     http.MethodPost,
		Path:       "/api/v1/modules/approvals/test-address/approve",
		BodyHash:   emptyBodyHashHex,
		Permission: "module:approve",
	}
}

func doLodgeCliPresence(t *testing.T, server *Server, principal *Principal, body LodgeCliPresenceRequestBody) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli-presence/lodge", bytes.NewReader(b))
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	rec := httptest.NewRecorder()
	server.handleLodgeCliPresenceRequest(rec, req)
	return rec
}

// doLodgeCliPresenceRaw lodges a hand-written JSON body, so a test can send fields the
// typed LodgeCliPresenceRequestBody does not declare.
func doLodgeCliPresenceRaw(t *testing.T, server *Server, principal *Principal, rawBody string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli-presence/lodge", bytes.NewReader([]byte(rawBody)))
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	rec := httptest.NewRecorder()
	server.handleLodgeCliPresenceRequest(rec, req)
	return rec
}

func doGetCliPresence(t *testing.T, server *Server, principal *Principal, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cli-presence/"+id, nil)
	req = withVars(req, map[string]string{"id": id})
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	rec := httptest.NewRecorder()
	server.handleGetCliPresenceRequest(rec, req)
	return rec
}

func doCollectCliPresence(t *testing.T, server *Server, principal *Principal, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli-presence/"+id+"/collect", nil)
	req = withVars(req, map[string]string{"id": id})
	if principal != nil {
		req = withPrincipal(req, principal)
	}
	rec := httptest.NewRecorder()
	server.handleCollectCliPresenceRequest(rec, req)
	return rec
}

func lodgeAndDecode(t *testing.T, server *Server, principal *Principal, body LodgeCliPresenceRequestBody) LodgeCliPresenceResponse {
	t.Helper()
	rec := doLodgeCliPresence(t, server, principal, body)
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var out LodgeCliPresenceResponse
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

// --- lodge ---

func TestHandleLodgeCliPresenceRequest_Success(t *testing.T) {
	server := setupTestServer(t)
	principal := testAdminPrincipal()

	out := lodgeAndDecode(t, server, principal, validLodgeBody())
	assert.NotEmpty(t, out.RequestID)
	assert.NotEmpty(t, out.UserCode)
	assert.NotEmpty(t, out.ExpiresAt)

	stored, err := server.getCliPresenceRequestByID(t.Context(), out.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, principal.ID, stored.LodgedByPrincipalID)
	assert.Equal(t, http.MethodPost, stored.Method)
	assert.Equal(t, "/api/v1/modules/approvals/test-address/approve", stored.Path)
	assert.Equal(t, emptyBodyHashHex, stored.BodyHash)
	assert.Equal(t, "module:approve", stored.PermissionID)
	assert.Equal(t, cliPresenceRequestStatusPending, stored.Status)
}

func TestHandleLodgeCliPresenceRequest_NoPrincipal_401(t *testing.T) {
	server := setupTestServer(t)
	rec := doLodgeCliPresence(t, server, nil, validLodgeBody())
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "AUTHENTICATION_REQUIRED", errCode(t, rec.Body.Bytes()))
}

// TestHandleLodgeCliPresenceRequest_MachinePrincipal_403 is the [REQUIRED TEST] for
// ADR-021 Amendment 7 Decision 2: an API-key (AssuranceMachine) principal cannot lodge a presence
// request — automation stays out of the presence relay entirely.
func TestHandleLodgeCliPresenceRequest_MachinePrincipal_403(t *testing.T) {
	server := setupTestServer(t)
	machine := &Principal{ID: "machine-key-1", Assurance: session.AssuranceMachine}
	rec := doLodgeCliPresence(t, server, machine, validLodgeBody())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "MACHINE_PRINCIPAL_CANNOT_LODGE", errCode(t, rec.Body.Bytes()))
}

func TestHandleLodgeCliPresenceRequest_InvalidPermission_400(t *testing.T) {
	server := setupTestServer(t)
	body := validLodgeBody()
	body.Permission = "steward:visibility" // registered, but RequireUserPresence is false
	rec := doLodgeCliPresence(t, server, testAdminPrincipal(), body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "INVALID_PERMISSION", errCode(t, rec.Body.Bytes()))
}

func TestHandleLodgeCliPresenceRequest_UnknownPermission_400(t *testing.T) {
	server := setupTestServer(t)
	body := validLodgeBody()
	body.Permission = "not-a-real-permission"
	rec := doLodgeCliPresence(t, server, testAdminPrincipal(), body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "INVALID_PERMISSION", errCode(t, rec.Body.Bytes()))
}

func TestHandleLodgeCliPresenceRequest_InvalidBodyHash_400(t *testing.T) {
	server := setupTestServer(t)
	body := validLodgeBody()
	body.BodyHash = "not-a-sha256-digest"
	rec := doLodgeCliPresence(t, server, testAdminPrincipal(), body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "INVALID_BODY_HASH", errCode(t, rec.Body.Bytes()))
}

func TestHandleLodgeCliPresenceRequest_MissingActionFields_400(t *testing.T) {
	server := setupTestServer(t)
	body := validLodgeBody()
	body.Path = ""
	rec := doLodgeCliPresence(t, server, testAdminPrincipal(), body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "INVALID_ACTION", errCode(t, rec.Body.Bytes()))
}

// TestHandleLodgeCliPresenceRequest_RejectsNonStandardMethod_400 pins the closed method
// set: requirePermission can only ever compare the binding against a real r.Method, and
// the relay page renders this value as consent text.
func TestHandleLodgeCliPresenceRequest_RejectsNonStandardMethod_400(t *testing.T) {
	for _, method := range []string{"post", "TRACE", "POST /x", "GET\r\nX-Evil: 1", ""} {
		t.Run(method, func(t *testing.T) {
			server := setupTestServer(t)
			body := validLodgeBody()
			body.Method = method
			rec := doLodgeCliPresence(t, server, testAdminPrincipal(), body)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, "INVALID_ACTION", errCode(t, rec.Body.Bytes()))
		})
	}
}

// TestHandleLodgeCliPresenceRequest_RejectsDeceptiveOrOversizedPath_400 covers the other
// half of the display-safety rule: a path the confirmation page would render must not be
// able to carry control characters, spaces, bidi-override codepoints, or unbounded
// length (the durable store write-amplification side of the same field).
func TestHandleLodgeCliPresenceRequest_RejectsDeceptiveOrOversizedPath_400(t *testing.T) {
	cases := map[string]string{
		"relative": "api/v1/modules/approvals/x/approve",
		"newline":  "/api/v1/modules/approvals/x/approve\nnot-really",
		"tab":      "/api/v1/modules/approvals/x/approve\tevil",
		"space":    "/api/v1/modules/approvals/x /approve",
		// \u202E is RIGHT-TO-LEFT OVERRIDE; \u0445 is the Cyrillic homoglyph of "x".
		"bidi_override":        "/api/v1/modules/approvals/\u202Eevorppa/x/approve",
		"non_ascii":            "/api/v1/modules/approvals/\u0445/approve",
		"over_length":          "/api/v1/" + strings.Repeat("a", cliPresenceMaxPathLen),
		"null_byte":            "/api/v1/modules\x00/approve",
		"delete_control_char":  "/api/v1/modules\x7f/approve",
		"empty_after_required": "",
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			server := setupTestServer(t)
			body := validLodgeBody()
			body.Path = path
			rec := doLodgeCliPresence(t, server, testAdminPrincipal(), body)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, "INVALID_ACTION", errCode(t, rec.Body.Bytes()))
		})
	}
}

// TestHandleLodgeCliPresenceRequest_IgnoresCallerSuppliedConsentText is the regression
// test for the authorization-display integrity hole: malware holding the CLI credential
// binds one action while describing another, and the admin's gesture then authorizes the
// bound action from the controller's own trusted origin. Lodge accepts no display text
// at all, so nothing the caller writes reaches the durable record or the read response.
func TestHandleLodgeCliPresenceRequest_IgnoresCallerSuppliedConsentText(t *testing.T) {
	server := setupTestServer(t)
	principal := testAdminPrincipal()

	const evil = "module:approve — POST /api/v1/modules/approvals/corp-baseline/approve"
	raw := `{"method":"POST",` +
		`"path":"/api/v1/modules/approvals/evil-bundle/approve",` +
		`"body_sha256":"` + emptyBodyHashHex + `",` +
		`"permission":"module:approve",` +
		`"description":"` + evil + `"}`

	rec := doLodgeCliPresenceRaw(t, server, principal, raw)
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
	var lodgeResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &lodgeResp))
	lodgeData, err := json.Marshal(lodgeResp.Data)
	require.NoError(t, err)
	var lodged LodgeCliPresenceResponse
	require.NoError(t, json.Unmarshal(lodgeData, &lodged))

	getRec := doGetCliPresence(t, server, principal, lodged.RequestID)
	require.Equal(t, http.StatusOK, getRec.Code, "body: %s", getRec.Body.String())
	assert.NotContains(t, getRec.Body.String(), "corp-baseline",
		"caller-supplied text must never reach the consent display")

	var resp APIResponse
	require.NoError(t, json.Unmarshal(getRec.Body.Bytes(), &resp))
	data, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var out GetCliPresenceResponse
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, "/api/v1/modules/approvals/evil-bundle/approve", out.Path,
		"the read must return the bound path, which is what requirePermission enforces")
}

// --- read ---

func TestHandleGetCliPresenceRequest_Success(t *testing.T) {
	server := setupTestServer(t)
	principal := testAdminPrincipal()
	lodged := lodgeAndDecode(t, server, principal, validLodgeBody())

	rec := doGetCliPresence(t, server, principal, lodged.RequestID)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var out GetCliPresenceResponse
	require.NoError(t, json.Unmarshal(data, &out))

	assert.Equal(t, lodged.RequestID, out.RequestID)
	assert.Equal(t, "pending", out.Status)
	assert.Equal(t, lodged.UserCode, out.UserCode)

	// The four bound values requirePermission enforces (middleware.go's action-binding
	// check) are exactly what the read returns, so the confirmation page can render the
	// action the gesture will actually authorize.
	assert.Equal(t, "module:approve", out.Permission)
	assert.Equal(t, http.MethodPost, out.Method)
	assert.Equal(t, "/api/v1/modules/approvals/test-address/approve", out.Path)
	assert.Equal(t, emptyBodyHashHex, out.BodyHash)
}

func TestHandleGetCliPresenceRequest_UnknownID_404(t *testing.T) {
	server := setupTestServer(t)
	rec := doGetCliPresence(t, server, testAdminPrincipal(), "cli-presence-does-not-exist")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "REQUEST_NOT_FOUND", errCode(t, rec.Body.Bytes()))
}

// TestHandleGetCliPresenceRequest_DifferentAccount_404 verifies the existence-oracle
// stance: a request read by an account other than the one that lodged it is
// indistinguishable from an unknown ID.
func TestHandleGetCliPresenceRequest_DifferentAccount_404(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeAndDecode(t, server, testAdminPrincipal(), validLodgeBody())

	other := &Principal{ID: "someone-else", Assurance: session.AssuranceStrong}
	rec := doGetCliPresence(t, server, other, lodged.RequestID)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "REQUEST_NOT_FOUND", errCode(t, rec.Body.Bytes()))
}

// --- collect ---

func TestHandleCollectCliPresenceRequest_Pending(t *testing.T) {
	server := setupTestServer(t)
	principal := testAdminPrincipal()
	lodged := lodgeAndDecode(t, server, principal, validLodgeBody())

	rec := doCollectCliPresence(t, server, principal, lodged.RequestID)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var out CollectCliPresenceResponse
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, "pending", out.Status)
	assert.Empty(t, out.PresenceToken)
}

func TestHandleCollectCliPresenceRequest_UnknownID_404(t *testing.T) {
	server := setupTestServer(t)
	rec := doCollectCliPresence(t, server, testAdminPrincipal(), "cli-presence-does-not-exist")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "REQUEST_NOT_FOUND", errCode(t, rec.Body.Bytes()))
}

// TestHandleCollectCliPresenceRequest_DifferentAccount_403 is the [REQUIRED TEST]: a
// collect attempt by a different account than the one that lodged the request fails.
func TestHandleCollectCliPresenceRequest_DifferentAccount_403(t *testing.T) {
	server := setupTestServer(t)
	lodged := lodgeAndDecode(t, server, testAdminPrincipal(), validLodgeBody())

	other := &Principal{ID: "someone-else", Assurance: session.AssuranceStrong}
	rec := doCollectCliPresence(t, server, other, lodged.RequestID)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "REQUEST_ACCOUNT_MISMATCH", errCode(t, rec.Body.Bytes()))
}

// TestHandleCollectCliPresenceRequest_SingleUse is the [REQUIRED TEST]: a token is
// collected at most once. This simulates the browser-side approval directly (real
// WebAuthn ceremony success is covered in handlers_webauthn_test.go) by transitioning
// the stored record to "approved" with a token, mirroring what handlePresenceFinish
// does on success.
func TestHandleCollectCliPresenceRequest_SingleUse(t *testing.T) {
	server := setupTestServer(t)
	principal := testAdminPrincipal()
	lodged := lodgeAndDecode(t, server, principal, validLodgeBody())

	stored, err := server.getCliPresenceRequestByID(t.Context(), lodged.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	now := time.Now().UTC()
	stored.Status = cliPresenceRequestStatusApproved
	stored.ApprovedAt = &now
	stored.ApprovedBy = principal.ID
	stored.PresenceToken = "test-minted-presence-token"
	require.NoError(t, server.persistCliPresenceRequest(t.Context(), stored))

	// First collect: must succeed and return the token.
	rec := doCollectCliPresence(t, server, principal, lodged.RequestID)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var out CollectCliPresenceResponse
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, "collected", out.Status)
	assert.Equal(t, "test-minted-presence-token", out.PresenceToken)

	// Second collect: must fail — the request is already collected.
	rec2 := doCollectCliPresence(t, server, principal, lodged.RequestID)
	assert.Equal(t, http.StatusGone, rec2.Code, "second collect must be rejected (single-use)")
}
