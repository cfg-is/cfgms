// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6381: a failed web passkey login is audited even when no account is resolved.
// The audit store refuses an empty user ID, so such a failure is recorded under the
// unauthenticated principal. A stored event also proves no "Failed to emit web login audit
// event" warning was logged: that warning is the only path that drops the event. All components are real; the assertion is the W3C
// NoneES256 vector.
package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/testutil/webauthntest"
)

// passkeyLoginAuditFailures returns the stored web.passkey.login.failure entries.
func passkeyLoginAuditFailures(t *testing.T, srv *Server) []business.AuditEntry {
	t.Helper()
	require.NoError(t, srv.auditManager.Flush(context.Background()))
	entries, err := srv.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"web.passkey.login.failure"},
	})
	require.NoError(t, err)
	out := make([]business.AuditEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, *e)
	}
	return out
}

func requireUnauthenticatedFailure(t *testing.T, e business.AuditEntry, reason string) {
	t.Helper()
	assert.Equal(t, unauthenticatedPrincipalID, e.UserID)
	assert.Equal(t, business.AuditUserTypeAPI, e.UserType)
	assert.Equal(t, unauthenticatedPrincipalID, e.ResourceID)
	assert.Equal(t, business.AuditEventAuthentication, e.EventType)
	assert.Equal(t, business.AuditResultFailure, e.Result)
	assert.Equal(t, reason, e.Details[auditKeyReason])
	assert.NotEmpty(t, e.Details[auditKeySourceIP], "the source IP must be recorded")
}

func TestPasskeyLoginAudit_IPThrottleRecordsUnauthenticatedFailure(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	ipKey := srv.clientIPKey(httptest.NewRequest(http.MethodPost, "/", nil))
	require.NotEmpty(t, ipKey)
	handlerspasskeyloginCharThrottle(srv, "ip:"+ipKey)
	id := handlerspasskeyloginCharStoreCeremony(t, srv, "", "", time.Now().Add(time.Minute))

	rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "THROTTLED", errCode(t, rec.Body.Bytes()))

	entries := passkeyLoginAuditFailures(t, srv)
	require.Len(t, entries, 1, "a throttled login must be audited")
	requireUnauthenticatedFailure(t, entries[0], auditReasonThrottledIP)
	assert.Equal(t, ipKey, entries[0].Details[auditKeySourceIP])
}

func TestPasskeyLoginAudit_AccountThrottleKeepsHintAndRecordsReason(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	handlerspasskeyloginCharThrottle(srv, "account:"+username)
	id := handlerspasskeyloginCharStoreCeremony(t, srv, username, "", time.Now().Add(time.Minute))

	rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	entries := passkeyLoginAuditFailures(t, srv)
	require.Len(t, entries, 1)
	assert.Equal(t, username, entries[0].UserID)
	assert.Equal(t, business.AuditUserTypeHuman, entries[0].UserType)
	assert.Equal(t, auditReasonThrottledAccount, entries[0].Details[auditKeyReason])
	assert.NotEmpty(t, entries[0].Details[auditKeySourceIP])
}

func TestPasskeyLoginAudit_UsernamelessUnknownCredentialRecordsUnauthenticatedFailure(t *testing.T) {
	cases := map[string]string{
		"unknown user handle": "no-such-account-id",
		"blank user handle":   "",
	}
	for name, handle := range cases {
		t.Run(name, func(t *testing.T) {
			srv, _ := setupPasskeySessionServer(t)
			id := handlerspasskeyloginCharStoreCeremony(t, srv, "", "", time.Now().Add(time.Minute))

			credID, err := hex.DecodeString(svAuthCredentialIDHex)
			require.NoError(t, err)
			authData, err := hex.DecodeString(svAuthAuthDataHex)
			require.NoError(t, err)
			cdj, err := hex.DecodeString(svAuthClientDataJSONHex)
			require.NoError(t, err)
			sig, err := hex.DecodeString(svAuthSignatureHex)
			require.NoError(t, err)
			body := webauthntest.RawAssertionBody(credID, authData, cdj, sig, []byte(handle))

			req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", bytes.NewReader(body))
			req.AddCookie(handlerspasskeyloginCharCeremonyCookie(id))
			rec := httptest.NewRecorder()
			srv.handlePasskeyLoginFinish(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))

			entries := passkeyLoginAuditFailures(t, srv)
			require.Len(t, entries, 1, "a failure with no resolved account must be audited")
			requireUnauthenticatedFailure(t, entries[0], auditReasonUnknownCredential)
		})
	}
}

func TestPasskeyLoginAudit_JunkAssertionRecordsUnauthenticatedFailure(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)
	id := handlerspasskeyloginCharStoreCeremony(t, srv, "", "", time.Now().Add(time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", junkBody())
	req.AddCookie(handlerspasskeyloginCharCeremonyCookie(id))
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	entries := passkeyLoginAuditFailures(t, srv)
	require.Len(t, entries, 1)
	assert.Equal(t, unauthenticatedPrincipalID, entries[0].UserID)
	assert.Equal(t, auditReasonUnknownCredential, entries[0].Details[auditKeyReason])
}

func TestPasskeyLoginAudit_UnresolvedAssertionForHintedAccountKeepsUsername(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	id := handlerspasskeyloginCharStoreCeremony(t, srv, username, "", time.Now().Add(time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", junkBody())
	req.AddCookie(handlerspasskeyloginCharCeremonyCookie(id))
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	entries := passkeyLoginAuditFailures(t, srv)
	require.Len(t, entries, 1)
	assert.Equal(t, username, entries[0].UserID, "a begin-time username hint is still the attribution")
	assert.Equal(t, business.AuditUserTypeHuman, entries[0].UserType)
	assert.Equal(t, auditReasonUnknownCredential, entries[0].Details[auditKeyReason])
	assert.NotEmpty(t, entries[0].Details[auditKeySourceIP])
}

func TestPasskeyLoginAudit_SignCountRegressionKeepsUsernameAndTenant(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	mutateStoredAccount(t, srv, username, func(a *account) {
		require.NotEmpty(t, a.Credentials)
		a.Credentials[0].SignCount = 5
	})
	srv.mu.Lock()
	delete(srv.accounts, username)
	srv.mu.Unlock()
	acct := storedAccount(t, srv, username)
	id := handlerspasskeyloginCharStoreCeremony(t, srv, "", "", time.Now().Add(time.Minute))

	rec := handlerspasskeyloginCharFinish(t, srv, username, handlerspasskeyloginCharCeremonyCookie(id))
	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())

	entries := passkeyLoginAuditFailures(t, srv)
	require.Len(t, entries, 1)
	assert.Equal(t, username, entries[0].UserID)
	assert.Equal(t, business.AuditUserTypeHuman, entries[0].UserType)
	assert.Equal(t, acct.TenantID, entries[0].TenantID)
}

func TestEmitWebLoginAudit_NeverPassesEmptyUserID(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)

	srv.emitWebLoginAudit(context.Background(), "", "", "web.passkey.login.failure", business.AuditResultFailure)

	entries := passkeyLoginAuditFailures(t, srv)
	require.Len(t, entries, 1)
	assert.Equal(t, unauthenticatedPrincipalID, entries[0].UserID)
	assert.Equal(t, business.AuditUserTypeAPI, entries[0].UserType)
}

// The audit store's validation is unchanged: it still refuses an empty user ID.
func TestAuditStore_StillRefusesEmptyUserID(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)
	err := srv.auditManager.RecordEvent(context.Background(), audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventAuthentication).
		Action("web.passkey.login.failure").
		User("", business.AuditUserTypeHuman).
		Resource("web-session", "x", "").
		Result(business.AuditResultFailure).
		Severity(business.AuditSeverityHigh))
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrUserIDRequired)
}
