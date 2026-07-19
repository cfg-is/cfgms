// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// postWebAccount calls handleCreateWebAccount directly with an mTLS admin principal
// injected, exactly as authenticationMiddleware would after admin-cert verification.
func postWebAccount(t *testing.T, server *Server, principal *Principal, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/accounts", bytes.NewReader(payload))
	req = withPrincipal(req, principal)
	rec := httptest.NewRecorder()
	server.handleCreateWebAccount(rec, req)
	return rec
}

// deleteWebAccount calls handleDeleteWebAccount directly with an mTLS admin principal
// and the {username} route variable injected.
func deleteWebAccount(t *testing.T, server *Server, principal *Principal, username string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/web/accounts/"+username, nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username})
	rec := httptest.NewRecorder()
	server.handleDeleteWebAccount(rec, req)
	return rec
}

func testAdminPrincipal() *Principal {
	return &Principal{ID: "test-mtls-admin", Name: "mtls-admin:test", Assurance: session.AssuranceBasic}
}

// dropWebAccountCache clears the in-memory web-account cache so the next lookup
// must reload the record from the central secret store.
func dropWebAccountCache(server *Server) {
	server.mu.Lock()
	server.webAccounts = nil
	server.mu.Unlock()
}

// TestWebAccounts_CreateVerifySuccess covers create -> verify-success: a created
// account verifies with the correct password and returns its principal identity
// (ID, tenant, permissions) — RBAC-equivalent to an API-key principal, not an
// implicit global admin.
func TestWebAccounts_CreateVerifySuccess(t *testing.T) {
	server := setupTestServer(t)

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username:    "fleet-admin",
		Password:    "correct-horse-battery",
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list", "steward:read"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	info, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "fleet-admin", info["username"])
	assert.Equal(t, "tenant-a", info["tenant_id"])
	assert.NotEmpty(t, info["id"])

	principalID, tenantID, permissions, err := server.VerifyWebCredential(
		context.Background(), "fleet-admin", "correct-horse-battery")
	require.NoError(t, err)
	assert.Equal(t, info["id"], principalID)
	assert.Equal(t, "tenant-a", tenantID)
	assert.ElementsMatch(t, []string{"steward:list", "steward:read"}, permissions,
		"web account carries exactly the granted permissions — no implicit admin grants")
}

// TestWebAccounts_VerifyFailureUniformity covers verify-wrong-password ->
// verify-unknown-user uniformity: both fail with the identical sentinel error and
// message so nothing in the error contract discloses whether the username exists.
func TestWebAccounts_VerifyFailureUniformity(t *testing.T) {
	server := setupTestServer(t)

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username: "uniform-user",
		Password: "the-real-password",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	_, _, _, wrongPwErr := server.VerifyWebCredential(
		context.Background(), "uniform-user", "not-the-password")
	require.Error(t, wrongPwErr)
	assert.ErrorIs(t, wrongPwErr, ErrInvalidWebCredential)

	_, _, _, unknownUserErr := server.VerifyWebCredential(
		context.Background(), "no-such-user", "not-the-password")
	require.Error(t, unknownUserErr)
	assert.ErrorIs(t, unknownUserErr, ErrInvalidWebCredential)

	assert.Equal(t, wrongPwErr.Error(), unknownUserErr.Error(),
		"unknown-user and wrong-password must be indistinguishable in the error contract")

	// The dummy hash used to equalize the unknown-user timing path must be a real
	// argon2id PHC hash so both paths perform the same key derivation work.
	dummy := dummyWebAccountHash()
	assert.True(t, strings.HasPrefix(dummy, "$argon2id$"),
		"dummy hash must be an argon2id PHC string, got %q", dummy)
	ok, err := verifyWebPassword("not-the-password", dummy)
	require.NoError(t, err)
	assert.False(t, ok, "dummy hash must never verify a real password")
}

// TestWebAccounts_PasswordResetChangesAcceptedCredential covers reset via the same
// POST endpoint (upsert): the old password stops verifying, the new one verifies,
// and the principal ID remains stable across the reset.
func TestWebAccounts_PasswordResetChangesAcceptedCredential(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username:    "reset-user",
		Password:    "original-password",
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	var createResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createResp))
	createdID := createResp.Data.(map[string]interface{})["id"]

	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username: "reset-user",
		Password: "replacement-password",
	})
	require.Equal(t, http.StatusOK, rec.Code, "reset of an existing account returns 200, not 201")

	_, _, _, err := server.VerifyWebCredential(context.Background(), "reset-user", "original-password")
	assert.ErrorIs(t, err, ErrInvalidWebCredential, "old password must stop verifying after reset")

	principalID, tenantID, permissions, err := server.VerifyWebCredential(
		context.Background(), "reset-user", "replacement-password")
	require.NoError(t, err)
	assert.Equal(t, createdID, principalID, "principal ID must be stable across password reset")
	assert.Equal(t, "tenant-a", tenantID, "tenant retained when reset omits tenant_id")
	assert.ElementsMatch(t, []string{"steward:list"}, permissions,
		"permissions retained when reset omits them")
}

// TestWebAccounts_AssuranceGateRejectsAPIKeyCaller verifies through the full router that an
// API-key principal (Machine-assurance) is rejected from both provisioning endpoints with 403
// INSUFFICIENT_PERMISSIONS — even when the key carries the matching web-account permissions.
// The assurance gate in requirePermission fires before the handler (Issue #2780).
func TestWebAccounts_AssuranceGateRejectsAPIKeyCaller(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"web-account:create", "web-account:delete"})

	body, err := json.Marshal(WebAccountRequest{Username: "tier3-user", Password: "password-123"})
	require.NoError(t, err)

	for _, tc := range []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodPost, "/api/v1/web/accounts", body},
		{http.MethodDelete, "/api/v1/web/accounts/tier3-user", nil},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			req.Header.Set("X-API-Key", apiKey)
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusForbidden, rec.Code)
			var errResp ErrorResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
			require.NotNil(t, errResp.Error)
			assert.Equal(t, "INSUFFICIENT_PERMISSIONS", errResp.Error.Code)
		})
	}
}

// TestWebAccounts_SecretStoreRoundTripAfterCacheDrop verifies durability through the
// central pkg/secrets seam: after the in-memory cache is dropped, the account is
// reloaded from the secret store and still verifies (simulates controller restart).
func TestWebAccounts_SecretStoreRoundTripAfterCacheDrop(t *testing.T) {
	server := setupTestServer(t)

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username:    "durable-user",
		Password:    "survives-restart",
		TenantID:    "tenant-b",
		Permissions: []string{"steward:read"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	dropWebAccountCache(server)

	principalID, tenantID, permissions, err := server.VerifyWebCredential(
		context.Background(), "durable-user", "survives-restart")
	require.NoError(t, err, "account must be reloaded from the secret store after cache drop")
	assert.NotEmpty(t, principalID)
	assert.Equal(t, "tenant-b", tenantID)
	assert.ElementsMatch(t, []string{"steward:read"}, permissions)

	// Wrong password still fails after reload.
	_, _, _, err = server.VerifyWebCredential(context.Background(), "durable-user", "wrong-password")
	assert.ErrorIs(t, err, ErrInvalidWebCredential)
}

// TestWebAccounts_LockoutState is the state-level lockout unit test (security B4.1,
// state half — enforcement lives with the login endpoint in #2493): 5 consecutive
// verification failures set a 15-minute lockout, a locked account's verification
// failure is indistinguishable from bad-password, and success resets the state.
func TestWebAccounts_LockoutState(t *testing.T) {
	server := setupTestServer(t)

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username: "lockout-user",
		Password: "lockout-password",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Four consecutive failures: not locked yet.
	for i := 0; i < 4; i++ {
		_, _, _, err := server.VerifyWebCredential(context.Background(), "lockout-user", "bad-password")
		require.ErrorIs(t, err, ErrInvalidWebCredential)
	}
	locked, _ := server.webAccountLocked("lockout-user")
	assert.False(t, locked, "4 consecutive failures must not lock the account")

	// Fifth consecutive failure: locked for 15 minutes.
	before := time.Now()
	_, _, _, err := server.VerifyWebCredential(context.Background(), "lockout-user", "bad-password")
	require.ErrorIs(t, err, ErrInvalidWebCredential)
	locked, until := server.webAccountLocked("lockout-user")
	require.True(t, locked, "5 consecutive failures must set the lockout")
	assert.WithinDuration(t, before.Add(webAccountLockoutDuration), until, time.Minute,
		"lockout window must be 15 minutes")

	// A locked account's verification failure is indistinguishable from bad-password.
	_, _, _, lockedErr := server.VerifyWebCredential(context.Background(), "lockout-user", "bad-password")
	require.Error(t, lockedErr)
	assert.ErrorIs(t, lockedErr, ErrInvalidWebCredential)
	_, _, _, plainBadPw := server.VerifyWebCredential(context.Background(), "no-such-lockout-user", "bad-password")
	assert.Equal(t, plainBadPw.Error(), lockedErr.Error(),
		"locked-account failure must be indistinguishable from bad-password")

	// Successful verification resets the lockout state. (Lockout ENFORCEMENT — refusing
	// a correct password while locked — is #2493's login-endpoint behavior, not state's.)
	_, _, _, err = server.VerifyWebCredential(context.Background(), "lockout-user", "lockout-password")
	require.NoError(t, err)
	locked, _ = server.webAccountLocked("lockout-user")
	assert.False(t, locked, "successful verification must reset the lockout state")

	// Counter restarted: a single failure after reset does not lock.
	_, _, _, err = server.VerifyWebCredential(context.Background(), "lockout-user", "bad-password")
	require.ErrorIs(t, err, ErrInvalidWebCredential)
	locked, _ = server.webAccountLocked("lockout-user")
	assert.False(t, locked, "failure counter must restart after a successful verification")
}

// TestWebAccounts_InputValidationBounds covers the validation ACs: password length
// bounded 8..128 bytes BEFORE hashing, username bounded and charset-restricted so it
// stays path- and log-safe (usernames appear in DELETE URL paths).
func TestWebAccounts_InputValidationBounds(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
	}{
		{"password 7 bytes rejected", "valid-user", "1234567", http.StatusBadRequest},
		{"password 129 bytes rejected", "valid-user", strings.Repeat("x", 129), http.StatusBadRequest},
		{"password 8 bytes accepted", "min-pw-user", "12345678", http.StatusCreated},
		{"password 128 bytes accepted", "max-pw-user", strings.Repeat("x", 128), http.StatusCreated},
		{"username too short rejected", "ab", "valid-password", http.StatusBadRequest},
		{"username too long rejected", strings.Repeat("a", 65), "valid-password", http.StatusBadRequest},
		{"username path traversal rejected", "../../etc/passwd", "valid-password", http.StatusBadRequest},
		{"username with slash rejected", "tenant/user", "valid-password", http.StatusBadRequest},
		{"username with space rejected", "some user", "valid-password", http.StatusBadRequest},
		{"username with newline rejected", "user\nname", "valid-password", http.StatusBadRequest},
		{"username with charset ok", "User.name_01-x", "valid-password", http.StatusCreated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := postWebAccount(t, server, admin, WebAccountRequest{
				Username: tc.username,
				Password: tc.password,
			})
			assert.Equal(t, tc.wantStatus, rec.Code, "body: %s", rec.Body.String())
		})
	}

	// Multibyte passwords are bounded by BYTES, not runes: 43 three-byte runes = 129 bytes.
	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "utf8-user",
		Password: strings.Repeat("€", 43),
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "password length must be counted in bytes")
}

// TestWebAccounts_UnknownPermissionRejected verifies web accounts use the same
// permission allow-list discipline as API keys ("*" and unknown IDs rejected).
func TestWebAccounts_UnknownPermissionRejected(t *testing.T) {
	server := setupTestServer(t)

	for _, perm := range []string{"*", "not-a-real:permission"} {
		rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
			Username:    "perm-user",
			Password:    "valid-password",
			Permissions: []string{perm},
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code, "permission %q must be rejected", perm)
	}
}

// TestWebAccounts_StoredRecordContainsNoPlaintext asserts the persisted record holds
// an argon2id PHC hash and never the password, in value, metadata, or description.
func TestWebAccounts_StoredRecordContainsNoPlaintext(t *testing.T) {
	server := setupTestServer(t)
	const password = "super-secret-plaintext"

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username: "no-plaintext-user",
		Password: password,
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	metas, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: webAccountSecretType,
			"username":                      "no-plaintext-user",
		},
	})
	require.NoError(t, err)
	require.Len(t, metas, 1, "exactly one persisted record for the account")

	secret, err := server.secretStore.GetSecret(context.Background(),
		metas[0].TenantID+"/"+metas[0].Key)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(secret.Value, "$argon2id$"),
		"stored value must be an argon2id PHC string, got %q", secret.Value)
	assert.NotEqual(t, password, secret.Value)

	raw, err := json.Marshal(secret)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), password,
		"password plaintext must not appear anywhere in the stored record")
}

// TestWebAccounts_DeleteRemovesCacheAndStore verifies DELETE removes the account from
// both the in-memory cache and the durable secret store, and a repeat delete is 404.
func TestWebAccounts_DeleteRemovesCacheAndStore(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "delete-user",
		Password: "delete-password",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	rec = deleteWebAccount(t, server, admin, "delete-user")
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	// Gone from the verification path (cache).
	_, _, _, err := server.VerifyWebCredential(context.Background(), "delete-user", "delete-password")
	assert.ErrorIs(t, err, ErrInvalidWebCredential)

	// Gone from the durable store — still gone after a cache drop.
	dropWebAccountCache(server)
	_, _, _, err = server.VerifyWebCredential(context.Background(), "delete-user", "delete-password")
	assert.ErrorIs(t, err, ErrInvalidWebCredential)

	metas, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: webAccountSecretType,
			"username":                      "delete-user",
		},
	})
	require.NoError(t, err)
	assert.Empty(t, metas, "record must be removed from the secret store")

	rec = deleteWebAccount(t, server, admin, "delete-user")
	assert.Equal(t, http.StatusNotFound, rec.Code, "repeat delete must be 404")
}

// TestWebAccounts_AuditEntriesEmitted is the [REQUIRED TEST] for founder condition 2:
// create, password reset, and delete each write an audit entry carrying the sanitized
// username and the acting admin principal.
func TestWebAccounts_AuditEntriesEmitted(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "audit-user",
		Password: "first-password",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username: "audit-user",
		Password: "second-password",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	rec = deleteWebAccount(t, server, admin, "audit-user")
	require.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))

	for _, action := range []string{
		"web_account.created",
		"web_account.password_reset",
		"web_account.deleted",
	} {
		entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
			Actions: []string{action},
		})
		require.NoError(t, err)
		require.NotEmpty(t, entries, "audit entry for %s must be written", action)
		e := entries[0]
		assert.Equal(t, action, e.Action)
		assert.Equal(t, "web-account", e.ResourceType)
		assert.Equal(t, "audit-user", e.ResourceID, "sanitized username is the resource ID")
		assert.Equal(t, admin.ID, e.UserID, "acting admin principal must be recorded")
		assert.Equal(t, business.AuditResultSuccess, e.Result)
	}
}

// TestWebAccounts_NoPasswordInLogsOrErrors is the second [REQUIRED TEST] half of
// founder condition 2: the password value never appears in any log line or error
// response across create, reset, delete, verify-success, and verify-failure paths.
func TestWebAccounts_NoPasswordInLogsOrErrors(t *testing.T) {
	clog := &captureAllLogger{}
	server := setupTestServerWithLogger(t, clog)
	admin := testAdminPrincipal()

	const password = "hyper-sensitive-password"
	const newPassword = "rotated-sensitive-password"
	var responses []string

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "log-safety-user", Password: password, TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	responses = append(responses, rec.Body.String())

	// Verify success + failure paths both log without the password.
	_, _, _, err := server.VerifyWebCredential(context.Background(), "log-safety-user", password)
	require.NoError(t, err)
	_, _, _, err = server.VerifyWebCredential(context.Background(), "log-safety-user", "wrong-"+password)
	require.ErrorIs(t, err, ErrInvalidWebCredential)
	require.NotContains(t, err.Error(), password, "verification error must not echo the password")

	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username: "log-safety-user", Password: newPassword,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	responses = append(responses, rec.Body.String())

	// Error paths must not echo the password either.
	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username: "bad/../username", Password: password,
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)
	responses = append(responses, rec.Body.String())
	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username: "short-pw-user", Password: "short",
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)
	responses = append(responses, rec.Body.String())

	rec = deleteWebAccount(t, server, admin, "log-safety-user")
	require.Equal(t, http.StatusOK, rec.Code)
	responses = append(responses, rec.Body.String())

	logged := clog.captured()
	assert.NotContains(t, logged, password, "password must never appear in logs")
	assert.NotContains(t, logged, newPassword, "reset password must never appear in logs")
	assert.NotContains(t, logged, "short", "even an invalid password value must never appear in logs")
	for i, body := range responses {
		assert.NotContains(t, body, password, "response %d must not contain the password", i)
		assert.NotContains(t, body, newPassword, "response %d must not contain the reset password", i)
	}
}

// TestWebAccounts_VerifyRejectsMalformedInputsUniformly verifies that syntactically
// invalid usernames/passwords fail verification with the same uniform error — the
// verification API never discloses why a credential was rejected.
func TestWebAccounts_VerifyRejectsMalformedInputsUniformly(t *testing.T) {
	server := setupTestServer(t)

	for _, tc := range []struct{ username, password string }{
		{"../../traversal", "some-password"},
		{"valid-user", ""},
		{"", "some-password"},
		{"valid-user", "short"},
	} {
		_, _, _, err := server.VerifyWebCredential(context.Background(), tc.username, tc.password)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidWebCredential,
			"malformed input (%q, %d-byte password) must fail with the uniform error",
			tc.username, len(tc.password))
	}
}

// listWebAccounts calls handleListWebAccounts directly with the given principal
// and returns the parsed slice of WebAccountInfo from the response.
func listWebAccounts(t *testing.T, server *Server, principal *Principal) (*httptest.ResponseRecorder, []WebAccountInfo) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/accounts", nil)
	req = withPrincipal(req, principal)
	rec := httptest.NewRecorder()
	server.handleListWebAccounts(rec, req)
	return rec, parseWebAccountInfoList(t, rec)
}

// parseWebAccountInfoList extracts the []WebAccountInfo from an APIResponse body.
func parseWebAccountInfoList(t *testing.T, rec *httptest.ResponseRecorder) []WebAccountInfo {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var accounts []WebAccountInfo
	require.NoError(t, json.Unmarshal(raw, &accounts))
	return accounts
}

// TestWebAccounts_ListReturnsAccountsWithNoSecretMaterial is the [REQUIRED TEST]:
// the list endpoint returns WebAccountInfo records and NEVER includes a password
// hash, password plaintext, or any other secret material in the response body.
func TestWebAccounts_ListReturnsAccountsWithNoSecretMaterial(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const password = "list-test-secret-password"

	// Create two accounts.
	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username:    "list-user-a",
		Password:    password,
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username:    "list-user-b",
		Password:    password,
		TenantID:    "tenant-b",
		Permissions: []string{"steward:read"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	// List returns 200 and the full response body.
	listRec, accounts := listWebAccounts(t, server, admin)
	require.Equal(t, http.StatusOK, listRec.Code, "body: %s", listRec.Body.String())

	// Both accounts appear in the list.
	usernames := make([]string, 0, len(accounts))
	for _, a := range accounts {
		usernames = append(usernames, a.Username)
	}
	assert.Contains(t, usernames, "list-user-a")
	assert.Contains(t, usernames, "list-user-b")

	// Every account has non-empty identity fields.
	for _, a := range accounts {
		assert.NotEmpty(t, a.ID, "account %q must have an id", a.Username)
		assert.NotEmpty(t, a.Username)
		assert.False(t, a.CreatedAt.IsZero(), "account %q must have a created_at", a.Username)
	}

	// [REQUIRED] The raw response body must not contain any password hash or
	// secret material — not the plaintext password, and not an argon2id prefix.
	body := listRec.Body.String()
	assert.NotContains(t, body, password, "list response must not contain the password plaintext")
	assert.NotContains(t, body, "$argon2id$", "list response must not contain any argon2id hash prefix")
}

// TestWebAccounts_ListReflectsDeletes confirms that after an account is deleted,
// it no longer appears in the list response.
func TestWebAccounts_ListReflectsDeletes(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "delete-list-user",
		Password: "some-valid-password",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	_, accounts := listWebAccounts(t, server, admin)
	found := false
	for _, a := range accounts {
		if a.Username == "delete-list-user" {
			found = true
		}
	}
	assert.True(t, found, "newly created account must appear in the list")

	delRec := deleteWebAccount(t, server, admin, "delete-list-user")
	require.Equal(t, http.StatusOK, delRec.Code, "body: %s", delRec.Body.String())

	_, accounts = listWebAccounts(t, server, admin)
	for _, a := range accounts {
		assert.NotEqual(t, "delete-list-user", a.Username,
			"deleted account must not appear in the list")
	}
}

// TestWebAccounts_ListRequiresPermissionNotTier3 verifies that an API-key caller
// with only the web-account:list permission CAN reach the list endpoint (no Tier-3
// gate), while the create/delete endpoints remain Tier-3 gated.
func TestWebAccounts_ListRequiresPermissionNotTier3(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"web-account:list"})

	// POST an account first (using the admin path so the store has content).
	postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username: "tier-check-user",
		Password: "valid-password-123",
	})

	// An API-key caller with web-account:list reaches GET /api/v1/web/accounts.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/accounts", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code,
		"API-key caller with web-account:list must reach the list endpoint (no Tier-3 gate)")

	// Confirm no secret material in the response even for API-key callers.
	body := rec.Body.String()
	assert.NotContains(t, body, "$argon2id$", "list response must not contain any argon2id hash")
}

// TestWebAccounts_HashParametersEncodedInPHCString pins the argon2id OWASP cost
// parameters and verifies that encodeArgon2idHash embeds them into the PHC string.
// Uses the *Default constants directly (not the active webArgon2* vars) so the test
// remains independent of the minimal-cost TestMain override (Issue #2591).
func TestWebAccounts_HashParametersEncodedInPHCString(t *testing.T) {
	// Derive with the production-default (OWASP) cost to verify the PHC prefix.
	// encodeArgon2idHash takes an explicit salt so no crypto/rand import is needed.
	phc := encodeArgon2idHash("parameter-check-password",
		[]byte("cfgms-param-test"), // 16-byte deterministic test vector
		webArgon2TimeDefault, webArgon2MemoryDefault, webArgon2ThreadsDefault)

	assert.True(t, strings.HasPrefix(phc, "$argon2id$v=19$m=19456,t=2,p=1$"),
		"OWASP production parameters must encode correctly in the PHC string, got %q", phc)

	ok, err := verifyWebPassword("parameter-check-password", phc)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = verifyWebPassword("different-password", phc)
	require.NoError(t, err)
	assert.False(t, ok)

	// A hash produced under legacy (different) parameters still verifies, because the
	// parameters are read from the PHC string, not assumed.
	legacy := encodeArgon2idHash("parameter-check-password",
		[]byte("0123456789abcdef"), 3, 65536, 4)
	ok, err = verifyWebPassword("parameter-check-password", legacy)
	require.NoError(t, err)
	assert.True(t, ok, "hashes created under older cost parameters must keep verifying")
}
