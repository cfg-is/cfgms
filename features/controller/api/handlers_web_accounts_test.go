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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/session"
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

// TestWebAccounts_CreateReturnsIdentity verifies that creating an account returns
// the expected principal identity fields in the response.
func TestWebAccounts_CreateReturnsIdentity(t *testing.T) {
	server := setupTestServer(t)

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username:    "fleet-admin",
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
	assert.NotEmpty(t, info["created_at"])
}

// TestWebAccounts_AssuranceGateRejectsAPIKeyCaller verifies through the full router that an
// API-key principal (Machine-assurance) is rejected from both provisioning endpoints with 403
// INSUFFICIENT_PERMISSIONS — even when the key carries the matching web-account permissions.
// The assurance gate in requirePermission fires before the handler (Issue #2780).
func TestWebAccounts_AssuranceGateRejectsAPIKeyCaller(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"web-account:create", "web-account:delete"})

	body, err := json.Marshal(WebAccountRequest{Username: "tier3-user"})
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

// TestWebAccounts_InputValidationBounds covers username validation: username bounded
// and charset-restricted so it stays path- and log-safe (usernames appear in DELETE
// URL paths). Password validation removed (Issue #2993).
func TestWebAccounts_InputValidationBounds(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	tests := []struct {
		name       string
		username   string
		wantStatus int
	}{
		{"username too short rejected", "ab", http.StatusBadRequest},
		{"username too long rejected", strings.Repeat("a", 65), http.StatusBadRequest},
		{"username path traversal rejected", "../../etc/passwd", http.StatusBadRequest},
		{"username with slash rejected", "tenant/user", http.StatusBadRequest},
		{"username with space rejected", "some user", http.StatusBadRequest},
		{"username with newline rejected", "user\nname", http.StatusBadRequest},
		{"username with charset ok", "User.name_01-x", http.StatusCreated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := postWebAccount(t, server, admin, WebAccountRequest{
				Username: tc.username,
			})
			assert.Equal(t, tc.wantStatus, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

// TestWebAccounts_UnknownPermissionRejected verifies web accounts use the same
// permission allow-list discipline as API keys ("*" and unknown IDs rejected).
func TestWebAccounts_UnknownPermissionRejected(t *testing.T) {
	server := setupTestServer(t)

	for _, perm := range []string{"*", "not-a-real:permission"} {
		rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
			Username:    "perm-user",
			Permissions: []string{perm},
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code, "permission %q must be rejected", perm)
	}
}

// TestWebAccounts_StoredRecordContainsNoSecretValue asserts the persisted record holds
// no sensitive value — since passkey login is credential-only, the stored Value is empty.
func TestWebAccounts_StoredRecordContainsNoSecretValue(t *testing.T) {
	server := setupTestServer(t)

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username: "no-secret-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	metas, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: webAccountSecretType,
			"username":                      "no-secret-user",
		},
	})
	require.NoError(t, err)
	require.Len(t, metas, 1, "exactly one persisted record for the account")

	secret, err := server.secretStore.GetSecret(context.Background(),
		metas[0].TenantID+"/"+metas[0].Key)
	require.NoError(t, err)

	assert.Empty(t, secret.Value, "stored value must be empty — accounts are passkey-only (Issue #2993)")
	assert.NotContains(t, string(secret.Value), "$argon2id$",
		"stored value must not contain any argon2id hash (passkey-only)")
}

// TestWebAccounts_DeleteRemovesCacheAndStore verifies DELETE removes the account from
// both the in-memory cache and the durable secret store, and a repeat delete is 404.
func TestWebAccounts_DeleteRemovesCacheAndStore(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "delete-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Account exists in cache.
	acct, err := server.getWebAccount(context.Background(), "delete-user")
	require.NoError(t, err)
	require.NotNil(t, acct, "account must exist before delete")

	rec = deleteWebAccount(t, server, admin, "delete-user")
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	// Gone from the cache.
	server.mu.RLock()
	_, inCache := server.webAccounts["delete-user"]
	server.mu.RUnlock()
	assert.False(t, inCache, "account must be removed from cache on delete")

	// Gone from the durable store after a cache drop.
	dropWebAccountCache(server)
	acct, err = server.getWebAccount(context.Background(), "delete-user")
	require.NoError(t, err)
	assert.Nil(t, acct, "account must be unreachable from the store after delete")

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
// create, reset, and delete each write an audit entry carrying the sanitized username
// and the acting admin principal.
func TestWebAccounts_AuditEntriesEmitted(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "audit-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username: "audit-user",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	rec = deleteWebAccount(t, server, admin, "audit-user")
	require.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))

	for _, action := range []string{
		"web_account.created",
		"web_account.reset",
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
// the list endpoint returns WebAccountInfo records and NEVER includes any secret
// material in the response body.
func TestWebAccounts_ListReturnsAccountsWithNoSecretMaterial(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username:    "list-user-a",
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username:    "list-user-b",
		TenantID:    "tenant-b",
		Permissions: []string{"steward:read"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	listRec, accounts := listWebAccounts(t, server, admin)
	require.Equal(t, http.StatusOK, listRec.Code, "body: %s", listRec.Body.String())

	usernames := make([]string, 0, len(accounts))
	for _, a := range accounts {
		usernames = append(usernames, a.Username)
	}
	assert.Contains(t, usernames, "list-user-a")
	assert.Contains(t, usernames, "list-user-b")

	for _, a := range accounts {
		assert.NotEmpty(t, a.ID, "account %q must have an id", a.Username)
		assert.NotEmpty(t, a.Username)
		assert.False(t, a.CreatedAt.IsZero(), "account %q must have a created_at", a.Username)
	}

	// [REQUIRED] The raw response body must not contain any argon2id hash prefix.
	body := listRec.Body.String()
	assert.NotContains(t, body, "$argon2id$", "list response must not contain any argon2id hash prefix")
}

// TestWebAccounts_ListReflectsDeletes confirms that after an account is deleted,
// it no longer appears in the list response.
func TestWebAccounts_ListReflectsDeletes(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "delete-list-user",
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
	})

	// An API-key caller with web-account:list reaches GET /api/v1/web/accounts.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/accounts", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code,
		"API-key caller with web-account:list must reach the list endpoint (no Tier-3 gate)")

	body := rec.Body.String()
	assert.NotContains(t, body, "$argon2id$", "list response must not contain any argon2id hash")
}

// ---- Issue #2919: root-scope web account tests ----

// TestWebAccounts_RootScope_NotDefaultedToDefault verifies that creating a web account
// with root_scope:true results in an account with empty TenantID, not "default".
func TestWebAccounts_RootScope_NotDefaultedToDefault(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username:    "root-admin",
		RootScope:   true,
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	info, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "", info["tenant_id"], "root-scoped account must have empty tenant_id, not 'default'")
	assert.Equal(t, true, info["root_scope"], "root_scope must be true in the response")
	assert.Equal(t, "root-admin", info["username"])

	// Account must be loadable from store with correct scope.
	acct, err := server.getWebAccount(context.Background(), "root-admin")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.True(t, acct.RootScope, "loaded account must have RootScope=true")
	assert.Empty(t, acct.TenantID, "loaded account must have empty TenantID")
}

// TestWebAccounts_RootScope_DurableAfterCacheDrop verifies that a root-scoped
// account survives a cache drop (store round-trip) and retains root scope.
func TestWebAccounts_RootScope_DurableAfterCacheDrop(t *testing.T) {
	server := setupTestServer(t)

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username:  "root-durable",
		RootScope: true,
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	dropWebAccountCache(server)

	acct, err := server.getWebAccount(context.Background(), "root-durable")
	require.NoError(t, err, "root-scoped account must be reloadable from the secret store")
	require.NotNil(t, acct)
	assert.True(t, acct.RootScope, "root scope must survive a cache drop + store reload")
	assert.Empty(t, acct.TenantID, "tenant_id must be empty after reload")
}

// TestWebAccounts_RootScope_MutuallyExclusiveWithTenantID verifies that specifying
// both root_scope:true and a non-empty tenant_id in the same request is rejected.
func TestWebAccounts_RootScope_MutuallyExclusiveWithTenantID(t *testing.T) {
	server := setupTestServer(t)

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username:  "conflict-user",
		TenantID:  "tenant-a",
		RootScope: true,
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "INVALID_SCOPE", errResp.Error.Code)
}

// TestWebAccounts_RootScope_ResetRetainsScope verifies that resetting a root-scoped
// account without specifying a new scope retains root scope.
func TestWebAccounts_RootScope_ResetRetainsScope(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username:  "root-reset-user",
		RootScope: true,
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Reset without specifying scope — root scope must be retained.
	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username: "root-reset-user",
	})
	require.Equal(t, http.StatusOK, rec.Code, "reset of existing account returns 200")

	// Reload from store and verify scope retained.
	dropWebAccountCache(server)
	acct, err := server.getWebAccount(context.Background(), "root-reset-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.True(t, acct.RootScope, "root scope must be retained across account reset")
	assert.Empty(t, acct.TenantID, "tenant_id must remain empty after reset")
}

// TestWebAccounts_RootScope_AppearsInList verifies that a root-scoped account
// appears in the list endpoint with root_scope:true and empty tenant_id.
func TestWebAccounts_RootScope_AppearsInList(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username:  "root-list-user",
		RootScope: true,
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	_, accounts := listWebAccounts(t, server, admin)
	var found *WebAccountInfo
	for i := range accounts {
		if accounts[i].Username == "root-list-user" {
			found = &accounts[i]
			break
		}
	}
	require.NotNil(t, found, "root-scoped account must appear in list")
	assert.True(t, found.RootScope, "root_scope must be true in list response")
	assert.Equal(t, "", found.TenantID, "tenant_id must be empty in list response for root-scoped account")
}

// TestWebAccounts_RootScope_DeleteWorks verifies that deleting a root-scoped
// account succeeds and the account is removed from the store.
func TestWebAccounts_RootScope_DeleteWorks(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username:  "root-delete-user",
		RootScope: true,
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Verify account exists before delete.
	acct, err := server.getWebAccount(context.Background(), "root-delete-user")
	require.NoError(t, err)
	require.NotNil(t, acct, "account must exist before delete")

	// Delete it.
	delRec := deleteWebAccount(t, server, admin, "root-delete-user")
	require.Equal(t, http.StatusOK, delRec.Code)

	// After deletion (and cache drop), account must be gone.
	dropWebAccountCache(server)
	acct, err = server.getWebAccount(context.Background(), "root-delete-user")
	require.NoError(t, err)
	assert.Nil(t, acct, "account must be unreachable from the store after delete")
}
