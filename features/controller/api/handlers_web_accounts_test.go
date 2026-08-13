// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
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
// API-key principal (Machine-assurance) is rejected from every provisioning endpoint with 403
// INSUFFICIENT_PERMISSIONS — even when the key carries the matching web-account permissions.
// The assurance gate in requirePermission fires before the handler (Issue #2780, #2974).
func TestWebAccounts_AssuranceGateRejectsAPIKeyCaller(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{
		"web-account:create", "web-account:delete", "web-account:revoke-enrollment-link",
	})

	body, err := json.Marshal(WebAccountRequest{Username: "tier3-user"})
	require.NoError(t, err)

	for _, tc := range []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodPost, "/api/v1/web/accounts", body},
		{http.MethodDelete, "/api/v1/web/accounts/tier3-user", nil},
		// Issue #2974: the enrollment-link revoke route is equally Strong-gated.
		{http.MethodPost, "/api/v1/web/accounts/tier3-user/enrollment-link/revoke", nil},
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
	assert.NotContains(t, secret.Value, "$argon2id$",
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

// ---- Issue #3137: tenant-subtree scope enforcement on GET /api/v1/web/accounts ----

// TestWebAccounts_TenantScope_SiblingExclusion is the [REQUIRED TEST] from Issue #3137:
// a caller scoped to client-1 must never see an account belonging to sibling tenant client-2.
func TestWebAccounts_TenantScope_SiblingExclusion(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "client2-user",
		TenantID: "root/msp-a/client-2",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username: "client1-user",
		TenantID: "root/msp-a/client-1",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	client1Principal := &Principal{
		ID:        "client1-admin",
		TenantID:  "root/msp-a/client-1",
		Assurance: session.AssuranceBasic,
	}
	_, accounts := listWebAccounts(t, server, client1Principal)

	usernames := make([]string, 0, len(accounts))
	for _, a := range accounts {
		usernames = append(usernames, a.Username)
	}
	assert.Contains(t, usernames, "client1-user", "caller must see own tenant's accounts")
	assert.NotContains(t, usernames, "client2-user", "caller must NOT see sibling tenant's accounts")
}

// TestWebAccounts_TenantScope_SubtreeInclusion is the [REQUIRED TEST] from Issue #3137:
// a caller scoped to root/msp-a DOES see an account belonging to root/msp-a/client-1
// (subtree inclusion, not exact-match-only).
func TestWebAccounts_TenantScope_SubtreeInclusion(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "parent-user",
		TenantID: "root/msp-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username: "child-user",
		TenantID: "root/msp-a/client-1",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	mspaAdmin := &Principal{
		ID:        "msp-a-admin",
		TenantID:  "root/msp-a",
		Assurance: session.AssuranceBasic,
	}
	_, accounts := listWebAccounts(t, server, mspaAdmin)

	usernames := make([]string, 0, len(accounts))
	for _, a := range accounts {
		usernames = append(usernames, a.Username)
	}
	assert.Contains(t, usernames, "parent-user", "parent-tenant admin must see own accounts")
	assert.Contains(t, usernames, "child-user", "parent-tenant admin must see child tenant accounts (subtree)")
}

// TestWebAccounts_TenantScope_UnscopedAdminSeesAll verifies that an unscoped mTLS admin
// (callerTenant == "") still sees all accounts including those in multiple tenants.
func TestWebAccounts_TenantScope_UnscopedAdminSeesAll(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	for _, req := range []WebAccountRequest{
		{Username: "scope-all-a", TenantID: "root/msp-a/client-1"},
		{Username: "scope-all-b", TenantID: "root/msp-a/client-2"},
		{Username: "scope-all-root", RootScope: true},
	} {
		rec := postWebAccount(t, server, admin, req)
		require.Equal(t, http.StatusCreated, rec.Code)
	}

	_, accounts := listWebAccounts(t, server, admin)
	usernames := make([]string, 0, len(accounts))
	for _, a := range accounts {
		usernames = append(usernames, a.Username)
	}
	assert.Contains(t, usernames, "scope-all-a")
	assert.Contains(t, usernames, "scope-all-b")
	assert.Contains(t, usernames, "scope-all-root")
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

// ---- Issue #2974: enrollment magic link tests ----

// revokeEnrollmentLink calls handleRevokeEnrollmentLink directly with an admin principal.
func revokeEnrollmentLink(t *testing.T, server *Server, principal *Principal, username string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/accounts/"+username+"/enrollment-link/revoke", nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username})
	rec := httptest.NewRecorder()
	server.handleRevokeEnrollmentLink(rec, req)
	return rec
}

// parseCreateResponse extracts WebAccountCreateResponse from an APIResponse body.
func parseCreateResponse(t *testing.T, rec *httptest.ResponseRecorder) WebAccountCreateResponse {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var cr WebAccountCreateResponse
	require.NoError(t, json.Unmarshal(raw, &cr))
	return cr
}

// TestWebAccounts_CreateMintsEnrollmentLink verifies that POST /api/v1/web/accounts returns
// an enrollment_magic_link field on creation (non-empty, >=40 hex chars for 160-bit entropy).
func TestWebAccounts_CreateMintsEnrollmentLink(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "link-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	cr := parseCreateResponse(t, rec)
	assert.NotEmpty(t, cr.EnrollmentMagicLink, "enrollment_magic_link must be non-empty on create")
	// 20 bytes hex-encoded = 40 chars (>=128-bit requirement).
	assert.GreaterOrEqual(t, len(cr.EnrollmentMagicLink), 40,
		"enrollment_magic_link must be at least 40 hex chars (160 bits)")
	// Verify has_outstanding_enrollment_link is true in the create response.
	assert.True(t, cr.HasOutstandingEnrollmentLink,
		"has_outstanding_enrollment_link must be true in create response")
}

// TestWebAccounts_EnrollmentLinkTTL_ConfiguredValue verifies the enrollment link
// TTL is sourced from cfg.Registration.EnrollmentLinkTTL rather than a hardcoded
// constant (PR #3277 review: TTL must be configurable, not just defaulted).
func TestWebAccounts_EnrollmentLinkTTL_ConfiguredValue(t *testing.T) {
	server := setupTestServer(t)
	server.cfg.Registration = &config.RegistrationConfig{
		EnrollmentLinkTTL: config.Duration(2 * time.Hour),
	}
	admin := testAdminPrincipal()

	before := time.Now().UTC()
	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "configured-ttl-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
	after := time.Now().UTC()

	server.mu.RLock()
	acct := server.webAccounts["configured-ttl-user"]
	server.mu.RUnlock()
	require.NotNil(t, acct)

	assert.True(t, acct.EnrollmentLinkExpiresAt.After(before.Add(2*time.Hour-time.Minute)),
		"expiry must reflect the configured 2h TTL, not the 72h default")
	assert.True(t, acct.EnrollmentLinkExpiresAt.Before(after.Add(2*time.Hour+time.Minute)),
		"expiry must not exceed the configured 2h TTL by more than test slack")
}

// TestWebAccounts_EnrollmentLinkStoredHashed verifies that the enrollment token is stored
// as a SHA-256 hash in the secret store — NEVER as plaintext. This is the [REQUIRED TEST]
// for the token-storage security property (Issue #2974, mirrors #2966).
func TestWebAccounts_EnrollmentLinkStoredHashed(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "hash-test-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	cr := parseCreateResponse(t, rec)
	rawToken := cr.EnrollmentMagicLink
	require.NotEmpty(t, rawToken, "raw token must be returned on create")

	// Load the account from the store and verify hash matches — plaintext absent.
	dropWebAccountCache(server)
	acct, err := server.getWebAccount(context.Background(), "hash-test-user")
	require.NoError(t, err)
	require.NotNil(t, acct)

	assert.NotEmpty(t, acct.EnrollmentLinkHash, "enrollment_link_hash must be stored")
	assert.NotEqual(t, rawToken, acct.EnrollmentLinkHash,
		"raw token must NOT be stored — only the hash")
	expectedHash := hashEnrollmentToken(rawToken)
	assert.Equal(t, expectedHash, acct.EnrollmentLinkHash,
		"stored hash must be SHA-256 of the raw token")

	// Verify the secret store metadata does not contain the raw token.
	metas, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: webAccountSecretType,
			"username":                      "hash-test-user",
		},
	})
	require.NoError(t, err)
	require.Len(t, metas, 1, "one persisted account record")

	secret, err := server.secretStore.GetSecret(context.Background(),
		metas[0].TenantID+"/"+metas[0].Key)
	require.NoError(t, err)

	// The raw token must not appear anywhere in the stored metadata.
	for k, v := range secret.Metadata {
		assert.NotContains(t, v, rawToken,
			"raw token must not appear in metadata key %q", k)
	}
	assert.NotContains(t, secret.Value, rawToken,
		"raw token must not appear in stored value")
}

// TestWebAccounts_CreateAuditNeverIncludesToken is the [REQUIRED TEST] for the audit
// security property: creation records account + delivery method, never the raw token value.
func TestWebAccounts_CreateAuditNeverIncludesToken(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "audit-link-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	cr := parseCreateResponse(t, rec)
	rawToken := cr.EnrollmentMagicLink
	require.NotEmpty(t, rawToken)

	require.NoError(t, server.auditManager.Flush(context.Background()))

	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"web_account.created"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "audit entry for web_account.created must be written")

	entry := entries[0]
	assert.Equal(t, "web_account.created", entry.Action)
	assert.Equal(t, "audit-link-user", entry.ResourceID, "username must be the resource ID")
	assert.Equal(t, admin.ID, entry.UserID)

	// delivery_method must be present and must be "ui-shown".
	deliveryMethod, hasDelivery := entry.Details["delivery_method"]
	assert.True(t, hasDelivery, "audit entry must include delivery_method")
	assert.Equal(t, "ui-shown", deliveryMethod, "delivery_method must be ui-shown")

	// The raw token must never appear in any audit field.
	rawJSON, _ := json.Marshal(entry)
	assert.NotContains(t, string(rawJSON), rawToken,
		"raw enrollment token must never appear in the audit entry")
}

// TestWebAccounts_EnrollmentLinkAppearsInList verifies that a newly created account shows
// has_outstanding_enrollment_link:true in the list response.
func TestWebAccounts_EnrollmentLinkAppearsInList(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "list-link-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	_, accounts := listWebAccounts(t, server, admin)
	var found *WebAccountInfo
	for i := range accounts {
		if accounts[i].Username == "list-link-user" {
			found = &accounts[i]
			break
		}
	}
	require.NotNil(t, found, "newly created account must appear in list")
	assert.True(t, found.HasOutstandingEnrollmentLink,
		"has_outstanding_enrollment_link must be true for newly created account")
}

// TestWebAccounts_RevokeEnrollmentLink verifies that POST .../enrollment-link/revoke
// invalidates an outstanding link and that has_outstanding_enrollment_link becomes false.
func TestWebAccounts_RevokeEnrollmentLink(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "revoke-link-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	// Verify link is outstanding before revoke.
	_, accounts := listWebAccounts(t, server, admin)
	var found *WebAccountInfo
	for i := range accounts {
		if accounts[i].Username == "revoke-link-user" {
			found = &accounts[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.True(t, found.HasOutstandingEnrollmentLink, "link must be outstanding before revoke")

	// Revoke it.
	revokeRec := revokeEnrollmentLink(t, server, admin, "revoke-link-user")
	require.Equal(t, http.StatusOK, revokeRec.Code, "body: %s", revokeRec.Body.String())

	// Drop cache so the list re-reads from store.
	dropWebAccountCache(server)
	_, accounts = listWebAccounts(t, server, admin)
	var foundAfter *WebAccountInfo
	for i := range accounts {
		if accounts[i].Username == "revoke-link-user" {
			foundAfter = &accounts[i]
			break
		}
	}
	require.NotNil(t, foundAfter)
	assert.False(t, foundAfter.HasOutstandingEnrollmentLink,
		"has_outstanding_enrollment_link must be false after revoke")
}

// TestWebAccounts_RevokeNonExistentLinkReturns409 verifies that revoking an account
// with no outstanding link returns 409 CONFLICT.
func TestWebAccounts_RevokeNonExistentLinkReturns409(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	// Create an account then immediately revoke its link.
	rec := postWebAccount(t, server, admin, WebAccountRequest{Username: "no-link-user"})
	require.Equal(t, http.StatusCreated, rec.Code)
	revokeRec := revokeEnrollmentLink(t, server, admin, "no-link-user")
	require.Equal(t, http.StatusOK, revokeRec.Code, "first revoke must succeed")

	// Second revoke must fail with 409.
	revokeRec = revokeEnrollmentLink(t, server, admin, "no-link-user")
	assert.Equal(t, http.StatusConflict, revokeRec.Code,
		"revoke with no outstanding link must return 409 CONFLICT")
}

// TestWebAccounts_EnrollmentLinkExpiredNotOutstanding verifies that an enrollment link
// with an expired TTL is not reported as outstanding in list responses.
func TestWebAccounts_EnrollmentLinkExpiredNotOutstanding(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "expired-link-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Back-date the expiry in the in-memory cache so the link is past its TTL.
	server.mu.Lock()
	if acct, ok := server.webAccounts["expired-link-user"]; ok {
		acct.EnrollmentLinkExpiresAt = time.Now().Add(-1 * time.Hour) // already expired
	}
	server.mu.Unlock()

	// Persist the expired state to the store so the list query sees it.
	acct, err := server.getWebAccount(context.Background(), "expired-link-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	require.NoError(t, server.persistWebAccount(context.Background(), acct, admin.ID))

	dropWebAccountCache(server)
	_, accounts := listWebAccounts(t, server, admin)
	var found *WebAccountInfo
	for i := range accounts {
		if accounts[i].Username == "expired-link-user" {
			found = &accounts[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.False(t, found.HasOutstandingEnrollmentLink,
		"has_outstanding_enrollment_link must be false for an expired link")
}

// TestWebAccounts_EnrollmentLinkAuditRevoke verifies that revocation is audited separately
// with the correct action.
func TestWebAccounts_EnrollmentLinkAuditRevoke(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{Username: "audit-revoke-user"})
	require.Equal(t, http.StatusCreated, rec.Code)

	revokeRec := revokeEnrollmentLink(t, server, admin, "audit-revoke-user")
	require.Equal(t, http.StatusOK, revokeRec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))

	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"web_account.enrollment_link.revoked"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "revoke audit entry must be written")
	e := entries[0]
	assert.Equal(t, "web_account.enrollment_link.revoked", e.Action)
	assert.Equal(t, "audit-revoke-user", e.ResourceID)
}

// TestWebAccounts_RevokeEnrollmentLink_CrossTenantForbidden is the [REQUIRED TEST] for
// the tenant-subtree authorization fix (Issue #2974): a caller scoped to client-1 must
// receive 403 when revoking the enrollment link of an account in sibling tenant client-2,
// regardless of whether a link is outstanding (prevents cross-tenant oracle).
func TestWebAccounts_RevokeEnrollmentLink_CrossTenantForbidden(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	// Create the target account in client-2.
	rec := postWebAccount(t, server, admin, WebAccountRequest{
		Username: "client2-target",
		TenantID: "root/msp-a/client-2",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "setup: create account in client-2")

	// Caller is a client-1 scoped admin — out-of-subtree for client-2.
	client1Admin := &Principal{
		ID:        "client1-admin",
		TenantID:  "root/msp-a/client-1",
		Assurance: session.AssuranceStrong,
	}
	revokeRec := revokeEnrollmentLink(t, server, client1Admin, "client2-target")
	assert.Equal(t, http.StatusForbidden, revokeRec.Code,
		"cross-tenant revoke must be 403 regardless of link state")
}

// TestWebAccounts_RevokeEnrollmentLinkRoute drives the revoke endpoint through the real
// router (server.router.ServeHTTP) rather than calling the handler directly, so route
// registration, the requirePermission("web-account", "revoke-enrollment-link") wrapper and
// the AssuranceStrong gate are all exercised as they are wired in production (Issue #2974).
func TestWebAccounts_RevokeEnrollmentLinkRoute(t *testing.T) {
	server := setupTestServer(t)
	const username = "router-revoke-user"
	const path = "/api/v1/web/accounts/" + username + "/enrollment-link/revoke"

	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username: username,
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	t.Run("unauthenticated caller is rejected before the handler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"revoke route must require authentication")
	})

	t.Run("GET is not routed to the revoke handler", func(t *testing.T) {
		req := makeAdminRequest(t, http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rec.Code,
			"revoke route is POST-only")
	})

	t.Run("strong mTLS admin revokes through the router", func(t *testing.T) {
		req := makeAdminRequest(t, http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		dropWebAccountCache(server)
		acct, err := server.getWebAccount(context.Background(), username)
		require.NoError(t, err)
		require.NotNil(t, acct)
		assert.False(t, enrollmentLinkOutstanding(acct),
			"link must not be outstanding after a router-served revoke")
	})
}

// errStoreSecretStore wraps a real SecretStore and forces StoreSecret to fail, so the
// durable-write failure path can be exercised against otherwise real components
// (same pattern as errListSecretStore in server_test.go — no mocking framework).
type errStoreSecretStore struct {
	secretsif.SecretStore
	storeErr error
}

func (s *errStoreSecretStore) StoreSecret(_ context.Context, _ *secretsif.SecretRequest) error {
	return s.storeErr
}

// TestWebAccounts_RevokeFailsClosedOnStoreError is the [REQUIRED TEST] for the
// fail-closed revocation property (Issue #2974): when the durable write fails the
// cached record must NOT be marked revoked, so a retry still finds an outstanding
// link and can complete the revocation instead of answering 409 forever.
func TestWebAccounts_RevokeFailsClosedOnStoreError(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "failclosed-user"

	rec := postWebAccount(t, server, admin, WebAccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	realStore := server.secretStore
	storeErr := errors.New("injected durable write failure")
	server.secretStore = &errStoreSecretStore{SecretStore: realStore, storeErr: storeErr}

	failed := revokeEnrollmentLink(t, server, admin, username)
	require.Equal(t, http.StatusInternalServerError, failed.Code,
		"a failed durable write must surface as 500, not a silent success")

	// The cache must still agree with the store: the link is live, not revoked.
	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.False(t, acct.EnrollmentLinkRevoked,
		"cache must not claim revoked when the durable write failed")
	assert.True(t, enrollmentLinkOutstanding(acct),
		"link must still be outstanding so the admin can retry")

	// Retry against a healthy store: the revoke must complete, not 409.
	server.secretStore = realStore
	retried := revokeEnrollmentLink(t, server, admin, username)
	require.Equal(t, http.StatusOK, retried.Code,
		"retry after a store failure must complete the revocation: %s", retried.Body.String())

	dropWebAccountCache(server)
	reloaded, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, reloaded)
	assert.True(t, reloaded.EnrollmentLinkRevoked,
		"durable record must carry the revocation after a successful retry")
}

// TestWebAccounts_NoLinkMintedForEnrolledAccount is the [REQUIRED TEST] for ADR-021
// Amendment 1 Decision 3 ("No magic link is involved after the first passkey"): an upsert
// against an account that already holds a registered passkey must not hand the caller a
// fresh enrollment bearer token, because redeeming it would enroll the bearer's own
// passkey onto a fully provisioned account (Issue #2974).
func TestWebAccounts_NoLinkMintedForEnrolledAccount(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "enrolled-user"

	rec := postWebAccount(t, server, admin, WebAccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Register a passkey, then revoke the first-enrollment link as the real flow does.
	injectCredential(t, server, username, []byte("enrolled-user-credential"))
	require.Equal(t, http.StatusOK, revokeEnrollmentLink(t, server, admin, username).Code)

	rec = postWebAccount(t, server, admin, WebAccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusOK, rec.Code, "reset of an existing account returns 200")

	cr := parseCreateResponse(t, rec)
	assert.Empty(t, cr.EnrollmentMagicLink,
		"no enrollment link may be minted for an account that already holds a passkey")
	assert.False(t, cr.HasOutstandingEnrollmentLink,
		"response must not advertise an outstanding link when none was minted")

	dropWebAccountCache(server)
	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	require.Len(t, acct.Credentials, 1, "registered passkey must survive the reset")
	assert.False(t, enrollmentLinkOutstanding(acct),
		"stored record must hold no outstanding link for an enrolled account")
}

// TestWebAccounts_ResetCredentialsMintsFreshLink covers ADR-021 Amendment 1 Decision 4:
// an admin-mediated reset re-provisions the account to the zero-authenticator state,
// invalidating residual credentials, and only then issues a fresh single-use link.
func TestWebAccounts_ResetCredentialsMintsFreshLink(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "reset-creds-user"

	rec := postWebAccount(t, server, admin, WebAccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusCreated, rec.Code)
	injectCredential(t, server, username, []byte("reset-creds-user-credential"))

	rec = postWebAccount(t, server, admin, WebAccountRequest{
		Username:         username,
		TenantID:         "tenant-a",
		ResetCredentials: true,
	})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	cr := parseCreateResponse(t, rec)
	require.NotEmpty(t, cr.EnrollmentMagicLink,
		"an explicit credential reset must issue a fresh enrollment link")
	assert.True(t, cr.HasOutstandingEnrollmentLink)

	dropWebAccountCache(server)
	acct, err := server.getWebAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.Empty(t, acct.Credentials,
		"residual credentials must be invalidated when a fresh link is issued")
	assert.True(t, verifyEnrollmentToken(acct, cr.EnrollmentMagicLink),
		"the returned token must be the one stored against the reset account")
}

// TestWebAccounts_CreateEnforcesTenantScope is the [REQUIRED TEST] for create-side tenant
// isolation (Issue #2974): POST /api/v1/web/accounts issues a bearer enrollment credential,
// so a tenant-scoped caller must not be able to target another tenant's subtree, mint a
// root-scoped account, or pull an out-of-subtree account into its own tenant.
func TestWebAccounts_CreateEnforcesTenantScope(t *testing.T) {
	server := setupTestServer(t)

	// An out-of-subtree account provisioned by an unscoped mTLS admin.
	rec := postWebAccount(t, server, testAdminPrincipal(), WebAccountRequest{
		Username: "sibling-tenant-user",
		TenantID: "root/msp-a/client-2",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "setup: create account in client-2")
	siblingToken := parseCreateResponse(t, rec).EnrollmentMagicLink
	require.NotEmpty(t, siblingToken, "setup: create must mint an enrollment token")
	sibling, err := server.getWebAccount(context.Background(), "sibling-tenant-user")
	require.NoError(t, err)
	require.NotNil(t, sibling)
	siblingHash := sibling.EnrollmentLinkHash

	client1Admin := &Principal{
		ID:        "client1-admin",
		TenantID:  "root/msp-a/client-1",
		Assurance: session.AssuranceStrong,
	}

	t.Run("cross-tenant create is forbidden", func(t *testing.T) {
		rec := postWebAccount(t, server, client1Admin, WebAccountRequest{
			Username: "cross-tenant-user",
			TenantID: "root/msp-a/client-2",
		})
		require.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())

		acct, err := server.getWebAccount(context.Background(), "cross-tenant-user")
		require.NoError(t, err)
		assert.Nil(t, acct, "a forbidden create must not write an account record")
	})

	t.Run("root-scope grant from a scoped caller is forbidden", func(t *testing.T) {
		rec := postWebAccount(t, server, client1Admin, WebAccountRequest{
			Username:  "root-grab-user",
			RootScope: true,
		})
		assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	})

	t.Run("reset of an out-of-subtree account is forbidden", func(t *testing.T) {
		rec := postWebAccount(t, server, client1Admin, WebAccountRequest{
			Username: "sibling-tenant-user",
			TenantID: "root/msp-a/client-1",
		})
		require.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())

		// Assert on the raw body: a 403 emits an ErrorResponse, whose keys share nothing
		// with WebAccountCreateResponse, so decoding into that struct would leave it at
		// its zero value and pass no matter what the handler returned.
		assert.NotContains(t, rec.Body.String(), "enrollment_magic_link",
			"a forbidden reset must not return a token")
		assert.NotContains(t, rec.Body.String(), siblingToken,
			"a forbidden reset must not leak the out-of-subtree account's token")

		acct, err := server.getWebAccount(context.Background(), "sibling-tenant-user")
		require.NoError(t, err)
		require.NotNil(t, acct)
		assert.Equal(t, "root/msp-a/client-2", acct.TenantID, "the record must stay in client-2")
		assert.Equal(t, siblingHash, acct.EnrollmentLinkHash, "the stored link must be untouched")
		assert.False(t, acct.EnrollmentLinkRevoked, "the stored link must be untouched")
	})

	t.Run("create inside the caller subtree succeeds", func(t *testing.T) {
		rec := postWebAccount(t, server, client1Admin, WebAccountRequest{
			Username: "in-subtree-user",
			TenantID: "root/msp-a/client-1/servers",
		})
		require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
		cr := parseCreateResponse(t, rec)
		assert.NotEmpty(t, cr.EnrollmentMagicLink)
	})
}

// TestWebAccounts_VerifyEnrollmentToken verifies constant-time token comparison (Issue #2974).
func TestWebAccounts_VerifyEnrollmentToken(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postWebAccount(t, server, admin, WebAccountRequest{Username: "verify-token-user"})
	require.Equal(t, http.StatusCreated, rec.Code)
	cr := parseCreateResponse(t, rec)
	rawToken := cr.EnrollmentMagicLink

	acct, err := server.getWebAccount(context.Background(), "verify-token-user")
	require.NoError(t, err)
	require.NotNil(t, acct)

	assert.True(t, verifyEnrollmentToken(acct, rawToken), "valid token must verify")
	assert.False(t, verifyEnrollmentToken(acct, "wrong-token"), "wrong token must not verify")
	assert.False(t, verifyEnrollmentToken(acct, ""), "empty token must not verify")
	assert.False(t, verifyEnrollmentToken(nil, rawToken), "nil account must not verify")
}
