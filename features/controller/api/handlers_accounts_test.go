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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// postAccount calls handleCreateAccount directly with an mTLS admin principal
// injected, exactly as authenticationMiddleware would after admin-cert verification.
func postAccount(t *testing.T, server *Server, principal *Principal, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/accounts", bytes.NewReader(payload))
	req = withPrincipal(req, principal)
	rec := httptest.NewRecorder()
	server.handleCreateAccount(rec, req)
	return rec
}

// deleteAccount calls handleDeleteAccount directly with an mTLS admin principal
// and the {username} route variable injected.
func deleteAccount(t *testing.T, server *Server, principal *Principal, username string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/accounts/"+username, nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username})
	rec := httptest.NewRecorder()
	server.handleDeleteAccount(rec, req)
	return rec
}

func testAdminPrincipal() *Principal {
	return &Principal{ID: "test-mtls-admin", Name: "mtls-admin:test", Assurance: session.AssuranceBasic}
}

// dropAccountCache clears the in-memory web-account cache so the next lookup
// must reload the record from the central secret store.
func dropAccountCache(server *Server) {
	server.mu.Lock()
	server.accounts = nil
	server.mu.Unlock()
}

// TestAccounts_CreateReturnsIdentity verifies that creating an account returns
// the expected principal identity fields in the response.
func TestAccounts_CreateReturnsIdentity(t *testing.T) {
	server := setupTestServer(t)

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
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

// TestAccounts_AssuranceGateRejectsAPIKeyCaller verifies through the full router that an
// API-key principal (Machine-assurance) is rejected from every provisioning endpoint with 403
// INSUFFICIENT_PERMISSIONS — even when the key carries the matching web-account permissions.
// The assurance gate in requirePermission fires before the handler (Issue #2780, #2974).
func TestAccounts_AssuranceGateRejectsAPIKeyCaller(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{
		"account:create", "account:delete", "account:revoke-enrollment-link",
	})

	body, err := json.Marshal(AccountRequest{Username: "tier3-user"})
	require.NoError(t, err)

	for _, tc := range []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodPost, "/api/v1/accounts", body},
		{http.MethodDelete, "/api/v1/accounts/tier3-user", nil},
		// Issue #2974: the enrollment-link revoke route is equally Strong-gated.
		{http.MethodPost, "/api/v1/accounts/tier3-user/enrollment-link/revoke", nil},
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

// TestAccounts_InputValidationBounds covers username validation: username bounded
// and charset-restricted so it stays path- and log-safe (usernames appear in DELETE
// URL paths). Password validation removed (Issue #2993).
func TestAccounts_InputValidationBounds(t *testing.T) {
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
			rec := postAccount(t, server, admin, AccountRequest{
				Username: tc.username,
			})
			assert.Equal(t, tc.wantStatus, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

// TestAccounts_UnknownPermissionRejected verifies web accounts use the same
// permission allow-list discipline as API keys ("*" and unknown IDs rejected).
func TestAccounts_UnknownPermissionRejected(t *testing.T) {
	server := setupTestServer(t)

	for _, perm := range []string{"*", "not-a-real:permission"} {
		rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
			Username:    "perm-user",
			Permissions: []string{perm},
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code, "permission %q must be rejected", perm)
	}
}

// TestAccounts_StoredRecordContainsNoSecretValue asserts the persisted record holds
// no sensitive value — since passkey login is credential-only, the stored Value is empty.
func TestAccounts_StoredRecordContainsNoSecretValue(t *testing.T) {
	server := setupTestServer(t)

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: "no-secret-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	metas, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: accountSecretType,
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

// TestAccounts_DeleteRemovesCacheAndStore verifies DELETE removes the account from
// both the in-memory cache and the durable secret store, and a repeat delete is 404.
func TestAccounts_DeleteRemovesCacheAndStore(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "delete-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Account exists in cache.
	acct, err := server.getAccount(context.Background(), "delete-user")
	require.NoError(t, err)
	require.NotNil(t, acct, "account must exist before delete")

	rec = deleteAccount(t, server, admin, "delete-user")
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	// Gone from the cache.
	server.mu.RLock()
	_, inCache := server.accounts["delete-user"]
	server.mu.RUnlock()
	assert.False(t, inCache, "account must be removed from cache on delete")

	// Gone from the durable store after a cache drop.
	dropAccountCache(server)
	acct, err = server.getAccount(context.Background(), "delete-user")
	require.NoError(t, err)
	assert.Nil(t, acct, "account must be unreachable from the store after delete")

	metas, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: accountSecretType,
			"username":                      "delete-user",
		},
	})
	require.NoError(t, err)
	assert.Empty(t, metas, "record must be removed from the secret store")

	rec = deleteAccount(t, server, admin, "delete-user")
	assert.Equal(t, http.StatusNotFound, rec.Code, "repeat delete must be 404")
}

// TestAccounts_AuditEntriesEmitted is the [REQUIRED TEST] for founder condition 2:
// create, reset, and delete each write an audit entry carrying the sanitized username
// and the acting admin principal.
func TestAccounts_AuditEntriesEmitted(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "audit-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	rec = postAccount(t, server, admin, AccountRequest{
		Username: "audit-user",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	rec = deleteAccount(t, server, admin, "audit-user")
	require.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))

	for _, action := range []string{
		"account.created",
		"account.reset",
		"account.deleted",
	} {
		entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
			Actions: []string{action},
		})
		require.NoError(t, err)
		require.NotEmpty(t, entries, "audit entry for %s must be written", action)
		e := entries[0]
		assert.Equal(t, action, e.Action)
		assert.Equal(t, "account", e.ResourceType)
		assert.Equal(t, "audit-user", e.ResourceID, "sanitized username is the resource ID")
		assert.Equal(t, admin.ID, e.UserID, "acting admin principal must be recorded")
		assert.Equal(t, business.AuditResultSuccess, e.Result)
	}
}

// listAccounts calls handleListAccounts directly with the given principal
// and returns the parsed slice of AccountInfo from the response.
func listAccounts(t *testing.T, server *Server, principal *Principal) (*httptest.ResponseRecorder, []AccountInfo) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
	req = withPrincipal(req, principal)
	rec := httptest.NewRecorder()
	server.handleListAccounts(rec, req)
	return rec, parseAccountInfoList(t, rec)
}

// parseAccountInfoList extracts the []AccountInfo from an APIResponse body.
func parseAccountInfoList(t *testing.T, rec *httptest.ResponseRecorder) []AccountInfo {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var accounts []AccountInfo
	require.NoError(t, json.Unmarshal(raw, &accounts))
	return accounts
}

// TestAccounts_ListReturnsAccountsWithNoSecretMaterial is the [REQUIRED TEST]:
// the list endpoint returns AccountInfo records and NEVER includes any secret
// material in the response body.
func TestAccounts_ListReturnsAccountsWithNoSecretMaterial(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username:    "list-user-a",
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	rec = postAccount(t, server, admin, AccountRequest{
		Username:    "list-user-b",
		TenantID:    "tenant-b",
		Permissions: []string{"steward:read"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	listRec, accounts := listAccounts(t, server, admin)
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

// TestAccounts_ListReflectsDeletes confirms that after an account is deleted,
// it no longer appears in the list response.
func TestAccounts_ListReflectsDeletes(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "delete-list-user",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	_, accounts := listAccounts(t, server, admin)
	found := false
	for _, a := range accounts {
		if a.Username == "delete-list-user" {
			found = true
		}
	}
	assert.True(t, found, "newly created account must appear in the list")

	delRec := deleteAccount(t, server, admin, "delete-list-user")
	require.Equal(t, http.StatusOK, delRec.Code, "body: %s", delRec.Body.String())

	_, accounts = listAccounts(t, server, admin)
	for _, a := range accounts {
		assert.NotEqual(t, "delete-list-user", a.Username,
			"deleted account must not appear in the list")
	}
}

// TestAccounts_ListRequiresPermissionNotTier3 verifies that an API-key caller
// with only the account:list permission CAN reach the list endpoint (no Tier-3
// gate), while the create/delete endpoints remain Tier-3 gated.
func TestAccounts_ListRequiresPermissionNotTier3(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"account:list"})

	// POST an account first (using the admin path so the store has content).
	postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: "tier-check-user",
	})

	// An API-key caller with account:list reaches GET /api/v1/accounts.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code,
		"API-key caller with account:list must reach the list endpoint (no Tier-3 gate)")

	body := rec.Body.String()
	assert.NotContains(t, body, "$argon2id$", "list response must not contain any argon2id hash")
}

// ---- Issue #2919: root-scope web account tests ----

// TestAccounts_RootScope_NotDefaultedToDefault verifies that creating a web account
// with root_scope:true results in an account with empty TenantID, not "default".
func TestAccounts_RootScope_NotDefaultedToDefault(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
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
	acct, err := server.getAccount(context.Background(), "root-admin")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.True(t, acct.RootScope, "loaded account must have RootScope=true")
	assert.Empty(t, acct.TenantID, "loaded account must have empty TenantID")
}

// TestAccounts_RootScope_DurableAfterCacheDrop verifies that a root-scoped
// account survives a cache drop (store round-trip) and retains root scope.
func TestAccounts_RootScope_DurableAfterCacheDrop(t *testing.T) {
	server := setupTestServer(t)

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username:  "root-durable",
		RootScope: true,
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	dropAccountCache(server)

	acct, err := server.getAccount(context.Background(), "root-durable")
	require.NoError(t, err, "root-scoped account must be reloadable from the secret store")
	require.NotNil(t, acct)
	assert.True(t, acct.RootScope, "root scope must survive a cache drop + store reload")
	assert.Empty(t, acct.TenantID, "tenant_id must be empty after reload")
}

// TestAccounts_RootScope_MutuallyExclusiveWithTenantID verifies that specifying
// both root_scope:true and a non-empty tenant_id in the same request is rejected.
func TestAccounts_RootScope_MutuallyExclusiveWithTenantID(t *testing.T) {
	server := setupTestServer(t)

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
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

// TestAccounts_RootScope_ResetRetainsScope verifies that resetting a root-scoped
// account without specifying a new scope retains root scope.
func TestAccounts_RootScope_ResetRetainsScope(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username:  "root-reset-user",
		RootScope: true,
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Reset without specifying scope — root scope must be retained.
	rec = postAccount(t, server, admin, AccountRequest{
		Username: "root-reset-user",
	})
	require.Equal(t, http.StatusOK, rec.Code, "reset of existing account returns 200")

	// Reload from store and verify scope retained.
	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), "root-reset-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.True(t, acct.RootScope, "root scope must be retained across account reset")
	assert.Empty(t, acct.TenantID, "tenant_id must remain empty after reset")
}

// TestAccounts_RootScope_AppearsInList verifies that a root-scoped account
// appears in the list endpoint with root_scope:true and empty tenant_id.
func TestAccounts_RootScope_AppearsInList(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username:  "root-list-user",
		RootScope: true,
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	_, accounts := listAccounts(t, server, admin)
	var found *AccountInfo
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

// ---- Issue #3137: tenant-subtree scope enforcement on GET /api/v1/accounts ----

// TestAccounts_TenantScope_SiblingExclusion is the [REQUIRED TEST] from Issue #3137:
// a caller scoped to client-1 must never see an account belonging to sibling tenant client-2.
func TestAccounts_TenantScope_SiblingExclusion(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "client2-user",
		TenantID: "root/msp-a/client-2",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	rec = postAccount(t, server, admin, AccountRequest{
		Username: "client1-user",
		TenantID: "root/msp-a/client-1",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	client1Principal := &Principal{
		ID:        "client1-admin",
		TenantID:  "root/msp-a/client-1",
		Assurance: session.AssuranceBasic,
	}
	_, accounts := listAccounts(t, server, client1Principal)

	usernames := make([]string, 0, len(accounts))
	for _, a := range accounts {
		usernames = append(usernames, a.Username)
	}
	assert.Contains(t, usernames, "client1-user", "caller must see own tenant's accounts")
	assert.NotContains(t, usernames, "client2-user", "caller must NOT see sibling tenant's accounts")
}

// TestAccounts_TenantScope_SubtreeInclusion is the [REQUIRED TEST] from Issue #3137:
// a caller scoped to root/msp-a DOES see an account belonging to root/msp-a/client-1
// (subtree inclusion, not exact-match-only).
func TestAccounts_TenantScope_SubtreeInclusion(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "parent-user",
		TenantID: "root/msp-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	rec = postAccount(t, server, admin, AccountRequest{
		Username: "child-user",
		TenantID: "root/msp-a/client-1",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	mspaAdmin := &Principal{
		ID:        "msp-a-admin",
		TenantID:  "root/msp-a",
		Assurance: session.AssuranceBasic,
	}
	_, accounts := listAccounts(t, server, mspaAdmin)

	usernames := make([]string, 0, len(accounts))
	for _, a := range accounts {
		usernames = append(usernames, a.Username)
	}
	assert.Contains(t, usernames, "parent-user", "parent-tenant admin must see own accounts")
	assert.Contains(t, usernames, "child-user", "parent-tenant admin must see child tenant accounts (subtree)")
}

// TestAccounts_TenantScope_UnscopedAdminSeesAll verifies that an unscoped mTLS admin
// (callerTenant == "") still sees all accounts including those in multiple tenants.
func TestAccounts_TenantScope_UnscopedAdminSeesAll(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	for _, req := range []AccountRequest{
		{Username: "scope-all-a", TenantID: "root/msp-a/client-1"},
		{Username: "scope-all-b", TenantID: "root/msp-a/client-2"},
		{Username: "scope-all-root", RootScope: true},
	} {
		rec := postAccount(t, server, admin, req)
		require.Equal(t, http.StatusCreated, rec.Code)
	}

	_, accounts := listAccounts(t, server, admin)
	usernames := make([]string, 0, len(accounts))
	for _, a := range accounts {
		usernames = append(usernames, a.Username)
	}
	assert.Contains(t, usernames, "scope-all-a")
	assert.Contains(t, usernames, "scope-all-b")
	assert.Contains(t, usernames, "scope-all-root")
}

// TestAccounts_RootScope_DeleteWorks verifies that deleting a root-scoped
// account succeeds and the account is removed from the store.
func TestAccounts_RootScope_DeleteWorks(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username:  "root-delete-user",
		RootScope: true,
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Verify account exists before delete.
	acct, err := server.getAccount(context.Background(), "root-delete-user")
	require.NoError(t, err)
	require.NotNil(t, acct, "account must exist before delete")

	// Delete it.
	delRec := deleteAccount(t, server, admin, "root-delete-user")
	require.Equal(t, http.StatusOK, delRec.Code)

	// After deletion (and cache drop), account must be gone.
	dropAccountCache(server)
	acct, err = server.getAccount(context.Background(), "root-delete-user")
	require.NoError(t, err)
	assert.Nil(t, acct, "account must be unreachable from the store after delete")
}

// ---- Issue #2974: enrollment magic link tests ----

// revokeEnrollmentLink calls handleRevokeEnrollmentLink directly with an admin principal.
func revokeEnrollmentLink(t *testing.T, server *Server, principal *Principal, username string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/accounts/"+username+"/enrollment-link/revoke", nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username})
	rec := httptest.NewRecorder()
	server.handleRevokeEnrollmentLink(rec, req)
	return rec
}

// parseCreateResponse extracts AccountCreateResponse from an APIResponse body.
func parseCreateResponse(t *testing.T, rec *httptest.ResponseRecorder) AccountCreateResponse {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var cr AccountCreateResponse
	require.NoError(t, json.Unmarshal(raw, &cr))
	return cr
}

// TestAccounts_CreateMintsEnrollmentLink verifies that POST /api/v1/accounts returns
// an enrollment_magic_link field on creation (non-empty, >=40 hex chars for 160-bit entropy).
func TestAccounts_CreateMintsEnrollmentLink(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
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

// TestAccounts_EnrollmentLinkTTL_ConfiguredValue verifies the enrollment link
// TTL is sourced from cfg.Registration.EnrollmentLinkTTL rather than a hardcoded
// constant (PR #3277 review: TTL must be configurable, not just defaulted).
func TestAccounts_EnrollmentLinkTTL_ConfiguredValue(t *testing.T) {
	server := setupTestServer(t)
	server.cfg.Registration = &config.RegistrationConfig{
		EnrollmentLinkTTL: config.Duration(2 * time.Hour),
	}
	admin := testAdminPrincipal()

	before := time.Now().UTC()
	rec := postAccount(t, server, admin, AccountRequest{
		Username: "configured-ttl-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
	after := time.Now().UTC()

	server.mu.RLock()
	acct := server.accounts["configured-ttl-user"]
	server.mu.RUnlock()
	require.NotNil(t, acct)

	assert.True(t, acct.EnrollmentLinkExpiresAt.After(before.Add(2*time.Hour-time.Minute)),
		"expiry must reflect the configured 2h TTL, not the 72h default")
	assert.True(t, acct.EnrollmentLinkExpiresAt.Before(after.Add(2*time.Hour+time.Minute)),
		"expiry must not exceed the configured 2h TTL by more than test slack")
}

// TestAccounts_EnrollmentLinkStoredHashed verifies that the enrollment token is stored
// as a SHA-256 hash in the secret store — NEVER as plaintext. This is the [REQUIRED TEST]
// for the token-storage security property (Issue #2974, mirrors #2966).
func TestAccounts_EnrollmentLinkStoredHashed(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "hash-test-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	cr := parseCreateResponse(t, rec)
	rawToken := cr.EnrollmentMagicLink
	require.NotEmpty(t, rawToken, "raw token must be returned on create")

	// Load the account from the store and verify hash matches — plaintext absent.
	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), "hash-test-user")
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
			secretsif.MetadataKeySecretType: accountSecretType,
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

// TestAccounts_CreateAuditNeverIncludesToken is the [REQUIRED TEST] for the audit
// security property: creation records account + delivery method, never the raw token value.
func TestAccounts_CreateAuditNeverIncludesToken(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "audit-link-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	cr := parseCreateResponse(t, rec)
	rawToken := cr.EnrollmentMagicLink
	require.NotEmpty(t, rawToken)

	require.NoError(t, server.auditManager.Flush(context.Background()))

	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"account.created"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "audit entry for account.created must be written")

	entry := entries[0]
	assert.Equal(t, "account.created", entry.Action)
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

// TestAccounts_EnrollmentLinkAppearsInList verifies that a newly created account shows
// has_outstanding_enrollment_link:true in the list response.
func TestAccounts_EnrollmentLinkAppearsInList(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "list-link-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	_, accounts := listAccounts(t, server, admin)
	var found *AccountInfo
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

// TestAccounts_RevokeEnrollmentLink verifies that POST .../enrollment-link/revoke
// invalidates an outstanding link and that has_outstanding_enrollment_link becomes false.
func TestAccounts_RevokeEnrollmentLink(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "revoke-link-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	// Verify link is outstanding before revoke.
	_, accounts := listAccounts(t, server, admin)
	var found *AccountInfo
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
	dropAccountCache(server)
	_, accounts = listAccounts(t, server, admin)
	var foundAfter *AccountInfo
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

// TestAccounts_RevokeNonExistentLinkReturns409 verifies that revoking an account
// with no outstanding link returns 409 CONFLICT.
func TestAccounts_RevokeNonExistentLinkReturns409(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	// Create an account then immediately revoke its link.
	rec := postAccount(t, server, admin, AccountRequest{Username: "no-link-user"})
	require.Equal(t, http.StatusCreated, rec.Code)
	revokeRec := revokeEnrollmentLink(t, server, admin, "no-link-user")
	require.Equal(t, http.StatusOK, revokeRec.Code, "first revoke must succeed")

	// Second revoke must fail with 409.
	revokeRec = revokeEnrollmentLink(t, server, admin, "no-link-user")
	assert.Equal(t, http.StatusConflict, revokeRec.Code,
		"revoke with no outstanding link must return 409 CONFLICT")
}

// TestAccounts_EnrollmentLinkExpiredNotOutstanding verifies that an enrollment link
// with an expired TTL is not reported as outstanding in list responses.
func TestAccounts_EnrollmentLinkExpiredNotOutstanding(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "expired-link-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Back-date the expiry directly in the in-memory struct and persist that to the store.
	// getAccount now always re-reads from the store (Issue #3311 cross-node fix), so we
	// read from the accounts map under the lock and persist the mutated value immediately
	// rather than reading it back via getAccount (which would see the on-disk state, not
	// the in-memory mutation).
	var acct *account
	server.mu.Lock()
	if found, ok := server.accounts["expired-link-user"]; ok {
		found.EnrollmentLinkExpiresAt = time.Now().Add(-1 * time.Hour) // already expired
		acct = found
	}
	server.mu.Unlock()
	require.NotNil(t, acct, "account must be in cache after creation")
	require.NoError(t, server.persistAccount(context.Background(), acct, admin.ID))

	dropAccountCache(server)
	_, accounts := listAccounts(t, server, admin)
	var found *AccountInfo
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

// TestAccounts_EnrollmentLinkAuditRevoke verifies that revocation is audited separately
// with the correct action.
func TestAccounts_EnrollmentLinkAuditRevoke(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{Username: "audit-revoke-user"})
	require.Equal(t, http.StatusCreated, rec.Code)

	revokeRec := revokeEnrollmentLink(t, server, admin, "audit-revoke-user")
	require.Equal(t, http.StatusOK, revokeRec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))

	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"account.enrollment_link.revoked"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "revoke audit entry must be written")
	e := entries[0]
	assert.Equal(t, "account.enrollment_link.revoked", e.Action)
	assert.Equal(t, "audit-revoke-user", e.ResourceID)
}

// TestAccounts_RevokeEnrollmentLink_CrossTenantForbidden is the [REQUIRED TEST] for
// the tenant-subtree authorization fix (Issue #2974): a caller scoped to client-1 must
// receive 403 when revoking the enrollment link of an account in sibling tenant client-2,
// regardless of whether a link is outstanding (prevents cross-tenant oracle).
func TestAccounts_RevokeEnrollmentLink_CrossTenantForbidden(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	// Create the target account in client-2.
	rec := postAccount(t, server, admin, AccountRequest{
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

// TestAccounts_RevokeEnrollmentLinkRoute drives the revoke endpoint through the real
// router (server.router.ServeHTTP) rather than calling the handler directly, so route
// registration, the requirePermission("account", "revoke-enrollment-link") wrapper and
// the AssuranceStrong gate are all exercised as they are wired in production (Issue #2974).
func TestAccounts_RevokeEnrollmentLinkRoute(t *testing.T) {
	server := setupTestServer(t)
	const username = "router-revoke-user"
	const path = "/api/v1/accounts/" + username + "/enrollment-link/revoke"

	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
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

		dropAccountCache(server)
		acct, err := server.getAccount(context.Background(), username)
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

// TestAccounts_RevokeFailsClosedOnStoreError is the [REQUIRED TEST] for the
// fail-closed revocation property (Issue #2974): when the durable write fails the
// cached record must NOT be marked revoked, so a retry still finds an outstanding
// link and can complete the revocation instead of answering 409 forever.
func TestAccounts_RevokeFailsClosedOnStoreError(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "failclosed-user"

	rec := postAccount(t, server, admin, AccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	realStore := server.secretStore
	storeErr := errors.New("injected durable write failure")
	server.secretStore = &errStoreSecretStore{SecretStore: realStore, storeErr: storeErr}

	failed := revokeEnrollmentLink(t, server, admin, username)
	require.Equal(t, http.StatusInternalServerError, failed.Code,
		"a failed durable write must surface as 500, not a silent success")

	// The cache must still agree with the store: the link is live, not revoked.
	acct, err := server.getAccount(context.Background(), username)
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

	dropAccountCache(server)
	reloaded, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, reloaded)
	assert.True(t, reloaded.EnrollmentLinkRevoked,
		"durable record must carry the revocation after a successful retry")
}

// TestAccounts_NoLinkMintedForEnrolledAccount is the [REQUIRED TEST] for ADR-021
// Amendment 1 Decision 3 ("No magic link is involved after the first passkey"): an upsert
// against an account that already holds a registered passkey must not hand the caller a
// fresh enrollment bearer token, because redeeming it would enroll the bearer's own
// passkey onto a fully provisioned account (Issue #2974).
func TestAccounts_NoLinkMintedForEnrolledAccount(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "enrolled-user"

	rec := postAccount(t, server, admin, AccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Register a passkey, then revoke the first-enrollment link as the real flow does.
	injectCredential(t, server, username, []byte("enrolled-user-credential"))
	require.Equal(t, http.StatusOK, revokeEnrollmentLink(t, server, admin, username).Code)

	rec = postAccount(t, server, admin, AccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusOK, rec.Code, "reset of an existing account returns 200")

	cr := parseCreateResponse(t, rec)
	assert.Empty(t, cr.EnrollmentMagicLink,
		"no enrollment link may be minted for an account that already holds a passkey")
	assert.False(t, cr.HasOutstandingEnrollmentLink,
		"response must not advertise an outstanding link when none was minted")

	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	require.Len(t, acct.Credentials, 1, "registered passkey must survive the reset")
	assert.False(t, enrollmentLinkOutstanding(acct),
		"stored record must hold no outstanding link for an enrolled account")
}

// TestAccounts_ResetCredentialsMintsFreshLink covers ADR-021 Amendment 1 Decision 4:
// an admin-mediated reset re-provisions the account to the zero-authenticator state,
// invalidating residual credentials, and only then issues a fresh single-use link.
func TestAccounts_ResetCredentialsMintsFreshLink(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "reset-creds-user"

	rec := postAccount(t, server, admin, AccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusCreated, rec.Code)
	injectCredential(t, server, username, []byte("reset-creds-user-credential"))

	rec = postAccount(t, server, admin, AccountRequest{
		Username:         username,
		TenantID:         "tenant-a",
		ResetCredentials: true,
	})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	cr := parseCreateResponse(t, rec)
	require.NotEmpty(t, cr.EnrollmentMagicLink,
		"an explicit credential reset must issue a fresh enrollment link")
	assert.True(t, cr.HasOutstandingEnrollmentLink)

	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.Empty(t, acct.Credentials,
		"residual credentials must be invalidated when a fresh link is issued")
	assert.True(t, verifyEnrollmentToken(acct, cr.EnrollmentMagicLink),
		"the returned token must be the one stored against the reset account")
}

// TestAccounts_CreateEnforcesTenantScope is the [REQUIRED TEST] for create-side tenant
// isolation (Issue #2974): POST /api/v1/accounts issues a bearer enrollment credential,
// so a tenant-scoped caller must not be able to target another tenant's subtree, mint a
// root-scoped account, or pull an out-of-subtree account into its own tenant.
func TestAccounts_CreateEnforcesTenantScope(t *testing.T) {
	server := setupTestServer(t)

	// An out-of-subtree account provisioned by an unscoped mTLS admin.
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: "sibling-tenant-user",
		TenantID: "root/msp-a/client-2",
	})
	require.Equal(t, http.StatusCreated, rec.Code, "setup: create account in client-2")
	siblingToken := parseCreateResponse(t, rec).EnrollmentMagicLink
	require.NotEmpty(t, siblingToken, "setup: create must mint an enrollment token")
	sibling, err := server.getAccount(context.Background(), "sibling-tenant-user")
	require.NoError(t, err)
	require.NotNil(t, sibling)
	siblingHash := sibling.EnrollmentLinkHash

	client1Admin := &Principal{
		ID:        "client1-admin",
		TenantID:  "root/msp-a/client-1",
		Assurance: session.AssuranceStrong,
	}

	t.Run("cross-tenant create is forbidden", func(t *testing.T) {
		rec := postAccount(t, server, client1Admin, AccountRequest{
			Username: "cross-tenant-user",
			TenantID: "root/msp-a/client-2",
		})
		require.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())

		acct, err := server.getAccount(context.Background(), "cross-tenant-user")
		require.NoError(t, err)
		assert.Nil(t, acct, "a forbidden create must not write an account record")
	})

	t.Run("root-scope grant from a scoped caller is forbidden", func(t *testing.T) {
		rec := postAccount(t, server, client1Admin, AccountRequest{
			Username:  "root-grab-user",
			RootScope: true,
		})
		assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	})

	t.Run("reset of an out-of-subtree account is forbidden", func(t *testing.T) {
		rec := postAccount(t, server, client1Admin, AccountRequest{
			Username: "sibling-tenant-user",
			TenantID: "root/msp-a/client-1",
		})
		require.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())

		// Assert on the raw body: a 403 emits an ErrorResponse, whose keys share nothing
		// with AccountCreateResponse, so decoding into that struct would leave it at
		// its zero value and pass no matter what the handler returned.
		assert.NotContains(t, rec.Body.String(), "enrollment_magic_link",
			"a forbidden reset must not return a token")
		assert.NotContains(t, rec.Body.String(), siblingToken,
			"a forbidden reset must not leak the out-of-subtree account's token")

		acct, err := server.getAccount(context.Background(), "sibling-tenant-user")
		require.NoError(t, err)
		require.NotNil(t, acct)
		assert.Equal(t, "root/msp-a/client-2", acct.TenantID, "the record must stay in client-2")
		assert.Equal(t, siblingHash, acct.EnrollmentLinkHash, "the stored link must be untouched")
		assert.False(t, acct.EnrollmentLinkRevoked, "the stored link must be untouched")
	})

	t.Run("create inside the caller subtree succeeds", func(t *testing.T) {
		rec := postAccount(t, server, client1Admin, AccountRequest{
			Username: "in-subtree-user",
			TenantID: "root/msp-a/client-1/servers",
		})
		require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
		cr := parseCreateResponse(t, rec)
		assert.NotEmpty(t, cr.EnrollmentMagicLink)
	})
}

// TestAccounts_VerifyEnrollmentToken verifies constant-time token comparison (Issue #2974).
func TestAccounts_VerifyEnrollmentToken(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{Username: "verify-token-user"})
	require.Equal(t, http.StatusCreated, rec.Code)
	cr := parseCreateResponse(t, rec)
	rawToken := cr.EnrollmentMagicLink

	acct, err := server.getAccount(context.Background(), "verify-token-user")
	require.NoError(t, err)
	require.NotNil(t, acct)

	assert.True(t, verifyEnrollmentToken(acct, rawToken), "valid token must verify")
	assert.False(t, verifyEnrollmentToken(acct, "wrong-token"), "wrong token must not verify")
	assert.False(t, verifyEnrollmentToken(acct, ""), "empty token must not verify")
	assert.False(t, verifyEnrollmentToken(nil, rawToken), "nil account must not verify")
}

// ---- Issue #3126: GET/PUT /api/v1/accounts/{username} ----

// getAccount calls handleGetAccount directly with the given principal.
func getAccountHandler(t *testing.T, server *Server, principal *Principal, username string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts/"+username, nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username})
	rec := httptest.NewRecorder()
	server.handleGetAccount(rec, req)
	return rec
}

// putAccount calls handleUpdateAccount directly with the given principal.
func putAccount(t *testing.T, server *Server, principal *Principal, username string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/accounts/"+username, bytes.NewReader(payload))
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username})
	rec := httptest.NewRecorder()
	server.handleUpdateAccount(rec, req)
	return rec
}

// parseAccountInfo extracts a AccountInfo from an APIResponse body.
func parseAccountInfo(t *testing.T, rec *httptest.ResponseRecorder) AccountInfo {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var info AccountInfo
	require.NoError(t, json.Unmarshal(raw, &info))
	return info
}

// parseUpdateResponse extracts a AccountUpdateResponse from an APIResponse body.
func parseUpdateResponse(t *testing.T, rec *httptest.ResponseRecorder) AccountUpdateResponse {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var ur AccountUpdateResponse
	require.NoError(t, json.Unmarshal(raw, &ur))
	return ur
}

// TestAccounts_Get_Returns200 verifies GET /web/accounts/{username} returns
// the account's identity fields with no secret material (Issue #3126 AC).
func TestAccounts_Get_Returns200(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username:    "get-user",
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	getRec := getAccountHandler(t, server, admin, "get-user")
	require.Equal(t, http.StatusOK, getRec.Code, "body: %s", getRec.Body.String())

	info := parseAccountInfo(t, getRec)
	assert.Equal(t, "get-user", info.Username)
	assert.Equal(t, "tenant-a", info.TenantID)
	assert.Equal(t, []string{"steward:list"}, info.Permissions)
	assert.NotEmpty(t, info.ID)
	assert.False(t, info.CreatedAt.IsZero())
	assert.False(t, info.Disabled, "newly created account must not be disabled")

	// Ensure no secret material in the raw response.
	body := getRec.Body.String()
	assert.NotContains(t, body, "$argon2id$", "response must not contain any argon2id hash")
}

// TestAccounts_Get_NotFound verifies GET returns 404 for an unknown username (Issue #3126 AC).
func TestAccounts_Get_NotFound(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := getAccountHandler(t, server, admin, "nonexistent-user")
	assert.Equal(t, http.StatusNotFound, rec.Code, "body: %s", rec.Body.String())
}

// TestAccounts_Get_CrossTenantGets404 is the [REQUIRED TEST] from Issue #3126 AC:
// a caller scoped to client-1 calling GET on an account belonging to client-2 gets 404,
// not 403 — the account's existence in another tenant must not be disclosed.
func TestAccounts_Get_CrossTenantGets404(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "client2-get-user",
		TenantID: "root/msp-a/client-2",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	client1Admin := &Principal{
		ID:        "client1-admin",
		TenantID:  "root/msp-a/client-1",
		Assurance: session.AssuranceStrong,
	}
	rec = getAccountHandler(t, server, client1Admin, "client2-get-user")
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant GET must return 404, not 403 (do not disclose account existence)")
}

// TestAccounts_UpdatePermissions verifies PUT /web/accounts/{username} updates permissions (Issue #3126 AC).
func TestAccounts_UpdatePermissions(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username:    "update-perms-user",
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	newPerms := []string{"steward:list", "steward:read"}
	putRec := putAccount(t, server, admin, "update-perms-user", AccountUpdateRequest{
		Permissions: &newPerms,
	})
	require.Equal(t, http.StatusOK, putRec.Code, "body: %s", putRec.Body.String())

	info := parseAccountInfo(t, putRec)
	assert.Equal(t, []string{"steward:list", "steward:read"}, info.Permissions)
	assert.False(t, info.Disabled, "update must not alter disabled state")

	// Verify durably persisted.
	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), "update-perms-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.Equal(t, []string{"steward:list", "steward:read"}, acct.Permissions)
}

// TestAccounts_Disabled_BlocksVerifyCredential is the [REQUIRED TEST] from Issue #3126 AC:
// disabling an account, then attempting VerifyCredential, fails with ErrInvalidWebCredential.
// ("correct password" maps to valid credentials in the passkey-only model — the enforcement
// point is VerifyCredential, called after successful WebAuthn assertion.)
func TestAccounts_Disabled_BlocksVerifyCredential(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "disabled-login-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Disable the account.
	disabled := true
	putRec := putAccount(t, server, admin, "disabled-login-user", AccountUpdateRequest{
		Disabled: &disabled,
	})
	require.Equal(t, http.StatusOK, putRec.Code, "body: %s", putRec.Body.String())

	// VerifyCredential must reject a disabled account.
	acct, err := server.getAccount(context.Background(), "disabled-login-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	require.True(t, acct.Disabled, "account must be persisted as disabled")

	err = server.VerifyCredential(acct)
	assert.ErrorIs(t, err, ErrInvalidWebCredential,
		"disabled account must be rejected by VerifyCredential")
}

// TestAccounts_Disabled_NilAccountRejected verifies VerifyCredential rejects nil.
func TestAccounts_Disabled_NilAccountRejected(t *testing.T) {
	server := setupTestServer(t)
	err := server.VerifyCredential(nil)
	assert.ErrorIs(t, err, ErrInvalidWebCredential, "nil account must be rejected")
}

// TestAccounts_Disabled_EnabledAccountPasses verifies VerifyCredential accepts a non-disabled account.
func TestAccounts_Disabled_EnabledAccountPasses(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "enabled-login-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	acct, err := server.getAccount(context.Background(), "enabled-login-user")
	require.NoError(t, err)
	require.NotNil(t, acct)

	err = server.VerifyCredential(acct)
	assert.NoError(t, err, "non-disabled account must pass VerifyCredential")
}

// TestAccounts_ReenableRestoresLogin verifies that re-enabling an account
// restores VerifyCredential success without requiring any credential reset (Issue #3126 AC).
func TestAccounts_ReenableRestoresLogin(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "reenable-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Disable.
	disabled := true
	putRec := putAccount(t, server, admin, "reenable-user", AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, putRec.Code)

	// Re-enable.
	disabled = false
	putRec = putAccount(t, server, admin, "reenable-user", AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, putRec.Code)

	// VerifyCredential must succeed after re-enable.
	acct, err := server.getAccount(context.Background(), "reenable-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.False(t, acct.Disabled, "account must be marked enabled after re-enable")
	assert.NoError(t, server.VerifyCredential(acct),
		"re-enabled account must pass VerifyCredential without credential reset")
}

// TestAccounts_UpdatePermissions_DoesNotAlterCredentials is the [REQUIRED TEST] from
// Issue #3126 AC: updating permissions alone does not alter the stored credentials (WebAuthn
// passkeys). In the passkey-only model there is no "password hash" — the equivalent
// invariant is that registered WebAuthn credentials survive a permissions-only PUT.
func TestAccounts_UpdatePermissions_DoesNotAlterCredentials(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username:    "perms-creds-user",
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Register a WebAuthn credential.
	injectCredential(t, server, "perms-creds-user", []byte("perms-creds-credential-id"))

	// Record the original credential set.
	before, err := server.getAccount(context.Background(), "perms-creds-user")
	require.NoError(t, err)
	require.NotNil(t, before)
	require.Len(t, before.Credentials, 1, "credential must be registered before update")
	origCredID := before.Credentials[0].ID

	// Update permissions only — no disabled field.
	newPerms := []string{"steward:list", "steward:read"}
	putRec := putAccount(t, server, admin, "perms-creds-user", AccountUpdateRequest{
		Permissions: &newPerms,
	})
	require.Equal(t, http.StatusOK, putRec.Code, "body: %s", putRec.Body.String())

	// Reload from store (not cache) and assert credentials unchanged.
	dropAccountCache(server)
	after, err := server.getAccount(context.Background(), "perms-creds-user")
	require.NoError(t, err)
	require.NotNil(t, after)
	assert.Equal(t, []string{"steward:list", "steward:read"}, after.Permissions,
		"permissions must be updated")
	require.Len(t, after.Credentials, 1, "credential count must be unchanged")
	assert.Equal(t, origCredID, after.Credentials[0].ID,
		"credential ID must be unchanged by a permissions-only update")
}

// TestAccounts_CrossTenantPut_Returns404_And_LeavesAccountUnmodified is the [REQUIRED TEST]
// from Issue #3126 AC: a caller scoped to tenant-a calling PUT on an account belonging to
// tenant-b gets 404 and leaves the target account completely unmodified.
func TestAccounts_CrossTenantPut_Returns404_And_LeavesAccountUnmodified(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	// Create target account in tenant-b.
	rec := postAccount(t, server, admin, AccountRequest{
		Username:    "tenantb-put-user",
		TenantID:    "tenant-b",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Record the original state from cache (before any cache drop).
	origAcct, err := server.getAccount(context.Background(), "tenantb-put-user")
	require.NoError(t, err)
	require.NotNil(t, origAcct)
	origPermissions := append([]string(nil), origAcct.Permissions...)
	origDisabled := origAcct.Disabled

	// Caller is scoped to tenant-a — not within tenant-b's subtree.
	tenantAAdmin := &Principal{
		ID:        "tenant-a-admin",
		TenantID:  "tenant-a",
		Assurance: session.AssuranceStrong,
	}
	disabled := true
	newPerms := []string{"steward:read"}
	putRec := putAccount(t, server, tenantAAdmin, "tenantb-put-user", AccountUpdateRequest{
		Permissions: &newPerms,
		Disabled:    &disabled,
	})
	assert.Equal(t, http.StatusNotFound, putRec.Code,
		"cross-tenant PUT must return 404, not 403 (do not disclose account existence)")

	// The account in tenant-b must be completely unmodified.
	// Check from cache — the handler returns before writing, so cache is the pre-PUT state.
	afterAcct, err := server.getAccount(context.Background(), "tenantb-put-user")
	require.NoError(t, err)
	require.NotNil(t, afterAcct)
	assert.Equal(t, origPermissions, afterAcct.Permissions,
		"permissions must be unchanged after a rejected cross-tenant PUT")
	assert.Equal(t, origDisabled, afterAcct.Disabled,
		"disabled state must be unchanged after a rejected cross-tenant PUT")
}

// TestAccounts_DisabledState_DurableAfterCacheDrop verifies the Disabled field
// survives a cache drop (store round-trip) in both directions (Issue #3126).
func TestAccounts_DisabledState_DurableAfterCacheDrop(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username: "durable-disabled-user",
		TenantID: "tenant-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Disable and verify durability.
	disabled := true
	putRec := putAccount(t, server, admin, "durable-disabled-user", AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, putRec.Code)

	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), "durable-disabled-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.True(t, acct.Disabled, "disabled flag must survive cache drop + store reload")

	// Re-enable and verify durability.
	disabled = false
	putRec = putAccount(t, server, admin, "durable-disabled-user", AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, putRec.Code)

	dropAccountCache(server)
	acct, err = server.getAccount(context.Background(), "durable-disabled-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.False(t, acct.Disabled, "re-enabled flag must survive cache drop + store reload")
}

// TestAccounts_UpdateAuditEmitted verifies that the update endpoint emits the correct
// audit events: account.disabled, account.enabled, and account.updated (Issue #3126).
func TestAccounts_UpdateAuditEmitted(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{Username: "audit-update-user"})
	require.Equal(t, http.StatusCreated, rec.Code)

	disabled := true
	rec = putAccount(t, server, admin, "audit-update-user", AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, rec.Code)

	disabled = false
	rec = putAccount(t, server, admin, "audit-update-user", AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, rec.Code)

	newPerms := []string{"steward:list"}
	rec = putAccount(t, server, admin, "audit-update-user", AccountUpdateRequest{Permissions: &newPerms})
	require.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))

	for _, action := range []string{
		"account.disabled",
		"account.enabled",
		"account.updated",
	} {
		entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
			Actions: []string{action},
		})
		require.NoError(t, err)
		require.NotEmpty(t, entries, "audit entry for %s must be written", action)
		e := entries[0]
		assert.Equal(t, action, e.Action)
		assert.Equal(t, "account", e.ResourceType)
		assert.Equal(t, "audit-update-user", e.ResourceID)
		assert.Equal(t, admin.ID, e.UserID)
	}
}

// TestAccounts_UpdateRoute_MachineAssuranceRejected verifies that an API-key
// caller (Machine-assurance) is rejected from the update endpoint with 403.
func TestAccounts_UpdateRoute_MachineAssuranceRejected(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"account:update"})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/accounts/any-user",
		bytes.NewReader([]byte(`{"disabled":true}`)))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "INSUFFICIENT_PERMISSIONS", errResp.Error.Code)
}

// TestAccounts_GetRoute_PermissionRequired verifies GET /web/accounts/{username}
// is permission-gated and returns 401 when unauthenticated (Issue #3126).
func TestAccounts_GetRoute_PermissionRequired(t *testing.T) {
	server := setupTestServer(t)
	postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: "route-get-user"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts/route-get-user", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"unauthenticated GET must be rejected")
}

// TestAccounts_Disabled_PasskeyLoginFinishRejected drives the disable gate through
// handlePasskeyLoginFinish rather than calling VerifyCredential directly: the account
// presents a cryptographically valid W3C spec-vector assertion (real go-webauthn
// verification, no mocks) and must still be refused because it is disabled.
//
// Asserts the full handler contract for that path (Issue #3126):
// 400 WEBAUTHN_VERIFY_ERROR — indistinguishable from an assertion failure, so the
// response is not a "this account is disabled" oracle — no session or CSRF cookie,
// and a web.passkey.login.failure authentication audit entry.
func TestAccounts_Disabled_PasskeyLoginFinishRejected(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	admin := testAdminPrincipal()

	// Control: the same assertion succeeds while the account is enabled, proving the
	// 400 below comes from the disable gate and not from a broken ceremony fixture.
	okRec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, okRec.Code, "enabled account must log in: %s", okRec.Body.String())

	disabled := true
	putRec := putAccount(t, srv, admin, username, AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, putRec.Code, "disable body: %s", putRec.Body.String())

	rec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusBadRequest, rec.Code,
		"disabled account must not complete passkey login: %s", rec.Body.String())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()),
		"rejection must be indistinguishable from an assertion failure")
	assert.Empty(t, extractCookie(rec, cookieWebSession),
		"no session cookie may be issued to a disabled account")
	assert.Empty(t, extractCookie(rec, cookieCSRFSession),
		"no session-bound CSRF cookie may be issued to a disabled account")

	require.NoError(t, srv.auditManager.Flush(context.Background()))
	entries, err := srv.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"web.passkey.login.failure"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "rejected login of a disabled account must emit a failure audit entry")
	assert.Equal(t, business.AuditEventAuthentication, entries[0].EventType)
	assert.Equal(t, business.AuditResultFailure, entries[0].Result)
}

// TestAccounts_Disabled_RevokesLiveSessions verifies that disabling an account
// terminates sessions that already exist, not just future logins (Issue #3126).
//
// Without this, a disabled account keeps full API access until its absolute session
// timeout (12h) — the exact window the disable control exists to close.
func TestAccounts_Disabled_RevokesLiveSessions(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	admin := testAdminPrincipal()

	perms := []string{"steward:list"}
	permRec := putAccount(t, srv, admin, username, AccountUpdateRequest{Permissions: &perms})
	require.Equal(t, http.StatusOK, permRec.Code, "grant body: %s", permRec.Body.String())

	loginRec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, loginRec.Code, "login body: %s", loginRec.Body.String())
	sessionToken := extractCookie(loginRec, cookieWebSession)
	require.NotEmpty(t, sessionToken)

	// The live session works before the disable.
	beforeReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	beforeReq.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionToken})
	beforeRec := httptest.NewRecorder()
	srv.router.ServeHTTP(beforeRec, beforeReq)
	require.Equal(t, http.StatusOK, beforeRec.Code, "session must work before disable: %s", beforeRec.Body.String())

	disabled := true
	putRec := putAccount(t, srv, admin, username, AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, putRec.Code, "disable body: %s", putRec.Body.String())

	// The session is revoked server-side by the disable itself.
	_, validateErr := srv.webSessionManager.Validate(context.Background(), sessionToken)
	assert.ErrorIs(t, validateErr, session.ErrSessionRevoked,
		"disabling an account must revoke its live sessions")

	// And the request path rejects the cookie with a uniform 401.
	afterReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	afterReq.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionToken})
	afterRec := httptest.NewRecorder()
	srv.router.ServeHTTP(afterRec, afterReq)
	require.Equal(t, http.StatusUnauthorized, afterRec.Code,
		"disabled account's session must lose API access immediately: %s", afterRec.Body.String())
	assert.Equal(t, "SESSION_REVOKED", errCode(t, afterRec.Body.Bytes()))
}

// TestAccounts_Disabled_MiddlewareRejectsSurvivingSession covers the fail-closed
// half of the control (Issue #3126): even a session that was never revoked — issued
// directly here, as one issued on another controller replica or by a failed
// revocation would be — must be rejected by authenticationMiddleware once the
// account carries Disabled=true.
func TestAccounts_Disabled_MiddlewareRejectsSurvivingSession(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	admin := testAdminPrincipal()

	perms := []string{"steward:list"}
	permRec := putAccount(t, srv, admin, username, AccountUpdateRequest{Permissions: &perms})
	require.Equal(t, http.StatusOK, permRec.Code, "grant body: %s", permRec.Body.String())

	disabled := true
	putRec := putAccount(t, srv, admin, username, AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, putRec.Code, "disable body: %s", putRec.Body.String())

	acct, err := srv.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	require.True(t, acct.Disabled)

	// Issue a session for the disabled account after the disable, bypassing revocation.
	_, token, issueErr := srv.webSessionManager.Issue(context.Background(), acct.ID, "web", acct.TenantID)
	require.NoError(t, issueErr)
	require.NotEmpty(t, token)
	_, validateErr := srv.webSessionManager.Validate(context.Background(), token)
	require.NoError(t, validateErr, "session must be valid at the session layer for this test to mean anything")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: token})
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code,
		"middleware must reject a live session whose account is disabled: %s", rec.Body.String())
	assert.Equal(t, "SESSION_REVOKED", errCode(t, rec.Body.Bytes()))
}

// putAccountRaw calls handleUpdateAccount with an arbitrary (possibly malformed)
// request body, which the typed putAccount helper cannot express.
func putAccountRaw(t *testing.T, server *Server, principal *Principal, username, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/accounts/"+username, strings.NewReader(body))
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username})
	rec := httptest.NewRecorder()
	server.handleUpdateAccount(rec, req)
	return rec
}

// TestAccounts_Update_MalformedJSONRejected covers the PUT INVALID_JSON path:
// an undecodable body is rejected with 400 before any account lookup or write.
func TestAccounts_Update_MalformedJSONRejected(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username:    "badjson-user",
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	for _, body := range []string{
		`{"disabled":`,                  // truncated object
		`{"disabled": "true"}`,          // wrong type for *bool
		`{"permissions": "all"}` + "\n", // wrong type for *[]string
		`not json at all`,
	} {
		putRec := putAccountRaw(t, server, admin, "badjson-user", body)
		require.Equal(t, http.StatusBadRequest, putRec.Code,
			"malformed body %q must be rejected: %s", body, putRec.Body.String())
		assert.Equal(t, "INVALID_JSON", errCode(t, putRec.Body.Bytes()),
			"malformed body %q must report INVALID_JSON", body)
	}

	// The account is untouched by every rejected request, in cache and in the store.
	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), "badjson-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.Equal(t, []string{"steward:list"}, acct.Permissions)
	assert.False(t, acct.Disabled)
}

// TestAccounts_Update_UnknownPermissionRejected covers the PUT INVALID_PERMISSION
// guard: web accounts are RBAC-equivalent to API-key principals, so the wildcard and
// unknown permission IDs must be refused before anything is written to the account.
func TestAccounts_Update_UnknownPermissionRejected(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username:    "update-badperm-user",
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	for _, perms := range [][]string{
		{"*"},
		{"not-a-real:permission"},
		{"steward:list", "*"}, // valid entry must not launder an invalid one
		{"steward:list", "not-a-real:permission"}, // ditto
	} {
		p := perms
		putRec := putAccount(t, server, admin, "update-badperm-user", AccountUpdateRequest{
			Permissions: &p,
		})
		require.Equal(t, http.StatusBadRequest, putRec.Code,
			"permissions %v must be rejected: %s", perms, putRec.Body.String())
		assert.Equal(t, "INVALID_PERMISSION", errCode(t, putRec.Body.Bytes()),
			"permissions %v must report INVALID_PERMISSION", perms)
	}

	// No rejected request may have persisted any part of its permission set.
	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), "update-badperm-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.Equal(t, []string{"steward:list"}, acct.Permissions,
		"a rejected permission update must leave the stored permissions unchanged")
}

// TestAccounts_ResetRetainsDisabled verifies that a POST upsert ("reset this admin")
// of a disabled account does not silently re-enable it. Disable is a containment control,
// so clearing it must require an explicit PUT {"disabled": false} — which is the only path
// that emits an account.enabled audit event.
func TestAccounts_ResetRetainsDisabled(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	rec := postAccount(t, server, admin, AccountRequest{
		Username:    "reset-disabled-user",
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// A registered passkey means the disabled account could log in the moment the
	// gate is cleared — the exact bypass this test pins shut.
	injectCredential(t, server, "reset-disabled-user", []byte("reset-disabled-credential-id"))

	disabled := true
	putRec := putAccount(t, server, admin, "reset-disabled-user", AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, putRec.Code, "disable body: %s", putRec.Body.String())

	// Reset the account (credentials retained — the routine "reset this admin" call).
	resetRec := postAccount(t, server, admin, AccountRequest{Username: "reset-disabled-user"})
	require.Equal(t, http.StatusOK, resetRec.Code, "reset body: %s", resetRec.Body.String())

	var createResp APIResponse
	require.NoError(t, json.Unmarshal(resetRec.Body.Bytes(), &createResp))
	raw, err := json.Marshal(createResp.Data)
	require.NoError(t, err)
	var info AccountInfo
	require.NoError(t, json.Unmarshal(raw, &info))
	assert.True(t, info.Disabled, "reset response must report the account as still disabled")

	// Durable: the disable survives the reset write and a store round-trip.
	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), "reset-disabled-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.True(t, acct.Disabled, "a POST reset must not clear the disable")
	assert.ErrorIs(t, server.VerifyCredential(acct), ErrInvalidWebCredential,
		"the reset account must still be refused at login")

	// Same for a reset that re-provisions to zero authenticators and mints a fresh
	// enrollment link: the link is useless while the account remains disabled.
	resetRec = postAccount(t, server, admin, AccountRequest{
		Username:         "reset-disabled-user",
		ResetCredentials: true,
	})
	require.Equal(t, http.StatusOK, resetRec.Code, "reset body: %s", resetRec.Body.String())

	dropAccountCache(server)
	acct, err = server.getAccount(context.Background(), "reset-disabled-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.True(t, acct.Disabled, "a credential-resetting POST must not clear the disable either")

	// The re-enable path stays available and is the only one that reports an enable.
	enabled := false
	putRec = putAccount(t, server, admin, "reset-disabled-user", AccountUpdateRequest{Disabled: &enabled})
	require.Equal(t, http.StatusOK, putRec.Code, "re-enable body: %s", putRec.Body.String())

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"account.enabled"},
	})
	require.NoError(t, err)
	require.Len(t, entries, 1,
		"exactly one enable — the explicit PUT — may appear in the audit trail; a reset must not enable")
	assert.Equal(t, "reset-disabled-user", entries[0].ResourceID)
}

// TestAccounts_UpdateResetCredentials_MintsFreshLink covers PR #3298 review follow-up
// (Issue #3126 AC #2): PUT .../{username} with reset_credentials:true is the passkey-only
// equivalent of "resets the password" — it re-provisions the account to the
// zero-authenticator state and mints a fresh enrollment link, mirroring
// handleCreateAccount's ResetCredentials path (ADR-021 Amendment 1 Decision 4).
func TestAccounts_UpdateResetCredentials_MintsFreshLink(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "put-reset-creds-user"

	rec := postAccount(t, server, admin, AccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusCreated, rec.Code)
	injectCredential(t, server, username, []byte("put-reset-creds-credential"))

	putRec := putAccount(t, server, admin, username, AccountUpdateRequest{ResetCredentials: true})
	require.Equal(t, http.StatusOK, putRec.Code, "body: %s", putRec.Body.String())

	ur := parseUpdateResponse(t, putRec)
	require.NotEmpty(t, ur.EnrollmentMagicLink,
		"an explicit credential reset via PUT must issue a fresh enrollment link")
	assert.True(t, ur.HasOutstandingEnrollmentLink)

	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.Empty(t, acct.Credentials,
		"residual credentials must be invalidated when a fresh link is issued via PUT")
	assert.True(t, verifyEnrollmentToken(acct, ur.EnrollmentMagicLink),
		"the returned token must be the one stored against the reset account")
}

// TestAccounts_UpdateResetCredentials_IndependentOfPermissions verifies that a single
// PUT can reset credentials and update permissions together, and that a permissions-only
// PUT (reset_credentials omitted) leaves credentials untouched — the "both optional,
// independently" half of Issue #3126 AC #2.
func TestAccounts_UpdateResetCredentials_IndependentOfPermissions(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "put-reset-creds-and-perms-user"

	rec := postAccount(t, server, admin, AccountRequest{
		Username:    username,
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	injectCredential(t, server, username, []byte("put-reset-creds-and-perms-credential"))

	newPerms := []string{"steward:list", "steward:read"}
	putRec := putAccount(t, server, admin, username, AccountUpdateRequest{
		Permissions:      &newPerms,
		ResetCredentials: true,
	})
	require.Equal(t, http.StatusOK, putRec.Code, "body: %s", putRec.Body.String())

	ur := parseUpdateResponse(t, putRec)
	require.NotEmpty(t, ur.EnrollmentMagicLink, "reset_credentials must mint a link even when permissions also change")
	assert.Equal(t, newPerms, ur.Permissions, "permissions must be updated in the same request")

	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.Empty(t, acct.Credentials, "credentials must be cleared")
	assert.Equal(t, newPerms, acct.Permissions, "permissions must be persisted")
}

// TestAccounts_CrossTenantPutResetCredentials_Returns404_And_LeavesCredentialsUnmodified
// extends the [REQUIRED TEST] cross-tenant PUT invariant to the credential-reset field: a
// cross-tenant PUT with reset_credentials:true must not mint a link, clear credentials, or
// leak any token, matching the existing 404-and-unmodified guarantee for permissions/disabled.
func TestAccounts_CrossTenantPutResetCredentials_Returns404_And_LeavesCredentialsUnmodified(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "tenantb-put-reset-creds-user"

	rec := postAccount(t, server, admin, AccountRequest{Username: username, TenantID: "tenant-b"})
	require.Equal(t, http.StatusCreated, rec.Code)
	injectCredential(t, server, username, []byte("tenantb-put-reset-creds-credential"))

	origAcct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, origAcct)
	require.Len(t, origAcct.Credentials, 1)
	origCredID := origAcct.Credentials[0].ID
	origLinkHash := origAcct.EnrollmentLinkHash

	tenantAAdmin := &Principal{
		ID:        "tenant-a-admin-reset-creds",
		TenantID:  "tenant-a",
		Assurance: session.AssuranceStrong,
	}
	putRec := putAccount(t, server, tenantAAdmin, username, AccountUpdateRequest{ResetCredentials: true})
	assert.Equal(t, http.StatusNotFound, putRec.Code,
		"cross-tenant PUT must return 404, not 403 (do not disclose account existence)")
	assert.NotContains(t, putRec.Body.String(), "enrollment_magic_link",
		"a forbidden cross-tenant PUT must not return a token")

	afterAcct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, afterAcct)
	require.Len(t, afterAcct.Credentials, 1, "credentials must be unchanged after a rejected cross-tenant PUT")
	assert.Equal(t, origCredID, afterAcct.Credentials[0].ID)
	assert.Equal(t, origLinkHash, afterAcct.EnrollmentLinkHash, "enrollment link state must be unchanged")
}

// TestAccounts_UpdateResetCredentials_AuditEmitted verifies the update endpoint emits a
// dedicated account.credentials_reset audit action, matching the granularity already
// used for disabled/enabled/updated (Issue #3126).
func TestAccounts_UpdateResetCredentials_AuditEmitted(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "audit-reset-creds-user"

	rec := postAccount(t, server, admin, AccountRequest{Username: username})
	require.Equal(t, http.StatusCreated, rec.Code)

	putRec := putAccount(t, server, admin, username, AccountUpdateRequest{ResetCredentials: true})
	require.Equal(t, http.StatusOK, putRec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"account.credentials_reset"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "audit entry for account.credentials_reset must be written")
	e := entries[0]
	assert.Equal(t, "account", e.ResourceType)
	assert.Equal(t, username, e.ResourceID)
	assert.Equal(t, admin.ID, e.UserID)
	// A credential reset mints a bearer enrollment credential, so the audit records
	// that it was minted and how it is delivered (Issue #2974), matching the POST path.
	require.NotNil(t, e.Details, "credential-reset audit must carry the mint details")
	assert.Equal(t, true, e.Details["enrollment_link_minted"])
	assert.Equal(t, "ui-shown", e.Details["delivery_method"])
}

// TestAccounts_UpdateDisableAndResetCredentials_EmitsBothAudits verifies that a single
// PUT performing both a disable transition and a credential reset audits both operations.
//
// A first-match switch over the two would emit only account.disabled, leaving the
// passkey wipe and the bearer enrollment-link mint with no audit trace at all — an
// audit-evasion path for a privileged actor (CWE-778).
func TestAccounts_UpdateDisableAndResetCredentials_EmitsBothAudits(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "audit-disable-and-reset-user"

	rec := postAccount(t, server, admin, AccountRequest{Username: username})
	require.Equal(t, http.StatusCreated, rec.Code)

	disabled := true
	putRec := putAccount(t, server, admin, username, AccountUpdateRequest{
		Disabled:         &disabled,
		ResetCredentials: true,
	})
	require.Equal(t, http.StatusOK, putRec.Code, "body: %s", putRec.Body.String())

	require.NoError(t, server.auditManager.Flush(context.Background()))
	for _, action := range []string{"account.disabled", "account.credentials_reset"} {
		entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
			Actions: []string{action},
		})
		require.NoError(t, err)
		require.NotEmpty(t, entries,
			"a combined disable + credential reset must emit %s, not just the first-matching action", action)
		assert.Equal(t, username, entries[0].ResourceID)
	}
}

// TestAccounts_UpdateResetCredentials_RevokesLiveSessions verifies that a credential
// reset terminates the account's live browser sessions (CWE-613).
//
// In the passkey-only model (ADR-021 Amendment 1 Decision 4) reset_credentials is the
// "reset the password" operation an admin reaches for on a suspected takeover. Wiping the
// passkeys without cutting the sessions they already minted would leave the attacker's
// cookie usable for the remainder of the absolute session lifetime (12h).
func TestAccounts_UpdateResetCredentials_RevokesLiveSessions(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	admin := testAdminPrincipal()

	perms := []string{"steward:list"}
	permRec := putAccount(t, srv, admin, username, AccountUpdateRequest{Permissions: &perms})
	require.Equal(t, http.StatusOK, permRec.Code, "grant body: %s", permRec.Body.String())

	loginRec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, loginRec.Code, "login body: %s", loginRec.Body.String())
	sessionToken := extractCookie(loginRec, cookieWebSession)
	require.NotEmpty(t, sessionToken)

	// The live session works before the reset.
	beforeReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	beforeReq.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionToken})
	beforeRec := httptest.NewRecorder()
	srv.router.ServeHTTP(beforeRec, beforeReq)
	require.Equal(t, http.StatusOK, beforeRec.Code, "session must work before reset: %s", beforeRec.Body.String())

	putRec := putAccount(t, srv, admin, username, AccountUpdateRequest{ResetCredentials: true})
	require.Equal(t, http.StatusOK, putRec.Code, "reset body: %s", putRec.Body.String())

	_, validateErr := srv.webSessionManager.Validate(context.Background(), sessionToken)
	assert.ErrorIs(t, validateErr, session.ErrSessionRevoked,
		"resetting credentials must revoke the account's live sessions")

	afterReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	afterReq.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionToken})
	afterRec := httptest.NewRecorder()
	srv.router.ServeHTTP(afterRec, afterReq)
	require.Equal(t, http.StatusUnauthorized, afterRec.Code,
		"a reset account's session must lose API access immediately: %s", afterRec.Body.String())
	assert.Equal(t, "SESSION_REVOKED", errCode(t, afterRec.Body.Bytes()))
}

// TestAccounts_CreateResetCredentials_RevokesLiveSessions covers the same containment
// gap on the POST reset path (handleCreateAccount, reset_credentials). Same feature,
// same guarantee — DSD rule 2, no pre-existing conditions.
func TestAccounts_CreateResetCredentials_RevokesLiveSessions(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	admin := testAdminPrincipal()

	perms := []string{"steward:list"}
	permRec := putAccount(t, srv, admin, username, AccountUpdateRequest{Permissions: &perms})
	require.Equal(t, http.StatusOK, permRec.Code, "grant body: %s", permRec.Body.String())

	loginRec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, loginRec.Code, "login body: %s", loginRec.Body.String())
	sessionToken := extractCookie(loginRec, cookieWebSession)
	require.NotEmpty(t, sessionToken)

	beforeReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	beforeReq.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionToken})
	beforeRec := httptest.NewRecorder()
	srv.router.ServeHTTP(beforeRec, beforeReq)
	require.Equal(t, http.StatusOK, beforeRec.Code, "session must work before reset: %s", beforeRec.Body.String())

	postRec := postAccount(t, srv, admin, AccountRequest{Username: username, ResetCredentials: true})
	require.Equal(t, http.StatusOK, postRec.Code, "reset body: %s", postRec.Body.String())

	_, validateErr := srv.webSessionManager.Validate(context.Background(), sessionToken)
	assert.ErrorIs(t, validateErr, session.ErrSessionRevoked,
		"a POST credential reset must revoke the account's live sessions")

	afterReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	afterReq.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionToken})
	afterRec := httptest.NewRecorder()
	srv.router.ServeHTTP(afterRec, afterReq)
	require.Equal(t, http.StatusUnauthorized, afterRec.Code,
		"a reset account's session must lose API access immediately: %s", afterRec.Body.String())
	assert.Equal(t, "SESSION_REVOKED", errCode(t, afterRec.Body.Bytes()))
}

// TestAccounts_UpdateDisableOnly_DoesNotEmitCredentialsReset guards the inverse of the
// combined-audit fix: making the two events independent must not make every disable look
// like a credential reset.
func TestAccounts_UpdateDisableOnly_DoesNotEmitCredentialsReset(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "audit-disable-only-user"

	rec := postAccount(t, server, admin, AccountRequest{Username: username})
	require.Equal(t, http.StatusCreated, rec.Code)

	disabled := true
	putRec := putAccount(t, server, admin, username, AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, putRec.Code, "body: %s", putRec.Body.String())

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"account.credentials_reset"},
	})
	require.NoError(t, err)
	assert.Empty(t, entries, "a disable without reset_credentials must not audit a credential reset")

	updatedEntries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"account.updated"},
	})
	require.NoError(t, err)
	assert.Empty(t, updatedEntries,
		"a disable must not also emit the generic updated action")
}

// ---- Issue #3311: cross-node disabled-status propagation ----

// setupTwoNodeSharedStoreServers creates two independent Server instances that share a
// single durable secret store. The secret-store env vars are set once before constructing
// either server; both servers therefore resolve to the same on-disk path, which is how
// a disable written through one node becomes visible to the other (Issue #3311).
//
// Non-secret storage (RBAC, tenant, audit) is independent per node — only the secret
// store needs to be shared for this test to be meaningful. Each node also runs its own
// independent in-memory web session manager, modelling separate process memory.
func setupTwoNodeSharedStoreServers(t *testing.T) (*Server, *Server) {
	t.Helper()
	// One call to setTestSecretsEnv so both servers share the same on-disk store.
	// Calling it twice would give each server its own TempDir, preventing sharing.
	setTestSecretsEnv(t)

	newNode := func() *Server {
		cfg := config.DefaultConfig()
		cfg.ExternalURL = "https://localhost:8080"
		cfg.Certificate.EnableCertManagement = false
		logger := logging.NewNoopLogger()

		storageManager := pkgtesting.SetupTestStorage(t)
		rbacManager := rbac.NewManagerWithStorage(
			storageManager.GetAuditStore(),
			storageManager.GetClientTenantStore(),
			storageManager.GetRBACStore(),
		)
		err := rbacManager.Initialize(context.Background())
		require.NoError(t, err)
		t.Cleanup(func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = rbacManager.Close(closeCtx)
		})

		tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
		tenantManager := tenant.NewManager(tenantStore, rbacManager)
		controllerSvc := service.NewControllerService(logger)
		configSvc := service.NewConfigurationServiceV2(logger, storageManager, controllerSvc)
		rbacSvc := service.NewRBACService(rbacManager)

		auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
		require.NoError(t, err)
		t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

		srv, err := New(
			cfg, logger, controllerSvc, configSvc,
			nil, rbacSvc, nil, tenantManager, rbacManager,
			nil, nil, nil, "", nil, auditMgr, nil, nil, nil,
		)
		require.NoError(t, err)
		t.Cleanup(func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Close(closeCtx)
		})

		// Each node runs its own independent in-memory web session manager.
		// Sessions are NOT shared — only the secret store is. This models separate
		// controller processes where each issues its own sessions but reads disabled
		// status from the shared durable store.
		webCfg := session.Config{
			IdleTimeout:     60 * time.Minute,
			AbsoluteTimeout: 12 * time.Hour,
			GraceWindow:     30 * time.Second,
		}
		sessStore := session.NewMemStore(webCfg, time.Now)
		t.Cleanup(sessStore.Close)
		srv.SetWebSessionManager(session.NewManager(webCfg, sessStore, time.Now))

		return srv
	}

	return newNode(), newNode()
}

// TestAccounts_CrossNode_DisabledStatusPropagates is the [REQUIRED TEST] for Issue #3311:
// two real Server instances share one durable secret store. Disable through node A, then
// assert node B's authenticationMiddleware rejects on its very next request — with no
// restart and no explicit cache-drop or warm-up step.
//
// Node B's accounts map holds a stale Disabled=false entry (injected via cacheAccount,
// bypassing the SOPS store so node B's in-process secret cache is never warmed). When the
// fix calls loadAccountFromStore on the cache hit, the SOPS store has no cached copy for
// node B and reads fresh from disk — picking up the Disabled=true written by node A.
func TestAccounts_CrossNode_DisabledStatusPropagates(t *testing.T) {
	nodeA, nodeB := setupTwoNodeSharedStoreServers(t)
	admin := testAdminPrincipal()
	const username = "cross-node-disable-user"

	// Step 1: Create the account through node A (writes to the shared secret store and
	// caches on node A; node B has no knowledge of the account yet).
	rec := postAccount(t, nodeA, admin, AccountRequest{
		Username:    username,
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "create body: %s", rec.Body.String())

	// Step 2: Obtain the account record from node A's store and inject a stale copy into
	// node B's in-memory accounts map via cacheAccount. Using cacheAccount directly
	// (rather than nodeB.getAccount) ensures node B's SOPS-provider cache is NOT warmed —
	// only the server-level accounts map gets the stale Disabled=false entry. This models
	// a replica that previously served the account but whose per-provider cache has since
	// expired (or never covered this particular key). The bug was that the old code returned
	// that stale map entry without ever touching the store; the fix re-checks the store on
	// every cache hit, and because node B's SOPS cache is cold, it reads fresh from disk.
	acctFromA, err := nodeA.loadAccountFromStore(context.Background(), username, "")
	require.NoError(t, err)
	require.NotNil(t, acctFromA, "node A must be able to load the account from the shared store")
	require.False(t, acctFromA.Disabled, "account must not be disabled before the disable operation")
	nodeB.cacheAccount(acctFromA) // inject stale Disabled=false into nodeB.accounts only

	// Step 3: Disable the account through node A, writing Disabled=true to the shared store.
	// Node A's cache and the store are updated; node B's accounts map still holds the
	// stale Disabled=false pointer, and node B's SOPS cache has no entry for this secret.
	disabled := true
	putRec := putAccount(t, nodeA, admin, username, AccountUpdateRequest{Disabled: &disabled})
	require.Equal(t, http.StatusOK, putRec.Code, "disable body: %s", putRec.Body.String())

	// Step 4: Mint a session on node B for the account. Node B's session manager is
	// independent of node A's — as it would be for separate controller processes.
	// The session is valid at the session layer; only the account status has changed.
	_, sessionToken, issueErr := nodeB.webSessionManager.Issue(
		context.Background(), acctFromA.ID, "web", acctFromA.TenantID,
	)
	require.NoError(t, issueErr)
	require.NotEmpty(t, sessionToken)

	// Step 5: Drive a real HTTP request through node B's router using the session cookie.
	// Node B's accounts map has the stale Disabled=false entry from step 2.
	// The fix makes getAccountByID call loadAccountFromStore on every cache hit;
	// node B's SOPS cache is cold, so it reads Disabled=true from disk and the
	// authenticationMiddleware rejects this first request with SESSION_REVOKED.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: sessionToken})
	routerRec := httptest.NewRecorder()
	nodeB.router.ServeHTTP(routerRec, req)
	require.Equal(t, http.StatusUnauthorized, routerRec.Code,
		"node B must reject the session of the account disabled on node A: %s", routerRec.Body.String())
	assert.Equal(t, "SESSION_REVOKED", errCode(t, routerRec.Body.Bytes()),
		"rejection must be SESSION_REVOKED — account is disabled and the store re-check identified it")
}

// cachedAccount returns the in-memory cache entry for username, or nil.
func cachedAccount(server *Server, username string) *account {
	server.mu.RLock()
	defer server.mu.RUnlock()
	return server.accounts[username]
}

// TestAccounts_Get_CacheHitPropagatesStoreError covers the error path the
// Issue #3311 re-verify introduced in getAccount: before the fix a cache hit returned
// immediately, so a failing store could not affect it. Now every cache hit queries the
// durable store, and a transient failure there must surface as an error rather than
// silently returning a possibly-disabled cached account.
func TestAccounts_Get_CacheHitPropagatesStoreError(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "cachehit-storeerr-user"

	rec := postAccount(t, server, admin, AccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	// Confirm the cache hit is real; otherwise this would exercise the cache-miss path.
	require.NotNil(t, cachedAccount(server, username),
		"account must be cached after creation so the cache-hit branch is exercised")

	listErr := errors.New("injected ListSecrets failure")
	server.secretStore = &errListSecretStore{SecretStore: server.secretStore, listErr: listErr}

	acct, err := server.getAccount(context.Background(), username)
	require.Error(t, err, "a store failure during the cache-hit re-verify must not be swallowed")
	assert.ErrorIs(t, err, listErr, "the underlying store error must be wrapped, not replaced")
	assert.Nil(t, acct, "no account may be returned when the durable re-verify failed")
}

// TestAccounts_GetAccountByID_CacheHitPropagatesStoreError covers the equivalent
// error path in getAccountByID — the authentication-middleware hot path. A store
// failure during the Issue #3311 re-verify must fail closed (error, no account) instead
// of returning the stale cached record.
func TestAccounts_GetAccountByID_CacheHitPropagatesStoreError(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "cachehit-byid-storeerr-user"

	rec := postAccount(t, server, admin, AccountRequest{Username: username, TenantID: "tenant-a"})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	cached := cachedAccount(server, username)
	require.NotNil(t, cached, "account must be cached so the by-ID cache-hit branch is exercised")
	require.NotEmpty(t, cached.ID)

	listErr := errors.New("injected ListSecrets failure")
	server.secretStore = &errListSecretStore{SecretStore: server.secretStore, listErr: listErr}

	acct, err := server.getAccountByID(context.Background(), cached.ID)
	require.Error(t, err, "a store failure during the by-ID cache-hit re-verify must not be swallowed")
	assert.ErrorIs(t, err, listErr, "the underlying store error must be wrapped, not replaced")
	assert.Nil(t, acct, "no account may be returned when the durable re-verify failed")
}

// TestAccounts_GetAccountByID_StaleCacheEntryDoesNotResolveToRecreatedAccount is the
// identity guard for the Issue #3311 re-verify: the cache is keyed by username while this
// lookup is by principal ID, so a delete-and-recreate of the same username leaves a stale
// entry whose ID belongs to a principal that no longer exists. Re-loading by username would
// otherwise return the NEW account's record — handing the orphaned session the recreated
// account's permissions and tenant scope (root scope here). The lookup must report the
// old principal as not found and drop the stale entry.
func TestAccounts_GetAccountByID_StaleCacheEntryDoesNotResolveToRecreatedAccount(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()
	const username = "recreated-user"

	rec := postAccount(t, server, admin, AccountRequest{
		Username:    username,
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	original := cachedAccount(server, username)
	require.NotNil(t, original)
	originalID := original.ID
	require.NotEmpty(t, originalID)

	// Delete, then recreate the same username as a root-scoped account. The recreate
	// mints a fresh ID (uuid.New), so the store record no longer matches originalID.
	require.Equal(t, http.StatusOK, deleteAccount(t, server, admin, username).Code)
	recreated := postAccount(t, server, admin, AccountRequest{
		Username:  username,
		RootScope: true,
	})
	require.Equal(t, http.StatusCreated, recreated.Code, "body: %s", recreated.Body.String())

	newAcct := cachedAccount(server, username)
	require.NotNil(t, newAcct)
	require.NotEqual(t, originalID, newAcct.ID, "recreate must mint a fresh principal ID")
	require.True(t, newAcct.RootScope, "recreated account must be root-scoped for this test to be meaningful")

	// Model a replica that still holds the pre-delete entry under the same username key.
	server.cacheAccount(original)

	acct, err := server.getAccountByID(context.Background(), originalID)
	require.NoError(t, err)
	assert.Nil(t, acct,
		"a principal ID that no longer exists must resolve to no account, never to the recreated account")

	// No stale entry may survive the lookup: the username key now holds the record
	// read from the store, not the deleted principal.
	remaining := cachedAccount(server, username)
	require.NotNil(t, remaining)
	assert.NotEqual(t, originalID, remaining.ID,
		"the stale cache entry must not survive the identity mismatch")

	// The recreated account is still resolvable by its own (new) ID.
	byNewID, err := server.getAccountByID(context.Background(), newAcct.ID)
	require.NoError(t, err)
	require.NotNil(t, byNewID, "the recreated account must still resolve by its own principal ID")
	assert.Equal(t, newAcct.ID, byNewID.ID)
	assert.True(t, byNewID.RootScope)
}

// listSecretsCall records one ListSecrets round-trip: the filter the caller asked
// for and the tenants the backend actually returned records for.
type listSecretsCall struct {
	filter        *secretsif.SecretFilter
	resultTenants []string
}

// listSecretsCapture is a secretsif.SecretStore wrapper that records each ListSecrets
// call and its results so tests can assert tenant-scoped dispatch — and the tenant
// footprint of what the backend materialised — without depending on any concrete
// provider implementation. It embeds the interface, so it is a real SecretStore
// delegating to the real store, not a mock.
type listSecretsCapture struct {
	secretsif.SecretStore
	mu    sync.Mutex
	calls []listSecretsCall
}

func (c *listSecretsCapture) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	metas, err := c.SecretStore.ListSecrets(ctx, filter)
	call := listSecretsCall{
		filter: &secretsif.SecretFilter{
			TenantID: filter.TenantID,
			Tags:     append([]string(nil), filter.Tags...),
			Metadata: filter.Metadata,
		},
	}
	for _, m := range metas {
		call.resultTenants = append(call.resultTenants, m.TenantID)
	}
	c.mu.Lock()
	c.calls = append(c.calls, call)
	c.mu.Unlock()
	return metas, err
}

// snapshot returns a copy of the recorded calls.
func (c *listSecretsCapture) snapshot() []listSecretsCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]listSecretsCall, len(c.calls))
	copy(out, c.calls)
	return out
}

// TestGetAccountByID_DecryptScopedToTenant is the [REQUIRED TEST] from Issue #3347 AC:
// resolving one web account must not decrypt secrets from other tenants.
// It populates the store with accounts across two tenants and asserts that
// getAccountByID on a cache hit calls ListSecrets scoped to the account's tenant
// (TenantID set), bounding what the backend returns before any decryption occurs.
// The backend honours filter.TenantID per #3438, so a scoped call = bounded decrypt.
func TestGetAccountByID_DecryptScopedToTenant(t *testing.T) {
	server := setupTestServer(t)
	admin := testAdminPrincipal()

	const tenantA = "msp-a"
	const tenantB = "msp-b"

	// Populate store: 3 accounts in tenantA, 4 in tenantB.
	for _, username := range []string{"scope-a1", "scope-a2", "scope-a3"} {
		rec := postAccount(t, server, admin, AccountRequest{Username: username, TenantID: tenantA})
		require.Equal(t, http.StatusCreated, rec.Code, "create %s: %s", username, rec.Body.String())
	}
	for _, username := range []string{"scope-b1", "scope-b2", "scope-b3", "scope-b4"} {
		rec := postAccount(t, server, admin, AccountRequest{Username: username, TenantID: tenantB})
		require.Equal(t, http.StatusCreated, rec.Code, "create %s: %s", username, rec.Body.String())
	}

	// Retrieve the cached entry to get the principal ID for the lookup target.
	server.mu.RLock()
	target := server.accounts["scope-a1"]
	server.mu.RUnlock()
	require.NotNil(t, target, "scope-a1 must be cached after creation")
	targetID := target.ID

	// Wrap the secret store at the secretsif.SecretStore interface level to capture
	// the filters used by each ListSecrets call — no concrete provider import needed.
	capture := &listSecretsCapture{SecretStore: server.secretStore}
	server.secretStore = capture
	t.Cleanup(func() { server.secretStore = capture.SecretStore })

	// getAccountByID takes the cache-hit path: cached entry exists, so it calls
	// loadAccountFromStore(ctx, cached.Username, accountStorageTenant(cached.TenantID))
	// which issues one ListSecrets scoped to tenantA.
	acct, err := server.getAccountByID(context.Background(), targetID)
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.Equal(t, tenantA, acct.TenantID)

	calls := capture.snapshot()

	require.GreaterOrEqual(t, len(calls), 1, "cache-hit path must trigger at least one ListSecrets call")
	first := calls[0]
	assert.Equal(t, tenantA, first.filter.TenantID,
		"first ListSecrets call must be scoped to tenantA, not left unscoped across all tenants")
	assert.Contains(t, first.filter.Tags, "account",
		"ListSecrets call must carry the web-account type tag to further limit the query")

	// Every call made while resolving a tenantA principal must be tenant-scoped.
	// An unscoped call is what makes the backend walk (and decrypt) other tenants'
	// records, even though the caller's metadata filter discards them afterwards.
	for i, call := range calls {
		assert.Equal(t, tenantA, call.filter.TenantID,
			"ListSecrets call %d was issued unscoped while resolving a tenantA principal", i)
	}

	// Establish the premise the assertions above rely on: that filter.TenantID actually
	// bounds what the backend materialises (Issue #3438). Without this, "we passed a
	// tenant filter" would prove nothing about decrypt scope. Compare a tenantA-scoped
	// listing against an unscoped one over the same corpus.
	base := capture.SecretStore
	scoped, err := base.ListSecrets(context.Background(), &secretsif.SecretFilter{
		TenantID: tenantA,
		Tags:     []string{"account"},
		Metadata: map[string]string{secretsif.MetadataKeySecretType: accountSecretType},
	})
	require.NoError(t, err)
	unscoped, err := base.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Tags:     []string{"account"},
		Metadata: map[string]string{secretsif.MetadataKeySecretType: accountSecretType},
	})
	require.NoError(t, err)

	for _, m := range scoped {
		assert.Equal(t, tenantA, m.TenantID,
			"tenant-scoped listing returned a record for tenant %q; filter.TenantID does not bound the backend",
			m.TenantID)
	}
	assert.Len(t, scoped, 3, "tenantA has 3 web accounts; a scoped listing must reach only those")
	assert.Len(t, unscoped, 7,
		"an unscoped listing reaches all 7 accounts across both tenants — this is the "+
			"cross-tenant decrypt surface that scoping the lookup avoids")
}

// TestAccounts_Delete_CascadesRevokesBindingsAndDeletes verifies that handleDeleteAccount
// implements the offboarding cascade (Issue #3581): it revokes all bound certificates
// via certManager and then deletes the account in one operation.
//
// This replaces the prior 409-refusal behavior. The certificate is revoked during the
// delete — an operator no longer needs to revoke bindings manually before deleting.
func TestAccounts_Delete_CascadesRevokesBindingsAndDeletes(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "offboard-me")
	serial := provisionTestClientCert(t, certMgr, "offboard-me-laptop")

	bindRec := bindCertReq(t, server, strongPrincipal(), "offboard-me", BindCertRequest{
		Serial: serial,
		Label:  "offboarding laptop",
	})
	require.Equal(t, http.StatusCreated, bindRec.Code, "bind: %s", bindRec.Body.String())
	revokedBefore, err := certMgr.IsRevoked(serial)
	require.NoError(t, err)
	assert.False(t, revokedBefore, "cert must not be revoked before delete")

	// Delete cascades: revokes the cert and then deletes the account in one step.
	delRec := deleteAccount(t, server, strongPrincipal(), "offboard-me")
	require.Equal(t, http.StatusOK, delRec.Code,
		"offboarding cascade must return 200: %s", delRec.Body.String())

	// Certificate must be revoked as part of the cascade.
	revokedAfter, err := certMgr.IsRevoked(serial)
	require.NoError(t, err)
	assert.True(t, revokedAfter,
		"delete must revoke every bound certificate via certManager")

	// Account must be gone from the store.
	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), "offboard-me")
	require.NoError(t, err)
	assert.Nil(t, acct, "account must be deleted from the store after offboarding")
}

// setupOffboardingServer creates a server with a real cert manager and both CLI + web
// session managers wired to a shared durable store — for offboarding cascade tests.
// Returns the server, cert manager, CLI session manager, web session manager, and store.
func setupOffboardingServer(t *testing.T) (*Server, *cert.Manager, session.Manager, session.Manager, *session.MemStore) {
	t.Helper()
	srv, certMgr := setupCertBindingServer(t)

	cliCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "web",
	}
	store := session.NewMemStore(cliCfg, time.Now)
	t.Cleanup(store.Close)
	cliMgr := session.NewManager(cliCfg, store, time.Now)
	webMgr := session.NewManager(webCfg, store, time.Now)
	srv.SetSessionManager(cliMgr)
	srv.SetWebSessionManager(webMgr)

	return srv, certMgr, cliMgr, webMgr, store
}

// TestAccounts_Offboarding_RevokesAllCertsAndSessions is the [REQUIRED TEST] for
// Issue #3581: full offboarding cascade revokes every bound certificate and every live
// session (web + CLI, including a cross-node-simulated session).
func TestAccounts_Offboarding_RevokesAllCertsAndSessions(t *testing.T) {
	srv, certMgr, cliMgr, webMgr, store := setupOffboardingServer(t)
	ctx := context.Background()

	createTestAccount(t, srv, "cascade-user")

	// Load the account to get its principal ID.
	acct, err := srv.getAccount(ctx, "cascade-user")
	require.NoError(t, err)
	require.NotNil(t, acct)
	principalID := acct.ID

	// Provision and bind two real client certificates.
	serial1 := provisionTestClientCert(t, certMgr, "cascade-laptop-1")
	serial2 := provisionTestClientCert(t, certMgr, "cascade-laptop-2")
	rec := bindCertReq(t, srv, strongPrincipal(), "cascade-user", BindCertRequest{Serial: serial1, Label: "laptop 1"})
	require.Equal(t, http.StatusCreated, rec.Code, "bind cert 1: %s", rec.Body.String())
	rec = bindCertReq(t, srv, strongPrincipal(), "cascade-user", BindCertRequest{Serial: serial2, Label: "laptop 2"})
	require.Equal(t, http.StatusCreated, rec.Code, "bind cert 2: %s", rec.Body.String())

	// Issue a CLI session and a web session on "this node".
	_, _, err = cliMgr.Issue(ctx, principalID, "cli-ctrl", "")
	require.NoError(t, err)
	_, _, err = webMgr.Issue(ctx, principalID, "web-ctrl", "")
	require.NoError(t, err)

	// Simulate a "cross-node" session: a second CLI manager over the same store
	// mimics a session issued on a different controller node.
	crossNodeCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	crossNodeMgr := session.NewManager(crossNodeCfg, store, time.Now)
	_, _, err = crossNodeMgr.Issue(ctx, principalID, "cross-node-ctrl", "")
	require.NoError(t, err)

	// Delete triggers the offboarding cascade.
	delRec := deleteAccount(t, srv, strongPrincipal(), "cascade-user")
	require.Equal(t, http.StatusOK, delRec.Code, "offboarding cascade must succeed: %s", delRec.Body.String())

	// All bound certificates must be revoked.
	revoked1, err := certMgr.IsRevoked(serial1)
	require.NoError(t, err)
	assert.True(t, revoked1, "first bound cert must be revoked by cascade")
	revoked2, err := certMgr.IsRevoked(serial2)
	require.NoError(t, err)
	assert.True(t, revoked2, "second bound cert must be revoked by cascade")

	// All CLI sessions (including cross-node) must be revoked.
	cliSessions, listErr := cliMgr.List(ctx)
	require.NoError(t, listErr)
	for _, s := range cliSessions {
		if s != nil {
			assert.NotEqual(t, principalID, s.PrincipalID,
				"CLI session for principal must be revoked by cascade (cross-node included)")
		}
	}

	// All web sessions must be revoked.
	webSessions, listErr := webMgr.List(ctx)
	require.NoError(t, listErr)
	for _, s := range webSessions {
		if s != nil {
			assert.NotEqual(t, principalID, s.PrincipalID,
				"web session for principal must be revoked by cascade")
		}
	}

	// Account must be deleted from the store.
	dropAccountCache(srv)
	gone, err := srv.getAccount(ctx, "cascade-user")
	require.NoError(t, err)
	assert.Nil(t, gone, "account must be deleted from the store after offboarding")

	// account.offboarded audit event must be emitted with revocation counts.
	require.NoError(t, srv.auditManager.Flush(ctx))
	offboardedEntries, err := srv.auditManager.QueryEntries(ctx, &business.AuditFilter{
		Actions: []string{"account.offboarded"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, offboardedEntries, "account.offboarded audit event must be emitted")
	offboardedEntry := offboardedEntries[0]
	assert.Equal(t, "account.offboarded", offboardedEntry.Action)
	assert.Equal(t, "cascade-user", offboardedEntry.ResourceID)
	certsRevokedVal, hasCerts := offboardedEntry.Details["certs_revoked"]
	assert.True(t, hasCerts, "account.offboarded must include certs_revoked count")
	assert.EqualValues(t, 2, certsRevokedVal, "certs_revoked must be 2")

	// account.deleted audit event must also be emitted.
	deletedEntries, err := srv.auditManager.QueryEntries(ctx, &business.AuditFilter{
		Actions: []string{"account.deleted"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, deletedEntries, "account.deleted audit event must be emitted")
}

// failingRevocationStore wraps a real RevocationStore and forces Revoke to
// fail, simulating a transient revocation-store outage. It is a real
// certinterfaces.RevocationStore implementation — no mock framework — matching
// failingListAllStore's convention below. Issue #3852 removed Manager.Revoke's
// former "serial must be present in the local FileStore" check (that check
// made revocation silently fail off the issuing node in a cluster — the exact
// bug Issue #3761's fix agent escalated), so tests that need a genuine
// revocation failure now inject a failing store instead of an unknown serial.
type failingRevocationStore struct {
	certinterfaces.RevocationStore
	failErr error
}

func (s *failingRevocationStore) Revoke(_ context.Context, _ certinterfaces.RevocationEntry) error {
	return s.failErr
}

// newFailingCertManager returns a cert.Manager whose RevocationStore always
// fails Revoke, for tests exercising the cascade's revocation-failure path.
func newFailingCertManager(t *testing.T) *cert.Manager {
	t.Helper()
	baseRevStore, err := cert.NewFileRevocationStore(t.TempDir())
	require.NoError(t, err)
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365},
		RevocationStore: &failingRevocationStore{
			RevocationStore: baseRevStore,
			failErr:         errors.New("revocation store temporarily unavailable"),
		},
	})
	require.NoError(t, err)
	return mgr
}

// TestAccounts_Offboarding_PartialCertFailureLeavesDisabledAndUndeleted is the [REQUIRED TEST]
// for Issue #3581: a failure during certificate revocation leaves the account in the
// more-restrictive state (disabled, not deleted) so that a retry is possible.
//
// The scenario: certManager's RevocationStore is swapped for one that always fails Revoke
// (failingRevocationStore above), simulating a transient revocation-store outage. The
// cascade disables the account (step 1) but fails at step 2 (cert revocation), returning
// 500 without proceeding to the delete step.
func TestAccounts_Offboarding_PartialCertFailureLeavesDisabledAndUndeleted(t *testing.T) {
	srv, _ := setupCertBindingServer(t)
	ctx := context.Background()

	createTestAccount(t, srv, "partial-fail-user")

	// Inject a cert manager whose RevocationStore always fails Revoke (real
	// implementation, injected failure — see failingRevocationStore above),
	// simulating a transient revocation-store outage.
	srv.SetCertManager(newFailingCertManager(t))

	// Bind a well-formed serial; the injected store above is what makes the
	// revocation attempt fail, not an unknown/malformed serial.
	srv.mu.Lock()
	acctPtr := srv.accounts["partial-fail-user"]
	require.NotNil(t, acctPtr, "account must be in cache after creation")
	acctCopy := *acctPtr
	acctCopy.CertBindings = []CertBinding{
		{Serial: "SOMESERIAL001", Fingerprint: "sha256:fake", Label: "injected"},
	}
	srv.accounts["partial-fail-user"] = &acctCopy
	srv.mu.Unlock()
	// Persist the injected binding so the handler reads it from the store.
	require.NoError(t, srv.persistAccount(ctx, &acctCopy, "test"))

	// Offboarding cascade: step 1 (disable) succeeds, step 2 (cert revoke) fails
	// because the injected RevocationStore always errors.
	delRec := deleteAccount(t, srv, strongPrincipal(), "partial-fail-user")
	require.Equal(t, http.StatusInternalServerError, delRec.Code,
		"partial cert revocation failure must return 500: %s", delRec.Body.String())
	assert.Contains(t, delRec.Body.String(), "CERT_REVOKE_FAILED",
		"response must indicate which step failed")

	// Account must be DISABLED (step 1 completed before the failure).
	dropAccountCache(srv)
	surviving, err := srv.getAccount(ctx, "partial-fail-user")
	require.NoError(t, err)
	require.NotNil(t, surviving, "account must still exist in the store (not deleted)")
	assert.True(t, surviving.Disabled,
		"account must be disabled — the cascade disables before attempting revocations")

	// The account record must still exist in the durable store.
	metas, err := srv.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags:     []string{"account"},
		Metadata: map[string]string{secretsif.MetadataKeySecretType: accountSecretType, "username": "partial-fail-user"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, metas, "account record must remain in the store for retry")
}

// failingListAllStore wraps a real MemStore and forces ListAll to return an error.
// It is a real Store implementation — no mock framework — used to verify that
// RevokeAllForPrincipal failure aborts the offboarding cascade before delete.
type failingListAllStore struct {
	*session.MemStore
	failErr error
}

func (s *failingListAllStore) ListAll(_ context.Context) ([]*session.Session, error) {
	return nil, s.failErr
}

// TestAccounts_Offboarding_SessionRevocationFailureLeavesDisabledAndUndeleted is the
// [REQUIRED TEST] for Issue #3581 security fix: when session revocation fails (e.g. a
// transient store outage), the cascade must abort before deleting the account record.
// Deleting the account without revoking its sessions would cause surviving CLI Bearer
// tokens to resolve to implicitAdmin=true (the middleware's fail-open for unknown accounts).
func TestAccounts_Offboarding_SessionRevocationFailureLeavesDisabledAndUndeleted(t *testing.T) {
	srv, _ := setupCertBindingServer(t)
	ctx := context.Background()

	// Inject a session manager backed by a store that fails ListAll.
	// RevokeAllForPrincipal calls store.ListAll, so it returns (0, err) immediately.
	baseCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	baseStore := session.NewMemStore(baseCfg, time.Now)
	t.Cleanup(baseStore.Close)
	failStore := &failingListAllStore{MemStore: baseStore, failErr: errors.New("store temporarily unavailable")}
	cliMgr := session.NewManager(baseCfg, failStore, time.Now)
	srv.SetSessionManager(cliMgr)
	// No webSessionManager — web step returns (0, nil) when mgr is nil, so the CLI
	// failure is what triggers the abort, which is what we are testing.

	createTestAccount(t, srv, "session-fail-user")

	// Offboarding: step 1 (disable) succeeds, step 2 (no cert bindings) succeeds,
	// step 3 (CLI session revocation) fails → cascade aborts with 500.
	delRec := deleteAccount(t, srv, strongPrincipal(), "session-fail-user")
	require.Equal(t, http.StatusInternalServerError, delRec.Code,
		"session revocation failure must return 500: %s", delRec.Body.String())
	assert.Contains(t, delRec.Body.String(), "SESSION_REVOKE_FAILED",
		"response must identify the failing step")

	// Account must be DISABLED (step 1 persisted before the failure).
	dropAccountCache(srv)
	surviving, err := srv.getAccount(ctx, "session-fail-user")
	require.NoError(t, err)
	require.NotNil(t, surviving, "account must still exist in the store (not deleted)")
	assert.True(t, surviving.Disabled,
		"account must be disabled — the cascade disables before attempting revocations")
}
