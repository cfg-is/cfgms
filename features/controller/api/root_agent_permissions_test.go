// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6225: the permission set of a flagged root-scope agent account (ADR-021
// Amendment 11). The principals here are built by the real accountSessionScope,
// bearerSessionPrincipal and sessionPrincipalRefresh, against accounts stored in the
// real account store.

package api

import (
	"context"
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/session"
)

// rootAgentWant is the allowlist the story names, spelled out here independently of
// rootAgentPermissions so a changed set fails.
var rootAgentWant = []string{
	"webauthn:assert-presence", "webauthn:elevate",
	"tenant:create", "tenant:list", "tenant:read",
	"account:create",
	"steward:list", "steward:read", "steward:read-scripts", "steward:execute-scripts",
	"operator-payload:sign",
	"workflow:publish", "workflow:read", "workflow:list",
	"module:approve", "module:list-approvals",
}

// storeRootAccount creates a root-scope account through the real create path and sets
// the software-authenticator flag directly on the stored record when flagged.
func storeRootAccount(t *testing.T, server *Server, username string, flagged bool) *account {
	t.Helper()
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: username, RootScope: true})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	ctx := context.Background()
	acct, err := server.loadAccountFromStore(ctx, username, "")
	require.NoError(t, err)
	require.NotNil(t, acct)
	acct.AllowSoftwareAuthenticator = flagged
	require.NoError(t, server.persistAccount(ctx, acct, "test"))
	dropAccountCache(server)
	got, err := server.getAccount(ctx, username)
	require.NoError(t, err)
	require.NotNil(t, got)
	return got
}

// sessionPrincipalFor builds the principal a Bearer session of acct carries.
func sessionPrincipalFor(server *Server, acct *account) *Principal {
	scope := server.accountSessionScope(context.Background(), acct)
	sess := &session.Session{PrincipalID: acct.ID, Assurance: session.AssuranceStrong}
	return bearerSessionPrincipal(sess, acct, scope)
}

func TestRootAgentPermissions_ExactSet(t *testing.T) {
	got := make([]string, 0, len(rootAgentPermissions))
	for id, allowed := range rootAgentPermissions {
		require.True(t, allowed, "an entry in the set must be true: %s", id)
		got = append(got, id)
	}
	want := append([]string(nil), rootAgentWant...)
	sort.Strings(got)
	sort.Strings(want)
	assert.Len(t, want, 16)
	assert.Equal(t, want, got, "the root agent allowlist is exactly the 16 permissions the story names")

	// The signing roster and the publish check answer true for any root-scope account;
	// they agree with the route check only while both stay members.
	assert.True(t, rootAgentPermitted("operator-payload:sign"))
	assert.True(t, rootAgentPermitted("workflow:publish"))
	assert.True(t, accountHoldsOperatorPayloadSigning(&account{RootScope: true}))
	assert.True(t, setupTestServer(t).accountHoldsWorkflowPublish(context.Background(), &account{RootScope: true}, "msp-a"))
	assert.Equal(t, OperatorPayloadSignGrant, "operator-payload:sign")
	assert.Equal(t, workflow.PublishPermission, "workflow:publish")

	// Only the two presence/step-up permissions are outside knownPermissions.
	for _, id := range rootAgentWant {
		_, inAssurance := permissionAssurance[id]
		if knownPermissions[id] {
			continue
		}
		assert.True(t, id == "webauthn:assert-presence" || id == "webauthn:elevate",
			"%s is outside knownPermissions and is not one of the two presence permissions", id)
		assert.True(t, inAssurance, "%s is outside knownPermissions and must be in permissionAssurance", id)
	}
}

func TestRootAgentPermissions_DefaultDeny(t *testing.T) {
	server := setupTestServer(t)
	agent := storeRootAccount(t, server, "agent-root", true)
	p := sessionPrincipalFor(server, agent)

	assert.True(t, p.RootAgent)
	assert.False(t, p.ImplicitAdmin, "a flagged root account does not receive ImplicitAdmin")
	assert.NotNil(t, p.Permissions)
	assert.Empty(t, p.Permissions)
	// Scope is untouched: the agent crosses tenants exactly like a human root account.
	assert.True(t, p.GlobalScope)
	assert.True(t, p.AccountBound)
	assert.True(t, p.RootScoped)

	allowed := map[string]bool{}
	for _, id := range rootAgentWant {
		allowed[id] = true
		assert.True(t, server.hasPermission(p, id), "allowlisted: %s", id)
	}
	universe := map[string]bool{}
	for id := range knownPermissions {
		universe[id] = true
	}
	for id := range permissionAssurance {
		universe[id] = true
	}
	require.Greater(t, len(universe), len(allowed))
	for id := range universe {
		if allowed[id] {
			continue
		}
		assert.False(t, server.hasPermission(p, id), "default deny: %s", id)
	}
	assert.False(t, server.hasPermission(p, "not:a-permission"))
	assert.False(t, server.hasPermission(p, "*"))
	assert.False(t, server.hasPermission(p, "account:set-software-authenticator"), "a flagged account cannot clear its own flag")

	// The same principal through the web-cookie constructor.
	webSess := &session.Session{PrincipalID: agent.ID, Assurance: session.AssuranceStrong}
	web := webSessionPrincipal(webSess, agent, server.accountSessionScope(context.Background(), agent), true)
	assert.True(t, web.RootAgent)
	assert.False(t, web.ImplicitAdmin)
	assert.False(t, server.hasPermission(web, "rbac:create-role"))
	assert.True(t, server.hasPermission(web, "module:approve"))
}

func TestRootAgentPermissions_HumanRootKeepsImplicitAdmin(t *testing.T) {
	server := setupTestServer(t)
	human := storeRootAccount(t, server, "human-root", false)
	p := sessionPrincipalFor(server, human)

	assert.False(t, p.RootAgent)
	assert.True(t, p.ImplicitAdmin)
	for id := range knownPermissions {
		assert.True(t, server.hasPermission(p, id), id)
	}
	for id := range permissionAssurance {
		assert.True(t, server.hasPermission(p, id), id)
	}
}

func TestRootAgentPermissions_TenantAccountIsNeverRootAgent(t *testing.T) {
	// The flag on a tenant-scoped account does not make it a root agent.
	acct := &account{ID: "t-1", Username: "tenant-user", TenantID: "msp-a", AllowSoftwareAuthenticator: true, Permissions: []string{"steward:list"}}
	server := setupTestServer(t)
	p := sessionPrincipalFor(server, acct)
	assert.False(t, p.RootAgent)
	assert.False(t, p.ImplicitAdmin)
	assert.True(t, server.hasPermission(p, "steward:list"))
	assert.False(t, server.hasPermission(p, "module:approve"))
}

func TestRootAgentPermissions_RefreshMatchesSessionScopeAndFollowsTheFlag(t *testing.T) {
	ctx := context.Background()
	server := setupTestServer(t)
	acct := storeRootAccount(t, server, "agent-refresh", true)
	orig := sessionPrincipalFor(server, acct)

	setFlag := func(v bool) {
		stored, err := server.loadAccountFromStore(ctx, "agent-refresh", "")
		require.NoError(t, err)
		stored.AllowSoftwareAuthenticator = v
		require.NoError(t, server.persistAccount(ctx, stored, "test"))
		dropAccountCache(server)
	}

	// Flagged: the refresh yields the same answer as accountSessionScope.
	refreshed, ok := server.sessionPrincipalRefresh(orig, false)(ctx)
	require.True(t, ok)
	assert.True(t, refreshed.RootAgent)
	assert.False(t, refreshed.ImplicitAdmin, "the refresh must not restore ImplicitAdmin")
	assert.NotNil(t, refreshed.Permissions)
	assert.Empty(t, refreshed.Permissions)
	assert.Equal(t, orig.GlobalScope, refreshed.GlobalScope)
	assert.Equal(t, orig.AccountBound, refreshed.AccountBound)

	// A principal built while the account was a human root account loses ImplicitAdmin
	// on the next refresh once the flag is set.
	setFlag(false)
	humanAcct, err := server.getAccountByID(ctx, acct.ID)
	require.NoError(t, err)
	humanPrincipal := sessionPrincipalFor(server, humanAcct)
	require.True(t, humanPrincipal.ImplicitAdmin)
	setFlag(true)
	stripped, ok := server.sessionPrincipalRefresh(humanPrincipal, false)(ctx)
	require.True(t, ok)
	assert.False(t, stripped.ImplicitAdmin)
	assert.True(t, stripped.RootAgent)
	assert.False(t, server.hasPermission(stripped, "rbac:create-role"))

	// Clearing the flag restores ImplicitAdmin on the next request.
	setFlag(false)
	restored, ok := server.sessionPrincipalRefresh(stripped, false)(ctx)
	require.True(t, ok)
	assert.True(t, restored.ImplicitAdmin)
	assert.False(t, restored.RootAgent)
	assert.True(t, server.hasPermission(restored, "rbac:create-role"))
}

func TestRootAgentPermissions_RestrictionIgnoresTheSettingAndTheCredential(t *testing.T) {
	// The limit keys on the flag alone: a human credential on the account, or the
	// root-agent setting being off, does not return the account to full admin.
	server := setupTestServer(t)
	server.SetSoftwareAuthenticatorRootAgentAccounts(false)
	acct := storeRootAccount(t, server, "agent-limited", true)
	acct.Credentials = append(acct.Credentials, WebAuthnCredential{ID: []byte("human"), AAGUID: make([]byte, 16)})
	acct.CertBindings = []CertBinding{{Serial: "1"}}
	p := sessionPrincipalFor(server, acct)
	assert.True(t, p.RootAgent)
	assert.False(t, p.ImplicitAdmin)
}

func TestRootAgentPermissions_CredentialRequestApproveGate(t *testing.T) {
	// A RootAgent principal is RootScoped, GlobalScope and Strong, so only the explicit
	// check keeps it out of the root-scope-marker gate.
	agent := &Principal{RootAgent: true, RootScoped: true, GlobalScope: true, AccountBound: true, Assurance: session.AssuranceStrong}
	assert.False(t, principalHasCertifiedRootScope(agent))
	assert.False(t, principalMayAdministerController(agent))

	human := &Principal{ImplicitAdmin: true, RootScoped: true, GlobalScope: true, AccountBound: true, Assurance: session.AssuranceStrong}
	assert.True(t, principalHasCertifiedRootScope(human))
	assert.True(t, principalMayAdministerController(human))
}
