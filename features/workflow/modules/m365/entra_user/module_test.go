// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package entra_user

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	stewardprovider "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

// fakeGraphClient is a minimal Microsoft Graph API test double. Embedding the
// graph.Client interface satisfies the (large, third-party-API-shaped)
// interface without implementing every method — only the ones entra_user's
// Set/Get actually call are overridden; any other method panics on a nil
// interface call, which is fine since this module never calls them.
type fakeGraphClient struct {
	graph.Client

	// tokensUsed records every access token string passed to GetUser/CreateUser,
	// so tests can assert which CFGMS tenant's credentials were actually used
	// on the wire.
	tokensUsed []string

	users map[string]*graph.User // keyed by UserPrincipalName

	updates        []*graph.UpdateUserRequest
	creates        []*graph.CreateUserRequest
	licenseCalls   int
	groupAddCalls  int
	groupDelCalls  int
	licenseRemoved int
}

func (f *fakeGraphClient) UpdateUser(_ context.Context, _ *auth.AccessToken, _ string, req *graph.UpdateUserRequest) error {
	f.updates = append(f.updates, req)
	return nil
}

func (f *fakeGraphClient) AssignLicense(_ context.Context, _ *auth.AccessToken, _, _ string, _ []string) error {
	f.licenseCalls++
	return nil
}

func (f *fakeGraphClient) RemoveLicense(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	f.licenseRemoved++
	return nil
}

func (f *fakeGraphClient) AddUserToGroup(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	f.groupAddCalls++
	return nil
}

func (f *fakeGraphClient) RemoveUserFromGroup(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	f.groupDelCalls++
	return nil
}

func newFakeGraphClient() *fakeGraphClient {
	return &fakeGraphClient{users: make(map[string]*graph.User)}
}

func (f *fakeGraphClient) GetUser(_ context.Context, token *auth.AccessToken, upn string) (*graph.User, error) {
	f.tokensUsed = append(f.tokensUsed, token.Token)
	u, ok := f.users[upn]
	if !ok {
		return nil, fmt.Errorf("does not exist")
	}
	return u, nil
}

func (f *fakeGraphClient) CreateUser(_ context.Context, token *auth.AccessToken, req *graph.CreateUserRequest) (*graph.User, error) {
	f.tokensUsed = append(f.tokensUsed, token.Token)
	f.creates = append(f.creates, req)
	u := &graph.User{
		ID:                "id-" + req.UserPrincipalName,
		UserPrincipalName: req.UserPrincipalName,
		DisplayName:       req.DisplayName,
		MailNickname:      req.MailNickname,
		AccountEnabled:    req.AccountEnabled,
	}
	f.users[req.UserPrincipalName] = u
	return u, nil
}

func (f *fakeGraphClient) GetUserLicenses(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.LicenseAssignment, error) {
	return nil, nil
}

func (f *fakeGraphClient) GetUserGroups(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}

// seedTenant stores a real OAuth2Config and a valid, non-expired AccessToken
// for cfgmsTenantID, addressed by the real CFGMS tenant per Issue #4325 (never
// by m365TenantID). GetAccessToken(ctx, cfgmsTenantID) then returns this
// token from the credential store without ever making a network call.
func seedTenant(t *testing.T, credStore auth.CredentialStore, cfgmsTenantID, m365TenantID, tokenValue string) {
	t.Helper()
	require.NoError(t, credStore.StoreConfig(cfgmsTenantID, &auth.OAuth2Config{
		ClientID:             "client-" + cfgmsTenantID,
		TenantID:             m365TenantID,
		UseClientCredentials: true,
	}))
	require.NoError(t, credStore.StoreToken(cfgmsTenantID, &auth.AccessToken{
		Token:     tokenValue,
		TokenType: "Bearer",
		TenantID:  m365TenantID,
		ExpiresAt: time.Now().Add(time.Hour),
	}))
}

func ctxForTenant(cfgmsTenantID string) context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, cfgmsTenantID)
}

func newTestModule(t *testing.T) (*entraUserModule, auth.CredentialStore, *fakeGraphClient) {
	t.Helper()
	sp := &stewardprovider.StewardProvider{}
	store, err := sp.CreateSecretStore(map[string]interface{}{"secrets_dir": filepath.Join(t.TempDir(), "secrets")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	credStore := auth.NewSecretStoreCredentialStore(store)
	authProvider := auth.NewOAuth2Provider(credStore, nil, logging.NewNoopLogger())
	graphClient := newFakeGraphClient()

	mod := New(authProvider, graphClient).(*entraUserModule)
	return mod, credStore, graphClient
}

// [REQUIRED TEST] Issue #4325: a workflow execution owned by tenant A cannot
// read or overwrite tenant B's stored M365 credentials, and cannot act on
// tenant B's M365 tenant.
func TestEntraUserModule_TenantIsolation(t *testing.T) {
	mod, credStore, fakeGraph := newTestModule(t)

	seedTenant(t, credStore, "tenant-a", "m365-org-a", "tok-a")
	seedTenant(t, credStore, "tenant-b", "m365-org-b", "tok-b")

	fakeGraph.users["alice@org-a.example"] = &graph.User{
		ID: "id-alice", UserPrincipalName: "alice@org-a.example", DisplayName: "Alice",
	}
	fakeGraph.users["bob@org-b.example"] = &graph.User{
		ID: "id-bob", UserPrincipalName: "bob@org-b.example", DisplayName: "Bob",
	}

	t.Run("tenant A reading its own M365 tenant succeeds and uses tenant A's token", func(t *testing.T) {
		state, err := mod.Get(ctxForTenant("tenant-a"), "m365-org-a:alice@org-a.example")
		require.NoError(t, err)
		cfg := state.(*EntraUserConfig)
		assert.Equal(t, "alice@org-a.example", cfg.UserPrincipalName)
		assert.Equal(t, "m365-org-a", cfg.TenantID)
		assert.Contains(t, fakeGraph.tokensUsed, "tok-a")
		assert.NotContains(t, fakeGraph.tokensUsed, "tok-b")
	})

	t.Run("tenant A cannot read tenant B's M365 tenant via a forged resource ID", func(t *testing.T) {
		before := len(fakeGraph.tokensUsed)
		_, err := mod.Get(ctxForTenant("tenant-a"), "m365-org-b:bob@org-b.example")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match the M365 tenant configured")
		// The mismatch must be refused before ever reaching Microsoft Graph —
		// tenant A's Get must never present tenant B's UPN to any token.
		assert.Equal(t, before, len(fakeGraph.tokensUsed), "refused request must not call Microsoft Graph")
	})

	t.Run("tenant A cannot overwrite tenant B's stored M365 credentials via Set", func(t *testing.T) {
		originalB, err := credStore.GetToken("tenant-b")
		require.NoError(t, err)

		forged := &EntraUserConfig{
			UserPrincipalName: "mallory@org-b.example",
			DisplayName:       "Mallory",
			MailNickname:      "mallory",
			AccountEnabled:    true,
			TenantID:          "m365-org-b", // claims tenant B's M365 org
		}
		err = mod.Set(ctxForTenant("tenant-a"), "mallory-resource", forged)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match the M365 tenant configured")

		// Tenant B's stored credential must be byte-for-byte unchanged.
		afterB, err := credStore.GetToken("tenant-b")
		require.NoError(t, err)
		assert.Equal(t, originalB.Token, afterB.Token)

		// No user must have been created under tenant B's M365 tenant.
		_, existed := fakeGraph.users["mallory@org-b.example"]
		assert.False(t, existed, "Set must not reach Microsoft Graph on tenant mismatch")
	})

	t.Run("missing execution tenant context is refused, not treated as unrestricted", func(t *testing.T) {
		_, err := mod.Get(context.Background(), "m365-org-a:alice@org-a.example")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenant context required")
	})

	t.Run("tenant B reading its own M365 tenant succeeds independently of tenant A", func(t *testing.T) {
		state, err := mod.Get(ctxForTenant("tenant-b"), "m365-org-b:bob@org-b.example")
		require.NoError(t, err)
		cfg := state.(*EntraUserConfig)
		assert.Equal(t, "bob@org-b.example", cfg.UserPrincipalName)
		assert.Contains(t, fakeGraph.tokensUsed, "tok-b")
	})
}

// TestEntraUserModule_Set_CreatesUser_WithinOwnTenant verifies the
// happy path still works end to end (Validate -> auth -> GetUser(not found)
// -> CreateUser) once the tenant enforcement is in place.
func TestEntraUserModule_Set_CreatesUser_WithinOwnTenant(t *testing.T) {
	mod, credStore, fakeGraph := newTestModule(t)
	seedTenant(t, credStore, "tenant-a", "m365-org-a", "tok-a")

	cfg := &EntraUserConfig{
		UserPrincipalName: "newuser@org-a.example",
		DisplayName:       "New User",
		MailNickname:      "newuser",
		AccountEnabled:    true,
		TenantID:          "m365-org-a",
	}

	err := mod.Set(ctxForTenant("tenant-a"), "newuser-resource", cfg)
	require.NoError(t, err)

	created, ok := fakeGraph.users["newuser@org-a.example"]
	require.True(t, ok, "CreateUser must have been called")
	assert.Equal(t, "New User", created.DisplayName)
}

func seedExistingUser(t *testing.T) (*entraUserModule, *fakeGraphClient) {
	t.Helper()
	mod, credStore, fakeGraph := newTestModule(t)
	seedTenant(t, credStore, "tenant-a", "m365-org-a", "tok-a")
	fakeGraph.users["alice@org-a.example"] = &graph.User{
		ID: "id-alice", UserPrincipalName: "alice@org-a.example", DisplayName: "Alice", AccountEnabled: true,
	}
	return mod, fakeGraph
}

func existingUserConfig() *EntraUserConfig {
	return &EntraUserConfig{
		UserPrincipalName: "alice@org-a.example",
		DisplayName:       "Alice",
		MailNickname:      "alice",
		AccountEnabled:    true,
		TenantID:          "m365-org-a",
	}
}

// [REQUIRED TEST] Issue #5334: a password reset on an existing user must reach Graph.
func TestEntraUserModule_Set_ExistingUser_PasswordReset(t *testing.T) {
	mod, fakeGraph := seedExistingUser(t)
	cfg := existingUserConfig()
	cfg.PasswordProfile = &PasswordProfile{Password: "s3cret-Value!", ForceChangePasswordNextSignIn: true}

	err := mod.Set(ctxForTenant("tenant-a"), "r", cfg)
	require.NoError(t, err)
	require.Len(t, fakeGraph.updates, 1)
	pp := fakeGraph.updates[0].PasswordProfile
	require.NotNil(t, pp)
	assert.Equal(t, "s3cret-Value!", pp.Password)
	assert.True(t, pp.ForceChangePasswordNextSignIn)
}

func TestEntraUserModule_Set_ExistingUser_ForceChangePasswordOnly(t *testing.T) {
	mod, fakeGraph := seedExistingUser(t)
	cfg := existingUserConfig()
	cfg.ForceChangePassword = true

	require.NoError(t, mod.Set(ctxForTenant("tenant-a"), "r", cfg))
	require.Len(t, fakeGraph.updates, 1)
	pp := fakeGraph.updates[0].PasswordProfile
	require.NotNil(t, pp)
	assert.Empty(t, pp.Password)
	assert.True(t, pp.ForceChangePasswordNextSignIn)
}

func TestEntraUserModule_Set_CreateUser_ForceChangePassword(t *testing.T) {
	cfg := existingUserConfig()
	cfg.ForceChangePassword = true
	cfg.PasswordProfile = &PasswordProfile{Password: "pw"}
	pp := cfg.graphPasswordProfile()
	require.NotNil(t, pp)
	assert.True(t, pp.ForceChangePasswordNextSignIn)
	assert.Equal(t, "pw", pp.Password)
}

// [REQUIRED TEST] Issue #5334: managed_fields limits the update.
func TestEntraUserModule_Set_ManagedFieldsSkipsLicensesAndGroups(t *testing.T) {
	for name, managed := range map[string]interface{}{
		"string slice": []string{"display_name"},
		"any slice":    []interface{}{"display_name"},
	} {
		t.Run(name, func(t *testing.T) {
			mod, fakeGraph := seedExistingUser(t)
			cfg := existingUserConfig()
			cfg.Licenses = []LicenseAssignment{{SkuID: "sku-1"}}
			cfg.Groups = []string{"g1"}
			cfg.PasswordProfile = &PasswordProfile{Password: "pw"}

			state := &mapState{m: cfg.AsMap()}
			state.m["managed_fields"] = managed
			state.m["licenses"] = cfg.Licenses
			state.m["groups"] = cfg.Groups

			require.NoError(t, mod.Set(ctxForTenant("tenant-a"), "r", state))
			assert.Zero(t, fakeGraph.licenseCalls+fakeGraph.licenseRemoved)
			assert.Zero(t, fakeGraph.groupAddCalls+fakeGraph.groupDelCalls)
			assert.Empty(t, fakeGraph.updates, "password_profile is not managed, nothing to update")
		})
	}
}

func TestEntraUserModule_Set_ManagedFieldsInvalidType(t *testing.T) {
	mod, _ := seedExistingUser(t)
	state := &mapState{m: existingUserConfig().AsMap()}
	state.m["managed_fields"] = "display_name"
	require.Error(t, mod.Set(ctxForTenant("tenant-a"), "r", state))
}

func TestEntraUserModule_Set_UnsetManagedFieldsSyncsGroups(t *testing.T) {
	mod, fakeGraph := seedExistingUser(t)
	cfg := existingUserConfig()
	cfg.Groups = []string{"g1"}
	require.NoError(t, mod.Set(ctxForTenant("tenant-a"), "r", cfg))
	assert.Equal(t, 1, fakeGraph.groupAddCalls)
}

// mapState overrides AsMap so tests can supply raw config-map shapes (such as
// managed_fields as []interface{}) the way a decoded workflow step does.
type mapState struct {
	EntraUserConfig
	m map[string]interface{}
}

func (s *mapState) AsMap() map[string]interface{} { return s.m }

// containsString walks v through nested maps and slices looking for needle.
func containsString(v interface{}, needle string) bool {
	switch x := v.(type) {
	case string:
		return x == needle
	case map[string]interface{}:
		for k, e := range x {
			if k == needle || containsString(e, needle) {
				return true
			}
		}
	case []interface{}:
		for _, e := range x {
			if containsString(e, needle) {
				return true
			}
		}
	case []string:
		for _, e := range x {
			if e == needle {
				return true
			}
		}
	}
	return false
}

// [REQUIRED TEST] Issue #5620: AsMap feeds workflow variables and must never carry the password.
func TestEntraUserConfig_AsMap_OmitsPassword(t *testing.T) {
	const pw = "known-S3cret-Value!"
	cfg := existingUserConfig()
	cfg.PasswordProfile = &PasswordProfile{Password: pw, ForceChangePasswordNextSignIn: true}

	m := cfg.AsMap()
	assert.False(t, containsString(m, pw), "password must not appear anywhere in AsMap output")

	pp, ok := m["password_profile"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, pp["force_change_password_next_signin"])
}

// [REQUIRED TEST] Issue #5620: typed config reaches Graph without AsMap.
func TestEntraUserModule_Set_TypedConfig_SendsPassword(t *testing.T) {
	mod, credStore, fakeGraph := newTestModule(t)
	seedTenant(t, credStore, "tenant-a", "m365-org-a", "tok-a")

	cfg := &EntraUserConfig{
		UserPrincipalName: "typed@org-a.example",
		DisplayName:       "Typed",
		MailNickname:      "typed",
		AccountEnabled:    true,
		TenantID:          "m365-org-a",
		PasswordProfile:   &PasswordProfile{Password: "typed-Pw-1!", ForceChangePasswordNextSignIn: true},
	}
	require.NoError(t, mod.Set(ctxForTenant("tenant-a"), "r", cfg))
	require.Len(t, fakeGraph.creates, 1)
	require.NotNil(t, fakeGraph.creates[0].PasswordProfile)
	assert.Equal(t, "typed-Pw-1!", fakeGraph.creates[0].PasswordProfile.Password)
	assert.True(t, fakeGraph.creates[0].PasswordProfile.ForceChangePasswordNextSignIn)
}

// [REQUIRED TEST] Issue #5620: the raw step map (non-typed ConfigState) still supplies the password.
func TestEntraUserModule_Set_MapConfig_SendsPassword(t *testing.T) {
	mod, credStore, fakeGraph := newTestModule(t)
	seedTenant(t, credStore, "tenant-a", "m365-org-a", "tok-a")

	state := &mapState{m: map[string]interface{}{
		"user_principal_name": "mapped@org-a.example",
		"display_name":        "Mapped",
		"mail_nickname":       "mapped",
		"account_enabled":     true,
		"tenant_id":           "m365-org-a",
		"password_profile": map[string]interface{}{
			"password":                          "mapped-Pw-1!",
			"force_change_password_next_signin": true,
		},
	}}
	require.NoError(t, mod.Set(ctxForTenant("tenant-a"), "r", state))
	require.Len(t, fakeGraph.creates, 1)
	require.NotNil(t, fakeGraph.creates[0].PasswordProfile)
	assert.Equal(t, "mapped-Pw-1!", fakeGraph.creates[0].PasswordProfile.Password)
}
