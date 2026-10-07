// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPartnerTenant   = "11111111-1111-1111-1111-111111111111"
	testCustomerTenantA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	testCustomerTenantB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	testDirectTenant    = "dddddddd-dddd-dddd-dddd-dddddddddddd"
)

// keyedCredentialStore is a real, in-memory CredentialStore keyed by the tenant ID
// string, as SecretStoreCredentialStore is. Unlike testCredentialStore it keeps one
// entry per key, so keyspace collisions are observable.
type keyedCredentialStore struct {
	mu      sync.Mutex
	tokens  map[string]*AccessToken
	configs map[string]*OAuth2Config
}

func newKeyedCredentialStore() *keyedCredentialStore {
	return &keyedCredentialStore{tokens: map[string]*AccessToken{}, configs: map[string]*OAuth2Config{}}
}

func (s *keyedCredentialStore) StoreToken(id string, t *AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[id] = t
	return nil
}

func (s *keyedCredentialStore) GetToken(id string) (*AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[id]; ok {
		return t, nil
	}
	return nil, ErrTokenNotFound
}

func (s *keyedCredentialStore) DeleteToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, id)
	return nil
}

func (s *keyedCredentialStore) StoreDelegatedToken(_, _ string, _ *AccessToken) error { return nil }
func (s *keyedCredentialStore) GetDelegatedToken(_, _ string) (*AccessToken, error) {
	return nil, ErrTokenNotFound
}
func (s *keyedCredentialStore) DeleteDelegatedToken(_, _ string) error             { return nil }
func (s *keyedCredentialStore) StoreUserContext(_, _ string, _ *UserContext) error { return nil }
func (s *keyedCredentialStore) GetUserContext(_, _ string) (*UserContext, error) {
	return nil, fmt.Errorf("no user context")
}
func (s *keyedCredentialStore) DeleteUserContext(_, _ string) error { return nil }

func (s *keyedCredentialStore) StoreConfig(id string, c *OAuth2Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs[id] = c
	return nil
}

func (s *keyedCredentialStore) GetConfig(id string) (*OAuth2Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.configs[id]; ok {
		cp := *c
		return &cp, nil
	}
	return nil, fmt.Errorf("no config for %q", id)
}

func (s *keyedCredentialStore) IsAvailable() bool { return true }

// partnerFixture is an httptest.Server standing in for Partner Center, the
// partner's login endpoint and each customer tenant's login endpoint.
type partnerFixture struct {
	t      *testing.T
	server *httptest.Server

	mu sync.Mutex
	// relationships are returned by the delegatedAdminRelationships endpoint.
	relationships []map[string]interface{}
	// tokenTID, if set, overrides the tid claim of Graph tokens (by tenant path).
	tokenTID map[string]string
	// customerTokenRequests counts client-credentials requests per tenant path.
	customerTokenRequests map[string]int
	partnerTokenRequests  int
}

func newPartnerFixture(t *testing.T) *partnerFixture {
	f := &partnerFixture{t: t, tokenTID: map[string]string{}, customerTokenRequests: map[string]int{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *partnerFixture) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/customers/relationships/delegatedAdminRelationships"):
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer partner-center-token") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"totalCount": len(f.relationships),
			"items":      f.relationships,
		})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		tenantPath := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[0]
		if r.FormValue("scope") == partnerCenterScope {
			f.partnerTokenRequests++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "partner-center-token", "token_type": "Bearer",
				"expires_in": 3600, "scope": partnerCenterScope,
			})
			return
		}
		f.customerTokenRequests[tenantPath]++
		tid := tenantPath
		if override, ok := f.tokenTID[tenantPath]; ok {
			tid = override
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": makeTestJWT(tid), "token_type": "Bearer", "expires_in": 3600,
			"scope": "https://graph.microsoft.com/.default",
		})
	default:
		http.NotFound(w, r)
	}
}

func (f *partnerFixture) grant(customerTenantID string, roles ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	unified := make([]map[string]string, 0, len(roles))
	for _, r := range roles {
		unified = append(unified, map[string]string{"roleDefinitionId": "id-" + r, "roleName": r})
	}
	f.relationships = append(f.relationships, map[string]interface{}{
		"id":          "rel-" + customerTenantID,
		"customer":    map[string]string{"tenantId": customerTenantID, "displayName": "Customer " + customerTenantID},
		"details":     map[string]interface{}{"unifiedRoles": unified},
		"status":      "Active",
		"endDateTime": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
}

func (f *partnerFixture) customerRequests(tenant string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.customerTokenRequests[tenant]
}

// delegatedConfig is the stored config of a CFGMS tenant reached through GDAP.
func (f *partnerFixture) delegatedConfig(customerTenantID string, roles ...string) *OAuth2Config {
	return &OAuth2Config{
		ClientID:          "partner-app",
		ClientSecret:      "partner-secret",
		PartnerDelegated:  true,
		PartnerTenantID:   testPartnerTenant,
		CustomerTenantID:  customerTenantID,
		GDAPRequiredRoles: roles,
		AuthorityURL:      f.server.URL + "/" + customerTenantID,
	}
}

func (f *partnerFixture) directConfig(tenantID string) *OAuth2Config {
	return &OAuth2Config{
		ClientID:             "direct-app",
		ClientSecret:         "direct-secret",
		TenantID:             tenantID,
		UseClientCredentials: true,
		AuthorityURL:         f.server.URL + "/" + tenantID,
	}
}

// provider returns an OAuth2Provider over store whose Partner Center endpoints
// point at the fixture.
func (f *partnerFixture) provider(store CredentialStore) *OAuth2Provider {
	p := NewOAuth2Provider(store, nil, nil)
	p.SetHTTPClient(f.server.Client())
	resolver := NewGDAPRelationshipResolver(f.server.Client(), "")
	resolver.gdapClient.baseURL = f.server.URL + "/v1"
	resolver.gdapClient.tokenBaseURL = f.server.URL
	p.SetGDAPResolver(resolver)
	t := f.t
	t.Cleanup(p.Close)
	return p
}

func TestGetAccessToken_DelegatedAndDirectBranches(t *testing.T) {
	f := newPartnerFixture(t)
	f.grant(testCustomerTenantA, "Groups Administrator")

	store := newKeyedCredentialStore()
	require.NoError(t, store.StoreConfig("cfgms-delegated", f.delegatedConfig(testCustomerTenantA, "Groups Administrator")))
	require.NoError(t, store.StoreConfig("cfgms-direct", f.directConfig(testDirectTenant)))
	p := f.provider(store)
	ctx := context.Background()

	t.Run("delegated config mints against the customer tenant", func(t *testing.T) {
		token, err := p.GetAccessToken(ctx, "cfgms-delegated")
		require.NoError(t, err)
		assert.Equal(t, testCustomerTenantA, token.TenantID)
		assert.Equal(t, 1, f.customerRequests(testCustomerTenantA))
		assert.Equal(t, 1, f.partnerTokenRequests, "relationship validation used a Partner Center token")

		// The minted token is the one that is stored, under the CFGMS tenant's key.
		stored, err := store.GetToken("cfgms-delegated")
		require.NoError(t, err)
		assert.Equal(t, testCustomerTenantA, stored.TenantID)
	})

	t.Run("direct config takes the existing path unchanged", func(t *testing.T) {
		token, err := p.GetAccessToken(ctx, "cfgms-direct")
		require.NoError(t, err)
		assert.Equal(t, testDirectTenant, token.TenantID)
		assert.Equal(t, 1, f.customerRequests(testDirectTenant))
		assert.Equal(t, 1, f.partnerTokenRequests, "a direct tenant must not touch Partner Center")
	})

	t.Run("default config cannot select a customer tenant", func(t *testing.T) {
		shared := f.delegatedConfig(testCustomerTenantA)
		dp := NewOAuth2Provider(newKeyedCredentialStore(), shared, nil)
		dp.SetHTTPClient(f.server.Client())
		t.Cleanup(dp.Close)
		cfg, err := dp.getOAuth2Config("cfgms-unconfigured")
		require.NoError(t, err)
		assert.False(t, cfg.PartnerDelegated)
		assert.Empty(t, cfg.CustomerTenantID)
		assert.Empty(t, cfg.PartnerTenantID)
	})

	t.Run("delegated token for another tenant than configured is refused", func(t *testing.T) {
		f.tokenTID[testCustomerTenantB] = "cccccccc-cccc-cccc-cccc-cccccccccccc"
		f.grant(testCustomerTenantB)
		require.NoError(t, store.StoreConfig("cfgms-wrong-tid", f.delegatedConfig(testCustomerTenantB)))
		_, err := p.GetAccessToken(ctx, "cfgms-wrong-tid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TENANT_MISMATCH")
	})

	t.Run("opaque token without a tid claim is accepted", func(t *testing.T) {
		opaque := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "opaque-token", "token_type": "Bearer", "expires_in": 3600,
			})
		}))
		defer opaque.Close()
		f.grant("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
		cfg := f.delegatedConfig("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
		cfg.AuthorityURL = opaque.URL
		require.NoError(t, store.StoreConfig("cfgms-opaque", cfg))
		token, err := p.GetAccessToken(ctx, "cfgms-opaque")
		require.NoError(t, err)
		assert.Equal(t, "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee", token.TenantID)
	})

	t.Run("incomplete delegated config is refused", func(t *testing.T) {
		cfg := f.delegatedConfig(testCustomerTenantA)
		cfg.CustomerTenantID = ""
		require.NoError(t, store.StoreConfig("cfgms-incomplete", cfg))
		_, err := p.GetAccessToken(ctx, "cfgms-incomplete")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DELEGATED_CONFIG_INVALID")
	})
}

func TestDelegatedAccessRefusedOnMissingRole(t *testing.T) {
	f := newPartnerFixture(t)
	f.grant(testCustomerTenantA, "Directory Readers")
	f.grant(testCustomerTenantB, "Groups Administrator", "Global Reader")

	store := newKeyedCredentialStore()
	// Needs two roles; the relationship grants neither.
	require.NoError(t, store.StoreConfig("cfgms-short",
		f.delegatedConfig(testCustomerTenantA, "Groups Administrator", "Global Administrator")))
	require.NoError(t, store.StoreConfig("cfgms-enough",
		f.delegatedConfig(testCustomerTenantB, "Groups Administrator")))
	p := f.provider(store)

	_, err := p.GetAccessToken(context.Background(), "cfgms-short")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Groups Administrator")
	assert.Contains(t, err.Error(), "Global Administrator")
	assert.Contains(t, err.Error(), "lacks required roles")
	assert.Zero(t, f.customerRequests(testCustomerTenantA), "no token request may reach the customer tenant")

	token, err := p.GetAccessToken(context.Background(), "cfgms-enough")
	require.NoError(t, err)
	assert.Equal(t, testCustomerTenantB, token.TenantID)
	assert.Equal(t, 1, f.customerRequests(testCustomerTenantB))
}

func TestDelegatedAccessRefusedWithoutActiveRelationship(t *testing.T) {
	f := newPartnerFixture(t)
	f.grant(testCustomerTenantB)
	// Expired relationship for A.
	f.relationships = append(f.relationships, map[string]interface{}{
		"id": "rel-expired", "customer": map[string]string{"tenantId": testCustomerTenantA},
		"details": map[string]interface{}{}, "status": "Active",
		"endDateTime": time.Now().Add(-time.Hour).Format(time.RFC3339),
	})
	store := newKeyedCredentialStore()
	require.NoError(t, store.StoreConfig("cfgms-expired", f.delegatedConfig(testCustomerTenantA)))
	p := f.provider(store)

	_, err := p.GetAccessToken(context.Background(), "cfgms-expired")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GDAP_ACCESS_REFUSED")
	assert.Zero(t, f.customerRequests(testCustomerTenantA))
}

func TestDelegatedTokenTenantContainment(t *testing.T) {
	f := newPartnerFixture(t)
	// The partner relationship exists only for customer B, reachable only through
	// CFGMS tenant B's config.
	f.grant(testCustomerTenantB)

	store := newKeyedCredentialStore()
	require.NoError(t, store.StoreConfig("cfgms-b", f.delegatedConfig(testCustomerTenantB)))
	// CFGMS tenant A is a direct tenant on its own M365 tenant.
	require.NoError(t, store.StoreConfig("cfgms-a", f.directConfig(testDirectTenant)))
	p := f.provider(store)
	ctx := context.Background()

	// Tenant B legitimately reaches customer B.
	tokenB, err := p.GetAccessToken(ctx, "cfgms-b")
	require.NoError(t, err)
	require.Equal(t, testCustomerTenantB, tokenB.TenantID)
	requestsBefore := f.customerRequests(testCustomerTenantB)

	// Tenant A never gets customer B's tenant.
	tokenA, err := p.GetAccessToken(ctx, "cfgms-a")
	require.NoError(t, err)
	assert.Equal(t, testDirectTenant, tokenA.TenantID)
	assert.NotEqual(t, testCustomerTenantB, tokenA.TenantID)

	// The customer tenant id supplied directly by the caller is the only way a
	// caller could name customer B. It selects nothing: with no config stored under
	// that key there is nothing to authenticate with.
	_, err = p.GetAccessToken(ctx, testCustomerTenantB)
	require.Error(t, err, "a caller-supplied customer tenant id must not select credentials")
	assert.Equal(t, requestsBefore, f.customerRequests(testCustomerTenantB), "no token request for the caller-supplied tenant")

	// A tenant whose own config names customer B but a partner/credentials that
	// have no relationship to it cannot borrow B's relationship: relationships are
	// listed with that tenant's own Partner Center token, and the fixture grants
	// the token only to the partner credentials used here, so the refusal comes from
	// the relationship check, not from B's cached state.
	cfg := f.delegatedConfig(testCustomerTenantA)
	require.NoError(t, store.StoreConfig("cfgms-a2", cfg))
	_, err = p.GetAccessToken(ctx, "cfgms-a2")
	require.Error(t, err, "customer A has no relationship; tenant B's relationship must not satisfy it")
	assert.Zero(t, f.customerRequests(testCustomerTenantA))

	// Persisted Partner Center tokens are scoped per CFGMS tenant.
	_, errA := store.GetToken(partnerCenterTokenKey("cfgms-a"))
	assert.Error(t, errA, "tenant A has no Partner Center token")
	_, errB := store.GetToken(partnerCenterTokenKey("cfgms-b"))
	assert.NoError(t, errB)
}

func TestPartnerCenterTokenKeyIsolation(t *testing.T) {
	f := newPartnerFixture(t)
	f.grant(testCustomerTenantA)

	store := newKeyedCredentialStore()
	cfg := f.delegatedConfig(testCustomerTenantA)
	require.NoError(t, store.StoreConfig("cfgms-a", cfg))
	p := f.provider(store)
	ctx := context.Background()

	t.Run("a stored Partner Center token is never returned by GetAccessToken", func(t *testing.T) {
		// Even stored directly in the Graph slot, it is not served.
		require.NoError(t, store.StoreToken("cfgms-a", &AccessToken{
			Token: "partner-center-token-poison", TokenType: "Bearer",
			ExpiresAt: time.Now().Add(time.Hour), Scope: partnerCenterScope, TenantID: testCustomerTenantA,
		}))
		token, err := p.GetAccessToken(ctx, "cfgms-a")
		require.NoError(t, err)
		assert.NotEqual(t, "partner-center-token-poison", token.Token)
		assert.NotContains(t, token.Scope, "partnercenter")
		assert.Equal(t, testCustomerTenantA, token.TenantID)
	})

	t.Run("storing a Partner Center token does not overwrite the Graph token", func(t *testing.T) {
		graphToken, err := store.GetToken("cfgms-a")
		require.NoError(t, err)
		require.NotContains(t, graphToken.Scope, "partnercenter")

		// Partner Center token acquisition persists under its own key.
		client := NewGDAPClient(f.server.Client(), testPartnerTenant)
		client.tokenBaseURL = f.server.URL
		client.SetCredentialStore(store)
		client.SetClientCredentials("partner-app", "partner-secret")
		client.SetTokenKeyID("cfgms-a")
		pc, err := client.getPartnerCenterToken(ctx)
		require.NoError(t, err)
		assert.Equal(t, partnerCenterScope, pc.Scope)

		after, err := store.GetToken("cfgms-a")
		require.NoError(t, err)
		assert.Equal(t, graphToken.Token, after.Token, "Graph token must be untouched")

		persisted, err := store.GetToken(partnerCenterTokenKey("cfgms-a"))
		require.NoError(t, err)
		assert.Equal(t, partnerCenterScope, persisted.Scope)
		assert.NotEqual(t, "cfgms-a", partnerCenterTokenKey("cfgms-a"))
	})

	t.Run("a direct tenant is not served a Partner Center token either", func(t *testing.T) {
		require.NoError(t, store.StoreConfig("cfgms-direct", f.directConfig(testDirectTenant)))
		require.NoError(t, store.StoreToken("cfgms-direct", &AccessToken{
			Token: "pc-in-graph-slot", TokenType: "Bearer",
			ExpiresAt: time.Now().Add(time.Hour), Scope: partnerCenterScope,
		}))
		token, err := p.GetAccessToken(ctx, "cfgms-direct")
		require.NoError(t, err)
		assert.NotEqual(t, "pc-in-graph-slot", token.Token)
	})
}

func TestGDAPRoleRequirementsKeyedByModuleContract(t *testing.T) {
	r := NewGDAPRelationshipResolver(nil, testPartnerTenant)
	assert.Contains(t, r.GetGDAPRoleRequirements("m365-entra-group", "Set"), "Groups Administrator")
	assert.Contains(t, r.GetGDAPRoleRequirements("m365-entra-group", "Get"), "Global Reader")
	assert.Contains(t, r.GetGDAPRoleRequirements("m365-entra-user", "Set"), "User Administrator")
	assert.Contains(t, r.GetGDAPRoleRequirements("m365-conditional-access", "Set"), "Conditional Access Administrator")
	assert.Contains(t, r.GetGDAPRoleRequirements("m365-intune-policy", "Get"), "Intune Administrator")
	assert.Equal(t, []string{"Global Administrator"}, r.GetGDAPRoleRequirements("m365-unknown", "Set"))
	assert.Equal(t, []string{"Global Administrator"}, r.GetGDAPRoleRequirements("m365-entra-group", "list"),
		"the retired CRUD verbs are not part of the module contract")
}
