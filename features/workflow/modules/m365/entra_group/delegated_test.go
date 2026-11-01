// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package entra_group

import (
	"context"
	"encoding/base64"
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

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

const (
	delegatedPartnerTenant  = "11111111-1111-1111-1111-111111111111"
	delegatedCustomerTenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	directM365Tenant        = "dddddddd-dddd-dddd-dddd-dddddddddddd"
)

// memCredentialStore is a real in-memory auth.CredentialStore. Only the methods
// OAuth2Provider.GetAccessToken uses are implemented; the embedded nil interface
// would panic on any other call, which would itself be a finding.
type memCredentialStore struct {
	auth.CredentialStore
	mu      sync.Mutex
	tokens  map[string]*auth.AccessToken
	configs map[string]*auth.OAuth2Config
}

func (s *memCredentialStore) StoreToken(id string, t *auth.AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[id] = t
	return nil
}

func (s *memCredentialStore) GetToken(id string) (*auth.AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[id]; ok {
		return t, nil
	}
	return nil, auth.ErrTokenNotFound
}

func (s *memCredentialStore) StoreConfig(id string, c *auth.OAuth2Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs[id] = c
	return nil
}

func (s *memCredentialStore) GetConfig(id string) (*auth.OAuth2Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.configs[id]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("no config")
}

func jwtForTenant(tid string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(fmt.Sprintf(`{"tid":%q}`, tid))) + ".sig"
}

func tenantOfBearer(r *http.Request) string {
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		TID string `json:"tid"`
	}
	_ = json.Unmarshal(raw, &claims)
	return claims.TID
}

// TestEntraGroupAgainstDelegatedTenant runs the unmodified entra_group module
// against one auth.OAuth2Provider as a direct CFGMS tenant and as a delegated one.
func TestEntraGroupAgainstDelegatedTenant(t *testing.T) {
	var mu sync.Mutex
	groupCreatedIn := map[string]string{} // CFGMS-visible group name -> tenant of the bearer token

	// One server plays Partner Center, every login endpoint and Microsoft Graph.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			require.NoError(t, r.ParseForm())
			if strings.Contains(r.FormValue("scope"), "partnercenter") {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "partner-center-token", "token_type": "Bearer", "expires_in": 3600,
					"scope": r.FormValue("scope"),
				})
				return
			}
			tenant := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[0]
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": jwtForTenant(tenant), "token_type": "Bearer", "expires_in": 3600,
			})
		case strings.HasSuffix(r.URL.Path, "/customers/relationships/delegatedAdminRelationships"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []map[string]interface{}{{
				"id":       "rel-1",
				"customer": map[string]string{"tenantId": delegatedCustomerTenant},
				"details": map[string]interface{}{"unifiedRoles": []map[string]string{
					{"roleDefinitionId": "r1", "roleName": "Groups Administrator"},
				}},
				"status":      "active",
				"endDateTime": time.Now().Add(time.Hour).Format(time.RFC3339),
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/graph/groups":
			var req graph.CreateGroupRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			mu.Lock()
			groupCreatedIn[req.DisplayName] = tenantOfBearer(r)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "group-1", "displayName": req.DisplayName})
		case r.Method == http.MethodGet && r.URL.Path == "/graph/groups":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"Request_ResourceNotFound","message":"not found"}}`))
		}
	}))
	defer srv.Close()

	store := &memCredentialStore{tokens: map[string]*auth.AccessToken{}, configs: map[string]*auth.OAuth2Config{}}
	require.NoError(t, store.StoreConfig("cfgms-direct", &auth.OAuth2Config{
		ClientID: "direct-app", ClientSecret: "direct-secret", TenantID: directM365Tenant,
		UseClientCredentials: true, AuthorityURL: srv.URL + "/" + directM365Tenant,
	}))
	require.NoError(t, store.StoreConfig("cfgms-delegated", &auth.OAuth2Config{
		ClientID: "partner-app", ClientSecret: "partner-secret",
		PartnerDelegated: true, PartnerTenantID: delegatedPartnerTenant, CustomerTenantID: delegatedCustomerTenant,
		GDAPRequiredRoles: []string{"Groups Administrator"},
		AuthorityURL:      srv.URL + "/" + delegatedCustomerTenant,
	}))

	provider := auth.NewOAuth2Provider(store, nil, nil)
	provider.SetHTTPClient(srv.Client())
	defer provider.Close()
	resolver := auth.NewGDAPRelationshipResolver(srv.Client(), "")
	resolver.SetEndpoints(srv.URL+"/v1", srv.URL)
	provider.SetGDAPResolver(resolver)

	mod := &entraGroupModule{
		authProvider: provider,
		graphClient:  graph.NewHTTPClient(graph.WithBaseURL(srv.URL+"/graph"), graph.WithHTTPClient(srv.Client())),
	}

	for _, tc := range []struct {
		name, cfgmsTenant, m365Tenant, group string
	}{
		{"direct", "cfgms-direct", directM365Tenant, "direct-group"},
		{"delegated", "cfgms-delegated", delegatedCustomerTenant, "delegated-group"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), ctxkeys.TenantID, tc.cfgmsTenant)
			err := mod.Set(ctx, tc.m365Tenant+":"+tc.group, &EntraGroupConfig{
				DisplayName:     tc.group,
				MailNickname:    tc.group,
				TenantID:        tc.m365Tenant,
				SecurityEnabled: true,
				GroupType:       "Security",
			})
			require.NoError(t, err)
			mu.Lock()
			defer mu.Unlock()
			assert.Equal(t, tc.m365Tenant, groupCreatedIn[tc.group],
				"the group must be created with a token for the %s M365 tenant", tc.name)
		})
	}
}
