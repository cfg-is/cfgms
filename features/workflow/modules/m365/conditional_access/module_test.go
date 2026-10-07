// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package conditional_access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// tenantIsolationAuthProvider is a real auth.Provider implementation (not a
// mock) that maps each CFGMS tenant to the M365 tenant its credentials belong
// to and records every tenant a token was requested for, so a test can prove
// which credentials a module invocation selected (Issue #4421).
type tenantIsolationAuthProvider struct {
	m365ByCFGMS map[string]string
	mu          sync.Mutex
	requested   []string
}

func (p *tenantIsolationAuthProvider) GetAccessToken(_ context.Context, tenantID string) (*auth.AccessToken, error) {
	p.mu.Lock()
	p.requested = append(p.requested, tenantID)
	p.mu.Unlock()
	m365, ok := p.m365ByCFGMS[tenantID]
	if !ok {
		return nil, fmt.Errorf("no credentials for tenant")
	}
	return &auth.AccessToken{Token: "tok-" + m365, TokenType: "Bearer", TenantID: m365, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (p *tenantIsolationAuthProvider) GetDelegatedAccessToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *tenantIsolationAuthProvider) RefreshToken(_ context.Context, _ string) (*auth.AccessToken, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *tenantIsolationAuthProvider) RefreshDelegatedToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *tenantIsolationAuthProvider) IsTokenValid(_ *auth.AccessToken) bool { return true }
func (p *tenantIsolationAuthProvider) ValidatePermissions(_ context.Context, _ *auth.AccessToken, _ []string) error {
	return nil
}

func (p *tenantIsolationAuthProvider) requestedTenants() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.requested...)
}

// unreachableGraphClient embeds a nil graph.Client: any Graph call made by a
// refused invocation panics, failing the test loudly.
type unreachableGraphClient struct{ graph.Client }

func newIsolationModule() (*conditionalAccessModule, *tenantIsolationAuthProvider) {
	ap := &tenantIsolationAuthProvider{m365ByCFGMS: map[string]string{
		"cfgms-tenant-a": "m365-tenant-a",
		"cfgms-tenant-b": "m365-tenant-b",
	}}
	return &conditionalAccessModule{authProvider: ap, graphClient: unreachableGraphClient{}}, ap
}

func isolationCtx(cfgmsTenant string) context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, cfgmsTenant)
}

func isolationConfig(tenant string) *ConditionalAccessConfig {
	return &ConditionalAccessConfig{DisplayName: "Policy", State: "enabled", TenantID: tenant, Conditions: ConditionalAccessConditions{Users: ConditionalAccessUsers{IncludeUsers: []string{"All"}}, Applications: ConditionalAccessApplications{IncludeApplications: []string{"All"}}}, GrantControls: ConditionalAccessGrantControls{Operator: "OR", BuiltInControls: []string{"mfa"}}}
}

// TestSet_RefusesConfigTenantOfAnotherM365Tenant proves a workflow whose
// execution context is CFGMS tenant A cannot select tenant B's credentials by
// naming B's M365 tenant in tenant_id.
func TestSet_RefusesConfigTenantOfAnotherM365Tenant(t *testing.T) {
	m, ap := newIsolationModule()

	err := m.Set(isolationCtx("cfgms-tenant-a"), "m365-tenant-b:obj-1", isolationConfig("m365-tenant-b"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "m365-tenant-b", "refusal must name the rejected tenant_id")
	assert.Equal(t, []string{"cfgms-tenant-a"}, ap.requestedTenants(),
		"only the execution tenant's credentials may be requested; none for tenant B")
}

// TestGet_RefusesResourceTenantOfAnotherM365Tenant proves the tenant segment of
// a resource ID never selects credentials.
func TestGet_RefusesResourceTenantOfAnotherM365Tenant(t *testing.T) {
	m, ap := newIsolationModule()

	_, err := m.Get(isolationCtx("cfgms-tenant-a"), "m365-tenant-b:obj-1")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "m365-tenant-b", "refusal must name the rejected tenant")
	assert.Equal(t, []string{"cfgms-tenant-a"}, ap.requestedTenants(),
		"only the execution tenant's credentials may be requested; none for tenant B")
}

// TestSetGet_FailClosedWithoutExecutionTenant proves a missing tenant context
// is refused before any token is requested.
func TestSetGet_FailClosedWithoutExecutionTenant(t *testing.T) {
	m, ap := newIsolationModule()

	err := m.Set(context.Background(), "m365-tenant-a:obj-1", isolationConfig("m365-tenant-a"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant context required")

	_, err = m.Get(context.Background(), "m365-tenant-a:obj-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant context required")

	assert.Empty(t, ap.requestedTenants(), "no token may be requested without an execution tenant")
}

// newGraphBackedModule wires the module to a real graph.HTTPClient pointed at
// an httptest.Server standing in for Microsoft Graph.
func newGraphBackedModule(t *testing.T, mux *http.ServeMux) (*conditionalAccessModule, *tenantIsolationAuthProvider) {
	t.Helper()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	ap := &tenantIsolationAuthProvider{m365ByCFGMS: map[string]string{"cfgms-tenant-a": "m365-tenant-a"}}
	return &conditionalAccessModule{
		authProvider: ap,
		graphClient:  graph.NewHTTPClient(graph.WithBaseURL(server.URL)),
	}, ap
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func TestSet_CreatesPolicyWhenAbsent(t *testing.T) {
	var created map[string]interface{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /identity/conditionalAccess/policies/pol-1", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": map[string]string{"code": "Request_ResourceNotFound", "message": "not found"}})
	})
	mux.HandleFunc("POST /identity/conditionalAccess/policies", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&created))
		writeJSON(w, http.StatusCreated, map[string]string{"id": "pol-1"})
	})
	m, ap := newGraphBackedModule(t, mux)

	err := m.Set(isolationCtx("cfgms-tenant-a"), "m365-tenant-a:pol-1", isolationConfig("m365-tenant-a"))

	require.NoError(t, err)
	assert.Equal(t, "Policy", created["displayName"])
	assert.Equal(t, "enabled", created["state"])
	assert.Equal(t, []string{"cfgms-tenant-a"}, ap.requestedTenants())
}

func TestSet_UpdatesExistingPolicy(t *testing.T) {
	var updated map[string]interface{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /identity/conditionalAccess/policies/pol-1", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"id": "pol-1", "displayName": "Old", "state": "disabled"})
	})
	mux.HandleFunc("PATCH /identity/conditionalAccess/policies/pol-1", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&updated))
		w.WriteHeader(http.StatusNoContent)
	})
	m, _ := newGraphBackedModule(t, mux)

	err := m.Set(isolationCtx("cfgms-tenant-a"), "m365-tenant-a:pol-1", isolationConfig("m365-tenant-a"))

	require.NoError(t, err)
	assert.Equal(t, "Policy", updated["displayName"])
}

func TestSet_ErrorPaths(t *testing.T) {
	t.Run("invalid configuration", func(t *testing.T) {
		m, ap := newIsolationModule()
		cfg := isolationConfig("m365-tenant-a")
		cfg.DisplayName = ""
		err := m.Set(isolationCtx("cfgms-tenant-a"), "m365-tenant-a:pol-1", cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid configuration")
		assert.Empty(t, ap.requestedTenants())
	})
	t.Run("authentication failure", func(t *testing.T) {
		m, _ := newIsolationModule()
		err := m.Set(isolationCtx("cfgms-tenant-unknown"), "m365-tenant-a:pol-1", isolationConfig("m365-tenant-a"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to authenticate")
	})
	t.Run("graph lookup failure other than not found", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /identity/conditionalAccess/policies/pol-1", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": map[string]string{"code": "Forbidden", "message": "denied"}})
		})
		m, _ := newGraphBackedModule(t, mux)
		err := m.Set(isolationCtx("cfgms-tenant-a"), "m365-tenant-a:pol-1", isolationConfig("m365-tenant-a"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to check if policy exists")
	})
}

func TestGet_ReturnsPolicyForMatchingTenant(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /identity/conditionalAccess/policies/pol-1", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id": "pol-1", "displayName": "Require MFA", "state": "enabled",
			"conditions":    map[string]interface{}{"users": map[string]interface{}{"includeUsers": []string{"All"}}},
			"grantControls": map[string]interface{}{"operator": "OR", "builtInControls": []string{"mfa"}},
		})
	})
	m, _ := newGraphBackedModule(t, mux)

	state, err := m.Get(isolationCtx("cfgms-tenant-a"), "m365-tenant-a:pol-1")

	require.NoError(t, err)
	cfg, ok := state.(*ConditionalAccessConfig)
	require.True(t, ok)
	assert.Equal(t, "Require MFA", cfg.DisplayName)
	assert.Equal(t, "m365-tenant-a", cfg.TenantID)
	assert.Equal(t, []string{"mfa"}, cfg.GrantControls.BuiltInControls)
}

func TestGet_ErrorPaths(t *testing.T) {
	m, _ := newIsolationModule()
	_, err := m.Get(isolationCtx("cfgms-tenant-a"), "no-colon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid resource ID format")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /identity/conditionalAccess/policies/missing", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": map[string]string{"code": "Request_ResourceNotFound", "message": "nf"}})
	})
	gm, _ := newGraphBackedModule(t, mux)
	_, err = gm.Get(isolationCtx("cfgms-tenant-a"), "m365-tenant-a:missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get policy from Graph API")
}

func TestConfigValidate_RejectsIncompleteConfigs(t *testing.T) {
	cases := map[string]func(c *ConditionalAccessConfig){
		"missing display name": func(c *ConditionalAccessConfig) { c.DisplayName = "" },
		"invalid state":        func(c *ConditionalAccessConfig) { c.State = "bogus" },
		"missing tenant":       func(c *ConditionalAccessConfig) { c.TenantID = "" },
		"no users":             func(c *ConditionalAccessConfig) { c.Conditions.Users = ConditionalAccessUsers{} },
		"no applications":      func(c *ConditionalAccessConfig) { c.Conditions.Applications = ConditionalAccessApplications{} },
		"no grant control":     func(c *ConditionalAccessConfig) { c.GrantControls.BuiltInControls = nil },
		"bad operator":         func(c *ConditionalAccessConfig) { c.GrantControls.Operator = "XOR" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := isolationConfig("m365-tenant-a")
			mutate(cfg)
			assert.Error(t, cfg.Validate())
		})
	}
	assert.NoError(t, isolationConfig("m365-tenant-a").Validate())
}

func TestParseCAResourceID(t *testing.T) {
	tenant, policy, err := parseCAResourceID("t1:p1")
	require.NoError(t, err)
	assert.Equal(t, "t1", tenant)
	assert.Equal(t, "p1", policy)
	_, _, err = parseCAResourceID("bare")
	assert.Error(t, err)
}
