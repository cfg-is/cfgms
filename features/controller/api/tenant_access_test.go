// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// TestCallerTenantFilter guards Issue #4665: "" (no tenant filter) only for an
// explicit root caller or a context marked system-internal; a tenant caller gets
// its own tenant; anything else gets the noTenantScope sentinel, which matches no
// tenant.
func TestCallerTenantFilter(t *testing.T) {
	bg := context.Background()
	cases := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"root scope", withCallerTenant(bg, ""), ""},
		{"tenant scope", withCallerTenant(bg, "tenant-a"), "tenant-a"},
		{"tenant ID only", context.WithValue(bg, ctxkeys.TenantID, "tenant-a"), "tenant-a"},
		{"system-internal", ctxkeys.WithSystem(bg), ""},
		{"no caller", bg, noTenantScope},
		{"empty tenant ID", context.WithValue(bg, ctxkeys.TenantID, ""), noTenantScope},
		{"unset scope", context.WithValue(bg, ctxkeys.TenantScopeKey, ctxkeys.TenantScope{}), noTenantScope},
		{"empty-path tenant scope", context.WithValue(bg, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("")), noTenantScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, callerTenantFilter(tc.ctx))
		})
	}
}

// listCaller is a caller shape the list-site table runs every handler under.
type listCaller struct {
	name string
	ctx  func(context.Context) context.Context
	// want is the set of tenants whose records the caller sees.
	want []string
}

var listCallers = []listCaller{
	{"root", func(ctx context.Context) context.Context {
		return context.WithValue(withCallerTenant(ctx, ""), principalContextKey, &Principal{ID: "root-op", GlobalScope: true, TenantID: testRootTenantID})
	}, []string{"tenant-a", "tenant-b"}},
	{"tenant", func(ctx context.Context) context.Context {
		return context.WithValue(withCallerTenant(ctx, "tenant-a"), principalContextKey, &Principal{ID: "tenant-op", TenantID: "tenant-a"})
	}, []string{"tenant-a"}},
	{"no scope", func(ctx context.Context) context.Context {
		return context.WithValue(ctx, principalContextKey, &Principal{ID: "unscoped"})
	}, nil},
}

// TestCallerTenantFilter_ListSites runs the account and session list handlers —
// two of the sites that scope reads through callerTenantFilter — under a root, a
// tenant and a scopeless caller (Issue #4665): root sees every tenant, a tenant
// caller its own, and a caller with no scope nothing.
func TestCallerTenantFilter_ListSites(t *testing.T) {
	t.Run("accounts", func(t *testing.T) {
		server := setupTestServer(t)
		for _, tenant := range []string{"tenant-a", "tenant-b"} {
			rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
				Username: "list-" + tenant, TenantID: tenant, Permissions: []string{"steward:list"},
			})
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		}
		for _, c := range listCallers {
			t.Run(c.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
				req = req.WithContext(c.ctx(req.Context()))
				rec := httptest.NewRecorder()
				server.handleListAccounts(rec, req)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				var resp struct {
					Data []AccountInfo `json:"data"`
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
				assert.Equal(t, c.want, tenantsOf(resp.Data, func(a AccountInfo) string { return a.TenantID }))
			})
		}
	})

	t.Run("sessions", func(t *testing.T) {
		server, mgr, _ := setupTestServerWithSession(t)
		issued := map[string]string{}
		for _, tenant := range []string{"tenant-a", "tenant-b"} {
			sess, _, err := mgr.Issue(context.Background(), "op-"+tenant, "list-"+tenant, tenant)
			require.NoError(t, err)
			issued[sess.ID] = tenant
		}
		for _, c := range listCallers {
			t.Run(c.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
				req = req.WithContext(c.ctx(req.Context()))
				rec := httptest.NewRecorder()
				server.handleSessionList(rec, req)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				var resp sessionListResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
				assert.Equal(t, c.want, tenantsOf(resp.Sessions, func(s sessionListItem) string { return issued[s.SessionID] }))
			})
		}
	})
}

// tenantsOf returns the sorted, de-duplicated tenants of items, or nil for none.
func tenantsOf[T any](items []T, tenant func(T) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		if t := tenant(it); t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}
