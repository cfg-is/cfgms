// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const authzTestRoute = "GET /api/v1/test/authz"

// captureAuthzRecheck authenticates req through the real authentication middleware
// and returns the authzRecheck the handler would hold for permissionID on resourceTenant.
func captureAuthzRecheck(t *testing.T, srv *Server, req *http.Request, permissionID, resourceTenant string) authRecheck {
	t.Helper()
	var recheck authRecheck
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recheck = srv.authzRecheck(r, permissionID, resourceTenant, authzTestRoute)
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, recheck)
	return recheck
}

// updateTestAccount rewrites the named account in the real account store.
func updateTestAccount(t *testing.T, srv *Server, username string, mutate func(*account)) *account {
	t.Helper()
	acct, err := srv.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	cp := *acct
	mutate(&cp)
	require.NoError(t, srv.persistAccount(context.Background(), &cp, "test-setup"))
	srv.cacheAccount(&cp)
	return &cp
}

// newBearerSessionForAccount wires a session manager and issues a Bearer token for a
// tenant-scoped account holding permissions.
func newBearerSessionForAccount(t *testing.T, srv *Server, username string, permissions []string) (token string, acct *account) {
	t.Helper()
	createTestAccount(t, srv, username)
	acct = updateTestAccount(t, srv, username, func(a *account) { a.Permissions = permissions })
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	srv.SetSessionManager(session.NewManager(cfg, store, time.Now))
	_, token, err := srv.sessionManager.Issue(context.Background(), acct.ID, "cfg-cli", acct.TenantID)
	require.NoError(t, err)
	return token, acct
}

func bearerRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test/authz", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func adminCertTLSRequest(c *x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test/authz", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
	return req
}

func TestAuthzRecheck_SessionPrincipal(t *testing.T) {
	t.Run("unchanged principal passes repeatedly", func(t *testing.T) {
		srv := setupTestServer(t)
		token, acct := newBearerSessionForAccount(t, srv, "authz-session-ok", []string{"case:read"})
		recheck := captureAuthzRecheck(t, srv, bearerRequest(token), "case:read", acct.TenantID)
		for i := 0; i < 3; i++ {
			assert.True(t, recheck(context.Background()), "tick %d", i)
		}
	})

	t.Run("permission removed in the account store", func(t *testing.T) {
		srv := setupTestServer(t)
		token, acct := newBearerSessionForAccount(t, srv, "authz-session-perm", []string{"case:read"})
		recheck := captureAuthzRecheck(t, srv, bearerRequest(token), "case:read", acct.TenantID)
		require.True(t, recheck(context.Background()))

		updateTestAccount(t, srv, "authz-session-perm", func(a *account) { a.Permissions = []string{"steward:read"} })
		assert.False(t, recheck(context.Background()))
	})

	t.Run("account disabled", func(t *testing.T) {
		srv := setupTestServer(t)
		token, acct := newBearerSessionForAccount(t, srv, "authz-session-disabled", []string{"case:read"})
		recheck := captureAuthzRecheck(t, srv, bearerRequest(token), "case:read", acct.TenantID)
		require.True(t, recheck(context.Background()))

		updateTestAccount(t, srv, "authz-session-disabled", func(a *account) { a.Disabled = true })
		assert.False(t, recheck(context.Background()))
	})

	t.Run("account store error fails closed", func(t *testing.T) {
		srv := setupTestServer(t)
		token, acct := newBearerSessionForAccount(t, srv, "authz-session-err", []string{"case:read"})
		recheck := captureAuthzRecheck(t, srv, bearerRequest(token), "case:read", acct.TenantID)
		require.True(t, recheck(context.Background()))

		healthy := srv.secretStore
		srv.secretStore = &errListSecretStore{SecretStore: healthy, listErr: errors.New("injected ListSecrets failure")}
		assert.False(t, recheck(context.Background()))
		srv.secretStore = healthy
		assert.True(t, recheck(context.Background()), "a transient error must not poison later ticks")
	})

	t.Run("resource tenant outside the refreshed tenant", func(t *testing.T) {
		srv := setupTestServer(t)
		token, _ := newBearerSessionForAccount(t, srv, "authz-session-tenant", []string{"case:read"})
		recheck := captureAuthzRecheck(t, srv, bearerRequest(token), "case:read", "some-other-tenant")
		assert.False(t, recheck(context.Background()))
	})
}

func TestAuthzRecheck_APIKeyPrincipal(t *testing.T) {
	t.Run("unchanged key passes repeatedly", func(t *testing.T) {
		srv := setupTestServer(t)
		key := NewEphemeralTestKey(t, srv, []string{"case:read"}, "test-tenant", 5*time.Minute)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test/authz", nil)
		req.Header.Set("X-API-Key", key)
		recheck := captureAuthzRecheck(t, srv, req, "case:read", "test-tenant")
		for i := 0; i < 3; i++ {
			assert.True(t, recheck(context.Background()), "tick %d", i)
		}
	})

	t.Run("key record deleted", func(t *testing.T) {
		srv := setupTestServer(t)
		key := NewEphemeralTestKey(t, srv, []string{"case:read"}, "test-tenant", 5*time.Minute)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test/authz", nil)
		req.Header.Set("X-API-Key", key)
		recheck := captureAuthzRecheck(t, srv, req, "case:read", "test-tenant")
		require.True(t, recheck(context.Background()))

		require.NoError(t, srv.deleteAPIKeyRecord(context.Background(), "test-tenant", hashAPIKey(key)))
		assert.False(t, recheck(context.Background()))
	})

	t.Run("key lacking the permission", func(t *testing.T) {
		srv := setupTestServer(t)
		key := NewEphemeralTestKey(t, srv, []string{"steward:read"}, "test-tenant", 5*time.Minute)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test/authz", nil)
		req.Header.Set("X-API-Key", key)
		recheck := captureAuthzRecheck(t, srv, req, "case:read", "test-tenant")
		assert.False(t, recheck(context.Background()))
	})
}

func TestAuthzRecheck_AdminCertPrincipal(t *testing.T) {
	t.Run("unbound implicit-admin certificate passes repeatedly", func(t *testing.T) {
		srv := setupTestServer(t)
		c := makeAdminCertWithAttrs(t, 51001, "authz-bootstrap-admin", false)
		recheck := captureAuthzRecheck(t, srv, adminCertTLSRequest(c), "case:read", testRootTenantID)
		for i := 0; i < 3; i++ {
			assert.True(t, recheck(context.Background()), "tick %d", i)
		}
	})

	t.Run("ended crossing for a root caller closes the stream", func(t *testing.T) {
		srv := setupCrossingTestServer(t)
		ctx := context.Background()
		require.NoError(t, ensureTestRootTenant(ctx, srv.tenantManager))
		_, err := srv.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-authz", ParentID: testRootTenantID})
		require.NoError(t, err)

		c := makeAdminCertWithAttrs(t, 51003, "authz-root-operator", true)
		recheck := captureAuthzRecheck(t, srv, adminCertTLSRequest(c), "case:read", "msp-authz")
		assert.False(t, recheck(ctx), "no crossing yet")

		now := time.Now().UTC()
		require.NoError(t, srv.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
			ID: "grant-authz-1", TenantID: "msp-authz", Kind: business.TenantCrossingKindGrant,
			GrantedBy: "msp-authz-admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}))
		assert.True(t, recheck(ctx), "active crossing admits the root caller")

		require.NoError(t, srv.tenantCrossingStore.RevokeTenantCrossing(ctx, "grant-authz-1"))
		assert.False(t, recheck(ctx), "ended crossing must close the stream")
	})
}

func TestAuthzRecheck_NoRecordedCredentialFailsClosed(t *testing.T) {
	srv := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test/authz", nil)
	assert.False(t, srv.authzRecheck(req, "case:read", "test-tenant", authzTestRoute)(context.Background()))
}
