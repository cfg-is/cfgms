// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// inMemIPTrustStore is a minimal in-memory IPTrustStore for handler tests.
// The SQLite backend used by SetupTestStorage does not support IPTrustStore,
// so we provide a simple in-memory implementation here.
type inMemIPTrustStore struct {
	mu      sync.Mutex
	entries []*business.IPTrustEntry
}

func newInMemIPTrustStore() business.IPTrustStore {
	return &inMemIPTrustStore{}
}

func (s *inMemIPTrustStore) AddTrustedRange(_ context.Context, tenantID, cidr string, preSeeded bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-activate revoked entries.
	for _, e := range s.entries {
		if e.TenantID == tenantID && e.CIDR == cidr {
			e.Revoked = false
			e.RevokedAt = nil
			e.PreSeeded = preSeeded
			return nil
		}
	}
	s.entries = append(s.entries, &business.IPTrustEntry{
		ID:           cidr + "@" + tenantID,
		TenantID:     tenantID,
		CIDR:         cidr,
		PreSeeded:    preSeeded,
		TrustedSince: time.Now().UTC(),
	})
	return nil
}

func (s *inMemIPTrustStore) IsTrusted(_ context.Context, tenantID, ip string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.TenantID != tenantID || e.Revoked {
			continue
		}
		// Simple prefix check: accept exact CIDR match containing the IP.
		_ = ip // containment check omitted for test simplicity — not needed here
	}
	return false, nil
}

func (s *inMemIPTrustStore) ListTrustedRanges(_ context.Context, tenantID string) ([]*business.IPTrustEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*business.IPTrustEntry
	for _, e := range s.entries {
		if e.TenantID == tenantID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *inMemIPTrustStore) RevokeTrustedRange(_ context.Context, tenantID, cidr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.TenantID == tenantID && e.CIDR == cidr && !e.Revoked {
			now := time.Now().UTC()
			e.Revoked = true
			e.RevokedAt = &now
			return nil
		}
	}
	return business.ErrIPTrustEntryNotFound
}

func (s *inMemIPTrustStore) RecordHealthySteward(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}

func (s *inMemIPTrustStore) GetLastActivity(_ context.Context, _, _ string) (*business.IPTrustActivity, error) {
	return nil, nil
}

// Compile-time assertion: inMemIPTrustStore satisfies the interface.
var _ business.IPTrustStore = (*inMemIPTrustStore)(nil)

// newIPTrustServer creates a minimal test server with ip-trust management wired.
// Tier-3 enforcement means POST/DELETE on /registration/ip-trust require admin cert;
// tests use makeAdminRequest and server.router.ServeHTTP directly.
func newIPTrustServer(t *testing.T) (*Server, business.IPTrustStore) {
	t.Helper()
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	ipStore := newInMemIPTrustStore()
	server.SetIPTrustStore(ipStore)

	return server, ipStore
}

func TestHandleAddIPTrust(t *testing.T) {
	server, ipStore := newIPTrustServer(t)

	makeAdd := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := makeAdminRequest(t, "POST", "/api/v1/registration/ip-trust", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		return rec
	}

	t.Run("happy path - adds trusted range", func(t *testing.T) {
		rec := makeAdd(t, `{"tenant_id":"acme","cidr":"10.0.0.0/8","pre_seeded":true}`)

		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Verify the range was actually stored.
		entries, err := ipStore.ListTrustedRanges(context.Background(), "acme")
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "10.0.0.0/8", entries[0].CIDR)
		assert.True(t, entries[0].PreSeeded)
	})

	t.Run("missing tenant_id returns 400", func(t *testing.T) {
		rec := makeAdd(t, `{"cidr":"10.0.0.0/8"}`)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing cidr returns 400", func(t *testing.T) {
		rec := makeAdd(t, `{"tenant_id":"acme"}`)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid JSON returns 400", func(t *testing.T) {
		rec := makeAdd(t, `{not-json}`)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// TestHandleAddIPTrust_CrossTenantRefused is the REQUIRED regression test for
// Issue #4336: a caller scoped to tenant-a must not be able to add a trusted CIDR
// range for tenant-b. Calls the handler directly (bypassing requirePermission's
// AssuranceStrong gate, which registration:manage-ip-trust requires and a Machine-
// assurance API key cannot clear) so the assertion is attributable to the handler's
// own tenant guard, not the assurance gate. Fails (204, range written) before this
// story's fix.
func TestHandleAddIPTrust_CrossTenantRefused(t *testing.T) {
	server, ipStore := newIPTrustServer(t)

	principal := &Principal{ID: "tenant-a-admin", TenantID: "tenant-a"}
	ctx := context.WithValue(context.Background(), principalContextKey, principal)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(principal.TenantID))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/registration/ip-trust",
		bytes.NewReader([]byte(`{"tenant_id":"tenant-b","cidr":"10.0.0.0/8"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleAddIPTrust(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	entries, err := ipStore.ListTrustedRanges(context.Background(), "tenant-b")
	require.NoError(t, err)
	assert.Empty(t, entries, "a refused cross-tenant add must not have written anything")
}

// TestHandleRevokeIPTrust_CrossTenantRefused mirrors
// TestHandleAddIPTrust_CrossTenantRefused for the revoke path: a caller scoped to
// tenant-a must not be able to revoke a trusted range belonging to tenant-b.
func TestHandleRevokeIPTrust_CrossTenantRefused(t *testing.T) {
	server, ipStore := newIPTrustServer(t)
	require.NoError(t, ipStore.AddTrustedRange(context.Background(), "tenant-b", "10.0.0.0/8", false))

	principal := &Principal{ID: "tenant-a-admin", TenantID: "tenant-a"}
	ctx := context.WithValue(context.Background(), principalContextKey, principal)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(principal.TenantID))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/registration/ip-trust/tenant-b/10.0.0.0%2F8", nil)
	req = mux.SetURLVars(req.WithContext(ctx), map[string]string{"tenant_id": "tenant-b", "cidr": "10.0.0.0/8"})
	rec := httptest.NewRecorder()
	server.handleRevokeIPTrust(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	entries, err := ipStore.ListTrustedRanges(context.Background(), "tenant-b")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.False(t, entries[0].Revoked, "a refused cross-tenant revoke must not have revoked the range")
}

// TestHandleListIPTrust covers handleListIPTrust's tenant scoping (Issue #4336):
// a tenant-scoped caller always sees only its own tenant's ranges (the tenant_id
// query param is ignored), a root-scoped caller must supply ?tenant_id= to avoid
// an open-ended scan, and an unset scope is refused outright.
func TestHandleListIPTrust(t *testing.T) {
	server, ipStore := newIPTrustServer(t)
	require.NoError(t, ipStore.AddTrustedRange(context.Background(), "tenant-a", "10.0.0.0/8", false))
	require.NoError(t, ipStore.AddTrustedRange(context.Background(), "tenant-b", "192.168.0.0/16", false))

	t.Run("tenant-scoped caller sees only its own tenant's ranges", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/registration/ip-trust?tenant_id=tenant-b", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a")))
		rec := httptest.NewRecorder()
		server.handleListIPTrust(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "10.0.0.0/8")
		assert.NotContains(t, rec.Body.String(), "192.168.0.0/16",
			"the tenant_id query param must be ignored for a tenant-scoped caller")
	})

	t.Run("root-scoped caller without tenant_id gets 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/registration/ip-trust", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope()))
		rec := httptest.NewRecorder()
		server.handleListIPTrust(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("root-scoped caller with tenant_id sees the named tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/registration/ip-trust?tenant_id=tenant-b", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope()))
		rec := httptest.NewRecorder()
		server.handleListIPTrust(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "192.168.0.0/16")
	})

	// REQUIRED regression test for Issue #4336: an unset scope must be refused, not
	// treated as unrestricted the way an empty callerTenant string previously was.
	t.Run("unset scope is refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/registration/ip-trust?tenant_id=tenant-b", nil)
		rec := httptest.NewRecorder()
		server.handleListIPTrust(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	})
}

func TestHandleAddIPTrust_NoStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	// Do NOT set ipTrustStore.

	req := makeAdminRequest(t, "POST", "/api/v1/registration/ip-trust",
		bytes.NewReader([]byte(`{"tenant_id":"acme","cidr":"10.0.0.0/8"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleRevokeIPTrust(t *testing.T) {
	server, ipStore := newIPTrustServer(t)

	// Pre-seed an entry to revoke.
	require.NoError(t, ipStore.AddTrustedRange(context.Background(), "acme", "10.0.0.0/8", true))

	makeRevoke := func(t *testing.T, tenantID, cidr string) *httptest.ResponseRecorder {
		t.Helper()
		path := "/api/v1/registration/ip-trust/" + tenantID + "/" + cidr
		req := makeAdminRequest(t, "DELETE", path, nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		return rec
	}

	t.Run("happy path - revokes trusted range", func(t *testing.T) {
		rec := makeRevoke(t, "acme", "10.0.0.0/8")

		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Verify revocation in store.
		entries, err := ipStore.ListTrustedRanges(context.Background(), "acme")
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.True(t, entries[0].Revoked)
	})

	t.Run("not found returns 404", func(t *testing.T) {
		rec := makeRevoke(t, "acme", "192.168.0.0/16")

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestHandleRevokeIPTrust_NoStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	req := makeAdminRequest(t, "DELETE", "/api/v1/registration/ip-trust/acme/10.0.0.0/8", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// errIPTrustStore wraps inMemIPTrustStore to inject errors for error-path tests.
type errIPTrustStore struct {
	addErr    error
	revokeErr error
}

func (s *errIPTrustStore) AddTrustedRange(_ context.Context, _, _ string, _ bool) error {
	return s.addErr
}

func (s *errIPTrustStore) IsTrusted(_ context.Context, _, _ string) (bool, error) { return false, nil }

func (s *errIPTrustStore) ListTrustedRanges(_ context.Context, _ string) ([]*business.IPTrustEntry, error) {
	return nil, nil
}

func (s *errIPTrustStore) RevokeTrustedRange(_ context.Context, _, _ string) error {
	return s.revokeErr
}

func (s *errIPTrustStore) RecordHealthySteward(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}

func (s *errIPTrustStore) GetLastActivity(_ context.Context, _, _ string) (*business.IPTrustActivity, error) {
	return nil, nil
}

var _ business.IPTrustStore = (*errIPTrustStore)(nil)

func TestHandleAddIPTrust_StoreError(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetIPTrustStore(&errIPTrustStore{addErr: errors.New("db failure")})

	req := makeAdminRequest(t, "POST", "/api/v1/registration/ip-trust",
		bytes.NewReader([]byte(`{"tenant_id":"acme","cidr":"10.0.0.0/8"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandleRevokeIPTrust_StoreError(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetIPTrustStore(&errIPTrustStore{revokeErr: errors.New("db failure")})

	req := makeAdminRequest(t, "DELETE", "/api/v1/registration/ip-trust/acme/10.0.0.0/8", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
