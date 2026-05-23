// SPDX-License-Identifier: Apache-2.0
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// newIPTrustServer creates a minimal test server with ip-trust management permissions.
func newIPTrustServer(t *testing.T) (*Server, *httptest.Server, business.IPTrustStore) {
	t.Helper()
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	ipStore := newInMemIPTrustStore()
	server.SetIPTrustStore(ipStore)

	server.apiKeys["ip-trust-key"] = &APIKey{
		ID:          "ip-trust-key-id",
		Key:         "ip-trust-key",
		Permissions: []string{"registration:manage-ip-trust"},
		TenantID:    "default",
	}

	ts := httptest.NewServer(server.router)
	return server, ts, ipStore
}

func TestHandleAddIPTrust(t *testing.T) {
	_, ts, ipStore := newIPTrustServer(t)
	defer ts.Close()

	makeAdd := func(t *testing.T, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), "POST",
			ts.URL+"/api/v1/registration/ip-trust",
			bytes.NewReader([]byte(body)))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer ip-trust-key")
		req.Header.Set("Content-Type", "application/json")
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("happy path - adds trusted range", func(t *testing.T) {
		resp := makeAdd(t, `{"tenant_id":"acme","cidr":"10.0.0.0/8","pre_seeded":true}`)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		// Verify the range was actually stored.
		entries, err := ipStore.ListTrustedRanges(context.Background(), "acme")
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "10.0.0.0/8", entries[0].CIDR)
		assert.True(t, entries[0].PreSeeded)
	})

	t.Run("missing tenant_id returns 400", func(t *testing.T) {
		resp := makeAdd(t, `{"cidr":"10.0.0.0/8"}`)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("missing cidr returns 400", func(t *testing.T) {
		resp := makeAdd(t, `{"tenant_id":"acme"}`)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid JSON returns 400", func(t *testing.T) {
		resp := makeAdd(t, `{not-json}`)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestHandleAddIPTrust_NoStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	// Do NOT set ipTrustStore.
	server.apiKeys["ip-trust-key"] = &APIKey{
		ID:          "ip-trust-key-id",
		Key:         "ip-trust-key",
		Permissions: []string{"registration:manage-ip-trust"},
		TenantID:    "default",
	}
	ts := httptest.NewServer(server.router)
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), "POST",
		ts.URL+"/api/v1/registration/ip-trust",
		bytes.NewReader([]byte(`{"tenant_id":"acme","cidr":"10.0.0.0/8"}`)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer ip-trust-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandleRevokeIPTrust(t *testing.T) {
	_, ts, ipStore := newIPTrustServer(t)
	defer ts.Close()

	// Pre-seed an entry to revoke.
	require.NoError(t, ipStore.AddTrustedRange(context.Background(), "acme", "10.0.0.0/8", true))

	makeRevoke := func(t *testing.T, tenantID, cidr string) *http.Response {
		t.Helper()
		// Use literal slash in the URL path; gorilla/mux {cidr:.+} matches across path segments.
		path := ts.URL + "/api/v1/registration/ip-trust/" + tenantID + "/" + cidr
		req, err := http.NewRequestWithContext(context.Background(), "DELETE", path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer ip-trust-key")
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("happy path - revokes trusted range", func(t *testing.T) {
		// Use literal slash in URL path; gorilla/mux {cidr:.+} matches across segments.
		resp := makeRevoke(t, "acme", "10.0.0.0/8")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		// Verify revocation in store.
		entries, err := ipStore.ListTrustedRanges(context.Background(), "acme")
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.True(t, entries[0].Revoked)
	})

	t.Run("not found returns 404", func(t *testing.T) {
		resp := makeRevoke(t, "acme", "192.168.0.0/16")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestHandleRevokeIPTrust_NoStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.apiKeys["ip-trust-key"] = &APIKey{
		ID:          "ip-trust-key-id",
		Key:         "ip-trust-key",
		Permissions: []string{"registration:manage-ip-trust"},
		TenantID:    "default",
	}
	ts := httptest.NewServer(server.router)
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), "DELETE",
		ts.URL+"/api/v1/registration/ip-trust/acme/10.0.0.0/8", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer ip-trust-key")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
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
	server.apiKeys["ip-trust-key"] = &APIKey{
		ID:          "ip-trust-key-id",
		Key:         "ip-trust-key",
		Permissions: []string{"registration:manage-ip-trust"},
		TenantID:    "default",
	}
	ts := httptest.NewServer(server.router)
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), "POST",
		ts.URL+"/api/v1/registration/ip-trust",
		bytes.NewReader([]byte(`{"tenant_id":"acme","cidr":"10.0.0.0/8"}`)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer ip-trust-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestHandleRevokeIPTrust_StoreError(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetIPTrustStore(&errIPTrustStore{revokeErr: errors.New("db failure")})
	server.apiKeys["ip-trust-key"] = &APIKey{
		ID:          "ip-trust-key-id",
		Key:         "ip-trust-key",
		Permissions: []string{"registration:manage-ip-trust"},
		TenantID:    "default",
	}
	ts := httptest.NewServer(server.router)
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), "DELETE",
		ts.URL+"/api/v1/registration/ip-trust/acme/10.0.0.0/8", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer ip-trust-key")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
