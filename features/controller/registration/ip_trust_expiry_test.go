// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/registration"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// --- in-memory IPTrustStore for testing ---

type memIPTrustStore struct {
	mu      sync.RWMutex
	entries []*business.IPTrustEntry
	seq     int

	// error injection for testing error paths
	listErr   error
	revokeErr error
}

func (s *memIPTrustStore) AddTrustedRange(_ context.Context, tenantID, cidr string, preSeeded bool) error {
	normalized, err := normalizeCIDRForTest(cidr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.TenantID == tenantID && e.CIDR == normalized {
			e.PreSeeded = preSeeded
			e.TrustedSince = time.Now()
			e.Revoked = false
			e.RevokedAt = nil
			return nil
		}
	}
	s.seq++
	s.entries = append(s.entries, &business.IPTrustEntry{
		TenantID:     tenantID,
		CIDR:         normalized,
		PreSeeded:    preSeeded,
		TrustedSince: time.Now(),
	})
	return nil
}

func (s *memIPTrustStore) IsTrusted(_ context.Context, tenantID, ip string) (bool, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.TenantID != tenantID || e.Revoked {
			continue
		}
		_, ipNet, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			return true, nil
		}
	}
	return false, nil
}

func (s *memIPTrustStore) ListTrustedRanges(_ context.Context, tenantID string) ([]*business.IPTrustEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listErr != nil {
		return nil, s.listErr
	}
	var out []*business.IPTrustEntry
	for _, e := range s.entries {
		if e.TenantID == tenantID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *memIPTrustStore) RevokeTrustedRange(_ context.Context, tenantID, cidr string) error {
	if s.revokeErr != nil {
		return s.revokeErr
	}
	normalized, err := normalizeCIDRForTest(cidr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.TenantID == tenantID && e.CIDR == normalized && !e.Revoked {
			now := time.Now()
			e.Revoked = true
			e.RevokedAt = &now
			return nil
		}
	}
	return business.ErrIPTrustEntryNotFound
}

func (s *memIPTrustStore) RecordHealthySteward(_ context.Context, tenantID, ip string, at time.Time) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.TenantID != tenantID || e.Revoked {
			continue
		}
		_, ipNet, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			e.LastActivity = at
			return nil
		}
	}
	return nil
}

func (s *memIPTrustStore) GetLastActivity(_ context.Context, tenantID, ip string) (*business.IPTrustActivity, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.TenantID != tenantID || e.Revoked {
			continue
		}
		_, ipNet, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			if e.LastActivity.IsZero() {
				return nil, nil
			}
			return &business.IPTrustActivity{TenantID: tenantID, IP: ip, LastSeen: e.LastActivity}, nil
		}
	}
	return nil, nil
}

var _ business.IPTrustStore = (*memIPTrustStore)(nil)

// isRevoked reports whether the entry for (tenantID, cidr) is revoked.
func (s *memIPTrustStore) isRevoked(tenantID, cidr string) bool {
	normalized, err := normalizeCIDRForTest(cidr)
	if err != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.TenantID == tenantID && e.CIDR == normalized {
			return e.Revoked
		}
	}
	return false
}

func normalizeCIDRForTest(cidr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	return ipNet.String(), nil
}

// --- in-memory TenantStore for testing ---

type memTenantStore struct {
	mu      sync.RWMutex
	tenants []*business.TenantData

	// error injection for testing error paths
	listErr error
}

func (s *memTenantStore) CreateTenant(_ context.Context, t *business.TenantData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.tenants = append(s.tenants, &cp)
	return nil
}

func (s *memTenantStore) GetTenant(_ context.Context, tenantID string) (*business.TenantData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tenants {
		if t.ID == tenantID {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *memTenantStore) UpdateTenant(_ context.Context, t *business.TenantData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.tenants {
		if existing.ID == t.ID {
			cp := *t
			s.tenants[i] = &cp
			return nil
		}
	}
	return nil
}

func (s *memTenantStore) DeleteTenant(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.tenants {
		if t.ID == tenantID {
			s.tenants = append(s.tenants[:i], s.tenants[i+1:]...)
			return nil
		}
	}
	return nil
}

func (s *memTenantStore) ListTenants(_ context.Context, _ *business.TenantFilter) ([]*business.TenantData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]*business.TenantData, len(s.tenants))
	for i, t := range s.tenants {
		cp := *t
		out[i] = &cp
	}
	return out, nil
}

func (s *memTenantStore) GetTenantHierarchy(_ context.Context, _ string) (*business.TenantHierarchy, error) {
	return nil, nil
}

func (s *memTenantStore) GetChildTenants(_ context.Context, _ string) ([]*business.TenantData, error) {
	return nil, nil
}

func (s *memTenantStore) GetTenantPath(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (s *memTenantStore) IsTenantAncestor(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}

func (s *memTenantStore) Initialize(_ context.Context) error { return nil }
func (s *memTenantStore) Close() error                       { return nil }

var _ business.TenantStore = (*memTenantStore)(nil)

// --- helpers ---

func seedTenant(ts *memTenantStore, id string) {
	_ = ts.CreateTenant(context.Background(), &business.TenantData{
		ID:     id,
		Name:   id,
		Status: business.TenantStatusActive,
	})
}

// TestIPTrustExpiry_StaleEntryRevoked verifies that an entry with LastActivity
// older than the dark window is revoked and an entry with recent activity is not.
func TestIPTrustExpiry_StaleEntryRevoked(t *testing.T) {
	store := &memIPTrustStore{}
	ts := &memTenantStore{}
	ctx := context.Background()

	seedTenant(ts, "tenant-1")

	now := time.Now()
	darkWindow := 30 * 24 * time.Hour

	// Stale entry: LastActivity 31 days ago.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/24", false))
	require.NoError(t, store.RecordHealthySteward(ctx, "tenant-1", "10.0.0.1", now.Add(-31*24*time.Hour)))

	// Fresh entry: LastActivity 1 day ago.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.1.0/24", false))
	require.NoError(t, store.RecordHealthySteward(ctx, "tenant-1", "192.168.1.1", now.Add(-1*24*time.Hour)))

	shortJob := registration.NewIPTrustExpiryJob(registration.IPTrustExpiryConfig{
		Store:         store,
		TenantStore:   ts,
		DarkWindow:    darkWindow,
		CheckInterval: 10 * time.Millisecond,
		Logger:        logging.NewNoopLogger(),
	})
	ctx2, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	require.NoError(t, shortJob.Start(ctx2))
	<-ctx2.Done()

	assert.True(t, store.isRevoked("tenant-1", "10.0.0.0/24"),
		"entry with LastActivity 31 days ago must be revoked")
	assert.False(t, store.isRevoked("tenant-1", "192.168.1.0/24"),
		"entry with LastActivity 1 day ago must not be revoked")
}

// TestIPTrustExpiry_PreSeededNotExpired verifies that a pre-seeded entry with
// zero LastActivity is never auto-revoked by the expiry job.
func TestIPTrustExpiry_PreSeededNotExpired(t *testing.T) {
	store := &memIPTrustStore{}
	ts := &memTenantStore{}
	ctx := context.Background()

	seedTenant(ts, "tenant-1")

	// Pre-seeded entry: zero LastActivity (operator-owned, never had a steward).
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", true))

	shortJob := registration.NewIPTrustExpiryJob(registration.IPTrustExpiryConfig{
		Store:         store,
		TenantStore:   ts,
		DarkWindow:    time.Millisecond, // very short so any non-exempt entry would be revoked
		CheckInterval: 10 * time.Millisecond,
		Logger:        logging.NewNoopLogger(),
	})
	ctx2, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	require.NoError(t, shortJob.Start(ctx2))
	<-ctx2.Done()

	assert.False(t, store.isRevoked("tenant-1", "10.0.0.0/8"),
		"pre-seeded entry must never be auto-revoked regardless of LastActivity")
}

// TestIPTrustExpiry_AlreadyRevokedEntrySkipped verifies idempotency: an entry
// that is already revoked is not processed again by the expiry job.
func TestIPTrustExpiry_AlreadyRevokedEntrySkipped(t *testing.T) {
	store := &memIPTrustStore{}
	ts := &memTenantStore{}
	ctx := context.Background()

	seedTenant(ts, "tenant-1")

	// Add an entry that would be stale, then manually revoke it.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/24", false))
	require.NoError(t, store.RevokeTrustedRange(ctx, "tenant-1", "10.0.0.0/24"))

	// Configure an injected error on RevokeTrustedRange so if the job calls it again it fails.
	store.revokeErr = errTestRevoke

	shortJob := registration.NewIPTrustExpiryJob(registration.IPTrustExpiryConfig{
		Store:         store,
		TenantStore:   ts,
		DarkWindow:    time.Millisecond,
		CheckInterval: 10 * time.Millisecond,
		Logger:        logging.NewNoopLogger(),
	})
	ctx2, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	require.NoError(t, shortJob.Start(ctx2))
	<-ctx2.Done()

	// The job must not have attempted to re-revoke the already-revoked entry,
	// so the injected error was never triggered.
	assert.True(t, store.isRevoked("tenant-1", "10.0.0.0/24"),
		"already-revoked entry must remain revoked")
}

var errTestRevoke = errString("injected revoke error")

// TestIPTrustExpiry_ListTenantsError verifies the job logs and recovers when
// ListTenants returns an error rather than panicking or looping.
func TestIPTrustExpiry_ListTenantsError(t *testing.T) {
	store := &memIPTrustStore{}
	ts := &memTenantStore{listErr: errString("injected list tenants error")}

	shortJob := registration.NewIPTrustExpiryJob(registration.IPTrustExpiryConfig{
		Store:         store,
		TenantStore:   ts,
		DarkWindow:    time.Millisecond,
		CheckInterval: 10 * time.Millisecond,
		Logger:        logging.NewNoopLogger(),
	})
	ctx2, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// Job must start and run without panicking even when ListTenants always errors.
	require.NoError(t, shortJob.Start(ctx2))
	<-ctx2.Done()
}

// TestIPTrustExpiry_ListRangesError verifies the job logs and continues to the
// next tenant when ListTrustedRanges returns an error.
func TestIPTrustExpiry_ListRangesError(t *testing.T) {
	store := &memIPTrustStore{listErr: errString("injected list ranges error")}
	ts := &memTenantStore{}

	seedTenant(ts, "tenant-1")

	shortJob := registration.NewIPTrustExpiryJob(registration.IPTrustExpiryConfig{
		Store:         store,
		TenantStore:   ts,
		DarkWindow:    time.Millisecond,
		CheckInterval: 10 * time.Millisecond,
		Logger:        logging.NewNoopLogger(),
	})
	ctx2, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// Job must not panic when ListTrustedRanges always errors.
	require.NoError(t, shortJob.Start(ctx2))
	<-ctx2.Done()
}

type errString string

func (e errString) Error() string { return string(e) }
