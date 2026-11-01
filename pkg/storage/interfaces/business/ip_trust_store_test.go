// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// inMemIPTrustStore is a minimal in-memory IPTrustStore used only for
// contract testing. It is NOT intended for production use.
type inMemIPTrustStore struct {
	mu      sync.RWMutex
	entries []*business.IPTrustEntry
	seq     int
}

// normalizeCIDR returns the network address form of cidr, e.g. "192.168.1.0/24".
func normalizeCIDR(cidr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	return ipNet.String(), nil
}

func (s *inMemIPTrustStore) AddTrustedRange(_ context.Context, tenantID, cidr string, preSeeded bool) error {
	normalized, err := normalizeCIDR(cidr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Upsert: re-activate if previously revoked, otherwise insert new.
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
		ID:           fmt.Sprintf("entry-%d", s.seq),
		TenantID:     tenantID,
		CIDR:         normalized,
		PreSeeded:    preSeeded,
		TrustedSince: time.Now(),
	})
	return nil
}

func (s *inMemIPTrustStore) IsTrusted(_ context.Context, tenantID, ip string) (bool, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
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

func (s *inMemIPTrustStore) ListTrustedRanges(_ context.Context, tenantID string) ([]*business.IPTrustEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
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
	normalized, err := normalizeCIDR(cidr)
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

func (s *inMemIPTrustStore) RecordHealthySteward(_ context.Context, tenantID, ip string, at time.Time) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
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
	return nil // no-op if no matching entry
}

func (s *inMemIPTrustStore) GetLastActivity(_ context.Context, tenantID, ip string) (*business.IPTrustActivity, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
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
			return &business.IPTrustActivity{
				TenantID: tenantID,
				IP:       ip,
				LastSeen: e.LastActivity,
			}, nil
		}
	}
	return nil, nil
}

// Compile-time assertion: inMemIPTrustStore satisfies the interface.
var _ business.IPTrustStore = (*inMemIPTrustStore)(nil)

// --- Contract tests ---

func newInMemStore() business.IPTrustStore {
	return &inMemIPTrustStore{}
}

func TestIPTrustStore_AddAndIsTrusted(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))

	trusted, err := store.IsTrusted(ctx, "tenant-1", "10.1.2.3")
	require.NoError(t, err)
	assert.True(t, trusted, "IP within /8 must be trusted")

	notTrusted, err := store.IsTrusted(ctx, "tenant-1", "192.168.1.1")
	require.NoError(t, err)
	assert.False(t, notTrusted, "IP outside range must not be trusted")
}

func TestIPTrustStore_TenantIsolation(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-A", "10.0.0.0/8", false))

	trusted, err := store.IsTrusted(ctx, "tenant-B", "10.1.2.3")
	require.NoError(t, err)
	assert.False(t, trusted, "tenant-B must not see tenant-A ranges")
}

func TestIPTrustStore_PreSeeded(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	// Pre-seeded entry trusts without requiring any liveness event.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "172.16.0.0/12", true))

	trusted, err := store.IsTrusted(ctx, "tenant-1", "172.20.1.1")
	require.NoError(t, err)
	assert.True(t, trusted, "pre-seeded CIDR must be trusted without liveness event")
}

func TestIPTrustStore_RevokeClearsAccess(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.0.0/16", false))

	trusted, err := store.IsTrusted(ctx, "tenant-1", "192.168.5.5")
	require.NoError(t, err)
	require.True(t, trusted, "expected trusted before revoke")

	require.NoError(t, store.RevokeTrustedRange(ctx, "tenant-1", "192.168.0.0/16"))

	trusted, err = store.IsTrusted(ctx, "tenant-1", "192.168.5.5")
	require.NoError(t, err)
	assert.False(t, trusted, "expected untrusted after revoke")
}

func TestIPTrustStore_RevokeNotFound(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	err := store.RevokeTrustedRange(ctx, "tenant-1", "10.0.0.0/8")
	assert.ErrorIs(t, err, business.ErrIPTrustEntryNotFound)
}

func TestIPTrustStore_CIDRNormalization(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	// Host address form normalises to network address.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.1.5/24", false))

	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "192.168.1.0/24", entries[0].CIDR, "CIDR must be stored in normalised form")

	// Re-adding via host address must not create a duplicate.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.1.99/24", false))
	entries, err = store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "normalised duplicates must not create a second entry")
}

func TestIPTrustStore_ListTrustedRanges(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.0.0/16", true))
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-2", "172.16.0.0/12", false))

	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	entries, err = store.ListTrustedRanges(ctx, "tenant-2")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestIPTrustStore_ListIncludesRevoked(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))
	require.NoError(t, store.RevokeTrustedRange(ctx, "tenant-1", "10.0.0.0/8"))

	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, entries[0].Revoked, "revoked entry must be included in list")
	assert.NotNil(t, entries[0].RevokedAt)
}

func TestIPTrustStore_RecordHealthySteward(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, store.RecordHealthySteward(ctx, "tenant-1", "10.1.2.3", now))

	activity, err := store.GetLastActivity(ctx, "tenant-1", "10.1.2.3")
	require.NoError(t, err)
	require.NotNil(t, activity)
	assert.Equal(t, "tenant-1", activity.TenantID)
	assert.Equal(t, "10.1.2.3", activity.IP)
	assert.Equal(t, now, activity.LastSeen)
}

func TestIPTrustStore_RecordHealthySteward_NoMatch_IsNoop(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	// No entry exists; RecordHealthySteward must be a no-op.
	err := store.RecordHealthySteward(ctx, "tenant-1", "10.0.0.1", time.Now())
	assert.NoError(t, err)
}

func TestIPTrustStore_GetLastActivity_NoActivity(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))

	activity, err := store.GetLastActivity(ctx, "tenant-1", "10.0.0.1")
	require.NoError(t, err)
	assert.Nil(t, activity, "no activity recorded yet")
}

func TestIPTrustStore_GetLastActivity_NotInRange(t *testing.T) {
	store := newInMemStore()
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))
	require.NoError(t, store.RecordHealthySteward(ctx, "tenant-1", "10.0.0.1", time.Now()))

	activity, err := store.GetLastActivity(ctx, "tenant-1", "192.168.1.1")
	require.NoError(t, err)
	assert.Nil(t, activity, "IP outside range has no activity")
}

func TestIPTrustStore_IPTrustEntryStructFields(t *testing.T) {
	now := time.Now()
	revokedAt := now.Add(time.Hour)
	entry := business.IPTrustEntry{
		ID:           "entry-001",
		TenantID:     "tenant-1",
		CIDR:         "10.0.0.0/8",
		PreSeeded:    true,
		TrustedSince: now,
		LastActivity: now,
		Revoked:      true,
		RevokedAt:    &revokedAt,
	}
	assert.Equal(t, "entry-001", entry.ID)
	assert.Equal(t, "tenant-1", entry.TenantID)
	assert.Equal(t, "10.0.0.0/8", entry.CIDR)
	assert.True(t, entry.PreSeeded)
	assert.Equal(t, now, entry.TrustedSince)
	assert.Equal(t, now, entry.LastActivity)
	assert.True(t, entry.Revoked)
	assert.Equal(t, revokedAt, *entry.RevokedAt)
}

func TestIPTrustStore_IPTrustActivityStructFields(t *testing.T) {
	now := time.Now()
	activity := business.IPTrustActivity{
		TenantID: "tenant-1",
		IP:       "10.0.0.1",
		LastSeen: now,
	}
	assert.Equal(t, "tenant-1", activity.TenantID)
	assert.Equal(t, "10.0.0.1", activity.IP)
	assert.Equal(t, now, activity.LastSeen)
}

func TestErrIPTrustEntryNotFound(t *testing.T) {
	assert.NotNil(t, business.ErrIPTrustEntryNotFound)
	assert.Equal(t, "ip trust entry not found", business.ErrIPTrustEntryNotFound.Error())
}
