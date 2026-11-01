// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestIPTrustStore(t *testing.T) *DatabaseIPTrustStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateIPTrustRangesTable(ctx, db))
	return &DatabaseIPTrustStore{db: db, schemas: schemas}
}

func TestIPTrustStore_AddAndQuery(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))

	trusted, err := store.IsTrusted(ctx, "tenant-1", "10.1.2.3")
	require.NoError(t, err)
	assert.True(t, trusted)

	notTrusted, err := store.IsTrusted(ctx, "tenant-1", "192.168.1.1")
	require.NoError(t, err)
	assert.False(t, notTrusted)
}

func TestIPTrustStore_TenantIsolation(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-A", "10.0.0.0/8", false))

	trusted, err := store.IsTrusted(ctx, "tenant-B", "10.1.2.3")
	require.NoError(t, err)
	assert.False(t, trusted, "tenant-B must not see tenant-A ranges")
}

func TestIPTrustStore_CIDRContainment(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	// Add a /24 range and a single /32.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.1.0/24", false))
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.5/32", false))

	tests := []struct {
		ip      string
		want    bool
		comment string
	}{
		{"192.168.1.1", true, "/24 containment — first host"},
		{"192.168.1.254", true, "/24 containment — last host"},
		{"192.168.2.1", false, "out-of-range — different subnet"},
		{"10.0.0.5", true, "/32 exact match"},
		{"10.0.0.6", false, "/32 — adjacent IP not in range"},
	}

	for _, tc := range tests {
		t.Run(tc.comment, func(t *testing.T) {
			got, err := store.IsTrusted(ctx, "tenant-1", tc.ip)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got, tc.comment)
		})
	}
}

func TestIPTrustStore_PreSeeded_RoundTrip(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "172.16.0.0/12", true))

	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, entries[0].PreSeeded, "pre_seeded flag must round-trip")
	assert.Equal(t, "172.16.0.0/12", entries[0].CIDR)

	// pre-seeded entry must be trusted without any liveness event.
	trusted, err := store.IsTrusted(ctx, "tenant-1", "172.20.1.1")
	require.NoError(t, err)
	assert.True(t, trusted)
}

func TestIPTrustStore_RevokeClearsAccess(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))

	trusted, err := store.IsTrusted(ctx, "tenant-1", "10.1.2.3")
	require.NoError(t, err)
	require.True(t, trusted, "expected trusted before revoke")

	require.NoError(t, store.RevokeTrustedRange(ctx, "tenant-1", "10.0.0.0/8"))

	trusted, err = store.IsTrusted(ctx, "tenant-1", "10.1.2.3")
	require.NoError(t, err)
	assert.False(t, trusted, "expected untrusted after revoke")
}

func TestIPTrustStore_RevokeNotFound(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	err := store.RevokeTrustedRange(ctx, "tenant-1", "10.0.0.0/8")
	require.ErrorIs(t, err, business.ErrIPTrustEntryNotFound)
}

func TestIPTrustStore_RecordHealthySteward_Upsert(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))

	t1 := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, store.RecordHealthySteward(ctx, "tenant-1", "10.0.0.1", t1))

	activity, err := store.GetLastActivity(ctx, "tenant-1", "10.0.0.1")
	require.NoError(t, err)
	require.NotNil(t, activity)
	assert.Equal(t, "tenant-1", activity.TenantID)
	assert.Equal(t, "10.0.0.1", activity.IP)
	assert.WithinDuration(t, t1, activity.LastSeen, time.Millisecond)

	// Second call updates the timestamp.
	t2 := t1.Add(time.Minute)
	require.NoError(t, store.RecordHealthySteward(ctx, "tenant-1", "10.0.0.1", t2))

	activity, err = store.GetLastActivity(ctx, "tenant-1", "10.0.0.1")
	require.NoError(t, err)
	require.NotNil(t, activity)
	assert.WithinDuration(t, t2, activity.LastSeen, time.Millisecond)
}

func TestIPTrustStore_RecordHealthySteward_NoMatch(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	// No entry exists; must be a no-op (no error).
	err := store.RecordHealthySteward(ctx, "tenant-1", "10.0.0.1", time.Now())
	assert.NoError(t, err)
}

func TestIPTrustStore_GetLastActivity_NoActivity(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))

	activity, err := store.GetLastActivity(ctx, "tenant-1", "10.0.0.1")
	require.NoError(t, err)
	assert.Nil(t, activity, "no activity recorded yet")
}

func TestIPTrustStore_CIDRNormalization(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	// Host-address form must be normalised.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.1.99/24", false))

	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "192.168.1.0/24", entries[0].CIDR)

	// Re-adding via another host address in the same /24 must not create a second row.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.1.5/24", false))
	entries, err = store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "normalised duplicate must not create a second entry")
}

func TestIPTrustStore_ListIncludesRevoked(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))
	require.NoError(t, store.RevokeTrustedRange(ctx, "tenant-1", "10.0.0.0/8"))

	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, entries[0].Revoked)
	assert.NotNil(t, entries[0].RevokedAt)
}

func TestIPTrustStore_ReactivateRevokedRange(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))
	require.NoError(t, store.RevokeTrustedRange(ctx, "tenant-1", "10.0.0.0/8"))

	// Re-adding after revoke should reactivate.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", true))

	trusted, err := store.IsTrusted(ctx, "tenant-1", "10.1.2.3")
	require.NoError(t, err)
	assert.True(t, trusted, "re-added CIDR must be trusted again")
}
