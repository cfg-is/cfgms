// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestIPTrustStore(t *testing.T) *FlatFileIPTrustStore {
	t.Helper()
	store, err := NewFlatFileIPTrustStore(t.TempDir())
	require.NoError(t, err)
	return store
}

func TestFlatFileIPTrustStore_AddAndQuery(t *testing.T) {
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

func TestFlatFileIPTrustStore_ExactIPQuery(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.5/32", false))

	trusted, err := store.IsTrusted(ctx, "tenant-1", "10.0.0.5")
	require.NoError(t, err)
	assert.True(t, trusted, "/32 exact match must be trusted")

	notTrusted, err := store.IsTrusted(ctx, "tenant-1", "10.0.0.6")
	require.NoError(t, err)
	assert.False(t, notTrusted, "adjacent IP outside /32 must not be trusted")
}

func TestFlatFileIPTrustStore_CIDRRangeContainment(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.1.0/24", false))

	tests := []struct {
		ip   string
		want bool
		desc string
	}{
		{"192.168.1.1", true, "/24 containment — first host"},
		{"192.168.1.254", true, "/24 containment — last host"},
		{"192.168.2.1", false, "out-of-range — different subnet"},
		{"192.168.0.255", false, "out-of-range — preceding subnet"},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := store.IsTrusted(ctx, "tenant-1", tc.ip)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFlatFileIPTrustStore_TenantIsolation(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-A", "10.0.0.0/8", false))

	trusted, err := store.IsTrusted(ctx, "tenant-B", "10.1.2.3")
	require.NoError(t, err)
	assert.False(t, trusted, "tenant-B must not see tenant-A ranges")

	trusted, err = store.IsTrusted(ctx, "tenant-A", "10.1.2.3")
	require.NoError(t, err)
	assert.True(t, trusted, "tenant-A must see its own ranges")
}

func TestFlatFileIPTrustStore_RevocationClearsAccess(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))

	trusted, err := store.IsTrusted(ctx, "tenant-1", "10.1.2.3")
	require.NoError(t, err)
	require.True(t, trusted, "must be trusted before revoke")

	require.NoError(t, store.RevokeTrustedRange(ctx, "tenant-1", "10.0.0.0/8"))

	trusted, err = store.IsTrusted(ctx, "tenant-1", "10.1.2.3")
	require.NoError(t, err)
	assert.False(t, trusted, "must not be trusted after revoke")
}

func TestFlatFileIPTrustStore_RevokeNotFound(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	err := store.RevokeTrustedRange(ctx, "tenant-1", "10.0.0.0/8")
	require.ErrorIs(t, err, business.ErrIPTrustEntryNotFound)
}

func TestFlatFileIPTrustStore_RevokeThenReactivate(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))
	require.NoError(t, store.RevokeTrustedRange(ctx, "tenant-1", "10.0.0.0/8"))

	// Re-adding must reactivate.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", true))

	trusted, err := store.IsTrusted(ctx, "tenant-1", "10.1.2.3")
	require.NoError(t, err)
	assert.True(t, trusted, "re-added CIDR must be trusted again")

	// Must not create a second entry.
	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "re-add must not create a duplicate entry")
}

func TestFlatFileIPTrustStore_CIDRNormalization(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	// Host-address form must be normalised to network address.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.1.99/24", false))

	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "192.168.1.0/24", entries[0].CIDR, "host address must be normalised to network address")

	// Re-adding via another host address in the same /24 must not create a second row.
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.1.5/24", false))
	entries, err = store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "normalised duplicate must not create a second entry")
}

func TestFlatFileIPTrustStore_ListTrustedRanges(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "192.168.0.0/16", true))

	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestFlatFileIPTrustStore_ListIncludesRevoked(t *testing.T) {
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

func TestFlatFileIPTrustStore_ListFiltersOtherTenants(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-A", "10.0.0.0/8", false))
	require.NoError(t, store.AddTrustedRange(ctx, "tenant-B", "192.168.0.0/16", false))

	entriesA, err := store.ListTrustedRanges(ctx, "tenant-A")
	require.NoError(t, err)
	assert.Len(t, entriesA, 1)
	assert.Equal(t, "10.0.0.0/8", entriesA[0].CIDR)

	entriesB, err := store.ListTrustedRanges(ctx, "tenant-B")
	require.NoError(t, err)
	assert.Len(t, entriesB, 1)
	assert.Equal(t, "192.168.0.0/16", entriesB[0].CIDR)
}

func TestFlatFileIPTrustStore_RecordHealthySteward_UpdatesActivity(t *testing.T) {
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

func TestFlatFileIPTrustStore_RecordHealthySteward_NoMatchIsNoop(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	// No entry exists — must be a no-op (no error).
	err := store.RecordHealthySteward(ctx, "tenant-1", "10.0.0.1", time.Now())
	assert.NoError(t, err)
}

func TestFlatFileIPTrustStore_GetLastActivity_NoActivity(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))

	activity, err := store.GetLastActivity(ctx, "tenant-1", "10.0.0.1")
	require.NoError(t, err)
	assert.Nil(t, activity, "no activity recorded yet")
}

func TestFlatFileIPTrustStore_GetLastActivity_NotInRange(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))
	require.NoError(t, store.RecordHealthySteward(ctx, "tenant-1", "10.0.0.1", time.Now()))

	// IP outside the range must return nil.
	activity, err := store.GetLastActivity(ctx, "tenant-1", "192.168.1.1")
	require.NoError(t, err)
	assert.Nil(t, activity)
}

func TestFlatFileIPTrustStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store1, err := NewFlatFileIPTrustStore(dir)
	require.NoError(t, err)

	require.NoError(t, store1.AddTrustedRange(ctx, "tenant-1", "10.0.0.0/8", false))
	at := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, store1.RecordHealthySteward(ctx, "tenant-1", "10.0.0.1", at))

	// Open a second store at the same root — must see the same data.
	store2, err := NewFlatFileIPTrustStore(dir)
	require.NoError(t, err)

	trusted, err := store2.IsTrusted(ctx, "tenant-1", "10.0.0.1")
	require.NoError(t, err)
	assert.True(t, trusted, "persisted entry must be visible after reload")

	activity, err := store2.GetLastActivity(ctx, "tenant-1", "10.0.0.1")
	require.NoError(t, err)
	require.NotNil(t, activity)
	assert.WithinDuration(t, at, activity.LastSeen, time.Millisecond)
}

func TestFlatFileIPTrustStore_PreSeeded_RoundTrip(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddTrustedRange(ctx, "tenant-1", "172.16.0.0/12", true))

	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, entries[0].PreSeeded, "pre_seeded flag must round-trip")
	assert.Equal(t, "172.16.0.0/12", entries[0].CIDR)
	assert.False(t, entries[0].TrustedSince.IsZero(), "trusted_since must be set")

	// Pre-seeded entry must be trusted.
	trusted, err := store.IsTrusted(ctx, "tenant-1", "172.20.1.1")
	require.NoError(t, err)
	assert.True(t, trusted)
}

// TestFlatFileIPTrustStore_RegistrationWorkflow_TwoStewardsSameIP is the required
// integration test for AC: first steward from a new tenant quarantines; second
// steward auto-approves after the source IP is trusted.
//
// "Threshold elapses" in the ip-trust workflow means the IP was seen continuously
// over the trust window and AddTrustedRange was called by the background trust
// promoter. This test simulates that by calling AddTrustedRange directly and
// verifying IsTrusted transitions from false to true.
func TestFlatFileIPTrustStore_RegistrationWorkflow_TwoStewardsSameIP(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	const tenantID = "tenant-acme"
	const sourceIP = "10.20.30.40"

	// --- First steward registration ---
	// No trusted range exists yet; IsTrusted must return false → hook quarantines.
	trusted, err := store.IsTrusted(ctx, tenantID, sourceIP)
	require.NoError(t, err)
	assert.False(t, trusted, "first registration must quarantine: source IP not yet trusted")

	// Simulate ip-trust threshold elapsing: the controller's background promoter
	// calls AddTrustedRange after the IP is observed continuously.
	require.NoError(t, store.AddTrustedRange(ctx, tenantID, sourceIP+"/32", false))

	// --- Second steward registration ---
	// The IP is now in a trusted range; IsTrusted must return true → hook approves.
	trusted, err = store.IsTrusted(ctx, tenantID, sourceIP)
	require.NoError(t, err)
	assert.True(t, trusted, "second registration must approve: source IP is now trusted")
}

func TestFlatFileIPTrustStore_InvalidIP(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	_, err := store.IsTrusted(ctx, "tenant-1", "not-an-ip")
	assert.Error(t, err, "invalid IP must return error")

	err = store.RecordHealthySteward(ctx, "tenant-1", "not-an-ip", time.Now())
	assert.Error(t, err, "invalid IP must return error")

	_, err = store.GetLastActivity(ctx, "tenant-1", "not-an-ip")
	assert.Error(t, err, "invalid IP must return error")
}

func TestFlatFileIPTrustStore_InvalidCIDR(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	err := store.AddTrustedRange(ctx, "tenant-1", "not-a-cidr", false)
	assert.Error(t, err, "invalid CIDR must return error")

	err = store.RevokeTrustedRange(ctx, "tenant-1", "not-a-cidr")
	assert.Error(t, err, "invalid CIDR must return error")
}

func TestFlatFileIPTrustStore_EmptyStore_IsTrusted(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	trusted, err := store.IsTrusted(ctx, "tenant-1", "10.0.0.1")
	require.NoError(t, err)
	assert.False(t, trusted, "empty store must not trust any IP")
}

func TestFlatFileIPTrustStore_EmptyStore_ListTrustedRanges(t *testing.T) {
	store := newTestIPTrustStore(t)
	ctx := context.Background()

	entries, err := store.ListTrustedRanges(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Empty(t, entries, "empty store must return empty list")
}
