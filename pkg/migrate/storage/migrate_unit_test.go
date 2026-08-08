// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/migrate"
	migratestorage "github.com/cfgis/cfgms/pkg/migrate/storage"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestStorageMigratorFactory_Registered verifies that importing pkg/migrate/storage
// registers the "storage" factory in the migrate registry.
func TestStorageMigratorFactory_Registered(t *testing.T) {
	factory, err := migrate.Lookup("storage")
	require.NoError(t, err, "storage factory must be registered via init()")
	assert.NotNil(t, factory)
}

// TestStorageMigratorFactory_UnknownBackend verifies that the factory rejects
// an unknown from-backend name with a descriptive error.
func TestStorageMigratorFactory_UnknownBackend(t *testing.T) {
	factory, err := migrate.Lookup("storage")
	require.NoError(t, err)

	_, err = factory("bogus-backend", "oss")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus-backend")
}

// TestStorageMigratorFactory_OSSMissingEnv verifies that the factory returns an
// error when the oss backend is requested but the required env vars are absent.
func TestStorageMigratorFactory_OSSMissingEnv(t *testing.T) {
	// Ensure the env vars are absent for this test.
	t.Setenv("CFGMS_STORAGE_FLATFILE_ROOT", "")
	t.Setenv("CFGMS_STORAGE_SQLITE_PATH", "")

	factory, err := migrate.Lookup("storage")
	require.NoError(t, err)

	_, err = factory("oss", "oss")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_STORAGE_FLATFILE_ROOT")
}

// TestNewStorageMigrator_NilPanics verifies that passing a nil StorageManager
// panics with a clear message.
func TestNewStorageMigrator_NilPanics(t *testing.T) {
	assert.Panics(t, func() {
		migratestorage.NewStorageMigrator(nil, nil)
	})
}

// TestStorageMigrator_PlanEmpty verifies that Plan on an empty OSS backend
// returns zero counts and no error.
func TestStorageMigrator_PlanEmpty(t *testing.T) {
	src := newOSSManager(t)
	dst := newOSSManager(t)

	m := migratestorage.NewStorageMigrator(src, dst)
	report, err := m.Plan(context.Background())
	require.NoError(t, err)
	total := 0
	for _, c := range report.Counts {
		total += c
	}
	assert.Equal(t, 0, total, "empty source must produce zero-count plan")
}

// TestStorageMigrator_RunEmpty verifies that migrating an empty source to an
// empty target succeeds with zero records.
func TestStorageMigrator_RunEmpty(t *testing.T) {
	src := newOSSManager(t)
	dst := newOSSManager(t)

	m := migratestorage.NewStorageMigrator(src, dst)
	report, err := m.Run(context.Background())
	require.NoError(t, err)
	total := 0
	for _, c := range report.Counts {
		total += c
	}
	assert.Equal(t, 0, total, "empty source must produce zero-count run report")
}

// TestStorageMigrator_OSStoOSSRoundTrip migrates a seeded OSS source to a
// second OSS target and verifies per-store counts are preserved — no Postgres needed.
func TestStorageMigrator_OSStoOSSRoundTrip(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedOSSManager(t, src)
	dst := newOSSManager(t)

	// Capture the source pending-registration entries before migration so the
	// post-migration comparison below is against actual source state, not
	// against literals that could drift from seedOSSManager.
	srcPending, err := src.GetPendingRegistrationStore().GetPendingByID(ctx, "pending-reg-seed-1")
	require.NoError(t, err, "read back source pending-reg-seed-1")
	srcClaimed, err := src.GetPendingRegistrationStore().GetPendingByID(ctx, "pending-reg-seed-2")
	require.NoError(t, err, "read back source pending-reg-seed-2")

	m := migratestorage.NewStorageMigrator(src, dst)
	report, err := m.Run(ctx)
	require.NoError(t, err, "OSS→OSS migration must succeed")

	// Verify counts for the non-RBAC stores we seeded.
	wantKinds := []string{"tenant", "config", "audit", "registration_token", "session", "steward", "command", "trigger", "push", "ip_trust", "refresh_policy", "pending_refresh", "pending_registration"}
	for _, kind := range wantKinds {
		c, ok := report.Counts[kind]
		assert.True(t, ok, "expected kind %q in OSS→OSS report", kind)
		assert.Greater(t, c, 0, "expected at least one %q record in OSS→OSS report", kind)
	}

	// A freshly-migrated (not pre-seeded in dest) pending-registration entry must
	// carry every field through unchanged — not just a count.
	dstPending, err := dst.GetPendingRegistrationStore().GetPendingByID(ctx, "pending-reg-seed-1")
	require.NoError(t, err, "read back destination pending-reg-seed-1")
	assert.Equal(t, srcPending.StewardID, dstPending.StewardID, "pending-reg-seed-1 StewardID")
	assert.Equal(t, srcPending.TenantID, dstPending.TenantID, "pending-reg-seed-1 TenantID")
	assert.Equal(t, srcPending.TokenStr, dstPending.TokenStr, "pending-reg-seed-1 TokenStr")
	assert.Equal(t, srcPending.SourceIP, dstPending.SourceIP, "pending-reg-seed-1 SourceIP")
	assert.Equal(t, srcPending.Status, dstPending.Status, "pending-reg-seed-1 Status")
	assert.True(t, srcPending.RegisteredAt.Equal(dstPending.RegisteredAt), "pending-reg-seed-1 RegisteredAt")
	assert.True(t, srcPending.ExpiresAt.Equal(dstPending.ExpiresAt), "pending-reg-seed-1 ExpiresAt")
	assert.Nil(t, dstPending.ClaimedAt, "pending-reg-seed-1 ClaimedAt")

	dstClaimed, err := dst.GetPendingRegistrationStore().GetPendingByID(ctx, "pending-reg-seed-2")
	require.NoError(t, err, "read back destination pending-reg-seed-2")
	assert.Equal(t, srcClaimed.StewardID, dstClaimed.StewardID, "pending-reg-seed-2 StewardID")
	assert.Equal(t, srcClaimed.TenantID, dstClaimed.TenantID, "pending-reg-seed-2 TenantID")
	assert.Equal(t, srcClaimed.TokenStr, dstClaimed.TokenStr, "pending-reg-seed-2 TokenStr")
	assert.Equal(t, srcClaimed.SourceIP, dstClaimed.SourceIP, "pending-reg-seed-2 SourceIP")
	assert.Equal(t, srcClaimed.Status, dstClaimed.Status, "pending-reg-seed-2 Status")
	assert.True(t, srcClaimed.RegisteredAt.Equal(dstClaimed.RegisteredAt), "pending-reg-seed-2 RegisteredAt")
	assert.True(t, srcClaimed.ExpiresAt.Equal(dstClaimed.ExpiresAt), "pending-reg-seed-2 ExpiresAt")
	if assert.NotNil(t, dstClaimed.ClaimedAt, "pending-reg-seed-2 ClaimedAt") {
		assert.True(t, srcClaimed.ClaimedAt.Equal(*dstClaimed.ClaimedAt), "pending-reg-seed-2 ClaimedAt")
	}
}

// TestStorageMigrator_PendingRegistrationStatusResync verifies that re-running a
// migration against a destination that has advanced past the source snapshot
// never regresses a registration out of a terminal state, and never undoes an
// operator approval. A claimed → approved regression would let a steward that
// still holds its token claim a second certificate for the same pending_id.
func TestStorageMigrator_PendingRegistrationStatusResync(t *testing.T) {
	cases := []struct {
		name   string
		source string
		dest   string
		want   string
	}{
		{"claimed destination is not re-armed by approved source", business.PendingRegistrationStatusApproved, business.PendingRegistrationStatusClaimed, business.PendingRegistrationStatusClaimed},
		{"claimed destination is not regressed to pending", business.PendingRegistrationStatusPending, business.PendingRegistrationStatusClaimed, business.PendingRegistrationStatusClaimed},
		{"denied destination is not resurrected", business.PendingRegistrationStatusPending, business.PendingRegistrationStatusDenied, business.PendingRegistrationStatusDenied},
		{"denied destination is not re-approved", business.PendingRegistrationStatusApproved, business.PendingRegistrationStatusDenied, business.PendingRegistrationStatusDenied},
		{"expired destination is not revived", business.PendingRegistrationStatusPending, business.PendingRegistrationStatusExpired, business.PendingRegistrationStatusExpired},
		{"approved destination is not regressed to pending", business.PendingRegistrationStatusPending, business.PendingRegistrationStatusApproved, business.PendingRegistrationStatusApproved},
		{"pending destination advances to approved", business.PendingRegistrationStatusApproved, business.PendingRegistrationStatusPending, business.PendingRegistrationStatusApproved},
		{"pending destination advances to denied", business.PendingRegistrationStatusDenied, business.PendingRegistrationStatusPending, business.PendingRegistrationStatusDenied},
		{"pending destination advances to expired", business.PendingRegistrationStatusExpired, business.PendingRegistrationStatusPending, business.PendingRegistrationStatusExpired},
		{"approved destination advances to claimed", business.PendingRegistrationStatusClaimed, business.PendingRegistrationStatusApproved, business.PendingRegistrationStatusClaimed},
		{"matching status is left alone", business.PendingRegistrationStatusApproved, business.PendingRegistrationStatusApproved, business.PendingRegistrationStatusApproved},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			src := newOSSManager(t)
			seedPendingRegistration(t, src, "pending-reg-resync", tc.source)
			dst := newOSSManager(t)
			seedPendingRegistration(t, dst, "pending-reg-resync", tc.dest)

			_, err := migratestorage.NewStorageMigrator(src, dst).Run(ctx)
			require.NoError(t, err, "migration must succeed")

			got := pendingRegistrationStatus(t, dst, "pending-reg-resync")
			assert.Equal(t, tc.want, got.Status, "destination status after resync")
		})
	}
}

// TestStorageMigrator_PendingRegistrationPendingToClaimed verifies that a
// destination still at "pending" is walked forward to "claimed" (through
// approved, which the store's claim guard requires) so that an operator cannot
// later approve a registration the steward has already claimed.
func TestStorageMigrator_PendingRegistrationPendingToClaimed(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedPendingRegistration(t, src, "pending-reg-claimed", business.PendingRegistrationStatusClaimed)
	dst := newOSSManager(t)
	seedPendingRegistration(t, dst, "pending-reg-claimed", business.PendingRegistrationStatusPending)

	_, err := migratestorage.NewStorageMigrator(src, dst).Run(ctx)
	require.NoError(t, err, "migration must succeed")

	got := pendingRegistrationStatus(t, dst, "pending-reg-claimed")
	assert.Equal(t, business.PendingRegistrationStatusClaimed, got.Status)
	assert.NotNil(t, got.ClaimedAt, "claimed_at must be persisted with the claimed status")
}

// TestStorageMigrator_PendingRegistrationUnknownStatus verifies that an
// unrecognized lifecycle status fails the migration loudly instead of being
// written blindly into the destination.
func TestStorageMigrator_PendingRegistrationUnknownStatus(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedPendingRegistration(t, src, "pending-reg-bogus", "not-a-status")
	dst := newOSSManager(t)
	seedPendingRegistration(t, dst, "pending-reg-bogus", business.PendingRegistrationStatusPending)

	_, err := migratestorage.NewStorageMigrator(src, dst).Run(ctx)
	require.Error(t, err, "unrecognized source status must fail the migration")
	assert.Contains(t, err.Error(), "unrecognized status")

	got := pendingRegistrationStatus(t, dst, "pending-reg-bogus")
	assert.Equal(t, business.PendingRegistrationStatusPending, got.Status, "destination must be untouched")
}

// TestStorageMigrator_OSStoOSS_Idempotent verifies that the OSS→OSS migration
// is idempotent: running it twice yields equal counts without duplicates.
func TestStorageMigrator_OSStoOSS_Idempotent(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedOSSManager(t, src)
	dst := newOSSManager(t)

	m := migratestorage.NewStorageMigrator(src, dst)

	report1, err := m.Run(ctx)
	require.NoError(t, err, "first OSS→OSS run must succeed")

	report2, err := m.Run(ctx)
	require.NoError(t, err, "second OSS→OSS run must succeed (idempotent)")

	for kind, c1 := range report1.Counts {
		c2, ok := report2.Counts[kind]
		assert.True(t, ok, "second run must include kind %q", kind)
		assert.Equal(t, c1, c2, "second run count for %q must match first", kind)
	}
}
