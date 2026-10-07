// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
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

	// Verify counts for all seeded store kinds, including RBAC and client_tenant.
	wantKinds := []string{
		"tenant", "config", "audit",
		"rbac_permission", "rbac_role", "rbac_subject", "rbac_role_assignment",
		"client_tenant",
		"registration_token", "session", "steward", "command",
		"trigger", "push",
		"ip_trust", "refresh_policy", "pending_refresh", "pending_registration",
	}
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

	// RBAC and client-tenant records must arrive field-for-field, not just as counts.
	assertRBACMatches(ctx, t, src, dst)
	assertClientTenantMatches(t, src, dst, "ct-tenant-seed-1")

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
		// approved → denied is forward progress, not a regression: an approved
		// entry stays claimable until ExpiresAt, so a source snapshot recording
		// the operator's later deny must carry across. Guarding the store's deny
		// transition on 'pending' alone would abort the migration here and leave
		// the destination approved, resurrecting a denied registration.
		{"approved destination advances to denied", business.PendingRegistrationStatusDenied, business.PendingRegistrationStatusApproved, business.PendingRegistrationStatusDenied},
		{"approved destination advances to expired", business.PendingRegistrationStatusExpired, business.PendingRegistrationStatusApproved, business.PendingRegistrationStatusExpired},
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

// TestStorageMigrator_RBACAndClientTenantUpsertOnRerun verifies the update half of
// the RBAC and client-tenant upserts: after a first migration the destination
// already holds every record, so a re-run must overwrite the existing rows with
// the current source values instead of failing or duplicating them.
func TestStorageMigrator_RBACAndClientTenantUpsertOnRerun(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedOSSManager(t, src)
	dst := newOSSManager(t)

	m := migratestorage.NewStorageMigrator(src, dst)
	_, err := m.Run(ctx)
	require.NoError(t, err, "first run must succeed")

	// Mutate every RBAC record and the client tenant at the source.
	rbac := src.GetRBACStore()
	require.NoError(t, rbac.StorePermission(ctx, &common.Permission{
		Id:           "perm-seed-1",
		Name:         "steward.register",
		Description:  "Register a steward (revised)",
		ResourceType: "steward",
		Actions:      []string{"create", "update"},
	}))
	require.NoError(t, rbac.StoreRole(ctx, &common.Role{
		Id:            "role-seed-1",
		Name:          "seed-role-renamed",
		Description:   "Seed role for migration tests (revised)",
		PermissionIds: []string{"perm-seed-1"},
	}))
	require.NoError(t, rbac.StoreSubject(ctx, &common.Subject{
		Id:          "subject-seed-1",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "seed-user-renamed",
		TenantId:    "tenant-seed-1",
		IsActive:    false,
	}))
	srcCT, err := src.GetClientTenantStore().GetClientTenant("ct-tenant-seed-1")
	require.NoError(t, err)
	srcCT.TenantName = "Seed Client Org (revised)"
	srcCT.Status = business.ClientTenantStatusSuspended
	require.NoError(t, src.GetClientTenantStore().StoreClientTenant(srcCT))

	report, err := m.Run(ctx)
	require.NoError(t, err, "re-run against a populated destination must succeed")

	// The destination now reflects the revised source values, with no duplicates.
	assertRBACMatches(ctx, t, src, dst)
	assertClientTenantMatches(t, src, dst, "ct-tenant-seed-1")

	dstRole, err := dst.GetRBACStore().GetRole(ctx, "role-seed-1")
	require.NoError(t, err)
	assert.Equal(t, "seed-role-renamed", dstRole.Name, "role update must reach the destination")
	dstSubj, err := dst.GetRBACStore().GetSubject(ctx, "subject-seed-1")
	require.NoError(t, err)
	assert.False(t, dstSubj.IsActive, "subject update must reach the destination")
	dstPerm, err := dst.GetRBACStore().GetPermission(ctx, "perm-seed-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"create", "update"}, dstPerm.Actions, "permission update must reach the destination")
	dstCT, err := dst.GetClientTenantStore().GetClientTenant("ct-tenant-seed-1")
	require.NoError(t, err)
	assert.Equal(t, business.ClientTenantStatusSuspended, dstCT.Status, "client tenant update must reach the destination")

	for _, kind := range []string{"rbac_permission", "rbac_role", "rbac_subject", "rbac_role_assignment", "client_tenant"} {
		assert.Equal(t, 1, report.Counts[kind], "re-run must migrate exactly one %q record", kind)
	}

	roles, err := dst.GetRBACStore().ListRoles(ctx, "")
	require.NoError(t, err)
	assert.Len(t, roles, 1, "re-run must not duplicate roles in the destination")
	perms, err := dst.GetRBACStore().ListPermissions(ctx, "")
	require.NoError(t, err)
	assert.Len(t, perms, 1, "re-run must not duplicate permissions in the destination")
	cts, err := dst.GetClientTenantStore().ListClientTenants("")
	require.NoError(t, err)
	assert.Len(t, cts, 1, "re-run must not duplicate client tenants in the destination")
}

// TestStorageMigrator_UnsupportedKind_DefaultFails verifies that migrating a kind
// the destination cannot accept fails loudly by default, with an error naming the
// kind, the number of records affected, and the destination provider.
func TestStorageMigrator_UnsupportedKind_DefaultFails(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedTriggerOnly(t, src)
	dst := newOSSManagerWithoutTriggerAndPush(t)

	m := migratestorage.NewStorageMigrator(src, dst)

	planErr := func() error {
		_, err := m.Plan(ctx)
		return err
	}()
	runErr := func() error {
		_, err := m.Run(ctx)
		return err
	}()

	// Both Plan and Run must fail.
	require.Error(t, planErr, "Plan must fail when destination lacks trigger store")
	require.Error(t, runErr, "Run must fail when destination lacks trigger store")

	// The error must name the kind, the affected count, and the destination provider.
	for label, err := range map[string]error{"Plan": planErr, "Run": runErr} {
		assert.True(t, strings.Contains(err.Error(), "trigger"),
			"%s error must name the unsupported kind", label)
		assert.True(t, strings.Contains(err.Error(), "1 record"),
			"%s error must name the record count", label)
		assert.True(t, strings.Contains(err.Error(), "composite"),
			"%s error must name the destination provider", label)
	}
}

// TestStorageMigrator_UnsupportedKind_DryRunMatchesLive verifies that Plan (dry-run)
// and Run produce the same error when the destination cannot accept a kind, so that
// operators learn about an unmigratable kind from the dry run, not a post-mortem.
func TestStorageMigrator_UnsupportedKind_DryRunMatchesLive(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedTriggerOnly(t, src)
	dst := newOSSManagerWithoutTriggerAndPush(t)

	m := migratestorage.NewStorageMigrator(src, dst)

	_, planErr := m.Plan(ctx)
	_, runErr := m.Run(ctx)

	require.Error(t, planErr, "Plan must fail")
	require.Error(t, runErr, "Run must fail")

	// Identical error class: both must mention the same unsupported kind.
	assert.Contains(t, planErr.Error(), "trigger",
		"Plan error must name the unsupported kind")
	assert.Contains(t, runErr.Error(), "trigger",
		"Run error must name the unsupported kind")
}

// TestStorageMigrator_UnsupportedKind_NoWritesOnFailure verifies that when the
// pre-flight check fails, no records are written to the destination.
func TestStorageMigrator_UnsupportedKind_NoWritesOnFailure(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedTriggerOnly(t, src)
	dst := newOSSManagerWithoutTriggerAndPush(t)

	m := migratestorage.NewStorageMigrator(src, dst)

	_, err := m.Run(ctx)
	require.Error(t, err, "Run must fail")

	// Re-export from destination: must be empty (no writes happened).
	dstSrc := newOSSManager(t)
	dstMigrator := migratestorage.NewStorageMigrator(dst, dstSrc)
	report, err2 := dstMigrator.Plan(ctx)
	require.NoError(t, err2)
	total := 0
	for _, c := range report.Counts {
		total += c
	}
	assert.Equal(t, 0, total, "destination must be empty after a failed run")
}

// TestStorageMigrator_AcknowledgedSkip verifies that WithSkippedKinds allows
// migration to proceed when the destination cannot accept those kinds, and that
// the skipped kinds appear in the MigrationReport with their source counts.
// The default path (without the option) must still fail.
func TestStorageMigrator_AcknowledgedSkip(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedTriggerOnly(t, src)
	seedPushOnly(t, src)
	dst := newOSSManagerWithoutTriggerAndPush(t)

	// Without the option: default fails.
	noSkip := migratestorage.NewStorageMigrator(src, dst)
	_, err := noSkip.Plan(ctx)
	require.Error(t, err, "default path must fail when destination lacks trigger/push")

	// With explicit acknowledged skip: both Plan and Run succeed.
	withSkip := migratestorage.NewStorageMigrator(src, dst,
		migratestorage.WithSkippedKinds("trigger", "push"))

	planReport, planErr := withSkip.Plan(ctx)
	require.NoError(t, planErr, "Plan must succeed with acknowledged skip")

	runReport, runErr := withSkip.Run(ctx)
	require.NoError(t, runErr, "Run must succeed with acknowledged skip")

	// Both reports must name the abandoned kinds with their source counts.
	for label, report := range map[string]migrate.MigrationReport{"Plan": planReport, "Run": runReport} {
		require.NotNil(t, report.SkippedKinds,
			"%s: report.SkippedKinds must not be nil when kinds are skipped", label)
		assert.Equal(t, 1, report.SkippedKinds["trigger"],
			"%s: SkippedKinds[trigger] must be 1", label)
		assert.Equal(t, 1, report.SkippedKinds["push"],
			"%s: SkippedKinds[push] must be 1", label)
	}
}

// TestStorageMigrator_AcknowledgedSkip_RecordsNotImported verifies that records
// of acknowledged-skip kinds are not written to the destination.
func TestStorageMigrator_AcknowledgedSkip_RecordsNotImported(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedTriggerOnly(t, src)
	dst := newOSSManagerWithoutTriggerAndPush(t)

	m := migratestorage.NewStorageMigrator(src, dst, migratestorage.WithSkippedKinds("trigger"))
	_, err := m.Run(ctx)
	require.NoError(t, err, "Run must succeed with acknowledged trigger skip")

	// Destination trigger store is nil — no trigger records could have been written.
	// Verify by re-exporting from dst into a full OSS manager and checking trigger count.
	dst2 := newOSSManager(t)
	m2 := migratestorage.NewStorageMigrator(dst, dst2)
	report, err2 := m2.Plan(ctx)
	require.NoError(t, err2, "re-export from dst must succeed")
	assert.Equal(t, 0, report.Counts["trigger"],
		"trigger records must not have been written to the destination")
}

// TestStorageMigrator_SkipSupportedKindFails verifies that WithSkippedKinds
// rejects any kind the destination DOES support. Accepting it would silently
// drop records the destination could have received, defeating the explicit-
// acknowledgement contract.
func TestStorageMigrator_SkipSupportedKindFails(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedOSSManager(t, src)
	dst := newOSSManager(t) // full OSS — supports every kind including "session"

	m := migratestorage.NewStorageMigrator(src, dst,
		migratestorage.WithSkippedKinds("session"))

	_, planErr := m.Plan(ctx)
	require.Error(t, planErr, "Plan must fail when skipping a kind the destination supports")
	assert.Contains(t, planErr.Error(), "session",
		"error must name the spuriously-skipped kind")
	assert.True(t, strings.Contains(planErr.Error(), "supports") ||
		strings.Contains(planErr.Error(), "supported"),
		"error must indicate the destination supports the kind")

	_, runErr := m.Run(ctx)
	require.Error(t, runErr, "Run must fail when skipping a kind the destination supports")
	assert.Contains(t, runErr.Error(), "session",
		"error must name the spuriously-skipped kind")
}

// TestStorageMigrator_AcknowledgedSkip_IdempotentRerun verifies that an
// idempotent re-run after a partial migration converges when skip kinds are acknowledged.
func TestStorageMigrator_AcknowledgedSkip_IdempotentRerun(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedOSSManager(t, src)
	dst := newOSSManagerWithoutTriggerAndPush(t)

	m := migratestorage.NewStorageMigrator(src, dst, migratestorage.WithSkippedKinds("trigger", "push"))

	report1, err := m.Run(ctx)
	require.NoError(t, err, "first run must succeed")

	report2, err := m.Run(ctx)
	require.NoError(t, err, "second (idempotent) run must succeed")

	// Per-kind counts must be identical between runs.
	for kind, c1 := range report1.Counts {
		c2, ok := report2.Counts[kind]
		assert.True(t, ok, "second run must report kind %q", kind)
		assert.Equal(t, c1, c2, "second run count for %q must match first", kind)
	}
}
