// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgmstesting "github.com/cfgis/cfgms/pkg/testing"
)

// makeSuspendedSubtree creates root → child → grandchild all suspended, then suspends them
// so they're in the right state for RequestTenantDeletion.
func makeSuspendedSubtree(t *testing.T, m *Manager) (rootID, childID, grandID string) {
	t.Helper()
	ctx := context.Background()

	root, err := m.CreateTenant(ctx, &TenantRequest{Name: "Del-Root"})
	require.NoError(t, err)
	rootID = root.ID

	child, err := m.CreateTenant(ctx, &TenantRequest{Name: "Del-Child", ParentID: rootID})
	require.NoError(t, err)
	childID = child.ID

	grand, err := m.CreateTenant(ctx, &TenantRequest{Name: "Del-Grand", ParentID: childID})
	require.NoError(t, err)
	grandID = grand.ID

	_, err = m.SuspendTenant(ctx, rootID)
	require.NoError(t, err)
	return
}

func TestRequestTenantDeletion_SubtreeNotFullySuspended(t *testing.T) {
	m := newTestTenantManager(t)
	ctx := context.Background()

	root, err := m.CreateTenant(ctx, &TenantRequest{Name: "Root"})
	require.NoError(t, err)
	child, err := m.CreateTenant(ctx, &TenantRequest{Name: "Child", ParentID: root.ID})
	require.NoError(t, err)

	// Manually mark root as suspended without cascading to child (child stays active).
	rootTenant, err := m.store.GetTenant(ctx, root.ID)
	require.NoError(t, err)
	rootTenant.Status = business.TenantStatusSuspended
	rootTenant.DirectlySuspended = true
	require.NoError(t, m.store.UpdateTenant(ctx, rootTenant))

	// child remains active — RequestTenantDeletion should find it and reject.
	_, err = m.RequestTenantDeletion(ctx, root.ID, "alice", 720*time.Hour)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTenantNotFullySuspended),
		"expected ErrTenantNotFullySuspended, got: %v", err)
	// Error message should name the unsuspended descendant.
	assert.Contains(t, err.Error(), child.ID)
}

func TestRequestTenantDeletion_StartsHoldTimer(t *testing.T) {
	m := newTestTenantManager(t)
	rootID, _, _ := makeSuspendedSubtree(t, m)
	ctx := context.Background()

	holdPeriod := 30 * 24 * time.Hour
	before := time.Now()
	pending, err := m.RequestTenantDeletion(ctx, rootID, "alice", holdPeriod)
	require.NoError(t, err)

	assert.Equal(t, rootID, pending.SubtreeRootID)
	assert.Equal(t, "alice", pending.RequestedBy)
	assert.True(t, pending.EligibleAt.After(before.Add(holdPeriod-time.Second)),
		"eligible_at must be at least holdPeriod from now")
	assert.Equal(t, business.DeletionStateHold, pending.State)
	assert.Contains(t, pending.PinnedMemberIDs, rootID)
}

func TestCreateTenant_RejectsUnderSuspendedParent(t *testing.T) {
	m := newTestTenantManager(t)
	ctx := context.Background()

	parent, err := m.CreateTenant(ctx, &TenantRequest{Name: "Parent"})
	require.NoError(t, err)

	_, err = m.SuspendTenant(ctx, parent.ID)
	require.NoError(t, err)

	_, err = m.CreateTenant(ctx, &TenantRequest{Name: "Child", ParentID: parent.ID})
	require.Error(t, err, "creating a tenant under a suspended parent must be rejected")
}

func TestCreateTenant_RejectsUnderParentWithPendingDeletion(t *testing.T) {
	m := newTestTenantManager(t)
	ctx := context.Background()

	rootID, _, _ := makeSuspendedSubtree(t, m)

	_, err := m.RequestTenantDeletion(ctx, rootID, "alice", 720*time.Hour)
	require.NoError(t, err)

	_, err = m.CreateTenant(ctx, &TenantRequest{Name: "NewChild", ParentID: rootID})
	require.Error(t, err, "creating a tenant under a parent with a pending deletion must be rejected")
}

func TestCancelTenantDeletion(t *testing.T) {
	m := newTestTenantManager(t)
	rootID, _, _ := makeSuspendedSubtree(t, m)
	ctx := context.Background()

	_, err := m.RequestTenantDeletion(ctx, rootID, "alice", 720*time.Hour)
	require.NoError(t, err)

	require.NoError(t, m.CancelTenantDeletion(ctx, rootID))

	// Pending record must be gone.
	_, err = m.GetPendingDeletion(ctx, rootID)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)

	// Subtree must still exist and remain suspended — cancel does not restore.
	root, err := m.GetTenant(ctx, rootID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, root.Status)
}

func TestGetPendingDeletion_NotFound(t *testing.T) {
	m := newTestTenantManager(t)
	ctx := context.Background()

	_, err := m.GetPendingDeletion(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

// TestGetPendingDeletion_StateReflectsElapsedHold pins the fix for a stale read path:
// storage writes State: DeletionStateHold once at request time and no production
// code path ever transitions it to DeletionStateEligible (ApproveDeletion branches on
// EligibleAt directly, never on the stored column). Without deriving State from
// EligibleAt on read, GET would report "hold" forever, even long after the hold
// period elapsed and the deletion became approvable.
func TestGetPendingDeletion_StateReflectsElapsedHold(t *testing.T) {
	m := newTestTenantManager(t)
	rootID, _, _ := makeSuspendedSubtree(t, m)
	ctx := context.Background()

	// Freshly requested: hold period has not elapsed yet.
	pending, err := m.RequestTenantDeletion(ctx, rootID, "alice", 720*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, business.DeletionStateHold, pending.State)

	got, err := m.GetPendingDeletion(ctx, rootID)
	require.NoError(t, err)
	assert.Equal(t, business.DeletionStateHold, got.State, "hold period has not elapsed")

	require.NoError(t, m.CancelTenantDeletion(ctx, rootID))

	// Re-suspend (cancel returns to plain Suspended, which it already is) and request
	// again with an elapsed hold period by writing the pending record directly.
	now := time.Now()
	elapsed := &business.PendingDeletion{
		SubtreeRootID:   rootID,
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateHold, // stored as Hold even though elapsed
		PinnedMemberIDs: []string{rootID},
	}
	require.NoError(t, m.store.RequestDeletion(ctx, elapsed))

	got, err = m.GetPendingDeletion(ctx, rootID)
	require.NoError(t, err)
	assert.Equal(t, business.DeletionStateEligible, got.State,
		"GetPendingDeletion must derive Eligible from EligibleAt, not trust the stale stored state")
}

func TestApproveTenantDeletion_HoldNotElapsed(t *testing.T) {
	m := newTestTenantManager(t)
	rootID, _, _ := makeSuspendedSubtree(t, m)
	ctx := context.Background()

	_, err := m.RequestTenantDeletion(ctx, rootID, "alice", 720*time.Hour)
	require.NoError(t, err)

	_, err = m.ApproveTenantDeletion(ctx, rootID, "bob", true)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrHoldNotElapsed)
}

func TestApproveTenantDeletion_SameApproverRejected(t *testing.T) {
	m := newTestTenantManager(t)
	rootID, childID, grandID := makeSuspendedSubtree(t, m)
	ctx := context.Background()
	_ = childID
	_ = grandID

	// Use a minimal hold period so we can test by injecting an elapsed pending record.
	store := cfgmstesting.SetupTestStorage(t)
	m2 := NewManager(store.GetTenantStore(), nil)

	// Create the subtree in store2.
	for _, td := range []struct{ id, parent string }{
		{rootID, ""},
		{childID, rootID},
		{grandID, childID},
	} {
		ts := business.TenantData{
			ID:                td.id,
			Name:              td.id,
			ParentID:          td.parent,
			Status:            business.TenantStatusSuspended,
			DirectlySuspended: true,
		}
		require.NoError(t, store.GetTenantStore().CreateTenant(ctx, &ts))
	}

	now := time.Now()
	pending := &business.PendingDeletion{
		SubtreeRootID:   rootID,
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: []string{rootID, childID, grandID},
	}
	require.NoError(t, store.GetTenantStore().RequestDeletion(ctx, pending))

	_, err := m2.ApproveTenantDeletion(ctx, rootID, "alice", true)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrSameApprover)
}

func TestApproveTenantDeletion_DualControlDisabledAllowsSameApprover(t *testing.T) {
	store := cfgmstesting.SetupTestStorage(t)
	m := NewManager(store.GetTenantStore(), nil)
	ctx := context.Background()

	rootID := "del-root"
	now := time.Now()
	td := business.TenantData{
		ID:                rootID,
		Name:              "Del-Root",
		Status:            business.TenantStatusSuspended,
		DirectlySuspended: true,
	}
	require.NoError(t, store.GetTenantStore().CreateTenant(ctx, &td))

	pending := &business.PendingDeletion{
		SubtreeRootID:   rootID,
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: []string{rootID},
	}
	require.NoError(t, store.GetTenantStore().RequestDeletion(ctx, pending))

	deleted, err := m.ApproveTenantDeletion(ctx, rootID, "alice", false)
	require.NoError(t, err)
	assert.Contains(t, deleted, rootID)
}

func TestApproveTenantDeletion_MembershipChangedRejected(t *testing.T) {
	store := cfgmstesting.SetupTestStorage(t)
	m := NewManager(store.GetTenantStore(), nil)
	ctx := context.Background()

	rootID := "mem-root"
	childID := "mem-child"
	now := time.Now()

	for _, td := range []business.TenantData{
		{ID: rootID, Name: "Root", Status: business.TenantStatusSuspended, DirectlySuspended: true},
	} {
		td := td
		require.NoError(t, store.GetTenantStore().CreateTenant(ctx, &td))
	}

	// Pin only rootID; later add childID to simulate membership change.
	pending := &business.PendingDeletion{
		SubtreeRootID:   rootID,
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: []string{rootID},
	}
	require.NoError(t, store.GetTenantStore().RequestDeletion(ctx, pending))

	// Add a child that was not pinned.
	child := business.TenantData{
		ID: childID, Name: "Child", ParentID: rootID,
		Status: business.TenantStatusSuspended, DirectlySuspended: true,
	}
	require.NoError(t, store.GetTenantStore().CreateTenant(ctx, &child))

	_, err := m.ApproveTenantDeletion(ctx, rootID, "bob", true)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrMembershipChanged)
}

func TestApproveTenantDeletion_DefaultTenantProtected(t *testing.T) {
	m := newTestTenantManager(t)
	ctx := context.Background()

	_, err := m.ApproveTenantDeletion(ctx, "default", "bob", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete default tenant")
}

func TestApproveTenantDeletion_CascadeDeletesEntireSubtree(t *testing.T) {
	store := cfgmstesting.SetupTestStorage(t)
	m := NewManager(store.GetTenantStore(), nil)
	ctx := context.Background()

	rootID := "cas-root"
	childID := "cas-child"
	grandID := "cas-grand"
	now := time.Now()

	for _, td := range []struct{ id, parent string }{
		{rootID, ""},
		{childID, rootID},
		{grandID, childID},
	} {
		ts := business.TenantData{
			ID:                td.id,
			Name:              td.id,
			ParentID:          td.parent,
			Status:            business.TenantStatusSuspended,
			DirectlySuspended: true,
		}
		require.NoError(t, store.GetTenantStore().CreateTenant(ctx, &ts))
	}

	pending := &business.PendingDeletion{
		SubtreeRootID:   rootID,
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: []string{rootID, childID, grandID},
	}
	require.NoError(t, store.GetTenantStore().RequestDeletion(ctx, pending))

	deleted, err := m.ApproveTenantDeletion(ctx, rootID, "bob", true)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{rootID, childID, grandID}, deleted)

	for _, id := range []string{rootID, childID, grandID} {
		_, err := m.GetTenant(ctx, id)
		assert.ErrorIs(t, err, business.ErrTenantDoesNotExist,
			"tenant %s must be deleted after approval", id)
	}
}

func TestDeleteTenant_HasChildrenGuardPreserved(t *testing.T) {
	// Ensure DeleteTenant still rejects when children exist (cascade path is via ApproveDeletion).
	m := newTestTenantManager(t)
	ctx := context.Background()

	parent, err := m.CreateTenant(ctx, &TenantRequest{Name: "Parent"})
	require.NoError(t, err)
	_, err = m.CreateTenant(ctx, &TenantRequest{Name: "Child", ParentID: parent.ID})
	require.NoError(t, err)

	err = m.DeleteTenant(ctx, parent.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantHasChildren)
}
