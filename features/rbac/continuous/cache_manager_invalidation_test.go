// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package continuous

import (
	"testing"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeDecision builds a CachedAuthDecision and stores it directly into only L2
// (bypassing the normal CacheAuth path so that L1 never sees the entry).
// This lets tests verify that invalidation scans L2 independently of L1.
func storeL2Only(t *testing.T, cm *CacheManager, subjectID, tenantID, permissionID string) string {
	t.Helper()
	req := &ContinuousAuthRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId:    subjectID,
			TenantId:     tenantID,
			PermissionId: permissionID,
			ResourceId:   "res-1",
		},
		SessionID: "session-" + subjectID,
	}
	key := cm.generateCacheKey(req)
	decision := &CachedAuthDecision{
		CacheKey:     key,
		CacheLevel:   CacheLevelL2,
		ValidUntil:   time.Now().Add(5 * time.Minute),
		SubjectID:    subjectID,
		TenantID:     tenantID,
		PermissionID: permissionID,
		SessionID:    "session-" + subjectID,
	}
	require.NoError(t, cm.l2Cache.Set(key, decision, 5*time.Minute))

	// Confirm L1 does NOT have this entry.
	_, inL1 := cm.l1Cache.Get(key)
	require.False(t, inL1, "entry must not be in L1 for this test to be meaningful")

	// Confirm L2 has it.
	_, inL2 := cm.l2Cache.Get(key)
	require.True(t, inL2, "entry must be in L2 before invalidation")

	return key
}

func newTestCacheManager() *CacheManager {
	return NewCacheManager(5*time.Minute, 100)
}

// TestInvalidateSubject_L2OnlyEntry verifies that InvalidateSubject removes entries
// that exist only in L2 (evicted from L1 or never promoted to L1).
func TestInvalidateSubject_L2OnlyEntry(t *testing.T) {
	cm := newTestCacheManager()

	key := storeL2Only(t, cm, "user-l2only", "tenant1", "perm1")

	require.NoError(t, cm.InvalidateSubject("user-l2only"))

	_, stillInL2 := cm.l2Cache.Get(key)
	assert.False(t, stillInL2, "L2-only entry for subject should be removed after InvalidateSubject")
}

// TestInvalidateSubject_UnrelatedEntryUntouched verifies that InvalidateSubject
// only removes entries for the target subject and leaves others intact.
func TestInvalidateSubject_UnrelatedEntryUntouched(t *testing.T) {
	cm := newTestCacheManager()

	targetKey := storeL2Only(t, cm, "user-target", "tenant1", "perm1")
	otherKey := storeL2Only(t, cm, "user-other", "tenant1", "perm1")

	require.NoError(t, cm.InvalidateSubject("user-target"))

	_, targetInL2 := cm.l2Cache.Get(targetKey)
	assert.False(t, targetInL2, "target subject entry should be removed")

	_, otherInL2 := cm.l2Cache.Get(otherKey)
	assert.True(t, otherInL2, "unrelated subject entry should survive InvalidateSubject")
}

// TestInvalidateTenant_L2OnlyEntry verifies that InvalidateTenant removes entries
// that exist only in L2.
func TestInvalidateTenant_L2OnlyEntry(t *testing.T) {
	cm := newTestCacheManager()

	key := storeL2Only(t, cm, "user1", "tenant-l2only", "perm1")

	require.NoError(t, cm.InvalidateTenant("tenant-l2only"))

	_, stillInL2 := cm.l2Cache.Get(key)
	assert.False(t, stillInL2, "L2-only entry for tenant should be removed after InvalidateTenant")
}

// TestInvalidateTenant_UnrelatedEntryUntouched verifies that InvalidateTenant
// only removes entries for the target tenant and leaves others intact.
func TestInvalidateTenant_UnrelatedEntryUntouched(t *testing.T) {
	cm := newTestCacheManager()

	targetKey := storeL2Only(t, cm, "user1", "tenant-target", "perm1")
	otherKey := storeL2Only(t, cm, "user1", "tenant-other", "perm1")

	require.NoError(t, cm.InvalidateTenant("tenant-target"))

	_, targetInL2 := cm.l2Cache.Get(targetKey)
	assert.False(t, targetInL2, "target tenant entry should be removed")

	_, otherInL2 := cm.l2Cache.Get(otherKey)
	assert.True(t, otherInL2, "unrelated tenant entry should survive InvalidateTenant")
}

// TestInvalidatePermission_L2OnlyEntry verifies that invalidatePermission removes
// entries that exist only in L2 (the L2 coverage gap fix).
func TestInvalidatePermission_L2OnlyEntry(t *testing.T) {
	cm := newTestCacheManager()

	key := storeL2Only(t, cm, "user1", "tenant1", "perm-l2only")

	require.NoError(t, cm.InvalidateCache(&CacheInvalidationRequest{
		InvalidationType: InvalidationTypePermission,
		PermissionID:     "perm-l2only",
		Reason:           "test",
	}))

	_, stillInL2 := cm.l2Cache.Get(key)
	assert.False(t, stillInL2, "L2-only entry for permission should be removed after invalidatePermission")
}

// TestInvalidatePermission_UnrelatedEntryUntouched verifies that invalidatePermission
// leaves entries for other permissions intact.
func TestInvalidatePermission_UnrelatedEntryUntouched(t *testing.T) {
	cm := newTestCacheManager()

	targetKey := storeL2Only(t, cm, "user1", "tenant1", "perm-target")
	otherKey := storeL2Only(t, cm, "user1", "tenant1", "perm-other")

	require.NoError(t, cm.InvalidateCache(&CacheInvalidationRequest{
		InvalidationType: InvalidationTypePermission,
		PermissionID:     "perm-target",
		Reason:           "test",
	}))

	_, targetInL2 := cm.l2Cache.Get(targetKey)
	assert.False(t, targetInL2, "target permission entry should be removed")

	_, otherInL2 := cm.l2Cache.Get(otherKey)
	assert.True(t, otherInL2, "unrelated permission entry should survive invalidation")
}
