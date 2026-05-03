// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package continuous

import (
	"fmt"
	"testing"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cacheEntry inserts one entry via the normal CacheAuth path and returns the cache key.
func cacheEntry(t *testing.T, cm *CacheManager, subjectID, tenantID, permissionID, sessionID, resourceID string) string {
	t.Helper()
	req := &ContinuousAuthRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId:    subjectID,
			TenantId:     tenantID,
			PermissionId: permissionID,
			ResourceId:   resourceID,
		},
		SessionID: sessionID,
	}
	resp := &ContinuousAuthResponse{
		AccessResponse: &common.AccessResponse{Granted: true},
		ValidUntil:     time.Now().Add(5 * time.Minute),
		DecisionID:     "dec-" + subjectID,
		DecisionTime:   time.Now(),
	}
	require.NoError(t, cm.CacheAuth(req, resp))
	return cm.generateCacheKey(req)
}

// TestInvalidateSubject_IndexBasedLookup verifies that invalidateSubject removes
// all entries for the target subject using the subject index (O(1) lookup),
// including entries that exist only in L2 (evicted from L1).
func TestInvalidateSubject_IndexBasedLookup(t *testing.T) {
	cm := newTestCacheManager()

	// Insert three entries for the target subject (different permissions/resources).
	key1 := cacheEntry(t, cm, "user-alpha", "tenant1", "perm-read", "sess-alpha", "res-1")
	key2 := cacheEntry(t, cm, "user-alpha", "tenant1", "perm-write", "sess-alpha", "res-2")
	key3 := cacheEntry(t, cm, "user-alpha", "tenant1", "perm-admin", "sess-alpha", "res-3")

	// Evict key2 from L1 to simulate an entry that is L2-only.
	cm.l1Cache.Delete(key2)
	_, inL1 := cm.l1Cache.Get(key2)
	require.False(t, inL1, "key2 must be L2-only for this test to be meaningful")

	// Insert an unrelated entry for a different subject.
	otherKey := cacheEntry(t, cm, "user-beta", "tenant1", "perm-read", "sess-beta", "res-1")

	require.NoError(t, cm.InvalidateSubject("user-alpha"))

	// All three target entries must be gone from both L1 and L2.
	for _, key := range []string{key1, key2, key3} {
		_, inL1 := cm.l1Cache.Get(key)
		_, inL2 := cm.l2Cache.Get(key)
		assert.False(t, inL1, "target entry must be removed from L1 after InvalidateSubject")
		assert.False(t, inL2, "target entry must be removed from L2 after InvalidateSubject")
	}

	// Unrelated subject entry must survive.
	_, otherInL1 := cm.l1Cache.Get(otherKey)
	_, otherInL2 := cm.l2Cache.Get(otherKey)
	assert.True(t, otherInL1 || otherInL2, "unrelated subject entry must survive InvalidateSubject")
}

// TestInvalidateTenant_IndexBasedLookup verifies that invalidateTenant removes
// all entries for the target tenant using the tenant index.
func TestInvalidateTenant_IndexBasedLookup(t *testing.T) {
	cm := newTestCacheManager()

	key1 := cacheEntry(t, cm, "user1", "tenant-x", "perm-read", "sess-1", "res-1")
	key2 := cacheEntry(t, cm, "user2", "tenant-x", "perm-read", "sess-2", "res-1")

	// Evict key1 from L1 to simulate L2-only state.
	cm.l1Cache.Delete(key1)

	otherKey := cacheEntry(t, cm, "user1", "tenant-y", "perm-read", "sess-1", "res-1")

	require.NoError(t, cm.InvalidateTenant("tenant-x"))

	for _, key := range []string{key1, key2} {
		_, inL1 := cm.l1Cache.Get(key)
		_, inL2 := cm.l2Cache.Get(key)
		assert.False(t, inL1, "target tenant entry must be removed from L1")
		assert.False(t, inL2, "target tenant entry must be removed from L2")
	}

	_, otherInL1 := cm.l1Cache.Get(otherKey)
	_, otherInL2 := cm.l2Cache.Get(otherKey)
	assert.True(t, otherInL1 || otherInL2, "unrelated tenant entry must survive InvalidateTenant")
}

// TestInvalidatePermission_IndexBasedLookup verifies that invalidatePermission removes
// all entries for the target permission using the permission index.
func TestInvalidatePermission_IndexBasedLookup(t *testing.T) {
	cm := newTestCacheManager()

	key1 := cacheEntry(t, cm, "user1", "tenant1", "perm-secret", "sess-1", "res-1")
	key2 := cacheEntry(t, cm, "user2", "tenant1", "perm-secret", "sess-2", "res-1")

	// Evict key1 from L1 to simulate L2-only state.
	cm.l1Cache.Delete(key1)

	otherKey := cacheEntry(t, cm, "user1", "tenant1", "perm-public", "sess-1", "res-1")

	require.NoError(t, cm.InvalidateCache(&CacheInvalidationRequest{
		InvalidationType: InvalidationTypePermission,
		PermissionID:     "perm-secret",
		Reason:           "permission revoked",
	}))

	for _, key := range []string{key1, key2} {
		_, inL1 := cm.l1Cache.Get(key)
		_, inL2 := cm.l2Cache.Get(key)
		assert.False(t, inL1, "target permission entry must be removed from L1")
		assert.False(t, inL2, "target permission entry must be removed from L2")
	}

	_, otherInL1 := cm.l1Cache.Get(otherKey)
	_, otherInL2 := cm.l2Cache.Get(otherKey)
	assert.True(t, otherInL1 || otherInL2, "unrelated permission entry must survive invalidation")
}

// TestInvalidateSubject_CrossIndexCleanup verifies that after subject invalidation
// the session index no longer contains the deleted keys, preventing stale index entries.
func TestInvalidateSubject_CrossIndexCleanup(t *testing.T) {
	cm := newTestCacheManager()

	cacheEntry(t, cm, "user-cleanup", "tenant1", "perm-read", "session-cleanup", "res-1")

	// Confirm the session index has the key before invalidation.
	cm.indexMutex.RLock()
	sessionKeys := cm.sessionIndex["session-cleanup"]
	cm.indexMutex.RUnlock()
	require.Len(t, sessionKeys, 1, "session index must have one entry before invalidation")

	require.NoError(t, cm.InvalidateSubject("user-cleanup"))

	// After subject invalidation, the session index must no longer have the key.
	cm.indexMutex.RLock()
	sessionKeysAfter := cm.sessionIndex["session-cleanup"]
	cm.indexMutex.RUnlock()
	assert.Empty(t, sessionKeysAfter, "session index must be clean after InvalidateSubject")
}

// makeBenchmarkCache creates a CacheManager populated with totalEntries entries,
// of which targetEntries belong to targetSubject.
func makeBenchmarkCache(b *testing.B, totalEntries, targetEntries int, targetSubject string) *CacheManager {
	b.Helper()
	// Size L1 to hold all entries so no LRU eviction fires during setup.
	// pkg/cache evictLRU uses an O(n²) sort; triggering it 90k times on a 10k-entry
	// L1 would make setup take hours. The benchmark measures invalidateSubject, not setup.
	cm := newCacheManagerSized(10*time.Minute, 100, totalEntries+1000, totalEntries+1000)
	otherCount := totalEntries - targetEntries

	for i := 0; i < otherCount; i++ {
		req := &ContinuousAuthRequest{
			AccessRequest: &common.AccessRequest{
				SubjectId:    fmt.Sprintf("other-subject-%d", i),
				TenantId:     "tenant1",
				PermissionId: fmt.Sprintf("perm-%d", i%100),
				ResourceId:   "res-1",
			},
			SessionID: fmt.Sprintf("sess-%d", i),
		}
		resp := &ContinuousAuthResponse{
			AccessResponse: &common.AccessResponse{Granted: true},
			ValidUntil:     time.Now().Add(10 * time.Minute),
			DecisionID:     fmt.Sprintf("dec-%d", i),
			DecisionTime:   time.Now(),
		}
		if err := cm.CacheAuth(req, resp); err != nil {
			b.Fatalf("CacheAuth failed during benchmark setup: %v", err)
		}
	}

	for i := 0; i < targetEntries; i++ {
		req := &ContinuousAuthRequest{
			AccessRequest: &common.AccessRequest{
				SubjectId:    targetSubject,
				TenantId:     "tenant1",
				PermissionId: fmt.Sprintf("perm-%d", i),
				ResourceId:   fmt.Sprintf("res-%d", i),
			},
			SessionID: fmt.Sprintf("sess-target-%d", i),
		}
		resp := &ContinuousAuthResponse{
			AccessResponse: &common.AccessResponse{Granted: true},
			ValidUntil:     time.Now().Add(10 * time.Minute),
			DecisionID:     fmt.Sprintf("dec-target-%d", i),
			DecisionTime:   time.Now(),
		}
		if err := cm.CacheAuth(req, resp); err != nil {
			b.Fatalf("CacheAuth failed during benchmark setup (target subject): %v", err)
		}
	}

	return cm
}

// BenchmarkInvalidateSubject measures the time to invalidate all cache entries for
// a single subject in a 100k-entry cache where the target subject has 100 entries.
// Expected: completes in <1ms per operation.
func BenchmarkInvalidateSubject(b *testing.B) {
	const totalEntries = 100_000
	const targetEntries = 100
	const targetSubject = "benchmark-target-subject"

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		cm := makeBenchmarkCache(b, totalEntries, targetEntries, targetSubject)
		b.StartTimer()

		_ = cm.invalidateSubject(targetSubject, "benchmark")
	}
}
