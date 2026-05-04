// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cache_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cache"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Test helper functions

func createTestSession(sessionID, userID, tenantID string) *business.Session {
	return &business.Session{
		SessionID:    sessionID,
		UserID:       userID,
		TenantID:     tenantID,
		SessionType:  business.SessionTypeTerminal,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Status:       business.SessionStatusActive,
	}
}

func TestCacheEntry(t *testing.T) {
	t.Run("IsExpired - not expired", func(t *testing.T) {
		entry := &cache.CacheEntry{
			Value:     "test",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		assert.False(t, entry.IsExpired())
	})

	t.Run("IsExpired - expired", func(t *testing.T) {
		entry := &cache.CacheEntry{
			Value:     "test",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}

		assert.True(t, entry.IsExpired())
	})
}

func TestSessionOperations(t *testing.T) {
	config := cache.DefaultCacheConfig()
	config.CleanupInterval = 0 // Disable background cleanup for testing
	rc := cache.NewRuntimeCache(config)
	defer func() { _ = rc.Close() }()

	ctx := context.Background()
	session := createTestSession("session1", "user1", "tenant1")

	t.Run("CreateSession", func(t *testing.T) {
		err := rc.CreateSession(ctx, session)
		require.NoError(t, err)

		// Verify stats were updated by CreateSession before any other operation increments Hits
		stats := rc.GetCacheStats()
		assert.Equal(t, int64(1), stats.Hits)

		// Verify session was stored via public API
		sessions, listErr := rc.ListSessions(ctx, nil)
		require.NoError(t, listErr)
		assert.Len(t, sessions, 1)
	})

	t.Run("CreateSession - duplicate", func(t *testing.T) {
		err := rc.CreateSession(ctx, session)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("GetSession", func(t *testing.T) {
		retrieved, err := rc.GetSession(ctx, "session1")
		require.NoError(t, err)
		assert.Equal(t, session.SessionID, retrieved.SessionID)
		assert.Equal(t, session.UserID, retrieved.UserID)
	})

	t.Run("GetSession - not found", func(t *testing.T) {
		_, err := rc.GetSession(ctx, "nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("UpdateSession", func(t *testing.T) {
		updatedSession := createTestSession("session1", "user1", "tenant1")
		updatedSession.Status = business.SessionStatusInactive

		err := rc.UpdateSession(ctx, "session1", updatedSession)
		require.NoError(t, err)

		retrieved, err := rc.GetSession(ctx, "session1")
		require.NoError(t, err)
		assert.Equal(t, business.SessionStatusInactive, retrieved.Status)
	})

	t.Run("DeleteSession", func(t *testing.T) {
		err := rc.DeleteSession(ctx, "session1")
		require.NoError(t, err)

		_, err = rc.GetSession(ctx, "session1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestSessionTTL(t *testing.T) {
	config := cache.DefaultCacheConfig()
	config.CleanupInterval = 0
	rc := cache.NewRuntimeCache(config)
	defer func() { _ = rc.Close() }()

	ctx := context.Background()
	session := createTestSession("session1", "user1", "tenant1")

	// Create session
	err := rc.CreateSession(ctx, session)
	require.NoError(t, err)

	t.Run("SetSessionTTL", func(t *testing.T) {
		newTTL := 10 * time.Minute
		err := rc.SetSessionTTL(ctx, "session1", newTTL)
		require.NoError(t, err)

		// Verify TTL was set
		retrieved, err := rc.GetSession(ctx, "session1")
		require.NoError(t, err)

		expectedExpiry := time.Now().Add(newTTL)
		assert.WithinDuration(t, expectedExpiry, retrieved.ExpiresAt, 1*time.Second)
	})
}

func TestSessionExpiration(t *testing.T) {
	config := cache.DefaultCacheConfig()
	config.DefaultTTL = 10 * time.Millisecond
	config.CleanupInterval = 0
	rc := cache.NewRuntimeCache(config)
	defer func() { _ = rc.Close() }()

	ctx := context.Background()
	session := createTestSession("session1", "user1", "tenant1")
	session.ExpiresAt = time.Now().Add(10 * time.Millisecond)

	// Create session
	err := rc.CreateSession(ctx, session)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	t.Run("GetSession - expired", func(t *testing.T) {
		_, err := rc.GetSession(ctx, "session1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("CleanupExpiredSessions", func(t *testing.T) {
		// Create fresh cache for this test to avoid interference
		cleanupConfig := cache.DefaultCacheConfig()
		cleanupConfig.CleanupInterval = 0
		cleanupCache := cache.NewRuntimeCache(cleanupConfig)
		defer func() { _ = cleanupCache.Close() }()

		// Create two explicitly expired sessions for testing
		now := time.Now()
		session2 := createTestSession("cleanup1", "user2", "tenant2")
		session2.CreatedAt = now.Add(-3 * time.Hour) // Created 3 hours ago
		session2.ExpiresAt = now.Add(-1 * time.Hour) // Expired 1 hour ago
		err := cleanupCache.CreateSession(ctx, session2)
		require.NoError(t, err, "Failed to create session2")

		session3 := createTestSession("cleanup2", "user3", "tenant2")
		session3.CreatedAt = now.Add(-4 * time.Hour) // Created 4 hours ago
		session3.ExpiresAt = now.Add(-2 * time.Hour) // Expired 2 hours ago
		err = cleanupCache.CreateSession(ctx, session3)
		require.NoError(t, err, "Failed to create session3")

		// Verify sessions were created — TotalSessions counts all entries including expired
		stats, statsErr := cleanupCache.GetStats(ctx)
		require.NoError(t, statsErr)
		assert.Equal(t, int64(2), stats.TotalSessions, "Expected 2 sessions in cache")

		count, err := cleanupCache.CleanupExpiredSessions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, count) // Both sessions should be cleaned up
	})
}

func TestRuntimeStateOperations(t *testing.T) {
	config := cache.DefaultCacheConfig()
	config.CleanupInterval = 0
	rc := cache.NewRuntimeCache(config)
	defer func() { _ = rc.Close() }()

	ctx := context.Background()

	t.Run("SetRuntimeState", func(t *testing.T) {
		err := rc.SetRuntimeState(ctx, "key1", "value1")
		require.NoError(t, err)

		// Verify via GetStats instead of internal field
		stats, statsErr := rc.GetStats(ctx)
		require.NoError(t, statsErr)
		assert.Equal(t, int64(1), stats.RuntimeStateKeys)
	})

	t.Run("GetRuntimeState", func(t *testing.T) {
		value, err := rc.GetRuntimeState(ctx, "key1")
		require.NoError(t, err)
		assert.Equal(t, "value1", value)
	})

	t.Run("GetRuntimeState - not found", func(t *testing.T) {
		_, err := rc.GetRuntimeState(ctx, "nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("ListRuntimeKeys", func(t *testing.T) {
		// Add more keys
		err := rc.SetRuntimeState(ctx, "key2", "value2")
		require.NoError(t, err)
		err = rc.SetRuntimeState(ctx, "prefix_key3", "value3")
		require.NoError(t, err)

		// List all keys with prefix
		keys, err := rc.ListRuntimeKeys(ctx, "key")
		require.NoError(t, err)
		assert.Equal(t, 2, len(keys))
		assert.Contains(t, keys, "key1")
		assert.Contains(t, keys, "key2")

		// List keys with specific prefix
		prefixKeys, err := rc.ListRuntimeKeys(ctx, "prefix_")
		require.NoError(t, err)
		assert.Equal(t, 1, len(prefixKeys))
		assert.Contains(t, prefixKeys, "prefix_key3")
	})

	t.Run("DeleteRuntimeState", func(t *testing.T) {
		err := rc.DeleteRuntimeState(ctx, "key1")
		require.NoError(t, err)

		_, err = rc.GetRuntimeState(ctx, "key1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestBatchOperations(t *testing.T) {
	config := cache.DefaultCacheConfig()
	config.CleanupInterval = 0
	rc := cache.NewRuntimeCache(config)
	defer func() { _ = rc.Close() }()

	ctx := context.Background()

	t.Run("CreateSessionsBatch", func(t *testing.T) {
		sessions := []*business.Session{
			createTestSession("batch1", "user1", "tenant1"),
			createTestSession("batch2", "user2", "tenant1"),
			createTestSession("batch3", "user1", "tenant2"),
		}

		err := rc.CreateSessionsBatch(ctx, sessions)
		require.NoError(t, err)

		// Verify all sessions were created via public API
		listed, listErr := rc.ListSessions(ctx, nil)
		require.NoError(t, listErr)
		assert.Len(t, listed, 3)

		for _, session := range sessions {
			_, err := rc.GetSession(ctx, session.SessionID)
			assert.NoError(t, err)
		}
	})

	t.Run("DeleteSessionsBatch", func(t *testing.T) {
		sessionIDs := []string{"batch1", "batch3"}

		err := rc.DeleteSessionsBatch(ctx, sessionIDs)
		require.NoError(t, err)

		// Verify sessions were deleted
		_, err = rc.GetSession(ctx, "batch1")
		assert.Error(t, err)

		_, err = rc.GetSession(ctx, "batch3")
		assert.Error(t, err)

		// Verify batch2 still exists
		_, err = rc.GetSession(ctx, "batch2")
		assert.NoError(t, err)
	})
}

func TestQueryMethods(t *testing.T) {
	config := cache.DefaultCacheConfig()
	config.CleanupInterval = 0
	rc := cache.NewRuntimeCache(config)
	defer func() { _ = rc.Close() }()

	ctx := context.Background()

	// Create test sessions
	sessions := []*business.Session{
		createTestSession("s1", "user1", "tenant1"),
		createTestSession("s2", "user1", "tenant2"),
		createTestSession("s3", "user2", "tenant1"),
	}
	sessions[1].SessionType = business.SessionTypeAPI
	sessions[2].Status = business.SessionStatusInactive

	for _, session := range sessions {
		err := rc.CreateSession(ctx, session)
		require.NoError(t, err)
	}

	t.Run("GetSessionsByUser", func(t *testing.T) {
		userSessions, err := rc.GetSessionsByUser(ctx, "user1")
		require.NoError(t, err)
		assert.Equal(t, 2, len(userSessions))
	})

	t.Run("GetSessionsByTenant", func(t *testing.T) {
		tenantSessions, err := rc.GetSessionsByTenant(ctx, "tenant1")
		require.NoError(t, err)
		assert.Equal(t, 2, len(tenantSessions))
	})

	t.Run("GetSessionsByType", func(t *testing.T) {
		terminalSessions, err := rc.GetSessionsByType(ctx, business.SessionTypeTerminal)
		require.NoError(t, err)
		assert.Equal(t, 2, len(terminalSessions))

		apiSessions, err := rc.GetSessionsByType(ctx, business.SessionTypeAPI)
		require.NoError(t, err)
		assert.Equal(t, 1, len(apiSessions))
	})

	t.Run("GetActiveSessionsCount", func(t *testing.T) {
		count, err := rc.GetActiveSessionsCount(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(2), count) // s1 and s2 are active, s3 is inactive
	})
}

func TestSizeLimits(t *testing.T) {
	config := cache.CacheConfig{
		Name:            "size-test",
		MaxSessions:     2,
		MaxRuntimeItems: 2,
		DefaultTTL:      1 * time.Hour,
		CleanupInterval: 0,
	}
	rc := cache.NewRuntimeCache(config)
	defer func() { _ = rc.Close() }()

	ctx := context.Background()

	t.Run("Session size limit", func(t *testing.T) {
		// Create sessions up to limit
		for i := 0; i < 3; i++ {
			session := createTestSession(fmt.Sprintf("session%d", i), "user1", "tenant1")
			err := rc.CreateSession(ctx, session)
			require.NoError(t, err)
		}

		// Should have enforced the limit
		stats, err := rc.GetStats(ctx)
		require.NoError(t, err)
		assert.LessOrEqual(t, int(stats.TotalSessions), config.MaxSessions)

		// Should have recorded evictions
		cacheStats := rc.GetCacheStats()
		assert.Greater(t, cacheStats.Evictions, int64(0))
	})

	t.Run("Runtime items size limit", func(t *testing.T) {
		// Create runtime items up to limit
		for i := 0; i < 3; i++ {
			err := rc.SetRuntimeState(ctx, fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i))
			require.NoError(t, err)
		}

		// Should have enforced the limit
		stats, err := rc.GetStats(ctx)
		require.NoError(t, err)
		assert.LessOrEqual(t, int(stats.RuntimeStateKeys), config.MaxRuntimeItems)
	})
}

func TestHealthAndStats(t *testing.T) {
	config := cache.DefaultCacheConfig()
	config.CleanupInterval = 0
	rc := cache.NewRuntimeCache(config)
	defer func() { _ = rc.Close() }()

	ctx := context.Background()

	t.Run("HealthCheck", func(t *testing.T) {
		err := rc.HealthCheck(ctx)
		assert.NoError(t, err) // Should always be healthy for in-memory cache
	})

	t.Run("GetStats", func(t *testing.T) {
		// Add some test data
		session := createTestSession("session1", "user1", "tenant1")
		err := rc.CreateSession(ctx, session)
		require.NoError(t, err)
		err = rc.SetRuntimeState(ctx, "key1", "value1")
		require.NoError(t, err)

		stats, err := rc.GetStats(ctx)
		require.NoError(t, err)

		assert.Equal(t, int64(1), stats.TotalSessions)
		assert.Equal(t, int64(1), stats.ActiveSessions)
		assert.Equal(t, int64(1), stats.RuntimeStateKeys)
		assert.Contains(t, stats.SessionsByType, string(business.SessionTypeTerminal))
		assert.Contains(t, stats.SessionsByStatus, string(business.SessionStatusActive))
	})

	t.Run("Vacuum", func(t *testing.T) {
		// Create an expired session
		now := time.Now()
		expiredSession := createTestSession("expired", "user2", "tenant2")
		expiredSession.CreatedAt = now.Add(-3 * time.Hour) // Created 3 hours ago
		expiredSession.ExpiresAt = now.Add(-1 * time.Hour) // Expired 1 hour ago
		err := rc.CreateSession(ctx, expiredSession)
		require.NoError(t, err)

		err = rc.Vacuum(ctx)
		require.NoError(t, err)

		// Expired session should be cleaned up
		_, err = rc.GetSession(ctx, "expired")
		assert.Error(t, err)
	})
}

func TestBackgroundCleanup(t *testing.T) {
	config := cache.CacheConfig{
		Name:            "cleanup-test",
		MaxSessions:     100,
		MaxRuntimeItems: 50,
		DefaultTTL:      50 * time.Millisecond,
		CleanupInterval: 20 * time.Millisecond,
	}
	rc := cache.NewRuntimeCache(config)
	defer func() { _ = rc.Close() }()

	ctx := context.Background()

	// Create sessions that will expire
	session := createTestSession("session1", "user1", "tenant1")
	session.ExpiresAt = time.Now().Add(30 * time.Millisecond)
	err := rc.CreateSession(ctx, session)
	require.NoError(t, err)

	// Add runtime state that will expire
	err = rc.SetRuntimeState(ctx, "key1", "value1")
	require.NoError(t, err)

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Items should be cleaned up
	_, err = rc.GetSession(ctx, "session1")
	assert.Error(t, err)

	_, err = rc.GetRuntimeState(ctx, "key1")
	assert.Error(t, err)

	// Check that cleanup stats were updated
	stats := rc.GetCacheStats()
	assert.Greater(t, stats.ItemsExpired, int64(0))
	assert.False(t, stats.LastCleanup.IsZero())
}

func TestConcurrency(t *testing.T) {
	config := cache.DefaultCacheConfig()
	config.CleanupInterval = 0
	rc := cache.NewRuntimeCache(config)
	defer func() { _ = rc.Close() }()

	ctx := context.Background()

	t.Run("Concurrent session operations", func(t *testing.T) {
		done := make(chan bool)

		// Writer goroutine
		go func() {
			for i := 0; i < 100; i++ {
				session := createTestSession(fmt.Sprintf("concurrent%d", i), "user1", "tenant1")
				_ = rc.CreateSession(ctx, session)
			}
			done <- true
		}()

		// Reader goroutine
		go func() {
			for i := 0; i < 100; i++ {
				_, _ = rc.GetSession(ctx, fmt.Sprintf("concurrent%d", i%10))
			}
			done <- true
		}()

		// Wait for both to complete
		<-done
		<-done

		// Should not panic and should have some sessions
		stats, err := rc.GetStats(ctx)
		require.NoError(t, err)
		assert.Greater(t, int(stats.TotalSessions), 0)
	})
}
