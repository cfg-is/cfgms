// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// Test helper functions

func createTestSession(sessionID, userID, tenantID string) *interfaces.Session {
	return &interfaces.Session{
		SessionID:    sessionID,
		UserID:       userID,
		TenantID:     tenantID,
		SessionType:  interfaces.SessionTypeTerminal,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Status:       interfaces.SessionStatusActive,
	}
}

func TestNewRuntimeCache(t *testing.T) {
	config := CacheConfig{
		Name:            "test-cache",
		MaxSessions:     100,
		MaxRuntimeItems: 50,
		DefaultTTL:      30 * time.Minute,
		CleanupInterval: 5 * time.Minute,
	}

	cache := NewRuntimeCache(config)
	defer cache.Close()

	assert.Equal(t, config.Name, cache.config.Name)
	assert.Equal(t, config.MaxSessions, cache.config.MaxSessions)
	assert.Equal(t, config.MaxRuntimeItems, cache.config.MaxRuntimeItems)
	assert.Equal(t, config.DefaultTTL, cache.config.DefaultTTL)

	// Verify initial state
	assert.NotNil(t, cache.sessions)
	assert.NotNil(t, cache.runtimeState)
	assert.NotNil(t, cache.mutex)
	assert.Equal(t, 0, len(cache.sessions))
	assert.Equal(t, 0, len(cache.runtimeState))
}

func TestDefaultCacheConfig(t *testing.T) {
	config := DefaultCacheConfig()

	assert.Equal(t, "runtime-cache", config.Name)
	assert.Equal(t, 1000, config.MaxSessions)
	assert.Equal(t, 500, config.MaxRuntimeItems)
	assert.Equal(t, 2*time.Hour, config.DefaultTTL)
	assert.Equal(t, 5*time.Minute, config.CleanupInterval)
}

func TestCacheEntry(t *testing.T) {
	t.Run("IsExpired - not expired", func(t *testing.T) {
		entry := &CacheEntry{
			Value:     "test",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		assert.False(t, entry.IsExpired())
	})

	t.Run("IsExpired - expired", func(t *testing.T) {
		entry := &CacheEntry{
			Value:     "test",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}

		assert.True(t, entry.IsExpired())
	})
}

func TestSessionOperations(t *testing.T) {
	config := DefaultCacheConfig()
	config.CleanupInterval = 0 // Disable background cleanup for testing
	cache := NewRuntimeCache(config)
	defer cache.Close()

	ctx := context.Background()
	session := createTestSession("session1", "user1", "tenant1")

	t.Run("CreateSession", func(t *testing.T) {
		err := cache.CreateSession(ctx, session)
		require.NoError(t, err)

		// Verify session was stored
		assert.Equal(t, 1, len(cache.sessions))

		// Verify stats were updated
		stats := cache.GetCacheStats()
		assert.Equal(t, int64(1), stats.Hits)
	})

	t.Run("CreateSession - duplicate", func(t *testing.T) {
		err := cache.CreateSession(ctx, session)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("GetSession", func(t *testing.T) {
		retrieved, err := cache.GetSession(ctx, "session1")
		require.NoError(t, err)
		assert.Equal(t, session.SessionID, retrieved.SessionID)
		assert.Equal(t, session.UserID, retrieved.UserID)
	})

	t.Run("GetSession - not found", func(t *testing.T) {
		_, err := cache.GetSession(ctx, "nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("UpdateSession", func(t *testing.T) {
		updatedSession := createTestSession("session1", "user1", "tenant1")
		updatedSession.Status = interfaces.SessionStatusInactive

		err := cache.UpdateSession(ctx, "session1", updatedSession)
		require.NoError(t, err)

		retrieved, err := cache.GetSession(ctx, "session1")
		require.NoError(t, err)
		assert.Equal(t, interfaces.SessionStatusInactive, retrieved.Status)
	})

	t.Run("DeleteSession", func(t *testing.T) {
		err := cache.DeleteSession(ctx, "session1")
		require.NoError(t, err)

		_, err = cache.GetSession(ctx, "session1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestSessionTTL(t *testing.T) {
	config := DefaultCacheConfig()
	config.CleanupInterval = 0
	cache := NewRuntimeCache(config)
	defer cache.Close()

	ctx := context.Background()
	session := createTestSession("session1", "user1", "tenant1")

	// Create session
	err := cache.CreateSession(ctx, session)
	require.NoError(t, err)

	t.Run("SetSessionTTL", func(t *testing.T) {
		newTTL := 10 * time.Minute
		err := cache.SetSessionTTL(ctx, "session1", newTTL)
		require.NoError(t, err)

		// Verify TTL was set
		retrieved, err := cache.GetSession(ctx, "session1")
		require.NoError(t, err)

		expectedExpiry := time.Now().Add(newTTL)
		assert.WithinDuration(t, expectedExpiry, retrieved.ExpiresAt, 1*time.Second)
	})
}

func TestSessionExpiration(t *testing.T) {
	config := DefaultCacheConfig()
	config.DefaultTTL = 10 * time.Millisecond
	config.CleanupInterval = 0
	cache := NewRuntimeCache(config)
	defer cache.Close()

	ctx := context.Background()
	session := createTestSession("session1", "user1", "tenant1")
	session.ExpiresAt = time.Now().Add(10 * time.Millisecond)

	// Create session
	err := cache.CreateSession(ctx, session)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	t.Run("GetSession - expired", func(t *testing.T) {
		_, err := cache.GetSession(ctx, "session1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("CleanupExpiredSessions", func(t *testing.T) {
		// Create fresh cache for this test to avoid interference
		cleanupConfig := DefaultCacheConfig()
		cleanupConfig.CleanupInterval = 0
		cleanupCache := NewRuntimeCache(cleanupConfig)
		defer cleanupCache.Close()

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

		// Verify sessions were created
		assert.Equal(t, 2, len(cleanupCache.sessions), "Expected 2 sessions in cache")

		// Check that both entries are expired
		for id, entry := range cleanupCache.sessions {
			t.Logf("Session %s expires at: %v, IsExpired: %v", id, entry.ExpiresAt, entry.IsExpired())
		}

		count, err := cleanupCache.CleanupExpiredSessions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, count) // Both sessions should be cleaned up
	})
}

func TestRuntimeStateOperations(t *testing.T) {
	config := DefaultCacheConfig()
	config.CleanupInterval = 0
	cache := NewRuntimeCache(config)
	defer cache.Close()

	ctx := context.Background()

	t.Run("SetRuntimeState", func(t *testing.T) {
		err := cache.SetRuntimeState(ctx, "key1", "value1")
		require.NoError(t, err)

		assert.Equal(t, 1, len(cache.runtimeState))
	})

	t.Run("GetRuntimeState", func(t *testing.T) {
		value, err := cache.GetRuntimeState(ctx, "key1")
		require.NoError(t, err)
		assert.Equal(t, "value1", value)
	})

	t.Run("GetRuntimeState - not found", func(t *testing.T) {
		_, err := cache.GetRuntimeState(ctx, "nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("ListRuntimeKeys", func(t *testing.T) {
		// Add more keys
		err := cache.SetRuntimeState(ctx, "key2", "value2")
		require.NoError(t, err)
		err = cache.SetRuntimeState(ctx, "prefix_key3", "value3")
		require.NoError(t, err)

		// List all keys with prefix
		keys, err := cache.ListRuntimeKeys(ctx, "key")
		require.NoError(t, err)
		assert.Equal(t, 2, len(keys))
		assert.Contains(t, keys, "key1")
		assert.Contains(t, keys, "key2")

		// List keys with specific prefix
		prefixKeys, err := cache.ListRuntimeKeys(ctx, "prefix_")
		require.NoError(t, err)
		assert.Equal(t, 1, len(prefixKeys))
		assert.Contains(t, prefixKeys, "prefix_key3")
	})

	t.Run("DeleteRuntimeState", func(t *testing.T) {
		err := cache.DeleteRuntimeState(ctx, "key1")
		require.NoError(t, err)

		_, err = cache.GetRuntimeState(ctx, "key1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestBatchOperations(t *testing.T) {
	config := DefaultCacheConfig()
	config.CleanupInterval = 0
	cache := NewRuntimeCache(config)
	defer cache.Close()

	ctx := context.Background()

	t.Run("CreateSessionsBatch", func(t *testing.T) {
		sessions := []*interfaces.Session{
			createTestSession("batch1", "user1", "tenant1"),
			createTestSession("batch2", "user2", "tenant1"),
			createTestSession("batch3", "user1", "tenant2"),
		}

		err := cache.CreateSessionsBatch(ctx, sessions)
		require.NoError(t, err)

		assert.Equal(t, 3, len(cache.sessions))

		// Verify all sessions were created
		for _, session := range sessions {
			_, err := cache.GetSession(ctx, session.SessionID)
			assert.NoError(t, err)
		}
	})

	t.Run("DeleteSessionsBatch", func(t *testing.T) {
		sessionIDs := []string{"batch1", "batch3"}

		err := cache.DeleteSessionsBatch(ctx, sessionIDs)
		require.NoError(t, err)

		// Verify sessions were deleted
		_, err = cache.GetSession(ctx, "batch1")
		assert.Error(t, err)

		_, err = cache.GetSession(ctx, "batch3")
		assert.Error(t, err)

		// Verify batch2 still exists
		_, err = cache.GetSession(ctx, "batch2")
		assert.NoError(t, err)
	})
}

func TestQueryMethods(t *testing.T) {
	config := DefaultCacheConfig()
	config.CleanupInterval = 0
	cache := NewRuntimeCache(config)
	defer cache.Close()

	ctx := context.Background()

	// Create test sessions
	sessions := []*interfaces.Session{
		createTestSession("s1", "user1", "tenant1"),
		createTestSession("s2", "user1", "tenant2"),
		createTestSession("s3", "user2", "tenant1"),
	}
	sessions[1].SessionType = interfaces.SessionTypeAPI
	sessions[2].Status = interfaces.SessionStatusInactive

	for _, session := range sessions {
		err := cache.CreateSession(ctx, session)
		require.NoError(t, err)
	}

	t.Run("GetSessionsByUser", func(t *testing.T) {
		userSessions, err := cache.GetSessionsByUser(ctx, "user1")
		require.NoError(t, err)
		assert.Equal(t, 2, len(userSessions))
	})

	t.Run("GetSessionsByTenant", func(t *testing.T) {
		tenantSessions, err := cache.GetSessionsByTenant(ctx, "tenant1")
		require.NoError(t, err)
		assert.Equal(t, 2, len(tenantSessions))
	})

	t.Run("GetSessionsByType", func(t *testing.T) {
		terminalSessions, err := cache.GetSessionsByType(ctx, interfaces.SessionTypeTerminal)
		require.NoError(t, err)
		assert.Equal(t, 2, len(terminalSessions))

		apiSessions, err := cache.GetSessionsByType(ctx, interfaces.SessionTypeAPI)
		require.NoError(t, err)
		assert.Equal(t, 1, len(apiSessions))
	})

	t.Run("GetActiveSessionsCount", func(t *testing.T) {
		count, err := cache.GetActiveSessionsCount(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(2), count) // s1 and s2 are active, s3 is inactive
	})
}

func TestSizeLimits(t *testing.T) {
	config := CacheConfig{
		Name:            "size-test",
		MaxSessions:     2,
		MaxRuntimeItems: 2,
		DefaultTTL:      1 * time.Hour,
		CleanupInterval: 0,
	}
	cache := NewRuntimeCache(config)
	defer cache.Close()

	ctx := context.Background()

	t.Run("Session size limit", func(t *testing.T) {
		// Create sessions up to limit
		for i := 0; i < 3; i++ {
			session := createTestSession(fmt.Sprintf("session%d", i), "user1", "tenant1")
			err := cache.CreateSession(ctx, session)
			require.NoError(t, err)
		}

		// Should have enforced the limit
		assert.LessOrEqual(t, len(cache.sessions), config.MaxSessions)

		// Should have recorded evictions
		stats := cache.GetCacheStats()
		assert.Greater(t, stats.Evictions, int64(0))
	})

	t.Run("Runtime items size limit", func(t *testing.T) {
		// Create runtime items up to limit
		for i := 0; i < 3; i++ {
			err := cache.SetRuntimeState(ctx, fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i))
			require.NoError(t, err)
		}

		// Should have enforced the limit
		assert.LessOrEqual(t, len(cache.runtimeState), config.MaxRuntimeItems)
	})
}

func TestHealthAndStats(t *testing.T) {
	config := DefaultCacheConfig()
	config.CleanupInterval = 0
	cache := NewRuntimeCache(config)
	defer cache.Close()

	ctx := context.Background()

	t.Run("HealthCheck", func(t *testing.T) {
		err := cache.HealthCheck(ctx)
		assert.NoError(t, err) // Should always be healthy for in-memory cache
	})

	t.Run("GetStats", func(t *testing.T) {
		// Add some test data
		session := createTestSession("session1", "user1", "tenant1")
		err := cache.CreateSession(ctx, session)
		require.NoError(t, err)
		err = cache.SetRuntimeState(ctx, "key1", "value1")
		require.NoError(t, err)

		stats, err := cache.GetStats(ctx)
		require.NoError(t, err)

		assert.Equal(t, int64(1), stats.TotalSessions)
		assert.Equal(t, int64(1), stats.ActiveSessions)
		assert.Equal(t, int64(1), stats.RuntimeStateKeys)
		assert.Contains(t, stats.SessionsByType, string(interfaces.SessionTypeTerminal))
		assert.Contains(t, stats.SessionsByStatus, string(interfaces.SessionStatusActive))
	})

	t.Run("Vacuum", func(t *testing.T) {
		// Create an expired session
		now := time.Now()
		expiredSession := createTestSession("expired", "user2", "tenant2")
		expiredSession.CreatedAt = now.Add(-3 * time.Hour) // Created 3 hours ago
		expiredSession.ExpiresAt = now.Add(-1 * time.Hour) // Expired 1 hour ago
		err := cache.CreateSession(ctx, expiredSession)
		require.NoError(t, err)

		err = cache.Vacuum(ctx)
		require.NoError(t, err)

		// Expired session should be cleaned up
		_, err = cache.GetSession(ctx, "expired")
		assert.Error(t, err)
	})
}

func TestBackgroundCleanup(t *testing.T) {
	config := CacheConfig{
		Name:            "cleanup-test",
		MaxSessions:     100,
		MaxRuntimeItems: 50,
		DefaultTTL:      50 * time.Millisecond,
		CleanupInterval: 20 * time.Millisecond,
	}
	cache := NewRuntimeCache(config)
	defer cache.Close()

	ctx := context.Background()

	// Create sessions that will expire
	session := createTestSession("session1", "user1", "tenant1")
	session.ExpiresAt = time.Now().Add(30 * time.Millisecond)
	err := cache.CreateSession(ctx, session)
	require.NoError(t, err)

	// Add runtime state that will expire
	err = cache.SetRuntimeState(ctx, "key1", "value1")
	require.NoError(t, err)

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Items should be cleaned up
	_, err = cache.GetSession(ctx, "session1")
	assert.Error(t, err)

	_, err = cache.GetRuntimeState(ctx, "key1")
	assert.Error(t, err)

	// Check that cleanup stats were updated
	stats := cache.GetCacheStats()
	assert.Greater(t, stats.ItemsExpired, int64(0))
	assert.False(t, stats.LastCleanup.IsZero())
}

func TestConcurrency(t *testing.T) {
	config := DefaultCacheConfig()
	config.CleanupInterval = 0
	cache := NewRuntimeCache(config)
	defer cache.Close()

	ctx := context.Background()

	t.Run("Concurrent session operations", func(t *testing.T) {
		done := make(chan bool)

		// Writer goroutine
		go func() {
			for i := 0; i < 100; i++ {
				session := createTestSession(fmt.Sprintf("concurrent%d", i), "user1", "tenant1")
				_ = cache.CreateSession(ctx, session)
			}
			done <- true
		}()

		// Reader goroutine
		go func() {
			for i := 0; i < 100; i++ {
				_, _ = cache.GetSession(ctx, fmt.Sprintf("concurrent%d", i%10))
			}
			done <- true
		}()

		// Wait for both to complete
		<-done
		<-done

		// Should not panic and should have some sessions
		assert.Greater(t, len(cache.sessions), 0)
	})
}
