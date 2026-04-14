// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func newSessionStore(t *testing.T) interfaces.SessionStore {
	t.Helper()
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	store, err := p.CreateSessionStore(map[string]interface{}{"path": filepath.Join(dir, "sessions.db")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func sampleSession(id string) *interfaces.Session {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &interfaces.Session{
		SessionID:    id,
		UserID:       "user-1",
		TenantID:     "tenant-1",
		SessionType:  interfaces.SessionTypeAPI,
		CreatedAt:    now,
		LastActivity: now,
		ExpiresAt:    now.Add(1 * time.Hour),
		Status:       interfaces.SessionStatusActive,
		Persistent:   true,
	}
}

func TestSessionStore_CreateAndGet(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	sess := sampleSession("sess-001")
	sess.CreatedBy = "admin"
	sess.Metadata = map[string]string{"source": "api"}
	sess.ClientInfo = &interfaces.ClientInfo{
		IPAddress: "192.168.1.1",
		Platform:  "linux",
	}

	require.NoError(t, store.CreateSession(ctx, sess))

	got, err := store.GetSession(ctx, "sess-001")
	require.NoError(t, err)
	assert.Equal(t, sess.SessionID, got.SessionID)
	assert.Equal(t, sess.UserID, got.UserID)
	assert.Equal(t, sess.TenantID, got.TenantID)
	assert.Equal(t, interfaces.SessionTypeAPI, got.SessionType)
	assert.Equal(t, interfaces.SessionStatusActive, got.Status)
	assert.True(t, got.Persistent)
	assert.Equal(t, "api", got.Metadata["source"])
	require.NotNil(t, got.ClientInfo)
	assert.Equal(t, "192.168.1.1", got.ClientInfo.IPAddress)
}

func TestSessionStore_GetNotFound(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()
	_, err := store.GetSession(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestSessionStore_Update(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	sess := sampleSession("sess-upd")
	require.NoError(t, store.CreateSession(ctx, sess))

	sess.Status = interfaces.SessionStatusInactive
	sess.LastActivity = time.Now().UTC()
	require.NoError(t, store.UpdateSession(ctx, "sess-upd", sess))

	got, err := store.GetSession(ctx, "sess-upd")
	require.NoError(t, err)
	assert.Equal(t, interfaces.SessionStatusInactive, got.Status)
	assert.NotNil(t, got.ModifiedAt)
}

func TestSessionStore_Update_NotFound(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()
	sess := sampleSession("nonexistent")
	assert.Error(t, store.UpdateSession(ctx, "nonexistent", sess))
}

func TestSessionStore_Delete(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	sess := sampleSession("sess-del")
	require.NoError(t, store.CreateSession(ctx, sess))
	require.NoError(t, store.DeleteSession(ctx, "sess-del"))
	_, err := store.GetSession(ctx, "sess-del")
	assert.Error(t, err)
}

func TestSessionStore_Delete_NotFound(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()
	assert.Error(t, store.DeleteSession(ctx, "nonexistent"))
}

func TestSessionStore_SetSessionTTL(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	sess := sampleSession("sess-ttl")
	require.NoError(t, store.CreateSession(ctx, sess))

	require.NoError(t, store.SetSessionTTL(ctx, "sess-ttl", 2*time.Hour))

	got, err := store.GetSession(ctx, "sess-ttl")
	require.NoError(t, err)
	// New expiry should be roughly 2 hours from now
	assert.True(t, got.ExpiresAt.After(time.Now().UTC().Add(90*time.Minute)))
}

func TestSessionStore_CleanupExpiredSessions(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	// Create a session already expired (CreatedAt must be before ExpiresAt to pass validation)
	pastCreated := time.Now().UTC().Add(-3 * time.Hour)
	pastExpired := time.Now().UTC().Add(-1 * time.Hour)
	expired := &interfaces.Session{
		SessionID:    "sess-exp",
		UserID:       "user-1",
		TenantID:     "tenant-1",
		SessionType:  interfaces.SessionTypeAPI,
		CreatedAt:    pastCreated,
		LastActivity: pastCreated,
		ExpiresAt:    pastExpired, // expired 1 hour ago
		Status:       interfaces.SessionStatusExpired,
		Persistent:   true,
	}
	require.NoError(t, store.CreateSession(ctx, expired))

	// Create a valid session
	valid := sampleSession("sess-ok")
	require.NoError(t, store.CreateSession(ctx, valid))

	n, err := store.CleanupExpiredSessions(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "exactly one expired session should be cleaned up")

	// Valid session must still exist
	_, err = store.GetSession(ctx, "sess-ok")
	assert.NoError(t, err)

	// Expired session must be gone
	_, err = store.GetSession(ctx, "sess-exp")
	assert.Error(t, err)
}

func TestSessionStore_GetSessionsByUser(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	s1 := sampleSession("by-user-1")
	s1.UserID = "alice"
	s2 := sampleSession("by-user-2")
	s2.UserID = "bob"
	require.NoError(t, store.CreateSession(ctx, s1))
	require.NoError(t, store.CreateSession(ctx, s2))

	results, err := store.GetSessionsByUser(ctx, "alice")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "alice", results[0].UserID)
}

func TestSessionStore_GetSessionsByTenant(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	s1 := sampleSession("by-tenant-1")
	s1.TenantID = "ta"
	s2 := sampleSession("by-tenant-2")
	s2.TenantID = "tb"
	require.NoError(t, store.CreateSession(ctx, s1))
	require.NoError(t, store.CreateSession(ctx, s2))

	results, err := store.GetSessionsByTenant(ctx, "ta")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "ta", results[0].TenantID)
}

func TestSessionStore_GetSessionsByType(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	s1 := sampleSession("by-type-api")
	s1.SessionType = interfaces.SessionTypeAPI
	s2 := sampleSession("by-type-web")
	s2.SessionType = interfaces.SessionTypeWeb
	require.NoError(t, store.CreateSession(ctx, s1))
	require.NoError(t, store.CreateSession(ctx, s2))

	results, err := store.GetSessionsByType(ctx, interfaces.SessionTypeAPI)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, interfaces.SessionTypeAPI, results[0].SessionType)
}

func TestSessionStore_GetActiveSessionsCount(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	active1 := sampleSession("active-1")
	active2 := sampleSession("active-2")
	inactive := sampleSession("inactive-1")
	inactive.Status = interfaces.SessionStatusInactive

	require.NoError(t, store.CreateSession(ctx, active1))
	require.NoError(t, store.CreateSession(ctx, active2))
	require.NoError(t, store.CreateSession(ctx, inactive))

	count, err := store.GetActiveSessionsCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestSessionStore_HealthCheck(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()
	assert.NoError(t, store.HealthCheck(ctx))
}

func TestSessionStore_GetStats(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	for _, sess := range []*interfaces.Session{
		sampleSession("stats-1"),
		sampleSession("stats-2"),
		{SessionID: "stats-3", UserID: "u", TenantID: "t",
			SessionType: interfaces.SessionTypeWeb,
			CreatedAt:   time.Now().UTC(), LastActivity: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(time.Hour),
			Status:    interfaces.SessionStatusActive, Persistent: true},
	} {
		require.NoError(t, store.CreateSession(ctx, sess))
	}

	stats, err := store.GetStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), stats.TotalSessions)
	assert.Greater(t, stats.ActiveSessions, int64(0))
}

func TestSessionStore_ListSessions_Filter(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for _, sess := range []*interfaces.Session{
		{SessionID: "f-1", UserID: "u1", TenantID: "t1", SessionType: interfaces.SessionTypeAPI,
			CreatedAt: now, LastActivity: now, ExpiresAt: now.Add(time.Hour),
			Status: interfaces.SessionStatusActive, Persistent: true},
		{SessionID: "f-2", UserID: "u2", TenantID: "t1", SessionType: interfaces.SessionTypeWeb,
			CreatedAt: now, LastActivity: now, ExpiresAt: now.Add(time.Hour),
			Status: interfaces.SessionStatusActive, Persistent: true},
		{SessionID: "f-3", UserID: "u1", TenantID: "t2", SessionType: interfaces.SessionTypeAPI,
			CreatedAt: now, LastActivity: now, ExpiresAt: now.Add(time.Hour),
			Status: interfaces.SessionStatusInactive, Persistent: true},
	} {
		require.NoError(t, store.CreateSession(ctx, sess))
	}

	// Filter by tenant
	byTenant, err := store.ListSessions(ctx, &interfaces.SessionFilter{TenantID: "t1"})
	require.NoError(t, err)
	assert.Len(t, byTenant, 2)

	// Filter by status
	active, err := store.ListSessions(ctx, &interfaces.SessionFilter{Status: interfaces.SessionStatusActive})
	require.NoError(t, err)
	assert.Len(t, active, 2)

	// Filter by limit
	limited, err := store.ListSessions(ctx, &interfaces.SessionFilter{Limit: 1})
	require.NoError(t, err)
	assert.Len(t, limited, 1)
}

// TestSessionStore_NoEphemeralMethods verifies that SessionStore only persists
// durable (Persistent=true) sessions and that non-persistent sessions are rejected.
func TestSessionStore_NoEphemeralMethods(t *testing.T) {
	store := newSessionStore(t)
	ctx := context.Background()

	ephemeral := sampleSession("sess-ephemeral")
	ephemeral.Persistent = false

	err := store.CreateSession(ctx, ephemeral)
	assert.Error(t, err, "non-persistent session must be rejected by the durable SessionStore")
}
