// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides integration tests for the three new PostgreSQL store implementations.
// These tests require a live Postgres instance (same setup as plugin_test.go) and are skipped
// when CFGMS_TEST_DB_PASSWORD is unset or short mode is active.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ── factory helpers ───────────────────────────────────────────────────────────

func newTestSessionStore(t *testing.T) *DatabaseSessionStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateSessionsTable(ctx, db))
	cfg := getTestConfig()
	cfg["session_hmac_key"] = "test-hmac-key-for-integration-tests-only-32bytes"
	store, err := NewDatabaseSessionStore(db, cfg)
	require.NoError(t, err)
	return store
}

func newTestStewardStore(t *testing.T) *DatabaseStewardStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateStewardRecordsTable(ctx, db))
	store, err := NewDatabaseStewardStore(db, getTestConfig())
	require.NoError(t, err)
	return store
}

func newTestCommandStore(t *testing.T) *DatabaseCommandStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateCommandRecordsTable(ctx, db))
	require.NoError(t, schemas.CreateCommandTransitionsTable(ctx, db))
	store, err := NewDatabaseCommandStore(db, getTestConfig())
	require.NoError(t, err)
	return store
}

func makeSampleSession(id, userID, tenantID string) *business.Session {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &business.Session{
		SessionID:    id,
		UserID:       userID,
		TenantID:     tenantID,
		SessionType:  business.SessionTypeAPI,
		CreatedAt:    now,
		LastActivity: now,
		ExpiresAt:    now.Add(time.Hour),
		Status:       business.SessionStatusActive,
		Persistent:   true,
		CreatedBy:    "test",
	}
}

func makeSampleSteward(id, tenantID string) *business.StewardRecord {
	return &business.StewardRecord{
		ID:       id,
		TenantID: tenantID,
		Hostname: "host-" + id,
		Platform: "linux",
		Arch:     "amd64",
		Version:  "1.0.0",
	}
}

func makeSampleCommand(id, stewardID, tenantID string) *business.CommandRecord {
	return &business.CommandRecord{
		ID:        id,
		Type:      "test-command",
		StewardID: stewardID,
		TenantID:  tenantID,
		Payload:   map[string]interface{}{"key": "value"},
		IssuedBy:  "admin",
	}
}

// ── session store tests ───────────────────────────────────────────────────────

func TestDatabaseSessionStore_CreateAndGet(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()

	sess := makeSampleSession("sess-001", "user-a", "tenant-a")
	sess.Metadata = map[string]string{"env": "test"}
	sess.ClientInfo = &business.ClientInfo{IPAddress: "10.0.0.1"}

	require.NoError(t, store.CreateSession(ctx, sess))

	got, err := store.GetSession(ctx, "sess-001")
	require.NoError(t, err)
	assert.Equal(t, "user-a", got.UserID)
	assert.Equal(t, "tenant-a", got.TenantID)
	assert.Equal(t, business.SessionTypeAPI, got.SessionType)
	assert.Equal(t, business.SessionStatusActive, got.Status)
	assert.True(t, got.Persistent)
	assert.Equal(t, "test", got.Metadata["env"])
	require.NotNil(t, got.ClientInfo)
	assert.Equal(t, "10.0.0.1", got.ClientInfo.IPAddress)
}

func TestDatabaseSessionStore_TokenHashing(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()

	plainToken := "my-secret-bearer-token-that-must-not-be-stored-plaintext"
	sess := makeSampleSession(plainToken, "user-x", "tenant-x")
	require.NoError(t, store.CreateSession(ctx, sess))

	// Query the DB directly; the stored session_id_hash must differ from the plaintext.
	var storedHash string
	err := store.db.QueryRowContext(ctx, `SELECT session_id_hash FROM sessions WHERE user_id = $1`, "user-x").Scan(&storedHash)
	require.NoError(t, err)
	assert.NotEqual(t, plainToken, storedHash, "bearer token must be stored as HMAC hash, not plaintext")
	assert.Len(t, storedHash, 64, "HMAC-SHA256 hex digest must be 64 characters")

	// GetSession must still work using the original plaintext token.
	got, err := store.GetSession(ctx, plainToken)
	require.NoError(t, err)
	assert.Equal(t, "user-x", got.UserID)
}

func TestDatabaseSessionStore_GetNotFound(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()
	_, err := store.GetSession(ctx, "nonexistent-token")
	assert.Error(t, err)
}

func TestDatabaseSessionStore_Update(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()

	sess := makeSampleSession("sess-upd", "user-b", "tenant-b")
	require.NoError(t, store.CreateSession(ctx, sess))

	sess.Status = business.SessionStatusInactive
	sess.LastActivity = time.Now().UTC()
	require.NoError(t, store.UpdateSession(ctx, "sess-upd", sess))

	got, err := store.GetSession(ctx, "sess-upd")
	require.NoError(t, err)
	assert.Equal(t, business.SessionStatusInactive, got.Status)
	assert.NotNil(t, got.ModifiedAt)
}

func TestDatabaseSessionStore_Delete(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()

	sess := makeSampleSession("sess-del", "user-c", "tenant-c")
	require.NoError(t, store.CreateSession(ctx, sess))

	require.NoError(t, store.DeleteSession(ctx, "sess-del"))

	_, err := store.GetSession(ctx, "sess-del")
	assert.Error(t, err)
}

func TestDatabaseSessionStore_EphemeralRejected(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()

	sess := makeSampleSession("ephemeral", "user-e", "tenant-e")
	sess.Persistent = false
	err := store.CreateSession(ctx, sess)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not persistent")
}

func TestDatabaseSessionStore_SetTTL(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()

	sess := makeSampleSession("sess-ttl", "user-t", "tenant-t")
	require.NoError(t, store.CreateSession(ctx, sess))

	require.NoError(t, store.SetSessionTTL(ctx, "sess-ttl", 2*time.Hour))

	got, err := store.GetSession(ctx, "sess-ttl")
	require.NoError(t, err)
	assert.True(t, got.ExpiresAt.After(sess.ExpiresAt))
}

func TestDatabaseSessionStore_CleanupExpired(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()

	// makeSampleSession stamps CreatedAt with its own time.Now() call; backdate both
	// CreatedAt and ExpiresAt so ExpiresAt stays after CreatedAt (Session.Validate
	// rejects the insert otherwise) while still landing in the past relative to now,
	// so CleanupExpiredSessions picks the row up.
	now := time.Now().UTC().Truncate(time.Millisecond)
	sess := makeSampleSession("sess-exp", "user-exp", "tenant-exp")
	sess.CreatedAt = now.Add(-2 * time.Hour)
	sess.ExpiresAt = now.Add(-time.Hour) // already expired
	require.NoError(t, store.CreateSession(ctx, sess))

	n, err := store.CleanupExpiredSessions(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, 1)

	_, err = store.GetSession(ctx, "sess-exp")
	assert.Error(t, err)
}

func TestDatabaseSessionStore_GetStats(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()

	sess := makeSampleSession("sess-stats", "user-s", "tenant-s")
	require.NoError(t, store.CreateSession(ctx, sess))

	stats, err := store.GetStats(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, stats.TotalSessions, int64(1))
	assert.NotNil(t, stats.SessionsByType)
	assert.NotNil(t, stats.SessionsByStatus)
}

// TestDatabaseSessionStore_CrossTenantIsolation verifies that GetSessionsByTenant
// only returns sessions belonging to the requested tenant.
// app.current_tenant is set via the Go store layer (not a raw SET in the test).
func TestDatabaseSessionStore_CrossTenantIsolation(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()

	sessA := makeSampleSession("iso-sess-a", "user-iso", "tenant-iso-a")
	sessB := makeSampleSession("iso-sess-b", "user-iso", "tenant-iso-b")

	require.NoError(t, store.CreateSession(ctx, sessA))
	require.NoError(t, store.CreateSession(ctx, sessB))

	aList, err := store.GetSessionsByTenant(ctx, "tenant-iso-a")
	require.NoError(t, err)
	for _, s := range aList {
		assert.Equal(t, "tenant-iso-a", s.TenantID, "tenant-iso-b session must not appear under tenant-iso-a")
	}
	assert.GreaterOrEqual(t, len(aList), 1)

	bList, err := store.GetSessionsByTenant(ctx, "tenant-iso-b")
	require.NoError(t, err)
	for _, s := range bList {
		assert.Equal(t, "tenant-iso-b", s.TenantID, "tenant-iso-a session must not appear under tenant-iso-b")
	}
	assert.GreaterOrEqual(t, len(bList), 1)

	// Verify tenant-iso-a result contains no tenant-iso-b sessions.
	for _, s := range aList {
		assert.NotEqual(t, "tenant-iso-b", s.TenantID)
	}
}

// ── steward store tests ───────────────────────────────────────────────────────

func TestDatabaseStewardStore_RegisterAndGet(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := makeSampleSteward("sw-001", "tenant-sw-a")
	rec.DeviceID = "aabbcc"
	rec.IdentityKeyPub = []byte("fake-ed25519-pubkey")

	require.NoError(t, store.RegisterSteward(ctx, rec))

	got, err := store.GetSteward(ctx, "sw-001")
	require.NoError(t, err)
	assert.Equal(t, "sw-001", got.ID)
	assert.Equal(t, "tenant-sw-a", got.TenantID)
	assert.Equal(t, "linux", got.Platform)
	assert.Equal(t, business.StewardStatusRegistered, got.Status)
	assert.Equal(t, "aabbcc", got.DeviceID)
	assert.Equal(t, []byte("fake-ed25519-pubkey"), got.IdentityKeyPub)
}

func TestDatabaseStewardStore_AlreadyExists(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := makeSampleSteward("sw-dup", "tenant-sw-dup")
	require.NoError(t, store.RegisterSteward(ctx, rec))
	err := store.RegisterSteward(ctx, rec)
	assert.ErrorIs(t, err, business.ErrStewardAlreadyExists)
}

func TestDatabaseStewardStore_NotFound(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	_, err := store.GetSteward(ctx, "nonexistent")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestDatabaseStewardStore_UpdateHeartbeat(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := makeSampleSteward("sw-hb", "tenant-sw-hb")
	require.NoError(t, store.RegisterSteward(ctx, rec))

	require.NoError(t, store.UpdateHeartbeat(ctx, "sw-hb"))

	got, err := store.GetSteward(ctx, "sw-hb")
	require.NoError(t, err)
	assert.False(t, got.LastHeartbeatAt.IsZero(), "last_heartbeat_at must be set after heartbeat")
}

func TestDatabaseStewardStore_GetByDeviceID(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := makeSampleSteward("sw-dev", "tenant-sw-dev")
	rec.DeviceID = "device-fingerprint-hex"
	require.NoError(t, store.RegisterSteward(ctx, rec))

	got, err := store.GetStewardByDeviceID(ctx, "device-fingerprint-hex")
	require.NoError(t, err)
	assert.Equal(t, "sw-dev", got.ID)
}

func TestDatabaseStewardStore_ListByStatus(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		r := makeSampleSteward(fmt.Sprintf("sw-ls-%d", i), "tenant-sw-ls")
		require.NoError(t, store.RegisterSteward(ctx, r))
	}

	list, err := store.ListStewardsByStatus(ctx, business.StewardStatusRegistered)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(list), 3)
}

func TestDatabaseStewardStore_UpdateStatus(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := makeSampleSteward("sw-status", "tenant-sw-status")
	require.NoError(t, store.RegisterSteward(ctx, rec))

	require.NoError(t, store.UpdateStewardStatus(ctx, "sw-status", business.StewardStatusActive))

	got, err := store.GetSteward(ctx, "sw-status")
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusActive, got.Status)
}

func TestDatabaseStewardStore_Deregister(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := makeSampleSteward("sw-dereg", "tenant-sw-dereg")
	require.NoError(t, store.RegisterSteward(ctx, rec))
	require.NoError(t, store.DeregisterSteward(ctx, "sw-dereg"))

	got, err := store.GetSteward(ctx, "sw-dereg")
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusDeregistered, got.Status)
}

func TestDatabaseStewardStore_UpdateStewardTenant(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := makeSampleSteward("sw-move", "tenant-src")
	require.NoError(t, store.RegisterSteward(ctx, rec))

	require.NoError(t, store.UpdateStewardTenant(ctx, "sw-move", "tenant-src", "tenant-dst"))

	got, err := store.GetSteward(ctx, "sw-move")
	require.NoError(t, err)
	assert.Equal(t, "tenant-dst", got.TenantID)
	// Status must not be promoted on move.
	assert.Equal(t, business.StewardStatusRegistered, got.Status)
}

func TestDatabaseStewardStore_UpdateStewardTenant_NotFound(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.UpdateStewardTenant(context.Background(), "nonexistent", "tenant-src", "tenant-dst")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

// TestDatabaseStewardStore_UpdateStewardTenant_StaleExpectedTenantLoses is the
// [REQUIRED TEST] regression coverage for Issue #3895 at the storage layer: a
// CAS write whose expectedTenantID no longer matches the record's current
// tenant (a concurrent writer already moved it) must lose cleanly
// (ErrStewardNotFound) without applying.
func TestDatabaseStewardStore_UpdateStewardTenant_StaleExpectedTenantLoses(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := makeSampleSteward("sw-move-cas", "tenant-src")
	require.NoError(t, store.RegisterSteward(ctx, rec))

	require.NoError(t, store.UpdateStewardTenant(ctx, "sw-move-cas", "tenant-src", "tenant-dst-a"))

	err := store.UpdateStewardTenant(ctx, "sw-move-cas", "tenant-src", "tenant-dst-b")
	assert.ErrorIs(t, err, business.ErrStewardNotFound, "a stale expectedTenantID CAS must lose cleanly")

	got, err := store.GetSteward(ctx, "sw-move-cas")
	require.NoError(t, err)
	assert.Equal(t, "tenant-dst-a", got.TenantID, "the winner's destination must survive; the loser's must never apply")
}

func TestDatabaseStewardStore_SetStewardHidden(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := makeSampleSteward("sw-hidden", "tenant-sw-hidden")
	require.NoError(t, store.RegisterSteward(ctx, rec))

	// Default: not hidden.
	got, err := store.GetSteward(ctx, "sw-hidden")
	require.NoError(t, err)
	assert.False(t, got.Hidden, "freshly registered steward must not be hidden")

	// Hide it.
	require.NoError(t, store.SetStewardHidden(ctx, "sw-hidden", true))
	got, err = store.GetSteward(ctx, "sw-hidden")
	require.NoError(t, err)
	assert.True(t, got.Hidden, "GetSteward must reflect hidden=true after SetStewardHidden")

	// Un-hide it.
	require.NoError(t, store.SetStewardHidden(ctx, "sw-hidden", false))
	got, err = store.GetSteward(ctx, "sw-hidden")
	require.NoError(t, err)
	assert.False(t, got.Hidden, "GetSteward must reflect hidden=false after SetStewardHidden")
}

func TestDatabaseStewardStore_SetStewardHidden_NotFound(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.SetStewardHidden(context.Background(), "nonexistent", true)
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestDatabaseStewardStore_GetStewardsSeen(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := makeSampleSteward("sw-seen", "tenant-sw-seen")
	require.NoError(t, store.RegisterSteward(ctx, rec))

	since := time.Now().UTC().Add(-time.Minute)
	list, err := store.GetStewardsSeen(ctx, since)
	require.NoError(t, err)
	found := false
	for _, r := range list {
		if r.ID == "sw-seen" {
			found = true
		}
	}
	assert.True(t, found)
}

// TestDatabaseStewardStore_CrossTenantIsolation verifies that the steward_records RLS policy
// (FORCE ROW LEVEL SECURITY, rls_read FOR SELECT) enforces per-tenant visibility when
// app.current_tenant is set inside a transaction via set_config.
//
// Reads run through a dedicated non-superuser probe role (provisionStewardRecordsProbeRole,
// shared with rls_unscoped_read_test.go), not through store.db. store.db connects as the
// database's owning role, which in this test environment is the Postgres bootstrap
// superuser (POSTGRES_USER) — and superusers bypass row-level security unconditionally,
// even under FORCE ROW LEVEL SECURITY. A query issued through store.db would therefore see
// every row regardless of whether the RLS policy is correct, enforced, or even present,
// silently passing against a real cross-tenant leak.
func TestDatabaseStewardStore_CrossTenantIsolation(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	recA := makeSampleSteward("iso-sw-a", "tenant-sw-iso-a")
	recB := makeSampleSteward("iso-sw-b", "tenant-sw-iso-b")
	require.NoError(t, store.RegisterSteward(ctx, recA))
	require.NoError(t, store.RegisterSteward(ctx, recB))

	probeDSN := provisionStewardRecordsProbeRole(t, store.db)
	probe, err := sql.Open("postgres", probeDSN)
	require.NoError(t, err)
	defer func() { _ = probe.Close() }()
	// One underlying connection only, so app.current_tenant state below is deterministic
	// (see rls_unscoped_read_test.go for why a shared pooled connection is unsafe here).
	probe.SetMaxOpenConns(1)
	require.NoError(t, probe.Ping())

	// Without tenant context, the permissive rls_read branch shows all rows. This must run
	// before any set_config call on this connection: current_setting() only reports NULL
	// (the permissive branch) on a connection that has never set the GUC.
	unscoped := crossTenantIsolationVisibleIDs(t, probe, nil)
	assert.True(t, unscoped["iso-sw-a"], "no-context query must see tenant-a steward")
	assert.True(t, unscoped["iso-sw-b"], "no-context query must see tenant-b steward")

	// With tenant A context set in a tx, the rls_read policy filters to tenant A only.
	tenantA := "tenant-sw-iso-a"
	visibleA := crossTenantIsolationVisibleIDs(t, probe, &tenantA)
	assert.True(t, visibleA["iso-sw-a"], "tenant A must see its own steward")
	assert.False(t, visibleA["iso-sw-b"], "tenant A must not see tenant B steward (RLS)")

	// With tenant B context set in a tx, only tenant B's steward is visible.
	tenantB := "tenant-sw-iso-b"
	visibleB := crossTenantIsolationVisibleIDs(t, probe, &tenantB)
	assert.True(t, visibleB["iso-sw-b"], "tenant B must see its own steward")
	assert.False(t, visibleB["iso-sw-a"], "tenant B must not see tenant A steward (RLS)")
}

// crossTenantIsolationVisibleIDs runs the registered-status steward query used by
// TestDatabaseStewardStore_CrossTenantIsolation against probe, optionally scoping the
// transaction to tenant via set_config first, and returns the set of visible steward IDs
// among this test's own fixture rows.
func crossTenantIsolationVisibleIDs(t *testing.T, probe *sql.DB, tenant *string) map[string]bool {
	t.Helper()
	ctx := context.Background()

	tx, err := probe.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	if tenant != nil {
		require.NoError(t, setTenantLocal(ctx, tx, *tenant))
	}

	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM steward_records WHERE status = $1 AND id = ANY($2)`,
		string(business.StewardStatusRegistered), pq.Array([]string{"iso-sw-a", "iso-sw-b"}))
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	visible := make(map[string]bool)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		visible[id] = true
	}
	require.NoError(t, rows.Err())
	require.NoError(t, tx.Commit())
	return visible
}

// ── command store tests ───────────────────────────────────────────────────────

func TestDatabaseCommandStore_CreateAndGet(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	cmd := makeSampleCommand("cmd-001", "sw-001", "tenant-cmd-a")
	require.NoError(t, store.CreateCommandRecord(ctx, cmd))

	got, err := store.GetCommandRecord(ctx, "cmd-001")
	require.NoError(t, err)
	assert.Equal(t, "cmd-001", got.ID)
	assert.Equal(t, business.CommandStatusPending, got.Status)
	assert.Equal(t, "tenant-cmd-a", got.TenantID)
	assert.Equal(t, "sw-001", got.StewardID)
	assert.False(t, got.IssuedAt.IsZero())
}

func TestDatabaseCommandStore_NotFound(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	_, err := store.GetCommandRecord(ctx, "nonexistent")
	assert.ErrorIs(t, err, business.ErrCommandNotFound)
}

func TestDatabaseCommandStore_StatusLifecycle(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	cmd := makeSampleCommand("cmd-lc", "sw-lc", "tenant-cmd-lc")
	require.NoError(t, store.CreateCommandRecord(ctx, cmd))

	// pending -> executing
	require.NoError(t, store.UpdateCommandStatus(ctx, "cmd-lc", business.CommandStatusExecuting, nil, ""))
	got, err := store.GetCommandRecord(ctx, "cmd-lc")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusExecuting, got.Status)
	assert.NotNil(t, got.StartedAt)
	assert.Nil(t, got.CompletedAt)

	// executing -> completed
	result := map[string]interface{}{"exit_code": 0}
	require.NoError(t, store.UpdateCommandStatus(ctx, "cmd-lc", business.CommandStatusCompleted, result, ""))
	got, err = store.GetCommandRecord(ctx, "cmd-lc")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusCompleted, got.Status)
	assert.NotNil(t, got.CompletedAt)
	assert.Equal(t, float64(0), got.Result["exit_code"])
}

func TestDatabaseCommandStore_AuditTrail(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	cmd := makeSampleCommand("cmd-audit", "sw-audit", "tenant-cmd-audit")
	require.NoError(t, store.CreateCommandRecord(ctx, cmd))
	require.NoError(t, store.UpdateCommandStatus(ctx, "cmd-audit", business.CommandStatusExecuting, nil, ""))
	require.NoError(t, store.UpdateCommandStatus(ctx, "cmd-audit", business.CommandStatusFailed, nil, "timeout"))

	trail, err := store.GetCommandAuditTrail(ctx, "cmd-audit")
	require.NoError(t, err)
	require.Len(t, trail, 3, "expected pending, executing, failed transitions")
	assert.Equal(t, business.CommandStatusPending, trail[0].Status)
	assert.Equal(t, business.CommandStatusExecuting, trail[1].Status)
	assert.Equal(t, business.CommandStatusFailed, trail[2].Status)
	assert.Equal(t, "timeout", trail[2].ErrorMessage)
}

func TestDatabaseCommandStore_ListByDevice(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		c := makeSampleCommand(fmt.Sprintf("cmd-dev-%d", i), "sw-multi", "tenant-cmd-dev")
		require.NoError(t, store.CreateCommandRecord(ctx, c))
	}

	list, err := store.ListCommandsByDevice(ctx, "sw-multi")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(list), 3)
}

func TestDatabaseCommandStore_PurgeExpired(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	old := makeSampleCommand("cmd-old", "sw-purge", "tenant-cmd-purge")
	old.IssuedAt = time.Now().UTC().Add(-48 * time.Hour)
	require.NoError(t, store.CreateCommandRecord(ctx, old))
	require.NoError(t, store.UpdateCommandStatus(ctx, "cmd-old", business.CommandStatusCompleted, nil, ""))

	n, err := store.PurgeExpiredRecords(ctx, time.Now().UTC().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(1))

	_, err = store.GetCommandRecord(ctx, "cmd-old")
	assert.ErrorIs(t, err, business.ErrCommandNotFound)
}

// TestDatabaseCommandStore_CrossTenantIsolation verifies that ListCommandRecords
// filtered by tenant only returns commands for that tenant.
// app.current_tenant is set via the Go store layer (not a raw SET in the test).
func TestDatabaseCommandStore_CrossTenantIsolation(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	cmdA := makeSampleCommand("iso-cmd-a", "sw-iso", "tenant-cmd-iso-a")
	cmdB := makeSampleCommand("iso-cmd-b", "sw-iso", "tenant-cmd-iso-b")
	require.NoError(t, store.CreateCommandRecord(ctx, cmdA))
	require.NoError(t, store.CreateCommandRecord(ctx, cmdB))

	aList, err := store.ListCommandRecords(ctx, &business.CommandFilter{TenantID: "tenant-cmd-iso-a"})
	require.NoError(t, err)
	for _, c := range aList {
		assert.Equal(t, "tenant-cmd-iso-a", c.TenantID, "tenant-cmd-iso-b command must not appear under tenant-cmd-iso-a")
	}
	assert.GreaterOrEqual(t, len(aList), 1)

	bList, err := store.ListCommandRecords(ctx, &business.CommandFilter{TenantID: "tenant-cmd-iso-b"})
	require.NoError(t, err)
	for _, c := range bList {
		assert.Equal(t, "tenant-cmd-iso-b", c.TenantID, "tenant-cmd-iso-a command must not appear under tenant-cmd-iso-b")
	}
	assert.GreaterOrEqual(t, len(bList), 1)
}

// ── plugin-level smoke tests ──────────────────────────────────────────────────

func TestDatabaseProvider_CreateSessionStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	cfg := getTestConfig()
	cfg["session_hmac_key"] = "test-hmac-key-for-integration-tests-only-32bytes"
	store, err := provider.CreateSessionStore(cfg)
	require.NoError(t, err)
	require.NotNil(t, store)
	if s, ok := store.(*DatabaseSessionStore); ok {
		_ = s.Close()
	}
}

func TestDatabaseProvider_CreateStewardStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	store, err := provider.CreateStewardStore(getTestConfig())
	require.NoError(t, err)
	require.NotNil(t, store)
	if s, ok := store.(*DatabaseStewardStore); ok {
		_ = s.Close()
	}
}

func TestDatabaseProvider_CreateCommandStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	store, err := provider.CreateCommandStore(getTestConfig())
	require.NoError(t, err)
	require.NotNil(t, store)
	if s, ok := store.(*DatabaseCommandStore); ok {
		_ = s.Close()
	}
}

// TestDatabaseStewardStore_DeviceIDUniquePerTenant is the PostgreSQL half of the
// database-level backstop for the tenant-scoped duplicate-device_id guard (Issue #3403).
// It mirrors TestSQLiteStewardStore_DeviceIDUniquePerTenant case for case so both
// providers are held to the same contract — the guard in
// features/controller/api/handlers_registration.go is check-then-act, and only the
// partial unique index on (tenant_id, device_id) decides a winner when two claims
// assert one device_id concurrently.
func TestDatabaseStewardStore_DeviceIDUniquePerTenant(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	deviceID := fmt.Sprintf("device-shared-%d", time.Now().UnixNano())
	const tenantA = "tenant-dup-a"
	const tenantB = "tenant-dup-b"

	first := makeSampleSteward("steward-dup-a", tenantA)
	first.DeviceID = deviceID
	require.NoError(t, store.RegisterSteward(ctx, first))

	// A different steward asserting the same device_id in the same tenant.
	second := makeSampleSteward("steward-dup-b", tenantA)
	second.DeviceID = deviceID
	err := store.RegisterSteward(ctx, second)
	require.Error(t, err, "a second steward must not take a device_id already held in the tenant")
	assert.ErrorIs(t, err, business.ErrStewardDeviceIDConflict,
		"the conflict must be reported as ErrStewardDeviceIDConflict, not the benign ErrStewardAlreadyExists")

	// Cross-tenant is a separate namespace and must still be allowed.
	other := makeSampleSteward("steward-dup-c", tenantB)
	other.DeviceID = deviceID
	assert.NoError(t, store.RegisterSteward(ctx, other),
		"the same device_id under a different tenant is a distinct namespace")

	// Empty device_id means "not asserted" and must not collide with itself.
	blankA := makeSampleSteward("steward-blank-a", tenantA)
	blankA.DeviceID = ""
	blankB := makeSampleSteward("steward-blank-b", tenantA)
	blankB.DeviceID = ""
	require.NoError(t, store.RegisterSteward(ctx, blankA))
	assert.NoError(t, store.RegisterSteward(ctx, blankB),
		"rows with no device_id must be excluded from the unique index")

	// Re-registering the SAME steward stays the benign duplicate. This is the case
	// that keeps an idempotent claim retry working: it violates both the primary key
	// and the device index, and must not be reported as a device_id conflict.
	dupSelf := makeSampleSteward("steward-dup-a", tenantA)
	dupSelf.DeviceID = deviceID
	selfErr := store.RegisterSteward(ctx, dupSelf)
	require.Error(t, selfErr)
	assert.ErrorIs(t, selfErr, business.ErrStewardAlreadyExists,
		"the same steward written twice stays ErrStewardAlreadyExists so idempotent retries remain benign")
}
