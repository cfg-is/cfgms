// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Unit tests for the PostgreSQL AlertStore (Issue #3266). The tests run against the
// real test database; they skip only when PostgreSQL is unavailable, following the
// setupTestDatabase convention used by the sibling store tests in this package.
package database

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestDatabaseAlertStore drops the existing schema, then builds the store through
// its real constructor so schema initialisation (advisory lock + CREATE TABLE) runs.
func newTestDatabaseAlertStore(t *testing.T) *DatabaseAlertStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewDatabaseAlertStore(db, getTestConfig())
	require.NoError(t, err)
	return store
}

func TestDatabaseAlertStore_CompileTimeAssertion(t *testing.T) {
	var _ business.AlertStore = (*DatabaseAlertStore)(nil)
}

// TestDatabaseAlertStore_InitSchemaIsIdempotent verifies that constructing the store a
// second time against the same database re-runs schema initialisation without error.
func TestDatabaseAlertStore_InitSchemaIsIdempotent(t *testing.T) {
	first := newTestDatabaseAlertStore(t)
	require.NotNil(t, first)

	dbSecond := getTestDB(t)
	t.Cleanup(func() { _ = dbSecond.Close() })
	second, err := NewDatabaseAlertStore(dbSecond, getTestConfig())
	require.NoError(t, err, "initSchema must be idempotent")

	// Both handles must see the same table.
	ctx := context.Background()
	now := time.Now().UTC()
	require.NoError(t, first.AcknowledgeAlert(ctx, "t-idem", "a1", "alice", now))
	st, err := second.GetAlertState(ctx, "t-idem", "a1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Equal(t, "alice", st.AcknowledgedBy)
}

func TestDatabaseAlertStore_AcknowledgeAndGet(t *testing.T) {
	store := newTestDatabaseAlertStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, store.AcknowledgeAlert(ctx, "tenant-1", "alert-1", "alice", now))

	st, err := store.GetAlertState(ctx, "tenant-1", "alert-1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Equal(t, "alert-1", st.AlertID)
	assert.Equal(t, "tenant-1", st.TenantID)
	assert.True(t, st.Acknowledged)
	assert.Equal(t, "alice", st.AcknowledgedBy)
	assert.WithinDuration(t, now, st.AcknowledgedAt, time.Second)
	assert.False(t, st.Silenced)
}

func TestDatabaseAlertStore_SilenceAndGet(t *testing.T) {
	store := newTestDatabaseAlertStore(t)
	ctx := context.Background()

	until := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, store.SilenceAlert(ctx, "tenant-1", "alert-1", "bob", until))

	st, err := store.GetAlertState(ctx, "tenant-1", "alert-1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, st.Silenced)
	assert.Equal(t, "bob", st.SilencedBy)
	assert.WithinDuration(t, until, st.SilencedUntil, time.Second)
	assert.False(t, st.Acknowledged)
}

// TestDatabaseAlertStore_UpsertPreservesOtherColumns exercises the ON CONFLICT branch:
// silencing an acknowledged alert must not clear the acknowledgement, and vice versa.
func TestDatabaseAlertStore_UpsertPreservesOtherColumns(t *testing.T) {
	store := newTestDatabaseAlertStore(t)
	ctx := context.Background()

	ackAt := time.Now().UTC().Truncate(time.Second)
	until := ackAt.Add(time.Hour)

	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "a1", "alice", ackAt))
	require.NoError(t, store.SilenceAlert(ctx, "t1", "a1", "bob", until))

	st, err := store.GetAlertState(ctx, "t1", "a1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, st.Acknowledged, "acknowledgement must survive a later silence")
	assert.Equal(t, "alice", st.AcknowledgedBy)
	assert.WithinDuration(t, ackAt, st.AcknowledgedAt, time.Second)
	assert.True(t, st.Silenced)
	assert.Equal(t, "bob", st.SilencedBy)
	assert.WithinDuration(t, until, st.SilencedUntil, time.Second)

	// Silence first, then acknowledge: the reverse ordering must also preserve state.
	require.NoError(t, store.SilenceAlert(ctx, "t1", "a2", "bob", until))
	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "a2", "alice", ackAt))

	st2, err := store.GetAlertState(ctx, "t1", "a2")
	require.NoError(t, err)
	require.NotNil(t, st2)
	assert.True(t, st2.Acknowledged)
	assert.True(t, st2.Silenced, "silence must survive a later acknowledgement")
	assert.Equal(t, "bob", st2.SilencedBy)
}

// TestDatabaseAlertStore_RepeatedWritesUpdateInPlace verifies the upsert updates the
// existing row rather than inserting duplicates (UNIQUE(tenant_id, alert_id)).
func TestDatabaseAlertStore_RepeatedWritesUpdateInPlace(t *testing.T) {
	store := newTestDatabaseAlertStore(t)
	ctx := context.Background()

	t1 := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "a1", "alice", t1))

	t2 := t1.Add(time.Minute)
	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "a1", "bob", t2))

	states, err := store.ListAlertStates(ctx, "t1")
	require.NoError(t, err)
	require.Len(t, states, 1, "re-acknowledging must update in place, not duplicate")
	assert.Equal(t, "bob", states[0].AcknowledgedBy)
	assert.WithinDuration(t, t2, states[0].AcknowledgedAt, time.Second)
}

func TestDatabaseAlertStore_GetUnknownReturnsNil(t *testing.T) {
	store := newTestDatabaseAlertStore(t)

	st, err := store.GetAlertState(context.Background(), "tenant-1", "never-touched")
	require.NoError(t, err, "unknown alertID must not be an error")
	assert.Nil(t, st, "unknown alertID must return nil, nil")
}

// TestDatabaseAlertStore_ListAlertStates covers tenant filtering, alert_id ordering and
// the empty-but-non-nil result contract.
func TestDatabaseAlertStore_ListAlertStates(t *testing.T) {
	store := newTestDatabaseAlertStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "b-alert", "alice", now))
	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "a-alert", "alice", now))
	require.NoError(t, store.SilenceAlert(ctx, "t2", "c-alert", "carol", now.Add(time.Hour)))

	states, err := store.ListAlertStates(ctx, "t1")
	require.NoError(t, err)
	require.Len(t, states, 2, "only t1 states may be returned")
	assert.Equal(t, "a-alert", states[0].AlertID, "results must be ordered by alert_id")
	assert.Equal(t, "b-alert", states[1].AlertID)

	empty, err := store.ListAlertStates(ctx, "tenant-with-no-alerts")
	require.NoError(t, err)
	assert.NotNil(t, empty, "must return a non-nil slice")
	assert.Empty(t, empty)
}

// TestDatabaseAlertStore_TenantIsolation verifies that the same alertID in two tenants
// yields two independent rows.
func TestDatabaseAlertStore_TenantIsolation(t *testing.T) {
	store := newTestDatabaseAlertStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "shared-id", "alice", now))
	require.NoError(t, store.AcknowledgeAlert(ctx, "t2", "shared-id", "bob", now))

	st1, err := store.GetAlertState(ctx, "t1", "shared-id")
	require.NoError(t, err)
	require.NotNil(t, st1)
	assert.Equal(t, "alice", st1.AcknowledgedBy)

	st2, err := store.GetAlertState(ctx, "t2", "shared-id")
	require.NoError(t, err)
	require.NotNil(t, st2)
	assert.Equal(t, "bob", st2.AcknowledgedBy)

	none, err := store.GetAlertState(ctx, "t3", "shared-id")
	require.NoError(t, err)
	assert.Nil(t, none, "a third tenant must not see either row")
}

// TestDatabaseAlertStore_ConcurrentAcknowledge verifies that concurrent writers to the
// same (tenant, alert) key converge on a single row without upsert conflicts.
func TestDatabaseAlertStore_ConcurrentAcknowledge(t *testing.T) {
	store := newTestDatabaseAlertStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			if err := store.AcknowledgeAlert(ctx, "t-concurrent", "a1", "alice", now); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	states, err := store.ListAlertStates(ctx, "t-concurrent")
	require.NoError(t, err)
	require.Len(t, states, 1, "concurrent acknowledgements must collapse into one row")
	assert.True(t, states[0].Acknowledged)
}

// TestDatabaseAlertStore_ContextCancellation verifies that a cancelled context surfaces
// as an error instead of a silent success.
func TestDatabaseAlertStore_ContextCancellation(t *testing.T) {
	store := newTestDatabaseAlertStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := store.AcknowledgeAlert(ctx, "t1", "a1", "alice", time.Now().UTC())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acknowledge alert")

	_, err = store.ListAlertStates(ctx, "t1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list alert states")
}
