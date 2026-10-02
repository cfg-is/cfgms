// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestAlertStore(t *testing.T) *FlatFileAlertStore {
	t.Helper()
	store, err := NewFlatFileAlertStore(t.TempDir())
	require.NoError(t, err)
	return store
}

func TestFlatFileAlertStore_AcknowledgeAndGet(t *testing.T) {
	store := newTestAlertStore(t)
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
	assert.Equal(t, now, st.AcknowledgedAt.Truncate(time.Second))
	assert.False(t, st.Silenced)
}

func TestFlatFileAlertStore_SilenceAndGet(t *testing.T) {
	store := newTestAlertStore(t)
	ctx := context.Background()

	until := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, store.SilenceAlert(ctx, "tenant-1", "alert-1", "bob", until))

	st, err := store.GetAlertState(ctx, "tenant-1", "alert-1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, st.Silenced)
	assert.Equal(t, "bob", st.SilencedBy)
	assert.Equal(t, until, st.SilencedUntil.Truncate(time.Second))
	assert.False(t, st.Acknowledged)
}

func TestFlatFileAlertStore_AcknowledgeThenSilence(t *testing.T) {
	store := newTestAlertStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	until := now.Add(time.Hour)

	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "a1", "alice", now))
	require.NoError(t, store.SilenceAlert(ctx, "t1", "a1", "bob", until))

	st, err := store.GetAlertState(ctx, "t1", "a1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, st.Acknowledged)
	assert.True(t, st.Silenced)
}

func TestFlatFileAlertStore_GetUnknown_ReturnsNil(t *testing.T) {
	store := newTestAlertStore(t)
	ctx := context.Background()

	st, err := store.GetAlertState(ctx, "tenant-1", "never-touched")
	require.NoError(t, err)
	assert.Nil(t, st, "unknown alertID should return nil, nil")
}

func TestFlatFileAlertStore_ListAlertStates(t *testing.T) {
	store := newTestAlertStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "a1", "alice", now))
	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "a2", "bob", now))
	require.NoError(t, store.AcknowledgeAlert(ctx, "t2", "a3", "carol", now)) // different tenant

	states, err := store.ListAlertStates(ctx, "t1")
	require.NoError(t, err)
	assert.Len(t, states, 2, "should only return states for t1")

	states2, err := store.ListAlertStates(ctx, "t-nonexistent")
	require.NoError(t, err)
	assert.Empty(t, states2, "unknown tenant returns empty slice")
	assert.NotNil(t, states2, "should return non-nil empty slice")
}

func TestFlatFileAlertStore_TenantIsolation(t *testing.T) {
	store := newTestAlertStore(t)
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
}

func TestFlatFileAlertStore_IdempotentAcknowledge(t *testing.T) {
	store := newTestAlertStore(t)
	ctx := context.Background()
	t1 := time.Now().UTC()

	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "a1", "alice", t1))

	// Re-acknowledge should update, not error.
	t2 := t1.Add(time.Minute)
	require.NoError(t, store.AcknowledgeAlert(ctx, "t1", "a1", "bob", t2))

	st, err := store.GetAlertState(ctx, "t1", "a1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Equal(t, "bob", st.AcknowledgedBy)
}

func TestFlatFileAlertStore_CompileTimeAssertion(t *testing.T) {
	var _ business.AlertStore = (*FlatFileAlertStore)(nil)
}
