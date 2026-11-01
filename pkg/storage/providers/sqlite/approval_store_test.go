// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestApprovalStoreAt builds the store through the provider factory so the
// tests also cover config parsing and path resolution.
func newTestApprovalStoreAt(t *testing.T, path string) business.ApprovalStore {
	t.Helper()
	store, err := NewSQLiteProvider(path).CreateApprovalStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.(*SQLiteApprovalStore).Close() })
	return store
}

func TestSQLiteApprovalStore_Contract(t *testing.T) {
	business.ApprovalStoreContract(t, newTestApprovalStoreAt(t, filepath.Join(t.TempDir(), "cfgms.db")))
}

// TestSQLiteApprovalStore_SurvivesRestart proves approvals are durable: a second
// store opened on the same file sees pending and decided-unresumed approvals.
func TestSQLiteApprovalStore_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	first, err := NewSQLiteProvider(path).CreateApprovalStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	for _, id := range []string{"a1", "a2"} {
		require.NoError(t, first.CreateApproval(ctx, &business.WorkflowApproval{
			ApprovalID: id, TenantID: "t1", RequestedAt: now, CheckpointRef: "secret://t1/" + id,
		}))
	}
	require.NoError(t, first.DecideApproval(ctx, "t1", "a2", business.ApprovalStatusApproved, "bob", "", now))
	require.NoError(t, first.(*SQLiteApprovalStore).Close())

	second := newTestApprovalStoreAt(t, path)
	pending, err := second.ListPending(ctx, "t1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, "a1", pending[0].ApprovalID)
	assert.Equal(t, "secret://t1/a1", pending[0].CheckpointRef)
	unresumed, err := second.ListUnresumed(ctx, now, time.Minute)
	require.NoError(t, err)
	require.Len(t, unresumed, 1)
	assert.Equal(t, "a2", unresumed[0].ApprovalID)
}
