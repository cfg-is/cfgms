// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Approval-store wiring tests (Issue #4607). These live in the external
// interfaces_test package because the real ApprovalStore implementations ship in
// pkg/storage/providers/*, which import pkg/storage/interfaces.
package interfaces_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestCreateOSSStorageManager_ApprovalStore verifies the OSS manager wires a durable
// ApprovalStore and that an approval survives closing and reopening the manager.
func TestCreateOSSStorageManager_ApprovalStore(t *testing.T) {
	ffRoot, dbPath := t.TempDir(), filepath.Join(t.TempDir(), "oss-approvals.db")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	sm, err := interfaces.CreateOSSStorageManager(ffRoot, dbPath)
	require.NoError(t, err)
	store := sm.GetApprovalStore()
	require.NotNil(t, store, "GetApprovalStore must be wired by the OSS storage manager")
	assert.True(t, sm.HasStore(interfaces.StoreNameApproval))
	require.NoError(t, store.CreateApproval(ctx, &business.WorkflowApproval{
		ApprovalID: "a1", TenantID: "t1", ExecutionID: "e1", RequestedAt: now,
	}))
	require.NoError(t, sm.Close())

	reopened, err := interfaces.CreateOSSStorageManager(ffRoot, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	pending, err := reopened.GetApprovalStore().ListPending(ctx, "t1")
	require.NoError(t, err)
	require.Len(t, pending, 1, "a pending approval survives a restart")
	assert.Equal(t, "a1", pending[0].ApprovalID)
}
