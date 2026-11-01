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

func TestFlatFileApprovalStore_Contract(t *testing.T) {
	store, err := NewFlatFileApprovalStore(t.TempDir())
	require.NoError(t, err)
	business.ApprovalStoreContract(t, store)
}

// TestFlatFileApprovalStore_SurvivesRestart proves a pending approval and a decided,
// unresumed one are durable: a second store opened on the same root sees them.
func TestFlatFileApprovalStore_SurvivesRestart(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	first, err := NewFlatFileApprovalStore(root)
	require.NoError(t, err)
	for _, id := range []string{"a1", "a2"} {
		require.NoError(t, first.CreateApproval(ctx, &business.WorkflowApproval{
			ApprovalID: id, TenantID: "t1", ExecutionID: "e-" + id, RequestedAt: now,
			CheckpointRef: "secret://t1/" + id,
		}))
	}
	require.NoError(t, first.DecideApproval(ctx, "t1", "a2", business.ApprovalStatusApproved, "bob", "", now))

	second, err := NewFlatFileApprovalStore(root)
	require.NoError(t, err)
	pending, err := second.ListPending(ctx, "t1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, "a1", pending[0].ApprovalID)
	unresumed, err := second.ListUnresumed(ctx, now, time.Minute)
	require.NoError(t, err)
	require.Len(t, unresumed, 1)
	assert.Equal(t, "a2", unresumed[0].ApprovalID)
}
