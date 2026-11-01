// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Workflow-execution-store wiring tests (Issue #4675). These live in the external
// interfaces_test package because the real WorkflowExecutionStore implementations
// ship in pkg/storage/providers/*, which import pkg/storage/interfaces.
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

// TestCreateOSSStorageManager_WorkflowExecutionStore verifies the OSS manager wires a
// durable WorkflowExecutionStore and that a record survives closing and reopening it.
func TestCreateOSSStorageManager_WorkflowExecutionStore(t *testing.T) {
	ffRoot, dbPath := t.TempDir(), filepath.Join(t.TempDir(), "oss-executions.db")
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Millisecond)

	sm, err := interfaces.CreateOSSStorageManager(ffRoot, dbPath)
	require.NoError(t, err)
	store := sm.GetWorkflowExecutionStore()
	require.NotNil(t, store, "GetWorkflowExecutionStore must be wired by the OSS storage manager")
	assert.True(t, sm.HasStore(interfaces.StoreNameWorkflowExecution))
	require.NoError(t, store.Save(ctx, &business.WorkflowExecutionRecord{
		TenantID: "t1", ExecutionID: "e1", WorkflowName: "wf", Status: "completed",
		StartTime: start, EndTime: start.Add(time.Second), Payload: []byte(`{}`),
	}))
	require.NoError(t, sm.Close())

	reopened, err := interfaces.CreateOSSStorageManager(ffRoot, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	got, err := reopened.GetWorkflowExecutionStore().Get(ctx, "t1", "e1")
	require.NoError(t, err)
	assert.Equal(t, "completed", got.Status, "an execution survives a restart")
}
