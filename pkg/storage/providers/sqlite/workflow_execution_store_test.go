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

// newTestWorkflowExecutionStoreAt builds the store through the provider factory so
// the tests also cover config parsing and path resolution.
func newTestWorkflowExecutionStoreAt(t *testing.T, path string) business.WorkflowExecutionStore {
	t.Helper()
	store, err := NewSQLiteProvider(path).CreateWorkflowExecutionStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.(*SQLiteWorkflowExecutionStore).Close() })
	return store
}

func TestSQLiteWorkflowExecutionStore_Contract(t *testing.T) {
	business.WorkflowExecutionStoreContract(t, newTestWorkflowExecutionStoreAt(t, filepath.Join(t.TempDir(), "cfgms.db")))
}

// TestSQLiteWorkflowExecutionStore_SurvivesRestart proves records are durable: a
// second store opened on the same file reads what the first one wrote.
func TestSQLiteWorkflowExecutionStore_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Millisecond)

	first, err := NewSQLiteProvider(path).CreateWorkflowExecutionStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	require.NoError(t, first.Save(ctx, &business.WorkflowExecutionRecord{
		TenantID: "t1", ExecutionID: "e1", WorkflowName: "wf", Status: "completed",
		StartTime: start, EndTime: start.Add(time.Second), Payload: []byte(`{"ok":true}`),
	}))
	require.NoError(t, first.(*SQLiteWorkflowExecutionStore).Close())

	second := newTestWorkflowExecutionStoreAt(t, path)
	got, err := second.Get(ctx, "t1", "e1")
	require.NoError(t, err)
	assert.Equal(t, "completed", got.Status)
	assert.JSONEq(t, `{"ok":true}`, string(got.Payload))
}
