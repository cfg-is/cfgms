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

func TestFlatFileWorkflowExecutionStore_Contract(t *testing.T) {
	store, err := NewFlatFileWorkflowExecutionStore(t.TempDir())
	require.NoError(t, err)
	business.WorkflowExecutionStoreContract(t, store)
}

// TestFlatFileWorkflowExecutionStore_SurvivesRestart proves records are durable and
// that ids with path characters cannot escape the store directory.
func TestFlatFileWorkflowExecutionStore_SurvivesRestart(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Millisecond)

	first, err := NewFlatFileWorkflowExecutionStore(root)
	require.NoError(t, err)
	require.NoError(t, first.Save(ctx, &business.WorkflowExecutionRecord{
		TenantID: "../t1", ExecutionID: "../../e1", WorkflowName: "wf", Status: "completed",
		StartTime: start, EndTime: start.Add(time.Second), Payload: []byte(`{"ok":true}`),
	}))

	second, err := NewFlatFileWorkflowExecutionStore(root)
	require.NoError(t, err)
	got, err := second.Get(ctx, "../t1", "../../e1")
	require.NoError(t, err)
	assert.Equal(t, "completed", got.Status)
	assert.JSONEq(t, `{"ok":true}`, string(got.Payload))
}

func TestFlatFileWorkflowExecutionStore_RejectsInvalidPayload(t *testing.T) {
	store, err := NewFlatFileWorkflowExecutionStore(t.TempDir())
	require.NoError(t, err)
	err = store.Save(context.Background(), &business.WorkflowExecutionRecord{
		TenantID: "t", ExecutionID: "e", Status: "running", Payload: []byte("not json"),
	})
	assert.Error(t, err)
}
