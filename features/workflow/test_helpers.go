// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"testing"
	"time"
)

// waitForWorkflowCompletion polls the workflow execution status until it reaches
// a terminal state (completed, failed, or cancelled) or times out.
//
// This is the correct pattern for testing async workflow execution, replacing
// fixed time.Sleep() calls that cause race conditions on slower systems (Windows CI).
//
// Note: This function polls the execution object's status directly. The workflow
// engine updates the status field atomically, so we can poll without fetching
// from the engine each time.
//
// Usage:
//
//	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
//	require.NoError(t, err)
//	waitForWorkflowCompletion(t, execution, 2*time.Second)
//	assert.Equal(t, StatusCompleted, execution.GetStatus())
func waitForWorkflowCompletion(t *testing.T, execution *WorkflowExecution, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Use GetStatus() which properly locks and reads the status
			status := execution.GetStatus()

			if status != StatusPending && status != StatusRunning {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timeout waiting for workflow completion after %v, status: %s, execution_id: %s",
					timeout, status, execution.ID)
			}
		}
	}
}
