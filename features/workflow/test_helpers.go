// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"testing"
	"time"
)

// waitForWorkflowCompletion waits for the workflow execution to fully complete.
//
// If the execution has a Done channel (created via ExecuteWorkflow), it waits on
// that channel which closes only after executeWorkflowAsync finishes all work
// including logging. This eliminates the race condition where tests exit while
// goroutines are still writing to stderr.
//
// If Done is nil (manually-created executions in tests), falls back to polling
// status until a terminal state is reached.
//
// Usage:
//
//	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
//	require.NoError(t, err)
//	waitForWorkflowCompletion(t, execution, 2*time.Second)
//	assert.Equal(t, StatusCompleted, execution.GetStatus())
func waitForWorkflowCompletion(t *testing.T, execution *WorkflowExecution, timeout time.Duration) {
	t.Helper()

	if execution.Done != nil {
		select {
		case <-execution.Done:
			return
		case <-time.After(timeout):
			t.Fatalf("timeout waiting for workflow completion after %v, status: %s, execution_id: %s",
				timeout, execution.GetStatus(), execution.ID)
		}
		return
	}

	// Fallback: poll status for manually-created executions without Done channel
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
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

// waitForWorkflowRunning polls until the workflow execution reaches StatusRunning.
// Use this to synchronize with async goroutine startup before performing actions
// like pause or cancel that require the workflow to be running.
func waitForWorkflowRunning(t *testing.T, execution *WorkflowExecution, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		status := execution.GetStatus()
		if status == StatusRunning {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for workflow to reach running status after %v, status: %s, execution_id: %s",
				timeout, status, execution.ID)
		}
	}
}
