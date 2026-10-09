// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// WorkflowExecutionStoreContract itself lives in contract_workflow_execution.go
// (non-test file) because the provider packages import it; each of the flatfile,
// sqlite and database providers runs it from its own workflow_execution_store_test.go.

func TestIsTerminalWorkflowExecutionStatus(t *testing.T) {
	for _, s := range []string{"completed", "failed", "cancelled"} {
		assert.True(t, IsTerminalWorkflowExecutionStatus(s), s)
	}
	for _, s := range []string{"", "pending", "running", "paused", "awaiting_approval"} {
		assert.False(t, IsTerminalWorkflowExecutionStatus(s), s)
	}
}
