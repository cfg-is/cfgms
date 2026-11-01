// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	workflowtrigger "github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func storeDelayWorkflow(t *testing.T, adapter *workflowEngineAdapter, tenant, name string, delay time.Duration) {
	t.Helper()
	semver, err := workflow.ParseSemanticVersion("1.0.0")
	require.NoError(t, err)
	require.NoError(t, workflow.NewWorkflowStore(adapter.configStore, tenant).StoreWorkflow(context.Background(), &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{Name: name, Version: "1.0.0", Steps: []workflow.Step{
			{Name: "pause", Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: delay}},
		}},
		SemanticVersion: *semver,
	}))
}

func waitTerminal(t *testing.T, engine *workflow.Engine, id string) workflow.ExecutionStatus {
	t.Helper()
	var status workflow.ExecutionStatus
	require.Eventually(t, func() bool {
		execution, err := engine.GetExecution(context.Background(), "acme-corp", id)
		require.NoError(t, err)
		status = execution.GetStatus()
		return status == workflow.StatusCompleted || status == workflow.StatusFailed || status == workflow.StatusCancelled
	}, 10*time.Second, 20*time.Millisecond)
	return status
}

// TestWorkflowEngineAdapter_ExecutionOutlivesCaller guards Issue #4658: a
// triggered execution runs to completion even though the context of the call
// that started it — an HTTP request for a manual execution, a callback
// goroutine for a schedule or webhook — is cancelled right after the start;
// and a trigger timeout shorter than the workflow ends the execution.
func TestWorkflowEngineAdapter_ExecutionOutlivesCaller(t *testing.T) {
	configStore := pkgtesting.SetupTestStorage(t).GetConfigStore()
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	adapter := &workflowEngineAdapter{engine: engine, configStore: configStore}
	storeDelayWorkflow(t, adapter, "acme-corp", "short", 300*time.Millisecond)
	storeDelayWorkflow(t, adapter, "acme-corp", "long", 5*time.Second)

	callerCtx, cancel := context.WithCancel(context.Background())
	execution, err := adapter.TriggerWorkflow(callerCtx, &workflowtrigger.Trigger{ID: "t1", TenantID: "acme-corp", WorkflowName: "short"}, nil)
	require.NoError(t, err)
	cancel() // the starting call returns
	assert.Equal(t, workflow.StatusCompleted, waitTerminal(t, engine, execution.ID),
		"the execution must not inherit the starting call's cancellation")

	execution, err = adapter.TriggerWorkflow(context.Background(), &workflowtrigger.Trigger{
		ID: "t2", TenantID: "acme-corp", WorkflowName: "long", Timeout: 200 * time.Millisecond,
	}, nil)
	require.NoError(t, err)
	start := time.Now()
	assert.NotEqual(t, workflow.StatusCompleted, waitTerminal(t, engine, execution.ID), "the trigger timeout must end the execution")
	assert.Less(t, time.Since(start), 4*time.Second, "the execution must end at the trigger timeout, not run its full length")
}
