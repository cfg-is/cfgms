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

// TestWorkflowEngineAdapter_RunsUnderTriggerTenant guards Issue #4640: an
// execution started by a trigger carries the trigger's tenant as its
// authenticated tenant — the tenant every tenant-scoped step acts on. Scheduled
// and webhook triggers fire with no caller context, so before this the
// execution had no tenant and tenant-scoped steps refused to run.
func TestWorkflowEngineAdapter_RunsUnderTriggerTenant(t *testing.T) {
	configStore := pkgtesting.SetupTestStorage(t).GetConfigStore()
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	adapter := &workflowEngineAdapter{engine: engine, configStore: configStore}

	semver, err := workflow.ParseSemanticVersion("1.0.0")
	require.NoError(t, err)
	require.NoError(t, workflow.NewWorkflowStore(configStore, "acme-corp").StoreWorkflow(context.Background(), &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{Name: "nightly", Version: "1.0.0", Steps: []workflow.Step{
			{Name: "pause", Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: time.Millisecond}},
		}},
		SemanticVersion: *semver,
	}))

	execution, err := adapter.TriggerWorkflow(context.Background(), &workflowtrigger.Trigger{
		ID: "nightly-trigger", TenantID: "acme-corp", WorkflowName: "nightly",
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "acme-corp", execution.TenantID)

	_, err = adapter.TriggerWorkflow(context.Background(), &workflowtrigger.Trigger{
		ID: "orphan-trigger", WorkflowName: "nightly",
	}, nil)
	assert.Error(t, err, "a trigger without a tenant must not start an execution")
}
