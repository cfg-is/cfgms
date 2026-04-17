// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	storageif "github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// workflowEngineAdapter implements WorkflowTrigger using a real *workflow.Engine and a real
// ConfigStore. This mirrors the unexported workflowEngineAdapter in
// features/controller/server/server.go; it is re-declared here because importing that
// package would create a circular dependency (controller/server → trigger → controller/server).
type workflowEngineAdapter struct {
	engine      *workflow.Engine
	configStore storageif.ConfigStore
}

func (a *workflowEngineAdapter) TriggerWorkflow(ctx context.Context, trig *Trigger, data map[string]interface{}) (*WorkflowExecution, error) {
	store := workflow.NewWorkflowStore(a.configStore, trig.TenantID)
	vw, err := store.GetLatestWorkflow(ctx, trig.WorkflowName)
	if err != nil {
		return nil, fmt.Errorf("workflow %q not found for trigger %q: %w", trig.WorkflowName, trig.ID, err)
	}
	vars := make(map[string]interface{})
	for k, v := range trig.Variables {
		vars[k] = v
	}
	for k, v := range data {
		vars[k] = v
	}
	exec, err := a.engine.ExecuteWorkflow(ctx, vw.Workflow, vars)
	if err != nil {
		return nil, fmt.Errorf("failed to start workflow %q: %w", trig.WorkflowName, err)
	}
	return &WorkflowExecution{
		ID:           exec.ID,
		WorkflowName: exec.WorkflowName,
		Status:       string(exec.GetStatus()),
		StartTime:    exec.StartTime,
	}, nil
}

func (a *workflowEngineAdapter) ValidateTrigger(_ context.Context, trig *Trigger) error {
	if trig.WorkflowName == "" {
		return fmt.Errorf("trigger %q must specify a workflow_name", trig.ID)
	}
	return nil
}

// newRealWorkflowTrigger creates a WorkflowTrigger backed by a real *workflow.Engine and
// real flatfile+SQLite ConfigStore, matching the production wiring in server.go.
func newRealWorkflowTrigger(tb testing.TB) WorkflowTrigger {
	tb.Helper()
	tmpDir := tb.TempDir()
	storageManager, err := storageif.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = storageManager.Close() })

	registry := make(discovery.ModuleRegistry)
	errCfg := stewardconfig.ErrorHandlingConfig{ModuleLoadFailure: stewardconfig.ActionContinue}
	eng := workflow.NewEngine(factory.New(registry, errCfg), logging.NewNoopLogger())

	return &workflowEngineAdapter{
		engine:      eng,
		configStore: storageManager.GetConfigStore(),
	}
}

// TestNewControllerTriggerManager_ReturnsWiredManager verifies that the factory creates a
// manager with all three components (scheduler, webhookHandler, siemIntegration) non-nil.
func TestNewControllerTriggerManager_ReturnsWiredManager(t *testing.T) {
	storage := &flatfile.FlatFileProvider{}
	wt := newRealWorkflowTrigger(t)

	manager := NewControllerTriggerManager(storage, wt)

	require.NotNil(t, manager, "manager must not be nil")
	assert.NotNil(t, manager.scheduler, "scheduler must be wired")
	assert.NotNil(t, manager.webhookHandler, "webhookHandler must be wired")
	assert.NotNil(t, manager.siemIntegration, "siemIntegration must be wired")
	assert.Equal(t, wt, manager.workflowTrigger, "workflowTrigger must be the provided WorkflowTrigger")
	assert.False(t, manager.running, "manager must not be running after construction")
}

// TestNewControllerTriggerManager_ComponentsReferenceManager verifies that the two-phase
// circular-dependency resolution wires each component back to the parent manager.
func TestNewControllerTriggerManager_ComponentsReferenceManager(t *testing.T) {
	storage := &flatfile.FlatFileProvider{}
	wt := newRealWorkflowTrigger(t)

	manager := NewControllerTriggerManager(storage, wt)
	require.NotNil(t, manager)

	cs, ok := manager.scheduler.(*CronScheduler)
	require.True(t, ok, "scheduler must be a *CronScheduler")
	assert.Equal(t, manager, cs.triggerManager, "CronScheduler must reference the parent manager")

	wh, ok := manager.webhookHandler.(*HTTPWebhookHandler)
	require.True(t, ok, "webhookHandler must be an *HTTPWebhookHandler")
	assert.Equal(t, manager, wh.triggerManager, "HTTPWebhookHandler must reference the parent manager")

	sp, ok := manager.siemIntegration.(*SIEMProcessor)
	require.True(t, ok, "siemIntegration must be a *SIEMProcessor")
	assert.Equal(t, manager, sp.triggerManager, "SIEMProcessor must reference the parent manager")
}

// TestNewControllerTriggerManager_StartStopLifecycle verifies that the manager created by
// the factory starts and stops cleanly using the real component implementations.
func TestNewControllerTriggerManager_StartStopLifecycle(t *testing.T) {
	storage := &flatfile.FlatFileProvider{}
	wt := newRealWorkflowTrigger(t)

	manager := NewControllerTriggerManager(storage, wt)
	require.NotNil(t, manager)

	ctx := context.Background()

	err := manager.Start(ctx)
	assert.NoError(t, err, "Start must succeed with real components")
	assert.True(t, manager.running, "manager must be running after Start")

	// Double-start must fail.
	err = manager.Start(ctx)
	assert.Error(t, err, "second Start must fail")

	err = manager.Stop(ctx)
	assert.NoError(t, err, "Stop must succeed")
	assert.False(t, manager.running, "manager must not be running after Stop")
}
