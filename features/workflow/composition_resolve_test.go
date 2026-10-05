// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// loadWorkflowFileForTest reads a repo workflow file the way the engine loads a
// flat definition. Test-only: the engine itself never reads workflow
// definitions from the filesystem (Issue #4638).
func loadWorkflowFileForTest(path string) (Workflow, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed repo test fixture path
	if err != nil {
		return Workflow{}, err
	}
	var w Workflow
	if err := yaml.Unmarshal(data, &w); err != nil {
		return Workflow{}, err
	}
	return w, nil
}

func waitForTerminal(t *testing.T, engine *Engine, execID string) *WorkflowExecution {
	t.Helper()
	var execution *WorkflowExecution
	require.Eventually(t, func() bool {
		var err error
		execution, err = engine.GetExecution(execID)
		require.NoError(t, err)
		s := execution.Status
		return s == StatusCompleted || s == StatusFailed || s == StatusCancelled
	}, 10*time.Second, 10*time.Millisecond)
	return execution
}

func tenantContext(tenantID string) context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, tenantID)
}

// TestComposition_FilesystemReferenceRefused guards Issue #4638: a nested
// workflow step, an error workflow and a composite component that reference a
// workflow by path are refused, and the referenced file is never read — its
// content must not surface in the execution's state.
func TestComposition_FilesystemReferenceRefused(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret.yaml")
	require.NoError(t, os.WriteFile(secret, []byte("name: leaked-marker-4638\nsteps: []\n"), 0600))

	cases := map[string]Step{
		"nested workflow step": {
			Name: "nested", Type: StepTypeWorkflow,
			WorkflowCall: &WorkflowCallConfig{WorkflowPath: secret},
		},
	}
	for name, step := range cases {
		t.Run(name, func(t *testing.T) {
			engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
			execution, err := engine.ExecuteWorkflow(tenantContext("acme-corp"), Workflow{Name: "outer", Steps: []Step{step}}, nil)
			require.NoError(t, err)
			final := waitForTerminal(t, engine, execution.ID)
			assert.Equal(t, StatusFailed, final.Status)
			msg := fmt.Sprintf("%v %v", final.Error, final.ErrorDetails)
			assert.Contains(t, msg, "workflow_path is not supported")
			assert.NotContains(t, msg, "leaked-marker-4638", "the referenced file must never be read")
		})
	}

	t.Run("error workflow", func(t *testing.T) {
		engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
		step := Step{Name: "on-error", Type: StepTypeTask, ErrorWorkflow: &ErrorWorkflowConfig{WorkflowPath: secret}}
		err := engine.executeErrorWorkflowStep(context.Background(), step, &WorkflowExecution{TenantID: "acme-corp", Variables: map[string]interface{}{}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), ErrFilesystemWorkflowReference.Error())
		assert.NotContains(t, err.Error(), "leaked-marker-4638")
	})

	t.Run("composite component", func(t *testing.T) {
		engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
		err := engine.executeComponent(context.Background(), WorkflowComponent{Name: "c", WorkflowPath: secret},
			&WorkflowExecution{TenantID: "acme-corp"}, "composite")
		require.ErrorIs(t, err, ErrFilesystemWorkflowReference)
	})
}

// TestComposition_ResolverScopesNameToExecutionTenant guards Issue #4638: with a
// resolver wired, a workflow referenced by name resolves in the execution's own
// tenant only, the in-memory registry is never consulted, and an execution
// without a tenant resolves nothing.
func TestComposition_ResolverScopesNameToExecutionTenant(t *testing.T) {
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	engine.RegisterWorkflow(Workflow{Name: "child", Description: "registry copy"})

	stored := map[string]Workflow{"acme-corp/child": {Name: "child", Description: "acme copy"}}
	var asked []string
	engine.SetWorkflowResolver(func(_ context.Context, tenantID, name string) (Workflow, error) {
		asked = append(asked, tenantID+"/"+name)
		w, ok := stored[tenantID+"/"+name]
		if !ok {
			return Workflow{}, fmt.Errorf("workflow %q not found", name)
		}
		return w, nil
	})

	got, err := engine.loadWorkflowByName(context.Background(), &WorkflowExecution{TenantID: "acme-corp"}, "child")
	require.NoError(t, err)
	assert.Equal(t, "acme copy", got.Description, "resolved from the execution tenant, not the registry")

	_, err = engine.loadWorkflowByName(context.Background(), &WorkflowExecution{TenantID: "vendor-a"}, "child")
	require.Error(t, err, "another tenant's workflow must not resolve")

	_, err = engine.loadWorkflowByName(context.Background(), &WorkflowExecution{}, "child")
	require.Error(t, err, "an execution without a tenant resolves nothing")

	assert.Equal(t, []string{"acme-corp/child", "vendor-a/child"}, asked)
}

// TestComposition_NestedWorkflowRunsFromTenantStore guards Issue #4638 end to
// end in the engine: a nested workflow step referencing a workflow by name runs
// the definition the resolver returns for the execution's tenant.
func TestComposition_NestedWorkflowRunsFromTenantStore(t *testing.T) {
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	engine.SetWorkflowResolver(func(_ context.Context, tenantID, name string) (Workflow, error) {
		if tenantID != "acme-corp" || name != "child" {
			return Workflow{}, fmt.Errorf("workflow %q not found", name)
		}
		return Workflow{Name: "child", Steps: []Step{{Name: "pause", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Millisecond}}}}, nil
	})

	outer := Workflow{Name: "outer", Steps: []Step{{Name: "call-child", Type: StepTypeWorkflow, WorkflowCall: &WorkflowCallConfig{WorkflowName: "child"}}}}

	execution, err := engine.ExecuteWorkflow(tenantContext("acme-corp"), outer, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, waitForTerminal(t, engine, execution.ID).Status)

	execution, err = engine.ExecuteWorkflow(tenantContext("vendor-a"), outer, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, waitForTerminal(t, engine, execution.ID).Status,
		"another tenant cannot run acme-corp's child workflow by name")
}

// TestContainsFilesystemWorkflowReference guards Issue #4638's create/update
// check: a workflow_path anywhere in the definition is found, including the
// workflow-level error workflows, while the same key inside free-form module
// config, variables or call parameters is not a reference.
func TestContainsFilesystemWorkflowReference(t *testing.T) {
	delay := Step{Name: "s", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Millisecond}}
	cases := map[string]struct {
		wf   Workflow
		want bool
	}{
		"none":                     {Workflow{Name: "w", Steps: []Step{delay}}, false},
		"workflow error_workflows": {Workflow{Name: "w", Steps: []Step{delay}, ErrorWorkflows: []ErrorWorkflowConfig{{WorkflowPath: "/x"}}}, true},
		"deeply nested call": {Workflow{Name: "w", Steps: []Step{{Name: "a", Type: StepTypeSequential, Steps: []Step{
			{Name: "b", Type: StepTypeParallel, Steps: []Step{{Name: "c", Type: StepTypeWorkflow, WorkflowCall: &WorkflowCallConfig{WorkflowPath: "/x"}}}},
		}}}}, true},
		"name reference only":          {Workflow{Name: "w", Steps: []Step{{Name: "c", Type: StepTypeWorkflow, WorkflowCall: &WorkflowCallConfig{WorkflowName: "child"}}}}, false},
		"free-form config key":         {Workflow{Name: "w", Steps: []Step{{Name: "t", Type: StepTypeTask, Module: "file", Config: map[string]interface{}{"workflow_path": "/x"}}}}, false},
		"variable named workflow_path": {Workflow{Name: "w", Variables: map[string]interface{}{"workflow_path": "/x"}, Steps: []Step{delay}}, false},
		"call parameter named workflow_path": {Workflow{Name: "w", Steps: []Step{{Name: "c", Type: StepTypeWorkflow,
			WorkflowCall: &WorkflowCallConfig{WorkflowName: "child", Parameters: map[string]interface{}{"workflow_path": "/x"}}}}}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ContainsFilesystemWorkflowReference(tc.wf)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
