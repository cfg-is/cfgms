// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	// The run may belong to any tenant; read it under the tenant the engine recorded.
	engine.mutex.RLock()
	tenantID := engine.executions[execID].TenantID
	engine.mutex.RUnlock()
	require.Eventually(t, func() bool {
		var err error
		execution, err = engine.GetExecution(context.Background(), tenantID, execID)
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

	got, _, err := engine.loadWorkflowByName(context.Background(), &WorkflowExecution{TenantID: "acme-corp"}, "child")
	require.NoError(t, err)
	assert.Equal(t, "acme copy", got.Description, "resolved from the execution tenant, not the registry")

	_, _, err = engine.loadWorkflowByName(context.Background(), &WorkflowExecution{TenantID: "vendor-a"}, "child")
	require.Error(t, err, "another tenant's workflow must not resolve")

	_, _, err = engine.loadWorkflowByName(context.Background(), &WorkflowExecution{}, "child")
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

// mapResolver resolves names from a fixed per-tenant set of workflows.
func mapResolver(workflows map[string]Workflow) WorkflowResolver {
	return func(_ context.Context, tenantID, name string) (Workflow, error) {
		w, ok := workflows[name]
		if !ok || tenantID != "acme-corp" {
			return Workflow{}, fmt.Errorf("workflow %q not found", name)
		}
		return w, nil
	}
}

func callStep(name string) Step {
	return Step{Name: "call-" + name, Type: StepTypeWorkflow, WorkflowCall: &WorkflowCallConfig{WorkflowName: name}}
}

// TestComposition_RecursionBounded guards Issue #4638: now that composed
// workflows resolve, a definition that calls itself, a cycle, an error workflow
// naming itself and an over-deep chain each fail with a clear error instead of
// recursing, and leave no goroutines running.
func TestComposition_RecursionBounded(t *testing.T) {
	chain := map[string]Workflow{}
	for i := 0; i < maxWorkflowNestingDepth+2; i++ {
		name := fmt.Sprintf("level-%d", i)
		chain[name] = Workflow{Name: name, Steps: []Step{callStep(fmt.Sprintf("level-%d", i+1))}}
	}
	chain[fmt.Sprintf("level-%d", maxWorkflowNestingDepth+2)] = Workflow{Name: "leaf", Steps: []Step{{Name: "pause", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Millisecond}}}}

	cases := []struct {
		name      string
		workflows map[string]Workflow
		start     string
		wantError string
	}{
		{"self call", map[string]Workflow{"loop": {Name: "loop", Steps: []Step{callStep("loop")}}}, "loop", "already running in this call chain"},
		{"A -> B -> A", map[string]Workflow{
			"a": {Name: "a", Steps: []Step{callStep("b")}},
			"b": {Name: "b", Steps: []Step{callStep("a")}},
		}, "a", "already running in this call chain"},
		{"error workflow names itself", map[string]Workflow{"self-handler": {Name: "self-handler", Steps: []Step{{
			Name: "handle", Type: StepTypeErrorWorkflow, ErrorWorkflow: &ErrorWorkflowConfig{WorkflowName: "self-handler"},
		}}}}, "self-handler", "already running in this call chain"},
		{"depth limit", chain, "level-0", fmt.Sprintf("deeper than %d", maxWorkflowNestingDepth)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := runtime.NumGoroutine()
			engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
			engine.SetWorkflowResolver(mapResolver(tc.workflows))

			execution, err := engine.ExecuteWorkflow(tenantContext("acme-corp"), tc.workflows[tc.start], nil)
			require.NoError(t, err)
			final := waitForTerminal(t, engine, execution.ID)
			assert.Equal(t, StatusFailed, final.Status)
			assert.Contains(t, fmt.Sprint(final.Error), tc.wantError)

			assert.Eventually(t, func() bool { return runtime.NumGoroutine() <= before+2 }, 5*time.Second, 20*time.Millisecond,
				"no composed executions may keep running after the refusal")
		})
	}
}

// TestComposition_DepthWithinLimit guards Issue #4638: a chain shorter than the
// limit still runs to completion — the bound refuses runaway composition, not
// legitimate nesting.
func TestComposition_DepthWithinLimit(t *testing.T) {
	workflows := map[string]Workflow{}
	last := maxWorkflowNestingDepth - 1
	for i := 0; i < last; i++ {
		name := fmt.Sprintf("level-%d", i)
		workflows[name] = Workflow{Name: name, Steps: []Step{callStep(fmt.Sprintf("level-%d", i+1))}}
	}
	workflows[fmt.Sprintf("level-%d", last)] = Workflow{Name: fmt.Sprintf("level-%d", last), Steps: []Step{{Name: "pause", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Millisecond}}}}

	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	engine.SetWorkflowResolver(mapResolver(workflows))
	execution, err := engine.ExecuteWorkflow(tenantContext("acme-corp"), workflows["level-0"], nil)
	require.NoError(t, err)
	final := waitForTerminal(t, engine, execution.ID)
	assert.Equal(t, StatusCompleted, final.Status, "error: %v", final.Error)
}

// fanOut returns a workflow named name whose steps call child n times.
func fanOut(name, child string, n int) Workflow {
	steps := make([]Step, n)
	for i := range steps {
		steps[i] = Step{Name: fmt.Sprintf("call-%s-%d", child, i), Type: StepTypeWorkflow, WorkflowCall: &WorkflowCallConfig{WorkflowName: child}}
	}
	return Workflow{Name: name, Steps: steps}
}

func leafWorkflow(name string) Workflow {
	return Workflow{Name: name, Steps: []Step{{Name: "pause", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Millisecond}}}}
}

// TestComposition_BreadthBudget guards Issue #4638: a fan-out that never repeats
// a name and stays within the depth limit — ten calls per level, three levels
// deep (1110 composed executions) — is refused once the execution has started
// maxComposedWorkflowsPerExecution composed workflows, and leaves nothing running.
func TestComposition_BreadthBudget(t *testing.T) {
	before := runtime.NumGoroutine()
	workflows := map[string]Workflow{
		"w1":   fanOut("w1", "w2", 10),
		"w2":   fanOut("w2", "w3", 10),
		"w3":   fanOut("w3", "leaf", 10),
		"leaf": leafWorkflow("leaf"),
	}
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	engine.SetWorkflowResolver(mapResolver(workflows))

	execution, err := engine.ExecuteWorkflow(tenantContext("acme-corp"), workflows["w1"], nil)
	require.NoError(t, err)
	final := waitForTerminal(t, engine, execution.ID)
	assert.Equal(t, StatusFailed, final.Status)
	assert.Contains(t, fmt.Sprint(final.Error), fmt.Sprintf("exceed %d composed workflows", maxComposedWorkflowsPerExecution))

	assert.Eventually(t, func() bool { return runtime.NumGoroutine() <= before+2 }, 5*time.Second, 20*time.Millisecond,
		"no composed executions may keep running after the refusal")
}

// TestComposition_BudgetIsPerExecution guards Issue #4638: the budget belongs to
// one top-level execution — separate executions each get their own, so a
// workflow within the budget runs every time it is started.
func TestComposition_BudgetIsPerExecution(t *testing.T) {
	workflows := map[string]Workflow{
		"parent": fanOut("parent", "leaf", 40),
		"leaf":   leafWorkflow("leaf"),
	}
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	engine.SetWorkflowResolver(mapResolver(workflows))

	for run := 0; run < 2; run++ {
		execution, err := engine.ExecuteWorkflow(tenantContext("acme-corp"), workflows["parent"], nil)
		require.NoError(t, err)
		final := waitForTerminal(t, engine, execution.ID)
		assert.Equal(t, StatusCompleted, final.Status, "run %d: %v", run, final.Error)
	}
}
