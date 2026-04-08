// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFleetQuery is a test double for fleet.FleetQuery.
// It records the filters it receives and returns a configurable device list.
type fakeFleetQuery struct {
	devices       []string
	searchErr     error
	calledFilters []fleet.Filter
}

func (f *fakeFleetQuery) Search(filter fleet.Filter) ([]string, error) {
	f.calledFilters = append(f.calledFilters, filter)
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return f.devices, nil
}

// buildScriptNode creates a ScriptNode with an inline script and the given fleet query.
func buildScriptNode(t *testing.T, config *ScriptStepConfig, fq fleet.FleetQuery) *ScriptNode {
	t.Helper()
	monitor := script.NewExecutionMonitor()
	node := NewScriptNode("test-node", "test", config, nil, monitor, nil)
	if fq != nil {
		node.SetFleetQuery(fq)
	}
	return node
}

// TestScriptNode_FleetQueryWiring verifies that the script node calls
// fleetQuery.Search with the configured filter to obtain device IDs.
func TestScriptNode_FleetQueryWiring(t *testing.T) {
	fq := &fakeFleetQuery{devices: []string{"dev-1", "dev-2"}}

	config := &ScriptStepConfig{
		InlineScript: "echo hello",
		Shell:        script.ShellBash,
		DeviceFilter: &fleet.Filter{
			OS:   "linux",
			Tags: []string{"prod"},
		},
		Timeout: 5 * time.Second,
	}

	node := buildScriptNode(t, config, fq)
	_, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)

	// Fleet query must have been called exactly once with the configured filter
	require.Len(t, fq.calledFilters, 1)
	assert.Equal(t, "linux", fq.calledFilters[0].OS)
	assert.Equal(t, []string{"prod"}, fq.calledFilters[0].Tags)
}

// TestScriptNode_ExplicitDevicesSkipFleetQuery verifies that when Devices is
// explicitly set, the fleet query is bypassed entirely.
func TestScriptNode_ExplicitDevicesSkipFleetQuery(t *testing.T) {
	fq := &fakeFleetQuery{devices: []string{"should-not-appear"}}

	config := &ScriptStepConfig{
		InlineScript: "echo hello",
		Shell:        script.ShellBash,
		Devices:      []string{"explicit-dev-1"},
		DeviceFilter: &fleet.Filter{OS: "linux"},
		Timeout:      5 * time.Second,
	}

	node := buildScriptNode(t, config, fq)
	_, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)

	// Fleet query must NOT have been called
	assert.Len(t, fq.calledFilters, 0, "explicit Devices list must bypass fleet query")
}

// TestScriptNode_ZeroMatchReturnsSuccessWithWarning verifies that when the
// fleet filter matches no devices, the step completes with success (not failure)
// and includes a warning in the output.
func TestScriptNode_ZeroMatchReturnsSuccessWithWarning(t *testing.T) {
	fq := &fakeFleetQuery{devices: []string{}} // returns no matches

	config := &ScriptStepConfig{
		InlineScript: "echo hello",
		Shell:        script.ShellBash,
		DeviceFilter: &fleet.Filter{OS: "windows"},
		Timeout:      5 * time.Second,
	}

	node := buildScriptNode(t, config, fq)
	output, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)

	// Zero matches must NOT cause failure
	assert.True(t, output.Success, "zero matching devices should succeed with warning, not fail")
	assert.Empty(t, output.Error, "zero matches should not set an error message")

	// Output must include a warning
	warning, hasWarning := output.Data["warning"].(string)
	assert.True(t, hasWarning, "output must contain a 'warning' field when no devices match")
	assert.Contains(t, warning, "no matching devices", "warning must contain 'no matching devices'")
}

// TestScriptNode_NoFilterNoDevicesDefaultsToLocalhost verifies the existing
// fallback behaviour: no explicit devices and no filter → targets localhost.
func TestScriptNode_NoFilterNoDevicesDefaultsToLocalhost(t *testing.T) {
	config := &ScriptStepConfig{
		InlineScript: "echo hello",
		Shell:        script.ShellBash,
		Timeout:      5 * time.Second,
	}

	node := buildScriptNode(t, config, nil)
	output, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)

	results, ok := output.Data["results"].(map[string]*script.ExecutionResult)
	require.True(t, ok, "output.Data[results] must be map[string]*script.ExecutionResult")
	assert.Contains(t, results, "localhost")
}

// TestScriptNode_RecurringFilterReEvaluated verifies that calling Execute
// multiple times re-evaluates the filter against current fleet state.
// This is the recurring workflow scenario: filter is stored in workflow
// definition, result set is NOT cached.
func TestScriptNode_RecurringFilterReEvaluated(t *testing.T) {
	fq := &fakeFleetQuery{devices: []string{"dev-1"}}

	config := &ScriptStepConfig{
		InlineScript: "echo hello",
		Shell:        script.ShellBash,
		DeviceFilter: &fleet.Filter{OS: "linux"},
		Timeout:      5 * time.Second,
	}

	node := buildScriptNode(t, config, fq)

	// First execution
	_, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)
	require.Len(t, fq.calledFilters, 1)

	// Simulate fleet change: a new device comes online
	fq.devices = []string{"dev-1", "dev-2"}

	// Second execution (recurring run) — filter must be re-evaluated
	_, err = node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)

	// Search must have been called again with the same filter
	require.Len(t, fq.calledFilters, 2, "filter must be re-evaluated on each execution")
	assert.Equal(t, fq.calledFilters[0], fq.calledFilters[1], "same filter reused across runs")
}

// TestScriptNode_DeviceFilterFieldsMatchFleetFilter verifies that the
// ScriptStepConfig.DeviceFilter is typed as *fleet.Filter (no separate struct).
func TestScriptNode_DeviceFilterFieldsMatchFleetFilter(t *testing.T) {
	filter := &fleet.Filter{
		OS:       "windows",
		Tags:     []string{"prod", "web"},
		Groups:   []string{"emea"},
		DNAQuery: map[string]string{"tier": "frontend"},
	}
	config := &ScriptStepConfig{
		InlineScript: "echo hello",
		DeviceFilter: filter,
	}

	// Verify the field is directly a *fleet.Filter — no conversion needed
	assert.Equal(t, "windows", config.DeviceFilter.OS)
	assert.Equal(t, []string{"prod", "web"}, config.DeviceFilter.Tags)
	assert.Equal(t, []string{"emea"}, config.DeviceFilter.Groups)
	assert.Equal(t, "frontend", config.DeviceFilter.DNAQuery["tier"])
}

// TestScriptStepExecutor_FleetQueryInjection verifies that FleetQuery can be
// injected into the step executor and is passed to the node during execution.
func TestScriptStepExecutor_FleetQueryInjection(t *testing.T) {
	fq := &fakeFleetQuery{devices: []string{"executor-dev-1"}}
	monitor := script.NewExecutionMonitor()
	executor := NewScriptStepExecutor(nil, monitor, nil)
	executor.SetFleetQuery(fq)

	step := workflow.Step{
		Name: "run-script",
		Type: workflow.StepTypeTask,
		Config: map[string]interface{}{
			"inline_script": "echo hello",
			"shell":         "bash",
			"device_filter": map[string]interface{}{
				"os": "linux",
			},
			"timeout": "5s",
		},
	}

	result, err := executor.ExecuteStep(context.Background(), step, map[string]interface{}{})
	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	// Fleet query must have been called
	require.GreaterOrEqual(t, len(fq.calledFilters), 1, "fleet query must be invoked during step execution")
	assert.Equal(t, "linux", fq.calledFilters[0].OS)
}

// TestScriptNode_FleetQueryError verifies that a fleet query failure propagates
// as a node failure (not a silent no-op or localhost fallback).
func TestScriptNode_FleetQueryError(t *testing.T) {
	fq := &fakeFleetQuery{
		searchErr: errors.New("registry unavailable"),
	}

	config := &ScriptStepConfig{
		InlineScript: "echo hello",
		Shell:        script.ShellBash,
		DeviceFilter: &fleet.Filter{OS: "linux"},
		Timeout:      5 * time.Second,
	}

	node := buildScriptNode(t, config, fq)
	output, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})

	// Fleet query error must propagate as node failure
	require.Error(t, err, "fleet query error must be returned")
	assert.False(t, output.Success, "node must fail when fleet query returns an error")
	assert.Contains(t, err.Error(), "fleet query failed")
}

// TestScriptNode_DeviceFilterWithoutFleetQueryReturnsError verifies that
// configuring a DeviceFilter without wiring a FleetQuery returns an error
// rather than silently falling back to localhost.
func TestScriptNode_DeviceFilterWithoutFleetQueryReturnsError(t *testing.T) {
	config := &ScriptStepConfig{
		InlineScript: "echo hello",
		Shell:        script.ShellBash,
		DeviceFilter: &fleet.Filter{OS: "linux"},
		Timeout:      5 * time.Second,
	}

	// Deliberately do NOT set a fleet query
	node := buildScriptNode(t, config, nil)
	output, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})

	// Must return an error — not silently target localhost
	require.Error(t, err, "misconfiguration (filter without FleetQuery) must return an error")
	assert.False(t, output.Success, "node must fail when DeviceFilter is set but FleetQuery is not wired")
	assert.Contains(t, err.Error(), "FleetQuery")
}
