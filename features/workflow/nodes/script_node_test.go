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

// testDeviceSource is a real DeviceSource backed by a configurable device list.
// Using a real DeviceSource with StewardFleetQuery exercises the actual filtering
// logic rather than bypassing it with a mock.
type testDeviceSource struct {
	devices []fleet.Device
}

func (s *testDeviceSource) ListDevices() ([]fleet.Device, error) { return s.devices, nil }

// errorDeviceSource is a DeviceSource that simulates a registry failure.
type errorDeviceSource struct {
	err error
}

func (s *errorDeviceSource) ListDevices() ([]fleet.Device, error) { return nil, s.err }

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

// TestScriptNode_FleetQueryWiring verifies that the script node uses the fleet
// query to resolve device IDs from the configured filter.
func TestScriptNode_FleetQueryWiring(t *testing.T) {
	src := &testDeviceSource{
		devices: []fleet.Device{
			{ID: "dev-1", OS: "linux", Tags: []string{"prod"}},
			{ID: "dev-2", OS: "linux", Tags: []string{"prod"}},
			{ID: "dev-3", OS: "windows", Tags: []string{"prod"}}, // must not match OS filter
		},
	}
	fq := fleet.NewStewardFleetQuery(src)

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
	output, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)
	assert.True(t, output.Success)

	// Fleet filter must have been applied: only linux+prod devices targeted
	results, ok := output.Data["results"].(map[string]*script.ExecutionResult)
	require.True(t, ok, "output must contain results map")
	assert.Contains(t, results, "dev-1")
	assert.Contains(t, results, "dev-2")
	assert.NotContains(t, results, "dev-3", "windows device must not be targeted by linux filter")
}

// TestScriptNode_ExplicitDevicesSkipFleetQuery verifies that when Devices is
// explicitly set, the fleet query is bypassed entirely.
func TestScriptNode_ExplicitDevicesSkipFleetQuery(t *testing.T) {
	// Source has a fleet device that would match the filter — but explicit
	// Devices list must take priority and fleet query must not be consulted.
	src := &testDeviceSource{
		devices: []fleet.Device{
			{ID: "fleet-dev", OS: "linux"},
		},
	}
	fq := fleet.NewStewardFleetQuery(src)

	config := &ScriptStepConfig{
		InlineScript: "echo hello",
		Shell:        script.ShellBash,
		Devices:      []string{"explicit-dev-1"},
		DeviceFilter: &fleet.Filter{OS: "linux"},
		Timeout:      5 * time.Second,
	}

	node := buildScriptNode(t, config, fq)
	output, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)

	results, ok := output.Data["results"].(map[string]*script.ExecutionResult)
	require.True(t, ok, "output must contain results map")
	assert.Contains(t, results, "explicit-dev-1")
	assert.NotContains(t, results, "fleet-dev", "explicit Devices list must bypass fleet query")
}

// TestScriptNode_ZeroMatchReturnsSuccessWithWarning verifies that when the
// fleet filter matches no devices, the step completes with success (not failure)
// and includes a warning in the output.
func TestScriptNode_ZeroMatchReturnsSuccessWithWarning(t *testing.T) {
	// Source has only windows devices; linux filter yields zero matches.
	src := &testDeviceSource{
		devices: []fleet.Device{
			{ID: "win-dev", OS: "windows"},
		},
	}
	fq := fleet.NewStewardFleetQuery(src)

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
	src := &testDeviceSource{
		devices: []fleet.Device{
			{ID: "dev-1", OS: "linux"},
		},
	}
	fq := fleet.NewStewardFleetQuery(src)

	config := &ScriptStepConfig{
		InlineScript: "echo hello",
		Shell:        script.ShellBash,
		DeviceFilter: &fleet.Filter{OS: "linux"},
		Timeout:      5 * time.Second,
	}

	node := buildScriptNode(t, config, fq)

	// First execution — one device in fleet
	output1, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)
	results1, ok := output1.Data["results"].(map[string]*script.ExecutionResult)
	require.True(t, ok)
	assert.Len(t, results1, 1, "first execution must target one device")

	// Simulate fleet change: a new device comes online
	src.devices = append(src.devices, fleet.Device{ID: "dev-2", OS: "linux"})

	// Second execution — filter must be re-evaluated against current fleet
	output2, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)
	results2, ok := output2.Data["results"].(map[string]*script.ExecutionResult)
	require.True(t, ok)
	assert.Len(t, results2, 2, "second execution must target two devices after fleet change")
	assert.Contains(t, results2, "dev-2", "newly added device must appear in second run")
}

// TestScriptNode_FilterANDSemantics verifies that a combined OS+Tags filter
// applies AND semantics: only devices matching ALL criteria are targeted.
func TestScriptNode_FilterANDSemantics(t *testing.T) {
	src := &testDeviceSource{
		devices: []fleet.Device{
			{ID: "prod-linux", OS: "linux", Tags: []string{"prod"}},
			{ID: "staging-linux", OS: "linux", Tags: []string{"staging"}},
			{ID: "prod-windows", OS: "windows", Tags: []string{"prod"}},
		},
	}
	fq := fleet.NewStewardFleetQuery(src)

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
	output, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)

	results, ok := output.Data["results"].(map[string]*script.ExecutionResult)
	require.True(t, ok)
	assert.Contains(t, results, "prod-linux")
	assert.NotContains(t, results, "staging-linux", "staging device fails prod tag filter")
	assert.NotContains(t, results, "prod-windows", "windows device fails linux OS filter")
}

// TestScriptStepExecutor_FleetQueryInjection verifies that FleetQuery can be
// injected into the step executor and is used to resolve devices during execution.
func TestScriptStepExecutor_FleetQueryInjection(t *testing.T) {
	src := &testDeviceSource{
		devices: []fleet.Device{
			{ID: "executor-dev-1", OS: "linux"},
		},
	}
	fq := fleet.NewStewardFleetQuery(src)
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

	// Fleet-targeted device must appear in results
	resultData, ok := result.Output["results"].(map[string]*script.ExecutionResult)
	require.True(t, ok, "output must include results map")
	assert.Contains(t, resultData, "executor-dev-1", "fleet device must be targeted during execution")
}

// TestScriptNode_FleetQueryError verifies that a fleet query failure propagates
// as a node failure (not a silent no-op or localhost fallback).
func TestScriptNode_FleetQueryError(t *testing.T) {
	// errorDeviceSource makes StewardFleetQuery.Search return an error,
	// exercising the fleet query error propagation path in the script node.
	src := &errorDeviceSource{err: errors.New("registry unavailable")}
	fq := fleet.NewStewardFleetQuery(src)

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

// TestScriptNode_WaitForCompletion verifies that when WaitForCompletion is true,
// Execute polls until the execution reaches a terminal status and returns success.
func TestScriptNode_WaitForCompletion(t *testing.T) {
	config := &ScriptStepConfig{
		InlineScript:      "echo hello",
		Shell:             script.ShellBash,
		Timeout:           5 * time.Second,
		WaitForCompletion: true,
	}

	node := buildScriptNode(t, config, nil)
	output, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})
	require.NoError(t, err)
	assert.True(t, output.Success)

	results, ok := output.Data["results"].(map[string]*script.ExecutionResult)
	require.True(t, ok, "output must include results map")
	assert.Contains(t, results, "localhost")
}

// TestScriptNode_WaitForCompletion_ZeroTimeoutError verifies that
// WaitForCompletion: true with Timeout: 0 returns an error rather than
// silently timing out immediately via time.After(0).
func TestScriptNode_WaitForCompletion_ZeroTimeoutError(t *testing.T) {
	config := &ScriptStepConfig{
		InlineScript:      "echo hello",
		Shell:             script.ShellBash,
		Timeout:           0, // zero value — misconfiguration
		WaitForCompletion: true,
	}

	node := buildScriptNode(t, config, nil)
	output, err := node.Execute(context.Background(), workflow.NodeInput{
		Data:    map[string]interface{}{},
		Context: map[string]interface{}{},
	})

	require.Error(t, err, "zero timeout with WaitForCompletion must return an error")
	assert.False(t, output.Success)
	assert.Contains(t, err.Error(), "timeout is zero")
}
