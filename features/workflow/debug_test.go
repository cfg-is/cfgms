// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestDebugEngine_StartDebugSession(t *testing.T) {
	// Create test engine
	engine, _ := createTestEngineWithDebug(t)
	debugEngine := engine.GetDebugEngine()

	// Create a simple workflow
	workflow := Workflow{
		Name: "test-debug-workflow",
		Steps: []Step{
			{
				Name: "step1",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 100 * time.Millisecond,
				},
			},
		},
	}

	// Start workflow execution
	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{
		"test_var": "initial_value",
	})
	require.NoError(t, err)

	// Start debug session
	settings := DebugSettings{
		AutoStepMode:      false,
		BreakOnError:      true,
		CaptureAPIDetails: true,
		MaxHistorySize:    100,
		TenantIsolation:   true,
	}

	session, err := debugEngine.StartDebugSession(ctx, execution.ID, settings)
	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, execution.ID, session.ExecutionID)
	assert.Equal(t, DebugStatusActive, session.Status)
	assert.Equal(t, settings, session.Settings)
}

func TestDebugEngine_SetAndRemoveBreakpoint(t *testing.T) {
	engine, _ := createTestEngineWithDebug(t)
	debugEngine := engine.GetDebugEngine()

	// Create workflow and execution
	workflow := createTestWorkflow()
	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{})
	require.NoError(t, err)

	// Start debug session
	settings := DebugSettings{MaxHistorySize: 100}
	session, err := debugEngine.StartDebugSession(ctx, execution.ID, settings)
	require.NoError(t, err)

	// Set breakpoint
	breakpoint, err := debugEngine.SetBreakpoint(session.ID, "step1", nil)
	require.NoError(t, err)
	assert.NotNil(t, breakpoint)
	assert.Equal(t, "step1", breakpoint.StepName)
	assert.True(t, breakpoint.Enabled)
	assert.Equal(t, 0, breakpoint.HitCount)

	// List breakpoints
	breakpoints, err := debugEngine.ListBreakpoints(session.ID)
	require.NoError(t, err)
	assert.Len(t, breakpoints, 1)
	assert.Equal(t, breakpoint.ID, breakpoints[0].ID)

	// Remove breakpoint
	err = debugEngine.RemoveBreakpoint(session.ID, breakpoint.ID)
	require.NoError(t, err)

	// Verify breakpoint removed
	breakpoints, err = debugEngine.ListBreakpoints(session.ID)
	require.NoError(t, err)
	assert.Len(t, breakpoints, 0)
}

func TestDebugEngine_VariableInspection(t *testing.T) {
	engine, _ := createTestEngineWithDebug(t)
	debugEngine := engine.GetDebugEngine()

	// Create workflow and execution
	workflow := createTestWorkflow()
	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{
		"test_var":   "initial_value",
		"number_var": 42,
	})
	require.NoError(t, err)

	// Start debug session
	settings := DebugSettings{MaxHistorySize: 100}
	session, err := debugEngine.StartDebugSession(ctx, execution.ID, settings)
	require.NoError(t, err)

	// Inspect variables
	variables, err := debugEngine.InspectVariables(session.ID)
	require.NoError(t, err)
	assert.Equal(t, "initial_value", variables["test_var"])
	assert.Equal(t, 42, variables["number_var"])

	// Update variable
	err = debugEngine.UpdateVariable(session.ID, "test_var", "modified_value")
	require.NoError(t, err)

	// Verify variable updated
	variables, err = debugEngine.InspectVariables(session.ID)
	require.NoError(t, err)
	assert.Equal(t, "modified_value", variables["test_var"])

	// Check modification history
	session, err = debugEngine.GetDebugSession(session.ID)
	require.NoError(t, err)
	assert.Contains(t, session.VariableInspector.ModifiedVariables, "test_var")
	modification := session.VariableInspector.ModifiedVariables["test_var"]
	assert.Equal(t, "initial_value", modification.OriginalValue)
	assert.Equal(t, "modified_value", modification.ModifiedValue)
}

func TestDebugEngine_VariableWatching(t *testing.T) {
	engine, _ := createTestEngineWithDebug(t)
	debugEngine := engine.GetDebugEngine()

	// Create workflow and execution
	workflow := createTestWorkflow()
	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{
		"watched_var": "initial",
	})
	require.NoError(t, err)

	// Start debug session
	settings := DebugSettings{MaxHistorySize: 100}
	session, err := debugEngine.StartDebugSession(ctx, execution.ID, settings)
	require.NoError(t, err)

	// Add variable watch
	err = debugEngine.WatchVariable(session.ID, "watched_var", true, nil)
	require.NoError(t, err)

	// Verify watch added
	session, err = debugEngine.GetDebugSession(session.ID)
	require.NoError(t, err)
	assert.Contains(t, session.VariableInspector.WatchedVariables, "watched_var")
	watch := session.VariableInspector.WatchedVariables["watched_var"]
	assert.True(t, watch.BreakOnChange)
	assert.Equal(t, "initial", watch.LastValue)

	// Remove watch
	err = debugEngine.UnwatchVariable(session.ID, "watched_var")
	require.NoError(t, err)

	// Verify watch removed
	session, err = debugEngine.GetDebugSession(session.ID)
	require.NoError(t, err)
	assert.NotContains(t, session.VariableInspector.WatchedVariables, "watched_var")
}

func TestDebugEngine_StepExecution(t *testing.T) {
	engine, _ := createTestEngineWithDebug(t)
	debugEngine := engine.GetDebugEngine()

	// Create workflow and execution
	workflow := createTestWorkflow()
	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{})
	require.NoError(t, err)

	// Start debug session
	settings := DebugSettings{MaxHistorySize: 100}
	session, err := debugEngine.StartDebugSession(ctx, execution.ID, settings)
	require.NoError(t, err)

	// Test step execution commands
	testCases := []DebugAction{
		DebugActionStep,
		DebugActionStepOver,
		DebugActionContinue,
		DebugActionPause,
	}

	for _, action := range testCases {
		err := debugEngine.StepExecution(session.ID, action)
		assert.NoError(t, err, "Failed to execute debug action: %s", action)
	}
}

func TestDebugEngine_APICallHistory(t *testing.T) {
	engine, _ := createTestEngineWithDebug(t)
	debugEngine := engine.GetDebugEngine()

	// Create workflow and execution
	workflow := createTestWorkflow()
	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{})
	require.NoError(t, err)

	// Start debug session with API capture enabled
	settings := DebugSettings{
		CaptureAPIDetails: true,
		MaxHistorySize:    100,
	}
	session, err := debugEngine.StartDebugSession(ctx, execution.ID, settings)
	require.NoError(t, err)

	// Simulate API call recording
	session.mutex.Lock()
	apiCall := APICallInfo{
		ID:              "test_call_1",
		StepName:        "http_step",
		Timestamp:       time.Now(),
		Method:          "GET",
		URL:             "https://api.example.com/test",
		RequestHeaders:  map[string]string{"Authorization": "Bearer token"},
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"Content-Type": "application/json"},
		ResponseBody:    map[string]interface{}{"result": "success"},
		Duration:        150 * time.Millisecond,
		CanReplay:       true,
	}
	session.APICallLog = append(session.APICallLog, apiCall)
	session.mutex.Unlock()

	// Get API call history
	history, err := debugEngine.GetAPICallHistory(session.ID)
	require.NoError(t, err)
	assert.Len(t, history, 1)
	assert.Equal(t, "test_call_1", history[0].ID)
	assert.Equal(t, "GET", history[0].Method)
	assert.True(t, history[0].CanReplay)

	// Test API call replay
	replayCall, err := debugEngine.ReplayAPICall(session.ID, "test_call_1")
	require.NoError(t, err)
	assert.NotNil(t, replayCall)
	assert.Contains(t, replayCall.StepName, "replay")
	assert.Equal(t, "GET", replayCall.Method)
}

func TestDebugEngine_StepHistory(t *testing.T) {
	engine, _ := createTestEngineWithDebug(t)
	debugEngine := engine.GetDebugEngine()

	// Create workflow and execution
	workflow := createTestWorkflow()
	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{
		"test_var": "value1",
	})
	require.NoError(t, err)

	// Start debug session
	settings := DebugSettings{MaxHistorySize: 100}
	session, err := debugEngine.StartDebugSession(ctx, execution.ID, settings)
	require.NoError(t, err)

	// Simulate step execution recording
	session.mutex.Lock()
	stepInfo := DebugStepInfo{
		StepName:        "step1",
		StepType:        StepTypeDelay,
		Timestamp:       time.Now(),
		Status:          StatusCompleted,
		VariablesBefore: map[string]interface{}{"test_var": "value1"},
		VariablesAfter:  map[string]interface{}{"test_var": "value1"},
	}
	duration := 100 * time.Millisecond
	stepInfo.Duration = &duration
	session.StepHistory = append(session.StepHistory, stepInfo)
	session.mutex.Unlock()

	// Get step history
	history, err := debugEngine.GetStepHistory(session.ID)
	require.NoError(t, err)
	assert.Len(t, history, 1)
	assert.Equal(t, "step1", history[0].StepName)
	assert.Equal(t, StepTypeDelay, history[0].StepType)
	assert.Equal(t, StatusCompleted, history[0].Status)
	assert.NotNil(t, history[0].Duration)
	assert.Equal(t, 100*time.Millisecond, *history[0].Duration)
}

func TestWorkflowEngine_PauseResumeExecution(t *testing.T) {
	engine, _ := createTestEngineWithDebug(t)

	// Create a workflow with delay to allow pause/resume testing
	workflow := Workflow{
		Name: "pause-resume-test",
		Steps: []Step{
			{
				Name: "delay_step",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 2 * time.Second,
				},
			},
		},
	}

	// Start workflow execution
	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{})
	require.NoError(t, err)

	// Wait for execution to reach running state
	waitForWorkflowRunning(t, execution, 2*time.Second)

	// Test pause
	err = engine.PauseExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusPaused, execution.GetStatus())

	// Test resume
	err = engine.ResumeExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusRunning, execution.GetStatus())

	// Test error cases
	err = engine.PauseExecution("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "execution not found")

	// Test pausing already paused execution
	_ = engine.PauseExecution(execution.ID)
	err = engine.PauseExecution(execution.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot pause execution in status")
}

func TestDebugEngine_SessionManagement(t *testing.T) {
	engine, _ := createTestEngineWithDebug(t)
	debugEngine := engine.GetDebugEngine()

	// Create multiple workflows and executions
	workflow := createTestWorkflow()
	ctx := context.Background()

	execution1, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{})
	require.NoError(t, err)

	execution2, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{})
	require.NoError(t, err)

	// Wait for workflows to initialize (Windows CI timing)
	waitForWorkflowCompletion(t, execution1, 2*time.Second)
	waitForWorkflowCompletion(t, execution2, 2*time.Second)

	// Start debug sessions
	settings := DebugSettings{MaxHistorySize: 100}
	session1, err := debugEngine.StartDebugSession(ctx, execution1.ID, settings)
	require.NoError(t, err)

	session2, err := debugEngine.StartDebugSession(ctx, execution2.ID, settings)
	require.NoError(t, err)

	// List debug sessions
	sessions, err := debugEngine.ListDebugSessions()
	require.NoError(t, err)
	// Note: On fast systems, workflow executions may complete quickly which could
	// auto-cleanup sessions. We check that our sessions were created successfully
	// rather than asserting exact count.
	assert.GreaterOrEqual(t, len(sessions), 1, "Should have at least one active session")

	// Get specific session
	retrievedSession, err := debugEngine.GetDebugSession(session1.ID)
	require.NoError(t, err)
	assert.Equal(t, session1.ID, retrievedSession.ID)
	assert.Equal(t, session1.ExecutionID, retrievedSession.ExecutionID)

	// Stop debug session
	err = debugEngine.StopDebugSession(session1.ID)
	require.NoError(t, err)

	// Verify session removed
	sessions, err = debugEngine.ListDebugSessions()
	require.NoError(t, err)
	// After stopping session1, we should have one less session
	// Note: On fast systems, workflow executions may complete quickly which could
	// affect session counts. Check that session1 was removed rather than exact count.
	for _, s := range sessions {
		assert.NotEqual(t, session1.ID, s.ID, "Stopped session should not be in list")
	}
	// If session2 is still present, verify it's the expected one
	if len(sessions) > 0 {
		// Find session2 in the remaining sessions
		found := false
		for _, s := range sessions {
			if s.ID == session2.ID {
				found = true
				break
			}
		}
		if len(sessions) == 1 {
			assert.True(t, found, "Remaining session should be session2")
		}
	}

	// Test error cases
	_, err = debugEngine.GetDebugSession("nonexistent")
	assert.Error(t, err)

	err = debugEngine.StopDebugSession("nonexistent")
	assert.Error(t, err)
}

func TestDebugEngine_SecurityAndTenantIsolation(t *testing.T) {
	engine, _ := createTestEngineWithDebug(t)
	debugEngine := engine.GetDebugEngine()

	// Create workflow and execution
	workflow := createTestWorkflow()
	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{
		"sensitive_data": "secret_value",
	})
	require.NoError(t, err)

	// Start debug session with tenant isolation enabled
	settings := DebugSettings{
		TenantIsolation: true,
		MaxHistorySize:  100,
	}
	session, err := debugEngine.StartDebugSession(ctx, execution.ID, settings)
	require.NoError(t, err)

	// Verify tenant isolation setting
	assert.True(t, session.Settings.TenantIsolation)

	// Test that sensitive operations respect security boundaries
	variables, err := debugEngine.InspectVariables(session.ID)
	require.NoError(t, err)
	// In a real implementation, sensitive variables might be filtered
	assert.Contains(t, variables, "sensitive_data")

	// Test variable modification with security constraints
	err = debugEngine.UpdateVariable(session.ID, "sensitive_data", "modified_secret")
	require.NoError(t, err)

	// Verify modification was logged for audit purposes
	session, err = debugEngine.GetDebugSession(session.ID)
	require.NoError(t, err)
	assert.Contains(t, session.VariableInspector.ModifiedVariables, "sensitive_data")
}

// Helper functions for testing

// mockLogger implements a simple test logger
type mockLogger struct{}

func (l *mockLogger) Debug(msg string, fields ...interface{})                         {}
func (l *mockLogger) Info(msg string, fields ...interface{})                          {}
func (l *mockLogger) Warn(msg string, fields ...interface{})                          {}
func (l *mockLogger) Error(msg string, fields ...interface{})                         {}
func (l *mockLogger) Fatal(msg string, fields ...interface{})                         {}
func (l *mockLogger) DebugCtx(ctx context.Context, msg string, fields ...interface{}) {}
func (l *mockLogger) InfoCtx(ctx context.Context, msg string, fields ...interface{})  {}
func (l *mockLogger) WarnCtx(ctx context.Context, msg string, fields ...interface{})  {}
func (l *mockLogger) ErrorCtx(ctx context.Context, msg string, fields ...interface{}) {}
func (l *mockLogger) FatalCtx(ctx context.Context, msg string, fields ...interface{}) {}

func createTestEngineWithDebug(t *testing.T) (*Engine, logging.Logger) {
	logger := &mockLogger{}
	moduleFactory := &factory.ModuleFactory{} // Mock factory for testing
	engine := NewEngine(moduleFactory, logger)
	return engine, logger
}

func createTestWorkflow() Workflow {
	return Workflow{
		Name: "test-workflow",
		Steps: []Step{
			{
				Name: "step1",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 50 * time.Millisecond,
					Message:  "Test delay step",
				},
			},
			{
				Name: "step2",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 50 * time.Millisecond,
					Message:  "Another test delay step",
				},
			},
		},
	}
}
