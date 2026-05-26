// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// debugIDCounter ensures unique IDs even when time.Now().UnixNano() returns
// the same value (Windows has ~15.6ms clock granularity).
var debugIDCounter atomic.Uint64

// DebugEngineImpl implements the DebugEngine interface
type DebugEngineImpl struct {
	// workflowEngine is the underlying workflow engine
	workflowEngine *Engine

	// debugSessions tracks active debug sessions
	debugSessions map[string]*DebugSession

	// logger for structured debug logging
	logger *logging.ModuleLogger

	// mutex protects concurrent access to debug sessions
	mutex sync.RWMutex
}

// NewDebugEngine creates a new debug engine instance
func NewDebugEngine(workflowEngine *Engine, logger logging.Logger) *DebugEngineImpl {
	debugLogger := logging.ForModule("workflow-debug").WithField("component", "debug-engine")

	return &DebugEngineImpl{
		workflowEngine: workflowEngine,
		debugSessions:  make(map[string]*DebugSession),
		logger:         debugLogger,
	}
}

// StartDebugSession starts a new debug session for a workflow execution
func (de *DebugEngineImpl) StartDebugSession(ctx context.Context, executionID string, settings DebugSettings) (*DebugSession, error) {
	de.mutex.Lock()
	defer de.mutex.Unlock()

	// Validate that the execution exists
	execution, err := de.workflowEngine.GetExecution(executionID)
	if err != nil {
		return nil, fmt.Errorf("execution not found: %w", err)
	}

	// Extract tenant context for security
	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := de.logger.WithTenant(tenantID)

	// Generate debug session ID
	sessionID := generateDebugSessionID()

	// Create debug context with cancellation
	debugCtx, cancel := context.WithCancel(ctx)

	// Initialize debug session
	session := &DebugSession{
		ID:          sessionID,
		ExecutionID: executionID,
		Status:      DebugStatusActive,
		StartTime:   time.Now(),
		Breakpoints: make(map[string]*Breakpoint),
		VariableInspector: &VariableInspector{
			CurrentVariables:  execution.GetVariables(),
			VariableHistory:   []VariableChange{},
			WatchedVariables:  make(map[string]*VariableWatch),
			ModifiedVariables: make(map[string]VariableModification),
		},
		StepHistory: []DebugStepInfo{},
		APICallLog:  []APICallInfo{},
		Settings:    settings,
		stepChan:    make(chan DebugStepControl, 10),
		Context:     debugCtx,
		Cancel:      cancel,
	}

	// Store debug session
	de.debugSessions[sessionID] = session

	logger.InfoCtx(ctx, "Started debug session",
		"operation", "debug_session_start",
		"session_id", sessionID,
		"execution_id", executionID,
		"tenant_isolation", settings.TenantIsolation)

	return session, nil
}

// GetDebugSession returns a debug session by ID
func (de *DebugEngineImpl) GetDebugSession(sessionID string) (*DebugSession, error) {
	de.mutex.RLock()
	defer de.mutex.RUnlock()

	session, exists := de.debugSessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("debug session not found: %s", sessionID)
	}

	return session, nil
}

// ListDebugSessions returns all active debug sessions
func (de *DebugEngineImpl) ListDebugSessions() ([]*DebugSession, error) {
	de.mutex.RLock()
	defer de.mutex.RUnlock()

	sessions := make([]*DebugSession, 0, len(de.debugSessions))
	for _, session := range de.debugSessions {
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// StopDebugSession stops a debug session
func (de *DebugEngineImpl) StopDebugSession(sessionID string) error {
	de.mutex.Lock()
	defer de.mutex.Unlock()

	session, exists := de.debugSessions[sessionID]
	if !exists {
		return fmt.Errorf("debug session not found: %s", sessionID)
	}

	// Cancel the debug context
	session.Cancel()

	// Update session status
	session.mutex.Lock()
	session.Status = DebugStatusCancelled
	session.mutex.Unlock()

	// Remove from active sessions
	delete(de.debugSessions, sessionID)

	de.logger.Info("Stopped debug session",
		"session_id", sessionID,
		"execution_id", session.ExecutionID)

	return nil
}

// StepExecution executes a single step in the debugged workflow
func (de *DebugEngineImpl) StepExecution(sessionID string, action DebugAction) error {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return err
	}

	// Send step control command
	select {
	case session.stepChan <- DebugStepControl{Action: action}:
		de.logger.Info("Sent debug step command",
			"session_id", sessionID,
			"action", action)
		return nil
	case <-session.Context.Done():
		return fmt.Errorf("debug session cancelled")
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout sending step command")
	}
}

// SetBreakpoint sets a breakpoint at the specified step
func (de *DebugEngineImpl) SetBreakpoint(sessionID string, stepName string, condition *Condition) (*Breakpoint, error) {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return nil, err
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Generate breakpoint ID
	breakpointID := generateBreakpointID()

	// Create breakpoint
	breakpoint := &Breakpoint{
		ID:        breakpointID,
		StepName:  stepName,
		Enabled:   true,
		Condition: condition,
		HitCount:  0,
		CreatedAt: time.Now(),
	}

	// Store breakpoint
	session.Breakpoints[breakpointID] = breakpoint

	de.logger.Info("Set breakpoint",
		"session_id", sessionID,
		"breakpoint_id", breakpointID,
		"step_name", stepName,
		"has_condition", condition != nil)

	// Return a copy to prevent concurrent access issues
	breakpointCopy := *breakpoint
	return &breakpointCopy, nil
}

// RemoveBreakpoint removes a breakpoint
func (de *DebugEngineImpl) RemoveBreakpoint(sessionID string, breakpointID string) error {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return err
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Check if breakpoint exists
	_, exists := session.Breakpoints[breakpointID]
	if !exists {
		return fmt.Errorf("breakpoint not found: %s", breakpointID)
	}

	// Remove breakpoint
	delete(session.Breakpoints, breakpointID)

	de.logger.Info("Removed breakpoint",
		"session_id", sessionID,
		"breakpoint_id", breakpointID)

	return nil
}

// ListBreakpoints returns all breakpoints for a debug session
func (de *DebugEngineImpl) ListBreakpoints(sessionID string) ([]*Breakpoint, error) {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return nil, err
	}

	session.mutex.RLock()
	defer session.mutex.RUnlock()

	breakpoints := make([]*Breakpoint, 0, len(session.Breakpoints))
	for _, breakpoint := range session.Breakpoints {
		// Return copies to prevent concurrent access issues
		breakpointCopy := *breakpoint
		breakpoints = append(breakpoints, &breakpointCopy)
	}

	return breakpoints, nil
}

// InspectVariables returns the current variable state
func (de *DebugEngineImpl) InspectVariables(sessionID string) (map[string]interface{}, error) {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return nil, err
	}

	session.VariableInspector.mutex.RLock()
	defer session.VariableInspector.mutex.RUnlock()

	// Return a copy to prevent external modification
	variables := make(map[string]interface{})
	for k, v := range session.VariableInspector.CurrentVariables {
		variables[k] = v
	}

	return variables, nil
}

// UpdateVariable modifies a variable value during debugging
func (de *DebugEngineImpl) UpdateVariable(sessionID string, variableName string, value interface{}) error {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return err
	}

	session.VariableInspector.mutex.Lock()
	defer session.VariableInspector.mutex.Unlock()

	// Store original value for rollback capability
	originalValue := session.VariableInspector.CurrentVariables[variableName]

	// Record the modification
	session.VariableInspector.ModifiedVariables[variableName] = VariableModification{
		OriginalValue: originalValue,
		ModifiedValue: value,
		ModifiedAt:    time.Now(),
		StepName:      session.CurrentStep,
	}

	// Update the variable
	session.VariableInspector.CurrentVariables[variableName] = value

	// Record the change in history
	change := VariableChange{
		VariableName: variableName,
		OldValue:     originalValue,
		NewValue:     value,
		StepName:     session.CurrentStep,
		Timestamp:    time.Now(),
	}
	session.VariableInspector.VariableHistory = append(session.VariableInspector.VariableHistory, change)

	// Limit history size
	if len(session.VariableInspector.VariableHistory) > session.Settings.MaxHistorySize {
		session.VariableInspector.VariableHistory = session.VariableInspector.VariableHistory[1:]
	}

	de.logger.Info("Updated variable during debug",
		"session_id", sessionID,
		"variable_name", variableName,
		"old_value", originalValue,
		"new_value", value)

	return nil
}

// WatchVariable adds a variable to the watch list
func (de *DebugEngineImpl) WatchVariable(sessionID string, variableName string, breakOnChange bool, condition *Condition) error {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return err
	}

	session.VariableInspector.mutex.Lock()
	defer session.VariableInspector.mutex.Unlock()

	// Create variable watch
	watch := &VariableWatch{
		Name:          variableName,
		Condition:     condition,
		BreakOnChange: breakOnChange,
		LastValue:     session.VariableInspector.CurrentVariables[variableName],
		ChangeCount:   0,
	}

	// Store watch
	session.VariableInspector.WatchedVariables[variableName] = watch

	de.logger.Info("Added variable watch",
		"session_id", sessionID,
		"variable_name", variableName,
		"break_on_change", breakOnChange,
		"has_condition", condition != nil)

	return nil
}

// UnwatchVariable removes a variable from the watch list
func (de *DebugEngineImpl) UnwatchVariable(sessionID string, variableName string) error {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return err
	}

	session.VariableInspector.mutex.Lock()
	defer session.VariableInspector.mutex.Unlock()

	// Remove watch
	delete(session.VariableInspector.WatchedVariables, variableName)

	de.logger.Info("Removed variable watch",
		"session_id", sessionID,
		"variable_name", variableName)

	return nil
}

// GetAPICallHistory returns the API call history for inspection
func (de *DebugEngineImpl) GetAPICallHistory(sessionID string) ([]APICallInfo, error) {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return nil, err
	}

	session.mutex.RLock()
	defer session.mutex.RUnlock()

	// Return a copy of the API call log
	history := make([]APICallInfo, len(session.APICallLog))
	copy(history, session.APICallLog)

	return history, nil
}

// ReplayAPICall replays a previous API call by re-issuing the original HTTP request
// and returning the actual response received from the server.
func (de *DebugEngineImpl) ReplayAPICall(sessionID string, callID string) (*APICallInfo, error) {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return nil, err
	}

	// Copy the call info under the read lock so we don't hold it during the HTTP call.
	session.mutex.RLock()
	var original APICallInfo
	found := false
	for _, call := range session.APICallLog {
		if call.ID == callID {
			original = call
			found = true
			break
		}
	}
	session.mutex.RUnlock()

	if !found {
		return nil, fmt.Errorf("API call not found: %s", callID)
	}
	if !original.CanReplay {
		return nil, fmt.Errorf("API call cannot be replayed: %s", callID)
	}

	// Prepare the request body.
	var bodyReader io.Reader
	if original.RequestBody != nil {
		bodyBytes, err := json.Marshal(original.RequestBody)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(session.Context, original.Method, original.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create replay request: %w", err)
	}
	for k, v := range original.RequestHeaders {
		req.Header.Set(k, v)
	}

	startTime := time.Now()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, doErr := client.Do(req)
	duration := time.Since(startTime)

	replayCall := &APICallInfo{
		ID:             generateAPICallID(),
		StepName:       original.StepName + "_replay",
		Timestamp:      time.Now(),
		Method:         original.Method,
		URL:            original.URL,
		RequestHeaders: original.RequestHeaders,
		RequestBody:    original.RequestBody,
		Duration:       duration,
		CanReplay:      true,
	}

	if doErr != nil {
		replayCall.Error = doErr.Error()
		de.logger.Warn("Replay HTTP request failed",
			"session_id", sessionID,
			"call_id", callID,
			"error", doErr)
		return replayCall, nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		replayCall.ResponseStatus = resp.StatusCode
		replayCall.Error = fmt.Sprintf("failed to read response body: %s", readErr)
		return replayCall, nil
	}
	replayCall.ResponseStatus = resp.StatusCode

	responseHeaders := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if len(v) > 0 {
			responseHeaders[k] = v[0]
		}
	}
	replayCall.ResponseHeaders = responseHeaders

	var jsonBody interface{}
	if json.Unmarshal(body, &jsonBody) == nil {
		replayCall.ResponseBody = jsonBody
	} else {
		replayCall.ResponseBody = string(body)
	}

	de.logger.Info("Replayed API call",
		"session_id", sessionID,
		"original_call_id", callID,
		"replay_call_id", replayCall.ID,
		"status", replayCall.ResponseStatus)

	return replayCall, nil
}

// GetStepHistory returns the step execution history
func (de *DebugEngineImpl) GetStepHistory(sessionID string) ([]DebugStepInfo, error) {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return nil, err
	}

	session.mutex.RLock()
	defer session.mutex.RUnlock()

	// Return a copy of the step history
	history := make([]DebugStepInfo, len(session.StepHistory))
	copy(history, session.StepHistory)

	return history, nil
}

// RollbackToStep rolls back execution to a previous step by truncating the step
// history and restoring variables to the snapshot recorded before that step ran.
func (de *DebugEngineImpl) RollbackToStep(sessionID string, stepName string) error {
	session, err := de.GetDebugSession(sessionID)
	if err != nil {
		return err
	}

	// Truncate step history and reset execution position under the session lock.
	// Do NOT hold session.mutex while acquiring VariableInspector.mutex — other
	// methods (InspectVariables, UpdateVariable) take only VariableInspector.mutex,
	// so nesting them would create an inconsistent lock ordering.
	session.mutex.Lock()
	targetIdx := -1
	for i, step := range session.StepHistory {
		if step.StepName == stepName {
			targetIdx = i
			break
		}
	}
	if targetIdx < 0 {
		session.mutex.Unlock()
		return fmt.Errorf("step not found in history: %s", stepName)
	}
	targetStep := session.StepHistory[targetIdx]
	session.StepHistory = session.StepHistory[:targetIdx]
	session.CurrentStep = stepName
	session.mutex.Unlock()

	// Restore variable state under the variable inspector lock (taken separately).
	if targetStep.VariablesBefore != nil {
		restoredVars := make(map[string]interface{}, len(targetStep.VariablesBefore))
		for k, v := range targetStep.VariablesBefore {
			restoredVars[k] = v
		}
		session.VariableInspector.mutex.Lock()
		session.VariableInspector.CurrentVariables = restoredVars
		session.VariableInspector.mutex.Unlock()
	}

	de.logger.Info("Rolled back to step",
		"session_id", sessionID,
		"target_step", stepName,
		"history_length", len(session.StepHistory))

	return nil
}

// checkBreakpoint checks if execution should pause at a breakpoint
func (de *DebugEngineImpl) checkBreakpoint(session *DebugSession, stepName string, variables map[string]interface{}) (*Breakpoint, bool) {
	// Use full Lock instead of RLock because we modify breakpoint.HitCount and breakpoint.LastHit
	session.mutex.Lock()
	defer session.mutex.Unlock()

	for _, breakpoint := range session.Breakpoints {
		if !breakpoint.Enabled || breakpoint.StepName != stepName {
			continue
		}

		// Check condition if present; skip this breakpoint when the condition is false.
		if breakpoint.Condition != nil {
			conditionMet, err := de.workflowEngine.evaluateCondition(breakpoint.Condition, variables)
			if err != nil || !conditionMet {
				continue
			}
		}

		// Update breakpoint hit information
		breakpoint.HitCount++
		now := time.Now()
		breakpoint.LastHit = &now

		return breakpoint, true
	}

	return nil, false
}

// Helper functions for ID generation.
// Each uses an atomic counter to guarantee uniqueness even on Windows
// where time.Now().UnixNano() has ~15.6ms granularity.
func generateDebugSessionID() string {
	return fmt.Sprintf("debug_session_%d_%d", time.Now().UnixNano(), debugIDCounter.Add(1))
}

func generateBreakpointID() string {
	return fmt.Sprintf("bp_%d_%d", time.Now().UnixNano(), debugIDCounter.Add(1))
}

func generateAPICallID() string {
	return fmt.Sprintf("api_call_%d_%d", time.Now().UnixNano(), debugIDCounter.Add(1))
}
