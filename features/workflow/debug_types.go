// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package workflow

import (
	"context"
	"sync"
	"time"
)

// DebugSession represents an interactive debugging session for workflow execution
type DebugSession struct {
	// ID is the unique identifier for this debug session
	ID string `json:"id"`

	// ExecutionID is the workflow execution being debugged
	ExecutionID string `json:"execution_id"`

	// Status is the current debug session status
	Status DebugStatus `json:"status"`

	// StartTime is when the debug session started
	StartTime time.Time `json:"start_time"`

	// Breakpoints contains active breakpoints for this session
	Breakpoints map[string]*Breakpoint `json:"breakpoints"`

	// CurrentStep is the currently paused step (if any)
	CurrentStep string `json:"current_step,omitempty"`

	// VariableInspector provides live variable viewing and modification
	VariableInspector *VariableInspector `json:"variable_inspector"`

	// StepHistory tracks the execution path for step-by-step debugging
	StepHistory []DebugStepInfo `json:"step_history"`

	// APICallLog tracks HTTP/API requests for inspection
	APICallLog []APICallInfo `json:"api_call_log"`

	// Settings contains debug session configuration
	Settings DebugSettings `json:"settings"`

	// mutex protects concurrent access to debug session data
	mutex sync.RWMutex `json:"-"`

	// stepChan is used for step-by-step execution control
	stepChan chan DebugStepControl `json:"-"`

	// Context for session cancellation
	Context context.Context `json:"-"`

	// Cancel function for stopping the debug session
	Cancel context.CancelFunc `json:"-"`
}

// DebugStatus represents the status of a debug session
type DebugStatus string

const (
	// DebugStatusActive indicates the debug session is active
	DebugStatusActive DebugStatus = "active"

	// DebugStatusPaused indicates the debug session is paused at a step
	DebugStatusPaused DebugStatus = "paused"

	// DebugStatusBreakpoint indicates the debug session hit a breakpoint
	DebugStatusBreakpoint DebugStatus = "breakpoint"

	// DebugStatusStepping indicates the debug session is in step-by-step mode
	DebugStatusStepping DebugStatus = "stepping"

	// DebugStatusCompleted indicates the debug session has completed
	DebugStatusCompleted DebugStatus = "completed"

	// DebugStatusCancelled indicates the debug session was cancelled
	DebugStatusCancelled DebugStatus = "cancelled"

	// DebugStatusError indicates the debug session encountered an error
	DebugStatusError DebugStatus = "error"
)

// Breakpoint represents a debugging breakpoint
type Breakpoint struct {
	// ID is the unique identifier for this breakpoint
	ID string `json:"id"`

	// StepName is the step where the breakpoint is set
	StepName string `json:"step_name"`

	// Enabled indicates if the breakpoint is active
	Enabled bool `json:"enabled"`

	// Condition is an optional condition for conditional breakpoints
	Condition *Condition `json:"condition,omitempty"`

	// HitCount tracks how many times this breakpoint has been hit
	HitCount int `json:"hit_count"`

	// CreatedAt is when the breakpoint was created
	CreatedAt time.Time `json:"created_at"`

	// LastHit is when the breakpoint was last hit
	LastHit *time.Time `json:"last_hit,omitempty"`
}

// VariableInspector provides live variable viewing and modification capabilities
type VariableInspector struct {
	// CurrentVariables contains the current variable state
	CurrentVariables map[string]interface{} `json:"current_variables"`

	// VariableHistory tracks variable changes over time
	VariableHistory []VariableChange `json:"variable_history"`

	// WatchedVariables contains variables being actively watched
	WatchedVariables map[string]*VariableWatch `json:"watched_variables"`

	// ModifiedVariables tracks variables that have been modified during debugging
	ModifiedVariables map[string]VariableModification `json:"modified_variables"`

	// mutex protects concurrent access to variable data
	mutex sync.RWMutex `json:"-"`
}

// VariableChange tracks a change to a variable during execution
type VariableChange struct {
	// VariableName is the name of the variable that changed
	VariableName string `json:"variable_name"`

	// OldValue is the previous value
	OldValue interface{} `json:"old_value"`

	// NewValue is the new value
	NewValue interface{} `json:"new_value"`

	// StepName is the step where the change occurred
	StepName string `json:"step_name"`

	// Timestamp is when the change occurred
	Timestamp time.Time `json:"timestamp"`
}

// VariableWatch represents a watched variable
type VariableWatch struct {
	// Name is the variable name being watched
	Name string `json:"name"`

	// Condition is an optional condition for when to trigger the watch
	Condition *Condition `json:"condition,omitempty"`

	// BreakOnChange indicates if execution should pause when this variable changes
	BreakOnChange bool `json:"break_on_change"`

	// LastValue is the last observed value
	LastValue interface{} `json:"last_value"`

	// ChangeCount tracks how many times this variable has changed
	ChangeCount int `json:"change_count"`
}

// VariableModification tracks a manual variable modification during debugging
type VariableModification struct {
	// OriginalValue is the value before modification
	OriginalValue interface{} `json:"original_value"`

	// ModifiedValue is the value after modification
	ModifiedValue interface{} `json:"modified_value"`

	// ModifiedAt is when the modification occurred
	ModifiedAt time.Time `json:"modified_at"`

	// StepName is the step where the modification occurred
	StepName string `json:"step_name"`
}

// DebugStepInfo contains information about a step during debugging
type DebugStepInfo struct {
	// StepName is the name of the step
	StepName string `json:"step_name"`

	// StepType is the type of step
	StepType StepType `json:"step_type"`

	// Timestamp is when the step was executed
	Timestamp time.Time `json:"timestamp"`

	// Duration is how long the step took (if completed)
	Duration *time.Duration `json:"duration,omitempty"`

	// Status is the step execution status
	Status ExecutionStatus `json:"status"`

	// VariablesBefore contains variable state before step execution
	VariablesBefore map[string]interface{} `json:"variables_before"`

	// VariablesAfter contains variable state after step execution
	VariablesAfter map[string]interface{} `json:"variables_after,omitempty"`

	// BreakpointHit indicates if a breakpoint was hit on this step
	BreakpointHit *string `json:"breakpoint_hit,omitempty"`

	// Error contains error information if the step failed
	Error *WorkflowError `json:"error,omitempty"`
}

// APICallInfo contains information about HTTP/API calls for inspection
type APICallInfo struct {
	// ID is the unique identifier for this API call
	ID string `json:"id"`

	// StepName is the step that made the API call
	StepName string `json:"step_name"`

	// Timestamp is when the call was made
	Timestamp time.Time `json:"timestamp"`

	// Method is the HTTP method
	Method string `json:"method"`

	// URL is the request URL
	URL string `json:"url"`

	// RequestHeaders contains the request headers
	RequestHeaders map[string]string `json:"request_headers"`

	// RequestBody contains the request body
	RequestBody interface{} `json:"request_body,omitempty"`

	// ResponseStatus is the HTTP response status code
	ResponseStatus int `json:"response_status,omitempty"`

	// ResponseHeaders contains the response headers
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`

	// ResponseBody contains the response body
	ResponseBody interface{} `json:"response_body,omitempty"`

	// Duration is how long the call took
	Duration time.Duration `json:"duration"`

	// Error contains error information if the call failed
	Error string `json:"error,omitempty"`

	// CanReplay indicates if this call can be replayed
	CanReplay bool `json:"can_replay"`
}

// DebugSettings contains configuration for debug sessions
type DebugSettings struct {
	// AutoStepMode indicates if the debugger should automatically step through
	AutoStepMode bool `json:"auto_step_mode"`

	// StepDelay is the delay between auto steps
	StepDelay time.Duration `json:"step_delay"`

	// BreakOnError indicates if execution should pause on any error
	BreakOnError bool `json:"break_on_error"`

	// BreakOnVariableChange indicates if execution should pause on variable changes
	BreakOnVariableChange bool `json:"break_on_variable_change"`

	// CaptureAPIDetails indicates if detailed API call information should be captured
	CaptureAPIDetails bool `json:"capture_api_details"`

	// MaxHistorySize limits the size of step and variable history
	MaxHistorySize int `json:"max_history_size"`

	// TenantIsolation ensures debug operations respect tenant boundaries
	TenantIsolation bool `json:"tenant_isolation"`
}

// DebugStepControl represents step control commands
type DebugStepControl struct {
	// Action is the debugging action to take
	Action DebugAction `json:"action"`

	// StepName is the target step for some actions
	StepName string `json:"step_name,omitempty"`

	// VariableUpdates contains variable modifications to apply
	VariableUpdates map[string]interface{} `json:"variable_updates,omitempty"`
}

// DebugAction defines debugging actions
type DebugAction string

const (
	// DebugActionStep executes the next step
	DebugActionStep DebugAction = "step"

	// DebugActionStepOver steps over the current step (doesn't enter nested steps)
	DebugActionStepOver DebugAction = "step_over"

	// DebugActionStepInto steps into nested steps
	DebugActionStepInto DebugAction = "step_into"

	// DebugActionStepOut steps out of current nested context
	DebugActionStepOut DebugAction = "step_out"

	// DebugActionContinue continues execution until next breakpoint
	DebugActionContinue DebugAction = "continue"

	// DebugActionPause pauses execution at the current step
	DebugActionPause DebugAction = "pause"

	// DebugActionStop stops the debug session
	DebugActionStop DebugAction = "stop"

	// DebugActionRestart restarts execution from the beginning
	DebugActionRestart DebugAction = "restart"

	// DebugActionUpdateVariables applies variable modifications
	DebugActionUpdateVariables DebugAction = "update_variables"
)

// DebugEngine defines the interface for workflow debugging
type DebugEngine interface {
	// StartDebugSession starts a new debug session for a workflow execution
	StartDebugSession(ctx context.Context, executionID string, settings DebugSettings) (*DebugSession, error)

	// GetDebugSession returns a debug session by ID
	GetDebugSession(sessionID string) (*DebugSession, error)

	// ListDebugSessions returns all active debug sessions
	ListDebugSessions() ([]*DebugSession, error)

	// StopDebugSession stops a debug session
	StopDebugSession(sessionID string) error

	// StepExecution executes a single step in the debugged workflow
	StepExecution(sessionID string, action DebugAction) error

	// SetBreakpoint sets a breakpoint at the specified step
	SetBreakpoint(sessionID string, stepName string, condition *Condition) (*Breakpoint, error)

	// RemoveBreakpoint removes a breakpoint
	RemoveBreakpoint(sessionID string, breakpointID string) error

	// ListBreakpoints returns all breakpoints for a debug session
	ListBreakpoints(sessionID string) ([]*Breakpoint, error)

	// InspectVariables returns the current variable state
	InspectVariables(sessionID string) (map[string]interface{}, error)

	// UpdateVariable modifies a variable value during debugging
	UpdateVariable(sessionID string, variableName string, value interface{}) error

	// WatchVariable adds a variable to the watch list
	WatchVariable(sessionID string, variableName string, breakOnChange bool, condition *Condition) error

	// UnwatchVariable removes a variable from the watch list
	UnwatchVariable(sessionID string, variableName string) error

	// GetAPICallHistory returns the API call history for inspection
	GetAPICallHistory(sessionID string) ([]APICallInfo, error)

	// ReplayAPICall replays a previous API call
	ReplayAPICall(sessionID string, callID string) (*APICallInfo, error)

	// GetStepHistory returns the step execution history
	GetStepHistory(sessionID string) ([]DebugStepInfo, error)

	// RollbackToStep rolls back execution to a previous step (for safe testing)
	RollbackToStep(sessionID string, stepName string) error
}
