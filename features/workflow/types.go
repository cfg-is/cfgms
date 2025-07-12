// Package workflow provides basic workflow engine capabilities for the CFGMS system.
//
// This package implements a basic workflow engine that supports sequential,
// parallel, and conditional execution of tasks. Workflows are defined using
// YAML configuration and can orchestrate multiple module operations.
//
// Basic workflow primitives:
//   - Sequential: Execute steps one after another
//   - Parallel: Execute multiple steps simultaneously
//   - Conditional: Execute steps based on conditions
//
// Example workflow definition:
//
//	workflow:
//	  name: "deploy-application"
//	  steps:
//	    - type: sequential
//	      steps:
//	        - name: "create-directory"
//	          module: "directory"
//	          config:
//	            path: "/opt/app"
//	            permissions: "755"
//	        - type: parallel
//	          steps:
//	            - name: "install-package"
//	              module: "package"
//	              config:
//	                name: "nginx"
//	                state: "present"
//	            - name: "configure-firewall"
//	              module: "firewall"
//	              config:
//	                port: 80
//	                action: "allow"
//
// The workflow engine integrates with the existing module system and provides
// state management, monitoring, and error handling capabilities.
package workflow

import (
	"context"
	"time"
)

// Workflow defines a complete workflow with metadata and execution steps
type Workflow struct {
	// Name is the unique identifier for this workflow
	Name string `yaml:"name" json:"name"`

	// Description provides human-readable documentation
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Version for workflow versioning support
	Version string `yaml:"version,omitempty" json:"version,omitempty"`

	// Variables define workflow-level variables that can be used in steps
	Variables map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`

	// Steps define the execution flow of the workflow
	Steps []Step `yaml:"steps" json:"steps"`

	// Timeout defines maximum execution time for the entire workflow
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// OnFailure defines what to do when a step fails
	OnFailure FailureAction `yaml:"on_failure,omitempty" json:"on_failure,omitempty"`
}

// Step represents a single execution unit in a workflow
type Step struct {
	// Name is the unique identifier for this step within the workflow
	Name string `yaml:"name" json:"name"`

	// Type defines the step execution type (task, sequential, parallel, conditional)
	Type StepType `yaml:"type" json:"type"`

	// Module is the name of the module to execute (for task steps)
	Module string `yaml:"module,omitempty" json:"module,omitempty"`

	// Config contains module-specific configuration (for task steps)
	Config map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`

	// Steps contains child steps (for sequential, parallel, conditional steps)
	Steps []Step `yaml:"steps,omitempty" json:"steps,omitempty"`

	// Condition defines when this step should execute (for conditional steps)
	Condition *Condition `yaml:"condition,omitempty" json:"condition,omitempty"`

	// Timeout defines maximum execution time for this step
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// OnFailure defines what to do when this step fails
	OnFailure FailureAction `yaml:"on_failure,omitempty" json:"on_failure,omitempty"`

	// Variables define step-level variables
	Variables map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`
}

// StepType defines the type of workflow step
type StepType string

const (
	// StepTypeTask executes a single module operation
	StepTypeTask StepType = "task"

	// StepTypeSequential executes child steps one after another
	StepTypeSequential StepType = "sequential"

	// StepTypeParallel executes child steps simultaneously
	StepTypeParallel StepType = "parallel"

	// StepTypeConditional executes child steps based on a condition
	StepTypeConditional StepType = "conditional"
)

// Condition defines execution conditions for conditional steps
type Condition struct {
	// Type defines the condition type
	Type ConditionType `yaml:"type" json:"type"`

	// Variable is the variable name to evaluate
	Variable string `yaml:"variable,omitempty" json:"variable,omitempty"`

	// Operator defines the comparison operator
	Operator ComparisonOperator `yaml:"operator,omitempty" json:"operator,omitempty"`

	// Value is the value to compare against
	Value interface{} `yaml:"value,omitempty" json:"value,omitempty"`

	// Expression allows for complex condition expressions
	Expression string `yaml:"expression,omitempty" json:"expression,omitempty"`
}

// ConditionType defines the type of condition
type ConditionType string

const (
	// ConditionTypeVariable evaluates a variable against a value
	ConditionTypeVariable ConditionType = "variable"

	// ConditionTypeExpression evaluates a complex expression
	ConditionTypeExpression ConditionType = "expression"
)

// ComparisonOperator defines comparison operators for conditions
type ComparisonOperator string

const (
	// OperatorEqual checks if values are equal
	OperatorEqual ComparisonOperator = "eq"

	// OperatorNotEqual checks if values are not equal
	OperatorNotEqual ComparisonOperator = "ne"

	// OperatorGreaterThan checks if left > right
	OperatorGreaterThan ComparisonOperator = "gt"

	// OperatorLessThan checks if left < right
	OperatorLessThan ComparisonOperator = "lt"

	// OperatorContains checks if left contains right
	OperatorContains ComparisonOperator = "contains"

	// OperatorExists checks if variable exists
	OperatorExists ComparisonOperator = "exists"
)

// FailureAction defines what to do when a step fails
type FailureAction string

const (
	// ActionStop stops the entire workflow on failure
	ActionStop FailureAction = "stop"

	// ActionContinue continues with the next step on failure
	ActionContinue FailureAction = "continue"

	// ActionRetry retries the failed step
	ActionRetry FailureAction = "retry"
)

// WorkflowExecution represents a running workflow instance
type WorkflowExecution struct {
	// ID is the unique identifier for this execution
	ID string `json:"id"`

	// WorkflowName is the name of the workflow being executed
	WorkflowName string `json:"workflow_name"`

	// Status is the current execution status
	Status ExecutionStatus `json:"status"`

	// StartTime is when the execution started
	StartTime time.Time `json:"start_time"`

	// EndTime is when the execution completed (if finished)
	EndTime *time.Time `json:"end_time,omitempty"`

	// CurrentStep is the currently executing step
	CurrentStep string `json:"current_step,omitempty"`

	// StepResults contains the results of completed steps
	StepResults map[string]StepResult `json:"step_results"`

	// Variables contains the current variable values
	Variables map[string]interface{} `json:"variables"`

	// Error contains error information if the execution failed
	Error string `json:"error,omitempty"`

	// Context for cancellation
	Context context.Context `json:"-"`

	// Cancel function for stopping execution
	Cancel context.CancelFunc `json:"-"`
}

// ExecutionStatus represents the status of a workflow execution
type ExecutionStatus string

const (
	// StatusPending indicates the workflow is waiting to start
	StatusPending ExecutionStatus = "pending"

	// StatusRunning indicates the workflow is currently executing
	StatusRunning ExecutionStatus = "running"

	// StatusCompleted indicates the workflow completed successfully
	StatusCompleted ExecutionStatus = "completed"

	// StatusFailed indicates the workflow failed
	StatusFailed ExecutionStatus = "failed"

	// StatusCancelled indicates the workflow was cancelled
	StatusCancelled ExecutionStatus = "cancelled"

	// StatusPaused indicates the workflow is paused
	StatusPaused ExecutionStatus = "paused"
)

// StepResult contains the result of a step execution
type StepResult struct {
	// Status is the execution status of the step
	Status ExecutionStatus `json:"status"`

	// StartTime is when the step started
	StartTime time.Time `json:"start_time"`

	// EndTime is when the step completed
	EndTime *time.Time `json:"end_time,omitempty"`

	// Duration is how long the step took to execute
	Duration time.Duration `json:"duration"`

	// Output contains any output from the step
	Output map[string]interface{} `json:"output,omitempty"`

	// Error contains error information if the step failed
	Error string `json:"error,omitempty"`

	// RetryCount tracks how many times this step has been retried
	RetryCount int `json:"retry_count"`
}

// WorkflowEngine defines the interface for workflow execution
type WorkflowEngine interface {
	// ExecuteWorkflow starts execution of a workflow
	ExecuteWorkflow(ctx context.Context, workflow Workflow, variables map[string]interface{}) (*WorkflowExecution, error)

	// GetExecution returns the status of a workflow execution
	GetExecution(executionID string) (*WorkflowExecution, error)

	// ListExecutions returns all workflow executions
	ListExecutions() ([]*WorkflowExecution, error)

	// CancelExecution cancels a running workflow execution
	CancelExecution(executionID string) error

	// PauseExecution pauses a running workflow execution
	PauseExecution(executionID string) error

	// ResumeExecution resumes a paused workflow execution
	ResumeExecution(executionID string) error
}

// StepExecutor defines the interface for executing individual steps
type StepExecutor interface {
	// ExecuteStep executes a single workflow step
	ExecuteStep(ctx context.Context, step Step, variables map[string]interface{}) (StepResult, error)
}