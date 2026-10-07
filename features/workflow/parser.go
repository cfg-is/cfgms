// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Parser handles loading and parsing workflow definitions from YAML files
type Parser struct{}

// NewParser creates a new workflow parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseFile loads and parses a workflow from a YAML file
func (p *Parser) ParseFile(filePath string) (Workflow, error) {
	// #nosec G304 - Workflow engine requires loading workflow files from controlled paths
	data, err := os.ReadFile(filePath)
	if err != nil {
		return Workflow{}, fmt.Errorf("failed to read workflow file: %w", err)
	}

	return p.ParseYAML(data)
}

// ParseYAML parses a workflow from YAML data
func (p *Parser) ParseYAML(data []byte) (Workflow, error) {
	var workflowDef workflowDefinition
	if err := yaml.Unmarshal(data, &workflowDef); err != nil {
		return Workflow{}, fmt.Errorf("failed to parse YAML: %w", err)
	}

	workflow, err := p.convertDefinition(workflowDef)
	if err != nil {
		return Workflow{}, fmt.Errorf("failed to convert workflow definition: %w", err)
	}

	// Validate the workflow
	if err := p.ValidateWorkflow(workflow); err != nil {
		return Workflow{}, fmt.Errorf("workflow validation failed: %w", err)
	}

	return workflow, nil
}

// workflowDefinition is the YAML representation of a workflow
type workflowDefinition struct {
	Workflow workflowMeta `yaml:"workflow"`
}

type workflowMeta struct {
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description,omitempty"`
	Version     string                 `yaml:"version,omitempty"`
	Variables   map[string]interface{} `yaml:"variables,omitempty"`
	Inputs      []InputSpec            `yaml:"inputs,omitempty"`
	Steps       []stepDefinition       `yaml:"steps"`
	Timeout     string                 `yaml:"timeout,omitempty"`
	OnFailure   string                 `yaml:"on_failure,omitempty"`
}

type stepDefinition struct {
	Name      string                 `yaml:"name"`
	Type      string                 `yaml:"type"`
	Module    string                 `yaml:"module,omitempty"`
	Config    map[string]interface{} `yaml:"config,omitempty"`
	Steps     []stepDefinition       `yaml:"steps,omitempty"`
	Condition *conditionDefinition   `yaml:"condition,omitempty"`
	Delay     *delayDefinition       `yaml:"delay,omitempty"`
	Approval  *approvalDefinition    `yaml:"approval,omitempty"`
	Notify    *NotifyConfig          `yaml:"notify,omitempty"`
	Timeout   string                 `yaml:"timeout,omitempty"`
	OnFailure string                 `yaml:"on_failure,omitempty"`
	Variables map[string]interface{} `yaml:"variables,omitempty"`
}

type delayDefinition struct {
	Duration string `yaml:"duration"`
	Message  string `yaml:"message,omitempty"`
}

type approvalDefinition struct {
	Message            string `yaml:"message"`
	ApproverPermission string `yaml:"approver_permission,omitempty"`
	Timeout            string `yaml:"timeout"`
}

type conditionDefinition struct {
	Type       string      `yaml:"type"`
	Variable   string      `yaml:"variable,omitempty"`
	Operator   string      `yaml:"operator,omitempty"`
	Value      interface{} `yaml:"value,omitempty"`
	Expression string      `yaml:"expression,omitempty"`
}

// convertDefinition converts the YAML definition to the internal workflow structure
func (p *Parser) convertDefinition(def workflowDefinition) (Workflow, error) {
	workflow := Workflow{
		Name:        def.Workflow.Name,
		Description: def.Workflow.Description,
		Version:     def.Workflow.Version,
		Variables:   def.Workflow.Variables,
		Inputs:      def.Workflow.Inputs,
	}

	// Parse timeout
	if def.Workflow.Timeout != "" {
		timeout, err := time.ParseDuration(def.Workflow.Timeout)
		if err != nil {
			return Workflow{}, fmt.Errorf("invalid timeout format: %w", err)
		}
		workflow.Timeout = timeout
	}

	// Parse failure action
	if def.Workflow.OnFailure != "" {
		workflow.OnFailure = FailureAction(def.Workflow.OnFailure)
	}

	// Convert steps
	steps, err := p.convertSteps(def.Workflow.Steps)
	if err != nil {
		return Workflow{}, fmt.Errorf("failed to convert steps: %w", err)
	}
	workflow.Steps = steps

	return workflow, nil
}

// convertSteps converts step definitions to internal step structures
func (p *Parser) convertSteps(stepDefs []stepDefinition) ([]Step, error) {
	steps := make([]Step, len(stepDefs))

	for i, stepDef := range stepDefs {
		step := Step{
			Name:      stepDef.Name,
			Type:      StepType(stepDef.Type),
			Module:    stepDef.Module,
			Config:    stepDef.Config,
			Variables: stepDef.Variables,
		}

		// Parse timeout
		if stepDef.Timeout != "" {
			timeout, err := time.ParseDuration(stepDef.Timeout)
			if err != nil {
				return nil, fmt.Errorf("invalid timeout format for step %s: %w", stepDef.Name, err)
			}
			step.Timeout = timeout
		}

		// Parse failure action
		if stepDef.OnFailure != "" {
			step.OnFailure = FailureAction(stepDef.OnFailure)
		}

		// Convert child steps
		if len(stepDef.Steps) > 0 {
			childSteps, err := p.convertSteps(stepDef.Steps)
			if err != nil {
				return nil, fmt.Errorf("failed to convert child steps for %s: %w", stepDef.Name, err)
			}
			step.Steps = childSteps
		}

		// Convert condition
		if stepDef.Condition != nil {
			condition, err := p.convertCondition(*stepDef.Condition)
			if err != nil {
				return nil, fmt.Errorf("failed to convert condition for step %s: %w", stepDef.Name, err)
			}
			step.Condition = &condition
		}

		// Convert delay config
		if stepDef.Delay != nil {
			dur, err := time.ParseDuration(stepDef.Delay.Duration)
			if err != nil {
				return nil, fmt.Errorf("invalid delay duration for step %s: %w", stepDef.Name, err)
			}
			step.Delay = &DelayConfig{
				Duration: dur,
				Message:  stepDef.Delay.Message,
			}
		}

		step.Notify = stepDef.Notify

		// Convert approval config
		if stepDef.Approval != nil {
			cfg := &ApprovalConfig{
				Message:            stepDef.Approval.Message,
				ApproverPermission: stepDef.Approval.ApproverPermission,
			}
			if stepDef.Approval.Timeout != "" {
				timeout, err := time.ParseDuration(stepDef.Approval.Timeout)
				if err != nil {
					return nil, fmt.Errorf("invalid approval timeout for step %s: %w", stepDef.Name, err)
				}
				cfg.Timeout = timeout
			}
			step.Approval = cfg
		}

		steps[i] = step
	}

	return steps, nil
}

// convertCondition converts a condition definition to internal condition structure
func (p *Parser) convertCondition(condDef conditionDefinition) (Condition, error) {
	condition := Condition{
		Type:       ConditionType(condDef.Type),
		Variable:   condDef.Variable,
		Value:      condDef.Value,
		Expression: condDef.Expression,
	}

	if condDef.Operator != "" {
		condition.Operator = ComparisonOperator(condDef.Operator)
	}

	return condition, nil
}

// ValidateWorkflow validates a workflow definition
func (p *Parser) ValidateWorkflow(workflow Workflow) error {
	// Validate workflow name
	if workflow.Name == "" {
		return fmt.Errorf("workflow name is required")
	}

	// Validate steps
	if len(workflow.Steps) == 0 {
		return fmt.Errorf("workflow must have at least one step")
	}

	if err := ValidateInputSpecs(workflow.Inputs); err != nil {
		return err
	}

	// Validate each step
	stepNames := make(map[string]bool)
	for _, step := range workflow.Steps {
		// Approval gates are resumed by replaying the top-level step list, so a
		// gate inside any other block is rejected rather than silently accepted.
		// Checked first so it is reported whatever the enclosing step's type.
		if nested := findNestedApproval(step); nested != "" {
			return fmt.Errorf("step validation failed: %w", &nestedApprovalError{step: nested})
		}
		if err := p.validateStep(step, stepNames); err != nil {
			return fmt.Errorf("step validation failed: %w", err)
		}
	}

	// Validate timeout
	if workflow.Timeout < 0 {
		return fmt.Errorf("workflow timeout cannot be negative")
	}

	// Validate failure action
	if workflow.OnFailure != "" {
		if !isValidFailureAction(workflow.OnFailure) {
			return fmt.Errorf("invalid failure action: %s", workflow.OnFailure)
		}
	}

	return nil
}

// validateStep validates a single step
func (p *Parser) validateStep(step Step, stepNames map[string]bool) error {
	// Validate step name
	if step.Name == "" {
		return fmt.Errorf("step name is required")
	}

	// Check for duplicate step names
	if stepNames[step.Name] {
		return fmt.Errorf("duplicate step name: %s", step.Name)
	}
	stepNames[step.Name] = true

	// Validate step type
	if !isValidStepType(step.Type) {
		return fmt.Errorf("invalid step type: %s", step.Type)
	}

	// Type-specific validation
	switch step.Type {
	case StepTypeTask:
		if step.Module == "" {
			return fmt.Errorf("module is required for task steps")
		}
		if step.Config == nil {
			return fmt.Errorf("config is required for task steps")
		}
	case StepTypeSequential, StepTypeParallel:
		if len(step.Steps) == 0 {
			return fmt.Errorf("%s steps must have child steps", step.Type)
		}
	case StepTypeApproval:
		if step.Approval == nil {
			return fmt.Errorf("approval configuration is required for approval steps")
		}
		if step.Approval.Message == "" {
			return fmt.Errorf("message is required for approval steps")
		}
		if step.Approval.Timeout <= 0 {
			return fmt.Errorf("timeout must be positive for approval steps")
		}
	case StepTypeNotify:
		if step.Notify == nil {
			return fmt.Errorf("notify configuration is required for notify steps")
		}
		if step.Notify.URL == "" {
			return fmt.Errorf("url is required for notify steps")
		}
		if step.Notify.Title == "" {
			return fmt.Errorf("title is required for notify steps")
		}
		switch step.Notify.Severity {
		case "", NotifySeverityInfo, NotifySeverityWarning, NotifySeverityCritical:
		default:
			return fmt.Errorf("invalid severity %q for notify steps: must be info, warning or critical", step.Notify.Severity)
		}
	case StepTypeConditional:
		if step.Condition == nil {
			return fmt.Errorf("condition is required for conditional steps")
		}
		if len(step.Steps) == 0 {
			return fmt.Errorf("conditional steps must have child steps")
		}
	}

	// Validate child steps recursively
	for _, childStep := range step.Steps {
		if err := p.validateStep(childStep, stepNames); err != nil {
			return fmt.Errorf("child step validation failed: %w", err)
		}
	}

	// Validate condition
	if step.Condition != nil {
		if err := p.validateCondition(*step.Condition); err != nil {
			return fmt.Errorf("condition validation failed: %w", err)
		}
	}

	// Validate timeout
	if step.Timeout < 0 {
		return fmt.Errorf("step timeout cannot be negative")
	}

	// Validate failure action
	if step.OnFailure != "" {
		if !isValidFailureAction(step.OnFailure) {
			return fmt.Errorf("invalid failure action for step %s: %s", step.Name, step.OnFailure)
		}
	}

	return nil
}

// validateCondition validates a condition
func (p *Parser) validateCondition(condition Condition) error {
	if !isValidConditionType(condition.Type) {
		return fmt.Errorf("invalid condition type: %s", condition.Type)
	}

	switch condition.Type {
	case ConditionTypeVariable:
		if condition.Variable == "" {
			return fmt.Errorf("variable is required for variable conditions")
		}
		if condition.Operator == "" {
			return fmt.Errorf("operator is required for variable conditions")
		}
		if !isValidComparisonOperator(condition.Operator) {
			return fmt.Errorf("invalid comparison operator: %s", condition.Operator)
		}
	case ConditionTypeExpression:
		if condition.Expression == "" {
			return fmt.Errorf("expression is required for expression conditions")
		}
	}

	return nil
}

// Validation helper functions
func isValidStepType(stepType StepType) bool {
	switch stepType {
	case StepTypeTask, StepTypeSequential, StepTypeParallel, StepTypeConditional,
		StepTypeDelay, StepTypeNotify, StepTypeApproval, StepTypeSetHARole, StepTypeMoveResourceToCluster:
		return true
	default:
		return false
	}
}

func isValidFailureAction(action FailureAction) bool {
	switch action {
	case ActionStop, ActionContinue, ActionRetry:
		return true
	default:
		return false
	}
}

func isValidConditionType(condType ConditionType) bool {
	switch condType {
	case ConditionTypeVariable, ConditionTypeExpression:
		return true
	default:
		return false
	}
}

func isValidComparisonOperator(operator ComparisonOperator) bool {
	switch operator {
	case OperatorEqual, OperatorNotEqual, OperatorGreaterThan, OperatorLessThan, OperatorContains, OperatorExists:
		return true
	default:
		return false
	}
}

// nestedApprovalError reports an approval step placed anywhere but the top level.
type nestedApprovalError struct {
	step string
}

func (e *nestedApprovalError) Error() string {
	return fmt.Sprintf("approval steps must be top-level (step %q is nested)", e.step)
}

// findNestedApproval returns the name of the first approval step found inside a
// child block of step (parallel, loop, try, conditional, switch, fallback), or "".
func findNestedApproval(step Step) string {
	return nestedApprovalIn(step)
}

func nestedApprovalIn(step Step) string {
	var blocks [][]Step
	blocks = append(blocks, step.Steps)
	if step.Try != nil {
		blocks = append(blocks, step.Try.Try, step.Try.Finally)
		for _, c := range step.Try.Catch {
			blocks = append(blocks, c.Steps)
		}
	}
	if step.Switch != nil {
		blocks = append(blocks, step.Switch.Default)
		for _, c := range step.Switch.Cases {
			blocks = append(blocks, c.Steps)
		}
	}
	if step.ErrorHandling != nil && step.ErrorHandling.FallbackStep != nil {
		blocks = append(blocks, []Step{*step.ErrorHandling.FallbackStep})
	}
	for _, block := range blocks {
		for _, child := range block {
			if child.Type == StepTypeApproval {
				return child.Name
			}
			if n := nestedApprovalIn(child); n != "" {
				return n
			}
		}
	}
	return ""
}
