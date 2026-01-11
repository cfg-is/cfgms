// SPDX-License-Identifier: Apache-2.0
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
	Timeout   string                 `yaml:"timeout,omitempty"`
	OnFailure string                 `yaml:"on_failure,omitempty"`
	Variables map[string]interface{} `yaml:"variables,omitempty"`
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

	// Validate each step
	stepNames := make(map[string]bool)
	for _, step := range workflow.Steps {
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
	case StepTypeTask, StepTypeSequential, StepTypeParallel, StepTypeConditional:
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
