// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

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

// ValidationIssue is one defect found in a workflow definition.
type ValidationIssue struct {
	// Path locates the defect, e.g. "steps[2].config" or "name".
	Path string `json:"path"`
	// StepName is the name of the step the defect belongs to, when there is one.
	StepName string `json:"step_name,omitempty"`
	// Message describes the defect. Step names, types and failure actions it
	// echoes are truncated to maxIssueValueLen bytes; input-declaration and
	// condition messages are not, but the response only goes back to the caller.
	Message string `json:"message"`

	// err is the full wrapped error ValidateWorkflow has always returned.
	err error
}

// maxIssueValueLen caps how much of a caller-supplied value an issue message echoes.
const maxIssueValueLen = 64

func truncateIssueValue(v string) string {
	if len(v) <= maxIssueValueLen {
		return v
	}
	cut := maxIssueValueLen
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "..."
}

// ValidateWorkflow validates a workflow definition and returns the first issue.
func (p *Parser) ValidateWorkflow(workflow Workflow) error {
	issues := p.ValidateWorkflowDetailed(workflow)
	if len(issues) == 0 {
		return nil
	}
	return issues[0].err
}

// ValidateWorkflowDetailed validates a workflow definition and returns every
// issue found, in the order ValidateWorkflow would have reported them.
func (p *Parser) ValidateWorkflowDetailed(workflow Workflow) []ValidationIssue {
	var issues []ValidationIssue
	add := func(path, stepName string, err error) {
		issues = append(issues, ValidationIssue{Path: path, StepName: stepName, Message: err.Error(), err: err})
	}

	if workflow.Name == "" {
		add("name", "", fmt.Errorf("workflow name is required"))
	}
	if len(workflow.Steps) == 0 {
		add("steps", "", fmt.Errorf("workflow must have at least one step"))
	}
	if err := ValidateInputSpecs(workflow.Inputs); err != nil {
		add("inputs", "", err)
	}

	stepNames := make(map[string]bool)
	for i, step := range workflow.Steps {
		path := fmt.Sprintf("steps[%d]", i)
		// Approval gates are resumed by replaying the top-level step list, so a
		// gate inside any other block is rejected rather than silently accepted.
		// Checked first so it is reported whatever the enclosing step's type.
		collectNestedApprovals(step, path, func(nestedPath, name string) {
			err := &nestedApprovalError{step: truncateIssueValue(name)}
			issues = append(issues, ValidationIssue{
				Path: nestedPath, StepName: truncateIssueValue(name), Message: err.Error(),
				err: fmt.Errorf("step validation failed: %w", err),
			})
		})
		p.collectStepIssues(step, path, 0, stepNames, &issues)
	}

	if workflow.Timeout < 0 {
		add("timeout", "", fmt.Errorf("workflow timeout cannot be negative"))
	}
	if workflow.OnFailure != "" && !isValidFailureAction(workflow.OnFailure) {
		add("on_failure", "", fmt.Errorf("invalid failure action: %s", truncateIssueValue(string(workflow.OnFailure))))
	}

	return issues
}

// collectStepIssues appends every defect of step (and its child steps) to issues.
// depth is the child nesting level, which only shapes the legacy error wrapping.
func (p *Parser) collectStepIssues(step Step, path string, depth int, stepNames map[string]bool, issues *[]ValidationIssue) {
	prefix := "step validation failed: " + strings.Repeat("child step validation failed: ", depth)
	name := truncateIssueValue(step.Name)
	add := func(field string, format string, args ...interface{}) {
		err := fmt.Errorf(format, args...)
		fieldPath := path
		if field != "" {
			fieldPath = path + "." + field
		}
		*issues = append(*issues, ValidationIssue{
			Path: fieldPath, StepName: name, Message: err.Error(),
			err: fmt.Errorf("%s%w", prefix, err),
		})
	}

	if step.Name == "" {
		add("name", "step name is required")
	} else if stepNames[step.Name] {
		add("name", "duplicate step name: %s", name)
	}
	stepNames[step.Name] = true

	if !isValidStepType(step.Type) {
		add("type", "invalid step type: %s", truncateIssueValue(string(step.Type)))
	}

	switch step.Type {
	case StepTypeTask:
		if step.Module == "" {
			add("module", "module is required for task steps")
		}
		if step.Config == nil {
			add("config", "config is required for task steps")
		}
	case StepTypeSequential, StepTypeParallel:
		if len(step.Steps) == 0 {
			add("steps", "%s steps must have child steps", step.Type)
		}
	case StepTypeApproval:
		switch {
		case step.Approval == nil:
			add("approval", "approval configuration is required for approval steps")
		case step.Approval.Message == "":
			add("approval.message", "message is required for approval steps")
		case step.Approval.Timeout <= 0:
			add("approval.timeout", "timeout must be positive for approval steps")
		}
	case StepTypeNotify:
		switch {
		case step.Notify == nil:
			add("notify", "notify configuration is required for notify steps")
		case step.Notify.URL == "":
			add("notify.url", "url is required for notify steps")
		case step.Notify.Title == "":
			add("notify.title", "title is required for notify steps")
		default:
			switch step.Notify.Severity {
			case "", NotifySeverityInfo, NotifySeverityWarning, NotifySeverityCritical:
			default:
				add("notify.severity", "invalid severity %q for notify steps: must be info, warning or critical", truncateIssueValue(step.Notify.Severity))
			}
		}
	case StepTypeConditional:
		if step.Condition == nil {
			add("condition", "condition is required for conditional steps")
		}
		if len(step.Steps) == 0 {
			add("steps", "conditional steps must have child steps")
		}
	}

	for i, child := range step.Steps {
		p.collectStepIssues(child, fmt.Sprintf("%s.steps[%d]", path, i), depth+1, stepNames, issues)
	}

	if step.Condition != nil {
		if err := p.validateCondition(*step.Condition); err != nil {
			*issues = append(*issues, ValidationIssue{
				Path: path + ".condition", StepName: name, Message: err.Error(),
				err: fmt.Errorf("%scondition validation failed: %w", prefix, err),
			})
		}
	}

	if step.Timeout < 0 {
		add("timeout", "step timeout cannot be negative")
	}

	if step.OnFailure != "" && !isValidFailureAction(step.OnFailure) {
		add("on_failure", "invalid failure action for step %s: %s", name, truncateIssueValue(string(step.OnFailure)))
	}
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

// collectNestedApprovals reports every approval step found inside a child block of
// step (parallel, loop, try, conditional, switch, fallback), with its path.
func collectNestedApprovals(step Step, path string, report func(path, name string)) {
	walk := func(block []Step, blockPath string) {
		for i, child := range block {
			childPath := fmt.Sprintf("%s[%d]", blockPath, i)
			if child.Type == StepTypeApproval {
				report(childPath, child.Name)
			}
			collectNestedApprovals(child, childPath, report)
		}
	}
	walk(step.Steps, path+".steps")
	if step.Try != nil {
		walk(step.Try.Try, path+".try.try")
		walk(step.Try.Finally, path+".try.finally")
		for i, c := range step.Try.Catch {
			walk(c.Steps, fmt.Sprintf("%s.try.catch[%d].steps", path, i))
		}
	}
	if step.Switch != nil {
		walk(step.Switch.Default, path+".switch.default")
		for i, c := range step.Switch.Cases {
			walk(c.Steps, fmt.Sprintf("%s.switch.cases[%d].steps", path, i))
		}
	}
	if step.ErrorHandling != nil && step.ErrorHandling.FallbackStep != nil {
		fb := step.ErrorHandling.FallbackStep
		fbPath := path + ".error_handling.fallback_step"
		if fb.Type == StepTypeApproval {
			report(fbPath, fb.Name)
		}
		collectNestedApprovals(*fb, fbPath, report)
	}
}
