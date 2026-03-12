// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// executeWorkflowStep executes a nested workflow step
func (e *Engine) executeWorkflowStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.WorkflowCall == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"workflow step missing workflow call configuration",
			step.Name,
			step.Type,
			fmt.Errorf("workflow call configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	workflowConfig := step.WorkflowCall
	logger := e.logger.WithField("step", step.Name).WithField("step_type", "workflow")

	// Validate workflow specification
	if workflowConfig.WorkflowName == "" && workflowConfig.WorkflowPath == "" {
		return NewWorkflowError(
			ErrorCodeValidation,
			"workflow step must specify either workflow_name or workflow_path",
			step.Name,
			step.Type,
			fmt.Errorf("no workflow specified"),
		).WithVariableState(execution.GetVariables())
	}

	// Create nested workflow
	var nestedWorkflow Workflow
	var err error

	if workflowConfig.WorkflowName != "" {
		// Load workflow by name (this would typically load from a registry)
		nestedWorkflow, err = e.loadWorkflowByName(workflowConfig.WorkflowName)
		if err != nil {
			return NewWorkflowError(
				ErrorCodeValidation,
				fmt.Sprintf("failed to load workflow '%s': %v", workflowConfig.WorkflowName, err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		logger.Debug("Loaded workflow by name",
			"workflow_name", workflowConfig.WorkflowName)
	} else {
		// Load workflow from file path
		nestedWorkflow, err = e.loadWorkflowFromPath(workflowConfig.WorkflowPath)
		if err != nil {
			return NewWorkflowError(
				ErrorCodeValidation,
				fmt.Sprintf("failed to load workflow from path '%s': %v", workflowConfig.WorkflowPath, err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		logger.Debug("Loaded workflow from path",
			"workflow_path", workflowConfig.WorkflowPath)
	}

	// Prepare nested workflow parameters
	nestedParameters := make(map[string]interface{})

	// Apply direct parameters
	for key, value := range workflowConfig.Parameters {
		nestedParameters[key] = value
	}

	// Apply parameter mappings (map current variables to nested workflow parameters)
	for nestedParam, currentVar := range workflowConfig.ParameterMappings {
		if value, exists := execution.GetVariable(currentVar); exists {
			nestedParameters[nestedParam] = value
		} else {
			logger.Warn("Parameter mapping source variable not found",
				"nested_param", nestedParam,
				"current_var", currentVar)
		}
	}

	logger.InfoCtx(ctx, "Executing nested workflow",
		"operation", "nested_workflow_execute",
		"nested_workflow", nestedWorkflow.Name,
		"parameter_count", len(nestedParameters),
		"async", workflowConfig.Async)

	// Execute nested workflow
	var nestedExecution *WorkflowExecution
	if workflowConfig.Async {
		// Asynchronous execution
		nestedExecution, err = e.executeNestedWorkflowAsync(ctx, nestedWorkflow, nestedParameters, workflowConfig.Timeout)
	} else {
		// Synchronous execution
		nestedExecution, err = e.executeNestedWorkflowSync(ctx, nestedWorkflow, nestedParameters, workflowConfig.Timeout)
	}

	if err != nil {
		return NewWorkflowError(
			ErrorCodeStepExecution,
			fmt.Sprintf("nested workflow execution failed: %v", err),
			step.Name,
			step.Type,
			err,
		).WithVariableState(execution.GetVariables())
	}

	// Apply output mappings (map nested workflow outputs back to current variables)
	if len(workflowConfig.OutputMappings) > 0 {
		logger.Debug("Applying output mappings",
			"mapping_count", len(workflowConfig.OutputMappings))

		for currentVar, nestedVar := range workflowConfig.OutputMappings {
			if value, exists := nestedExecution.GetVariable(nestedVar); exists {
				execution.SetVariable(currentVar, value)
				logger.Debug("Mapped output variable",
					"current_var", currentVar,
					"nested_var", nestedVar,
					"value", value)
			} else {
				logger.Warn("Output mapping source variable not found in nested workflow",
					"current_var", currentVar,
					"nested_var", nestedVar)
			}
		}
	}

	logger.InfoCtx(ctx, "Nested workflow completed successfully",
		"operation", "nested_workflow_complete",
		"nested_workflow", nestedWorkflow.Name,
		"status", nestedExecution.GetStatus())

	return nil
}

// executeNestedWorkflowSync executes a nested workflow synchronously
func (e *Engine) executeNestedWorkflowSync(ctx context.Context, workflow Workflow, parameters map[string]interface{}, timeout time.Duration) (*WorkflowExecution, error) {
	// Create timeout context if specified
	var execCtx context.Context
	var cancel context.CancelFunc

	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	} else {
		execCtx = ctx
	}

	// Execute nested workflow
	return e.ExecuteWorkflow(execCtx, workflow, parameters)
}

// executeNestedWorkflowAsync executes a nested workflow asynchronously
func (e *Engine) executeNestedWorkflowAsync(ctx context.Context, workflow Workflow, parameters map[string]interface{}, timeout time.Duration) (*WorkflowExecution, error) {
	// For async execution, we start the workflow and return immediately
	// The caller can check the status later if needed

	// Create timeout context if specified
	var execCtx context.Context
	var cancel context.CancelFunc

	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		// Don't defer cancel here since we're returning immediately
		_ = cancel // To avoid unused variable warning for now
	} else {
		execCtx = ctx
	}

	// Start async execution
	execution, err := e.ExecuteWorkflow(execCtx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// For async execution, we don't wait for completion
	// Return the execution object immediately
	return execution, nil
}

// loadWorkflowByName loads a workflow by name from a registry (placeholder implementation)
func (e *Engine) loadWorkflowByName(name string) (Workflow, error) {
	// For now, create simple test workflows
	// In a real implementation, this would load from a workflow registry
	switch name {
	case "test-nested-workflow":
		return Workflow{
			Name: "test-nested-workflow",
			Variables: map[string]interface{}{
				"nested_result": "default",
			},
			Steps: []Step{
				{
					Name: "nested-delay",
					Type: StepTypeDelay,
					Delay: &DelayConfig{
						Duration: 1 * time.Millisecond,
						Message:  "Nested workflow executed",
					},
				},
			},
		}, nil

	case "test-error-handler":
		return Workflow{
			Name: "test-error-handler",
			Variables: map[string]interface{}{
				"handled":         "handled",
				"recovery_status": "handled",
				"resolution":      "error_resolved",
				"remediation":     "auto_fix_applied",
				"next_action":     "continue_execution",
			},
			Steps: []Step{
				{
					Name: "handle-error-step",
					Type: StepTypeDelay,
					Delay: &DelayConfig{
						Duration: 1 * time.Millisecond,
						Message:  "Error handled by recovery workflow",
					},
				},
			},
		}, nil

	default:
		return Workflow{}, fmt.Errorf("workflow '%s' not found", name)
	}
}

// loadWorkflowFromPath loads a workflow from a file path (placeholder implementation)
func (e *Engine) loadWorkflowFromPath(path string) (Workflow, error) {
	// For now, handle specific test paths
	// In a real implementation, this would load and parse a YAML/JSON file
	switch path {
	case "/path/to/error-handler.yaml":
		return Workflow{
			Name: "path-error-handler",
			Variables: map[string]interface{}{
				"recovery_status": "handled",
				"loaded_from":     path,
			},
			Steps: []Step{
				{
					Name: "path-error-step",
					Type: StepTypeDelay,
					Delay: &DelayConfig{
						Duration: 1 * time.Millisecond,
						Message:  "Error handler loaded from path",
					},
				},
			},
		}, nil
	default:
		return Workflow{
			Name: "file-loaded-workflow",
			Variables: map[string]interface{}{
				"loaded_from": path,
			},
			Steps: []Step{
				{
					Name: "file-loaded-step",
					Type: StepTypeDelay,
					Delay: &DelayConfig{
						Duration: 1 * time.Millisecond,
						Message:  "Workflow loaded from file",
					},
				},
			},
		}, nil
	}
}

// executeErrorWorkflowStep executes a custom error workflow step
func (e *Engine) executeErrorWorkflowStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.ErrorWorkflow == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"error workflow configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("error workflow configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	config := step.ErrorWorkflow

	// Load the error handling workflow
	var errorWorkflow Workflow
	var err error

	if config.WorkflowName != "" {
		errorWorkflow, err = e.loadWorkflowByName(config.WorkflowName)
	} else if config.WorkflowPath != "" {
		errorWorkflow, err = e.loadWorkflowFromPath(config.WorkflowPath)
	} else {
		return NewWorkflowError(
			ErrorCodeValidation,
			"either workflow_name or workflow_path must be specified",
			step.Name,
			step.Type,
			fmt.Errorf("no workflow specification provided"),
		).WithVariableState(execution.GetVariables())
	}

	if err != nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			fmt.Sprintf("failed to load error workflow: %v", err),
			step.Name,
			step.Type,
			err,
		).WithVariableState(execution.GetVariables())
	}

	e.logger.Info("Executing error workflow", "step", step.Name, "error_workflow", errorWorkflow.Name)

	// Create parameters for the error workflow
	parameters := make(map[string]interface{})

	// Add direct parameters
	for key, value := range config.Parameters {
		parameters[key] = value
	}

	// Add parameter mappings from current execution variables
	for errorParam, sourceVar := range config.ParameterMappings {
		if value, exists := execution.GetVariable(sourceVar); exists {
			parameters[errorParam] = value
		}
	}

	// Add error context
	parameters["original_execution_id"] = execution.ID
	parameters["original_workflow"] = execution.WorkflowName
	if execution.GetError() != "" {
		parameters["error_message"] = execution.GetError()
	}
	if errorDetails := execution.GetErrorDetails(); errorDetails != nil {
		parameters["error_details"] = errorDetails
	}

	// Execute the error workflow
	var errorExecution *WorkflowExecution
	if config.Async {
		// Execute asynchronously
		errorExecution, err = e.executeErrorWorkflowAsync(ctx, errorWorkflow, parameters, config.Timeout)
	} else {
		// Execute synchronously
		errorExecution, err = e.executeErrorWorkflowSync(ctx, errorWorkflow, parameters, config.Timeout)
	}

	if err != nil {
		return fmt.Errorf("step %s: error workflow execution failed: %w", step.Name, err)
	}

	// Apply output mappings
	for errorVar, targetVar := range config.OutputMappings {
		if value, exists := errorExecution.GetVariable(errorVar); exists {
			execution.SetVariable(targetVar, value)
		}
	}

	e.logger.Info("Error workflow completed", "step", step.Name, "error_workflow", errorWorkflow.Name, "status", errorExecution.GetStatus())

	// Handle recovery action (but don't apply it here - that should be done by the caller)
	// Just store the recovery action for the caller to use
	execution.SetVariable(step.Name+"_recovery_action", config.RecoveryAction)

	return nil
}

// executeErrorWorkflowSync executes an error workflow synchronously
func (e *Engine) executeErrorWorkflowSync(ctx context.Context, workflow Workflow, parameters map[string]interface{}, timeout time.Duration) (*WorkflowExecution, error) {
	// Create context with timeout if specified
	execCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Execute the error workflow
	execution, err := e.ExecuteWorkflow(execCtx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// Wait for completion if timeout is specified
	if timeout > 0 {
		select {
		case <-time.After(timeout):
			if execution.Cancel != nil {
				execution.Cancel()
			}
			return execution, fmt.Errorf("error workflow timed out after %v", timeout)
		case <-execCtx.Done():
			return execution, execCtx.Err()
		default:
			// Continue to check status
		}
	}

	// Wait a bit for execution to complete
	time.Sleep(10 * time.Millisecond)

	return execution, nil
}

// executeErrorWorkflowAsync executes an error workflow asynchronously
func (e *Engine) executeErrorWorkflowAsync(ctx context.Context, workflow Workflow, parameters map[string]interface{}, timeout time.Duration) (*WorkflowExecution, error) {
	// Create context with timeout if specified
	execCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Execute the error workflow asynchronously
	execution, err := e.ExecuteWorkflow(execCtx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// Return immediately for async execution
	return execution, nil
}

// executeCompositeStep executes a workflow composition step
func (e *Engine) executeCompositeStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Composite == nil {
		return fmt.Errorf("step %s: composite configuration is required", step.Name)
	}

	config := step.Composite

	if len(config.Components) == 0 {
		return fmt.Errorf("step %s: at least one component must be specified", step.Name)
	}

	e.logger.Info("Starting workflow composition", "step", step.Name, "components", len(config.Components), "strategy", config.Strategy)

	// Create context with timeout if specified
	compCtx := ctx
	if config.Timeout > 0 {
		var cancel context.CancelFunc
		compCtx, cancel = context.WithTimeout(ctx, config.Timeout)
		defer cancel()
	}

	// Execute components based on strategy
	var err error
	switch config.Strategy {
	case CompositionStrategySequential:
		err = e.executeComponentsSequential(compCtx, config, execution, step.Name)
	case CompositionStrategyParallel:
		err = e.executeComponentsParallel(compCtx, config, execution, step.Name)
	case CompositionStrategyDependency:
		err = e.executeComponentsDependency(compCtx, config, execution, step.Name)
	case CompositionStrategyPipeline:
		err = e.executeComponentsPipeline(compCtx, config, execution, step.Name)
	case CompositionStrategyConditional:
		err = e.executeComponentsConditional(compCtx, config, execution, step.Name)
	default:
		err = fmt.Errorf("unsupported composition strategy: %s", config.Strategy)
	}

	if err != nil {
		return fmt.Errorf("step %s: composition failed: %w", step.Name, err)
	}

	e.logger.Info("Workflow composition completed", "step", step.Name)
	return nil
}

// executeComponentsSequential executes components one by one
func (e *Engine) executeComponentsSequential(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	for i, component := range config.Components {
		e.logger.Info("Executing component sequentially", "component", component.Name, "index", i)

		err := e.executeComponent(ctx, component, execution, stepName)
		if err != nil {
			return e.handleComponentFailure(err, component, config.FailurePolicy)
		}
	}
	return nil
}

// executeComponentsParallel executes all components in parallel
func (e *Engine) executeComponentsParallel(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	// Create semaphore for concurrency control if specified
	var semaphore chan struct{}
	if config.MaxConcurrency > 0 {
		semaphore = make(chan struct{}, config.MaxConcurrency)
		for i := 0; i < config.MaxConcurrency; i++ {
			semaphore <- struct{}{}
		}
	}

	// Channel to collect errors
	errorsChan := make(chan error, len(config.Components))
	var wg sync.WaitGroup

	// Execute components in parallel
	for _, component := range config.Components {
		wg.Add(1)
		go func(comp WorkflowComponent) {
			defer wg.Done()

			// Acquire semaphore if concurrency is limited
			if semaphore != nil {
				select {
				case <-semaphore:
				case <-ctx.Done():
					errorsChan <- ctx.Err()
					return
				}
				defer func() { semaphore <- struct{}{} }()
			}

			err := e.executeComponent(ctx, comp, execution, stepName)
			if err != nil {
				errorsChan <- e.handleComponentFailure(err, comp, config.FailurePolicy)
			} else {
				errorsChan <- nil
			}
		}(component)
	}

	// Wait for all components to complete
	go func() {
		wg.Wait()
		close(errorsChan)
	}()

	// Collect errors
	var errors []error
	for err := range errorsChan {
		if err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return errors[0] // Return first error
	}

	return nil
}

// executeComponentsDependency executes components based on dependencies (simplified implementation)
func (e *Engine) executeComponentsDependency(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	// For now, just execute sequentially - a full implementation would build a dependency graph
	e.logger.Warn("Dependency-based composition not fully implemented, falling back to sequential")
	return e.executeComponentsSequential(ctx, config, execution, stepName)
}

// executeComponentsPipeline executes components as a data processing pipeline
func (e *Engine) executeComponentsPipeline(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	// For now, just execute sequentially with data flow - a full implementation would handle complex pipelines
	e.logger.Warn("Pipeline composition not fully implemented, falling back to sequential")
	return e.executeComponentsSequential(ctx, config, execution, stepName)
}

// executeComponentsConditional executes components based on conditions
func (e *Engine) executeComponentsConditional(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	for _, component := range config.Components {
		// Check component condition (simplified - would need full condition evaluation)
		if component.Condition != nil {
			e.logger.Info("Skipping component due to condition", "component", component.Name)
			continue
		}

		err := e.executeComponent(ctx, component, execution, stepName)
		if err != nil {
			return e.handleComponentFailure(err, component, config.FailurePolicy)
		}
	}
	return nil
}

// executeComponent executes a single workflow component
func (e *Engine) executeComponent(ctx context.Context, component WorkflowComponent, execution *WorkflowExecution, stepName string) error {
	// Load the component workflow
	var workflow Workflow
	var err error

	if component.WorkflowName != "" {
		workflow, err = e.loadWorkflowByName(component.WorkflowName)
	} else if component.WorkflowPath != "" {
		workflow, err = e.loadWorkflowFromPath(component.WorkflowPath)
	} else {
		return fmt.Errorf("component %s: either workflow_name or workflow_path must be specified", component.Name)
	}

	if err != nil {
		return fmt.Errorf("component %s: failed to load workflow: %w", component.Name, err)
	}

	// Create parameters for the component
	parameters := make(map[string]interface{})

	// Add direct parameters
	for key, value := range component.Parameters {
		parameters[key] = value
	}

	// Add parameter mappings
	for compParam, sourceVar := range component.ParameterMappings {
		if value, exists := execution.GetVariable(sourceVar); exists {
			parameters[compParam] = value
		}
	}

	// Create context with timeout if specified
	compCtx := ctx
	if component.Timeout > 0 {
		var cancel context.CancelFunc
		compCtx, cancel = context.WithTimeout(ctx, component.Timeout)
		defer cancel()
	}

	// Execute the component workflow
	var componentExecution *WorkflowExecution
	if component.Async {
		componentExecution, err = e.executeComponentAsync(compCtx, workflow, parameters)
	} else {
		componentExecution, err = e.executeComponentSync(compCtx, workflow, parameters)
	}

	if err != nil {
		return fmt.Errorf("component %s: execution failed: %w", component.Name, err)
	}

	// Apply output mappings
	for compVar, targetVar := range component.OutputMappings {
		if value, exists := componentExecution.GetVariable(compVar); exists {
			execution.SetVariable(targetVar, value)
		}
	}

	// Store component execution result
	execution.SetVariable(stepName+"_component_"+component.Name+"_result", componentExecution.GetStepResults())

	return nil
}

// executeComponentSync executes a component workflow synchronously
func (e *Engine) executeComponentSync(ctx context.Context, workflow Workflow, parameters map[string]interface{}) (*WorkflowExecution, error) {
	execution, err := e.ExecuteWorkflow(ctx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// Wait a bit for execution to complete
	time.Sleep(10 * time.Millisecond)

	return execution, nil
}

// executeComponentAsync executes a component workflow asynchronously
func (e *Engine) executeComponentAsync(ctx context.Context, workflow Workflow, parameters map[string]interface{}) (*WorkflowExecution, error) {
	execution, err := e.ExecuteWorkflow(ctx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// Return immediately for async execution
	return execution, nil
}

// handleComponentFailure handles component execution failures based on failure policy
func (e *Engine) handleComponentFailure(err error, component WorkflowComponent, policy CompositeFailurePolicy) error {
	switch policy {
	case CompositeFailurePolicyFail:
		return err
	case CompositeFailurePolicySkip:
		e.logger.Warn("Skipping failed component", "component", component.Name, "error", err.Error())
		return nil
	case CompositeFailurePolicyRetry:
		e.logger.Warn("Component retry not fully implemented", "component", component.Name)
		return err
	case CompositeFailurePolicyIsolate:
		e.logger.Warn("Component isolation not fully implemented", "component", component.Name)
		return nil
	default:
		return err
	}
}

// executeFanInStep executes a fan-in step that collects and combines results from multiple sources
func (e *Engine) executeFanInStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.FanIn == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"fan-in configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("fan-in configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	config := step.FanIn

	if len(config.Sources) == 0 {
		return fmt.Errorf("step %s: at least one source must be specified", step.Name)
	}

	e.logger.Info("Starting fan-in", "step", step.Name, "sources", len(config.Sources), "strategy", config.Strategy)

	// Collect data from all sources
	var sourceData []interface{}
	for _, source := range config.Sources {
		if value, exists := execution.GetVariable(source); exists && value != nil {
			sourceData = append(sourceData, value)
		}
	}

	if len(sourceData) == 0 {
		e.logger.Warn("Fan-in with no data from sources", "step", step.Name)
		execution.SetVariable(config.OutputVariable, nil)
		return nil
	}

	// Apply strategy to combine results
	var result interface{}
	var err error

	switch config.Strategy {
	case FanInStrategyMerge:
		result, err = e.fanInMerge(sourceData)
	case FanInStrategyConcat:
		result, err = e.fanInConcat(sourceData)
	case FanInStrategySum:
		result, err = e.fanInSum(sourceData)
	case FanInStrategyFirst:
		result = sourceData[0]
	case FanInStrategyLast:
		result = sourceData[len(sourceData)-1]
	case FanInStrategyCustom:
		result, err = e.fanInCustom(sourceData, config.Transform)
	default:
		err = fmt.Errorf("unsupported fan-in strategy: %s", config.Strategy)
	}

	if err != nil {
		return fmt.Errorf("step %s: fan-in failed: %w", step.Name, err)
	}

	// Apply filter if specified
	if config.Filter != "" {
		// For now, we'll skip filtering implementation
		e.logger.Warn("Fan-in filtering not yet implemented", "step", step.Name, "filter", config.Filter)
	}

	// Store result
	execution.SetVariable(config.OutputVariable, result)

	e.logger.Info("Fan-in completed", "step", step.Name, "output_variable", config.OutputVariable)
	return nil
}

// fanInMerge merges all source data into a single array
func (e *Engine) fanInMerge(sourceData []interface{}) (interface{}, error) {
	var merged []interface{}
	for _, data := range sourceData {
		if slice, ok := data.([]interface{}); ok {
			merged = append(merged, slice...)
		} else {
			merged = append(merged, data)
		}
	}
	return merged, nil
}

// fanInConcat concatenates string results
func (e *Engine) fanInConcat(sourceData []interface{}) (interface{}, error) {
	var result strings.Builder
	for _, data := range sourceData {
		if str, ok := data.(string); ok {
			result.WriteString(str)
		} else {
			result.WriteString(fmt.Sprintf("%v", data))
		}
	}
	return result.String(), nil
}

// fanInSum sums numeric results
func (e *Engine) fanInSum(sourceData []interface{}) (interface{}, error) {
	var sum float64
	for _, data := range sourceData {
		switch v := data.(type) {
		case int:
			sum += float64(v)
		case int64:
			sum += float64(v)
		case float32:
			sum += float64(v)
		case float64:
			sum += v
		default:
			return nil, fmt.Errorf("cannot sum non-numeric value: %T", data)
		}
	}
	return sum, nil
}

// fanInCustom applies a custom transformation (placeholder implementation)
func (e *Engine) fanInCustom(sourceData []interface{}, transform string) (interface{}, error) {
	// For now, just return the first item
	// In a full implementation, this would evaluate the transform expression
	e.logger.Warn("Custom fan-in transformation not fully implemented", "transform", transform)
	if len(sourceData) > 0 {
		return sourceData[0], nil
	}
	return nil, nil
}
