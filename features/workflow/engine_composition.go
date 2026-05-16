// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
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
	} else {
		execCtx = ctx
	}

	// Start async execution
	execution, err := e.ExecuteWorkflow(execCtx, workflow, parameters)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, err
	}

	// Release the timeout context when the execution finishes to avoid leaking resources.
	if cancel != nil {
		go func() {
			<-execution.Done
			cancel()
		}()
	}

	return execution, nil
}

// loadWorkflowByName looks up a workflow by name from the engine's in-memory registry.
func (e *Engine) loadWorkflowByName(name string) (Workflow, error) {
	e.mutex.RLock()
	w, ok := e.workflows[name]
	e.mutex.RUnlock()
	if !ok {
		return Workflow{}, fmt.Errorf("workflow '%s' not found in registry", name)
	}
	return w, nil
}

// loadWorkflowFromPath reads a YAML workflow definition from disk and unmarshals it.
func (e *Engine) loadWorkflowFromPath(path string) (Workflow, error) {
	data, err := os.ReadFile(path) // #nosec G304 - Workflow engine requires loading workflow files from controlled paths
	if err != nil {
		return Workflow{}, fmt.Errorf("failed to read workflow file '%s': %w", path, err)
	}
	var w Workflow
	if err := yaml.Unmarshal(data, &w); err != nil {
		return Workflow{}, fmt.Errorf("failed to parse workflow file '%s': %w", path, err)
	}
	return w, nil
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
	execCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	execution, err := e.ExecuteWorkflow(execCtx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// Block until the workflow goroutine signals completion or the context expires.
	select {
	case <-execution.Done:
		return execution, nil
	case <-execCtx.Done():
		if execution.Cancel != nil {
			execution.Cancel()
		}
		return execution, execCtx.Err()
	}
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

// executeComponentsDependency executes components based on their DependsOn fields.
// It builds a DAG, detects cycles before any component runs, then executes
// independent components in parallel using topological-order scheduling.
func (e *Engine) executeComponentsDependency(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	adjList, inDegree, err := buildDependencyGraph(config.Components)
	if err != nil {
		return err
	}
	if err := detectDependencyCycle(config.Components, adjList); err != nil {
		return err
	}
	return e.executeTopological(ctx, config, execution, stepName, adjList, inDegree)
}

// executeComponentsPipeline executes components sequentially in declaration order,
// threading each component's output into the next via DataFlow mappings.
func (e *Engine) executeComponentsPipeline(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	if len(config.Components) == 0 {
		return nil
	}

	for i, component := range config.Components {
		e.logger.Info("Executing pipeline component", "component", component.Name, "index", i)

		err := e.executeComponent(ctx, component, execution, stepName)
		if err != nil {
			return e.handleComponentFailure(err, component, config.FailurePolicy)
		}

		e.applyDataFlowMappings(config.DataFlow, component.Name, execution)
	}
	return nil
}

// applyDataFlowMappings copies variables from the completed component's outputs into
// the execution context so the next pipeline component can pick them up as inputs.
// Missing source variables are logged as warnings and skipped (non-fatal).
func (e *Engine) applyDataFlowMappings(dataFlow []DataFlowMapping, fromComponent string, execution *WorkflowExecution) {
	for _, mapping := range dataFlow {
		if mapping.FromComponent != fromComponent {
			continue
		}
		value, exists := execution.GetVariable(mapping.FromVariable)
		if !exists {
			e.logger.Warn("DataFlow mapping source variable not found",
				"from_component", mapping.FromComponent,
				"from_variable", mapping.FromVariable,
				"to_component", mapping.ToComponent,
				"to_variable", mapping.ToVariable)
			continue
		}
		execution.SetVariable(mapping.ToVariable, value)
	}
}

// executeComponentsConditional executes components based on conditions
func (e *Engine) executeComponentsConditional(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	for _, component := range config.Components {
		// Design decision: composite conditional execution skips components whose Condition field is set;
		// full expression evaluation is deferred to a future workflow expression engine.
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

	// Block until the workflow goroutine signals completion or the context expires.
	select {
	case <-execution.Done:
		return execution, nil
	case <-ctx.Done():
		return execution, ctx.Err()
	}
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

// buildDependencyGraph returns an adjacency list and in-degree slice for the given components.
// adjList[i] holds the indices of components that list component i in their DependsOn,
// meaning those components become unblocked when component i completes.
// Returns an error if any DependsOn name does not match a component in the slice.
func buildDependencyGraph(components []WorkflowComponent) (adjList [][]int, inDegree []int, err error) {
	n := len(components)
	nameToIdx := make(map[string]int, n)
	for i, c := range components {
		nameToIdx[c.Name] = i
	}

	adjList = make([][]int, n)
	inDegree = make([]int, n)

	for i, c := range components {
		for _, dep := range c.DependsOn {
			depIdx, ok := nameToIdx[dep]
			if !ok {
				return nil, nil, fmt.Errorf("component %q depends on unknown component %q", c.Name, dep)
			}
			adjList[depIdx] = append(adjList[depIdx], i)
			inDegree[i]++
		}
	}
	return adjList, inDegree, nil
}

// detectDependencyCycle runs a DFS over the dependency graph and returns an error
// describing the cycle path if one is found, or nil if the graph is acyclic.
func detectDependencyCycle(components []WorkflowComponent, adjList [][]int) error {
	n := len(components)
	// color: 0=unvisited, 1=in-progress, 2=done
	color := make([]int, n)
	path := make([]int, 0, n)

	var dfs func(u int) error
	dfs = func(u int) error {
		color[u] = 1
		path = append(path, u)
		for _, v := range adjList[u] {
			if color[v] == 1 {
				// Back edge found — locate where the cycle starts in path.
				start := 0
				for start < len(path) && path[start] != v {
					start++
				}
				parts := make([]string, 0, len(path)-start+1)
				for _, idx := range path[start:] {
					parts = append(parts, components[idx].Name)
				}
				parts = append(parts, components[v].Name)
				return fmt.Errorf("dependency cycle detected: %s", strings.Join(parts, " → "))
			}
			if color[v] == 0 {
				if err := dfs(v); err != nil {
					return err
				}
			}
		}
		path = path[:len(path)-1]
		color[u] = 2
		return nil
	}

	for i := 0; i < n; i++ {
		if color[i] == 0 {
			if err := dfs(i); err != nil {
				return err
			}
		}
	}
	return nil
}

// compResult carries the outcome of a single component execution.
type compResult struct {
	idx int
	err error
}

// executeTopological runs components in topological order, dispatching all
// zero-in-degree components in parallel and unlocking dependents as each finishes.
func (e *Engine) executeTopological(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string, adjList [][]int, inDegree []int) error {
	n := len(config.Components)
	if n == 0 {
		return nil
	}

	// Work on a copy so the original slice is not mutated.
	curInDegree := make([]int, n)
	copy(curInDegree, inDegree)

	// Buffer accommodates one result per component so goroutines never block on send.
	resultChan := make(chan compResult, n)

	dispatch := func(idx int) {
		go func(i int) {
			err := e.executeComponent(ctx, config.Components[i], execution, stepName)
			if err != nil {
				err = e.handleComponentFailure(err, config.Components[i], config.FailurePolicy)
			}
			resultChan <- compResult{idx: i, err: err}
		}(idx)
	}

	// Enqueue all components that have no dependencies.
	for i := 0; i < n; i++ {
		if curInDegree[i] == 0 {
			dispatch(i)
		}
	}

	for completed := 0; completed < n; completed++ {
		select {
		case res := <-resultChan:
			if res.err != nil {
				return res.err
			}
			// Unlock dependents whose last dependency just completed.
			for _, next := range adjList[res.idx] {
				curInDegree[next]--
				if curInDegree[next] == 0 {
					dispatch(next)
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
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
		// Design decision: fan-in filter expressions require a predicate evaluator;
		// the filter field is reserved for a future workflow expression engine.
		e.logger.Warn("Fan-in filter expression is reserved for a future expression engine", "step", step.Name, "filter", config.Filter)
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
			fmt.Fprintf(&result, "%v", data)
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

// fanInCustom applies a named transform expression to the collected source data.
// Supported expressions: "first", "last", "count", "join:<sep>" (e.g. "join:,").
func (e *Engine) fanInCustom(sourceData []interface{}, transform string) (interface{}, error) {
	switch {
	case transform == "first":
		if len(sourceData) > 0 {
			return sourceData[0], nil
		}
		return nil, nil
	case transform == "last":
		if len(sourceData) > 0 {
			return sourceData[len(sourceData)-1], nil
		}
		return nil, nil
	case transform == "count":
		return len(sourceData), nil
	case strings.HasPrefix(transform, "join:"):
		sep := strings.TrimPrefix(transform, "join:")
		parts := make([]string, len(sourceData))
		for i, v := range sourceData {
			parts[i] = fmt.Sprintf("%v", v)
		}
		return strings.Join(parts, sep), nil
	default:
		return nil, fmt.Errorf("unsupported custom fan-in transform expression: %q", transform)
	}
}
