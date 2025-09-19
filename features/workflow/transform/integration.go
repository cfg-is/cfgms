package transform

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/workflow"
)

// Integration with the existing workflow system

// TransformConfig defines configuration for transform workflow steps
type TransformConfig struct {
	// Transform specifies the transform name to execute
	Transform string `yaml:"transform" json:"transform"`

	// Config provides configuration for the transform
	Config map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`

	// Chain defines a sequence of transforms to execute
	Chain []TransformStep `yaml:"chain,omitempty" json:"chain,omitempty"`

	// InputMapping defines how to map workflow variables to transform input
	InputMapping map[string]string `yaml:"input_mapping,omitempty" json:"input_mapping,omitempty"`

	// OutputMapping defines how to map transform output to workflow variables
	OutputMapping map[string]string `yaml:"output_mapping,omitempty" json:"output_mapping,omitempty"`

	// CacheEnabled controls whether to cache the transform result
	CacheEnabled bool `yaml:"cache_enabled,omitempty" json:"cache_enabled,omitempty"`

	// CacheTTL defines how long to cache the result
	CacheTTL time.Duration `yaml:"cache_ttl,omitempty" json:"cache_ttl,omitempty"`

	// OnError defines error handling behavior
	OnError TransformErrorAction `yaml:"on_error,omitempty" json:"on_error,omitempty"`

	// Timeout defines maximum execution time for the transform
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// WorkflowTransformExecutor integrates transform execution into workflow steps
//
// This executor bridges the transform framework with the existing workflow system,
// allowing transforms to be executed as regular workflow steps while maintaining
// full access to workflow context and variables.
type WorkflowTransformExecutor struct {
	// executor is the core transform executor
	executor TransformExecutor

	// registry provides access to available transforms
	registry TransformRegistry

	// logger provides logging capabilities
	logger TransformLogger
}

// NewWorkflowTransformExecutor creates a new workflow transform executor
func NewWorkflowTransformExecutor(executor TransformExecutor, registry TransformRegistry, logger TransformLogger) *WorkflowTransformExecutor {
	return &WorkflowTransformExecutor{
		executor: executor,
		registry: registry,
		logger:   logger,
	}
}

// ExecuteTransformStep executes a transform as part of a workflow step
//
// This method integrates with the existing workflow execution engine and
// provides the transform with full access to workflow context, variables,
// and step configuration.
func (e *WorkflowTransformExecutor) ExecuteTransformStep(ctx context.Context, step workflow.Step, execution *workflow.WorkflowExecution) (workflow.StepResult, error) {
	startTime := time.Now()

	// Extract transform configuration
	transformConfig, err := e.extractTransformConfig(step)
	if err != nil {
		return workflow.StepResult{
			Status:       workflow.StatusFailed,
			StartTime:    startTime,
			Error:        fmt.Sprintf("Invalid transform configuration: %v", err),
			ErrorDetails: e.createWorkflowError(workflow.ErrorCodeValidation, err.Error(), step.Name),
		}, err
	}

	// Apply timeout if specified
	stepCtx := ctx
	if transformConfig.Timeout > 0 {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithTimeout(ctx, transformConfig.Timeout)
		defer cancel()
	}

	// Get workflow variables
	variables := execution.GetVariables()

	// Apply input mapping to create transform input data
	inputData := e.applyInputMapping(transformConfig.InputMapping, variables, step.Config)

	// Execute the transform(s)
	var result TransformResult
	if len(transformConfig.Chain) > 0 {
		// Execute transform chain
		result, err = e.executor.ExecuteChain(stepCtx, transformConfig.Chain, inputData, variables)
	} else if transformConfig.Transform != "" {
		// Execute single transform
		result, err = e.executor.Execute(stepCtx, transformConfig.Transform, transformConfig.Config, inputData, variables)
	} else {
		err = fmt.Errorf("either 'transform' or 'chain' must be specified")
	}

	endTime := time.Now()

	// Handle execution errors
	if err != nil {
		errorDetails := e.createWorkflowError(workflow.ErrorCodeStepExecution, err.Error(), step.Name)
		return workflow.StepResult{
			Status:       workflow.StatusFailed,
			StartTime:    startTime,
			EndTime:      &endTime,
			Duration:     endTime.Sub(startTime),
			Error:        err.Error(),
			ErrorDetails: errorDetails,
		}, err
	}

	// Handle transform result errors
	if !result.Success {
		errorDetails := e.createWorkflowError(workflow.ErrorCodeStepExecution, result.Error, step.Name)
		return workflow.StepResult{
			Status:       workflow.StatusFailed,
			StartTime:    startTime,
			EndTime:      &endTime,
			Duration:     endTime.Sub(startTime),
			Error:        result.Error,
			ErrorDetails: errorDetails,
		}, fmt.Errorf("transform execution failed: %s", result.Error)
	}

	// Apply output mapping to update workflow variables
	e.applyOutputMapping(transformConfig.OutputMapping, result.Data, execution)

	// Create successful step result
	stepResult := workflow.StepResult{
		Status:    workflow.StatusCompleted,
		StartTime: startTime,
		EndTime:   &endTime,
		Duration:  endTime.Sub(startTime),
		Output:    result.Data,
	}

	// Add warnings if any
	if len(result.Warnings) > 0 {
		stepResult.Output["warnings"] = result.Warnings
	}

	// Add metadata if any
	if len(result.Metadata) > 0 {
		stepResult.Output["metadata"] = result.Metadata
	}

	return stepResult, nil
}

// ValidateTransformStep validates a transform step configuration
func (e *WorkflowTransformExecutor) ValidateTransformStep(step workflow.Step) error {
	transformConfig, err := e.extractTransformConfig(step)
	if err != nil {
		return fmt.Errorf("invalid transform configuration: %w", err)
	}

	// Validate transform chain or single transform
	if len(transformConfig.Chain) > 0 {
		for i, chainStep := range transformConfig.Chain {
			if err := e.executor.Validate(chainStep.Name, chainStep.Config); err != nil {
				return fmt.Errorf("chain step %d (%s) validation failed: %w", i+1, chainStep.Name, err)
			}
		}
	} else if transformConfig.Transform != "" {
		if err := e.executor.Validate(transformConfig.Transform, transformConfig.Config); err != nil {
			return fmt.Errorf("transform %s validation failed: %w", transformConfig.Transform, err)
		}
	} else {
		return fmt.Errorf("either 'transform' or 'chain' must be specified")
	}

	return nil
}

// GetAvailableTransforms returns all available transforms for workflow configuration
func (e *WorkflowTransformExecutor) GetAvailableTransforms() []TransformMetadata {
	return e.executor.ListAvailableTransforms()
}

// extractTransformConfig extracts transform configuration from a workflow step
func (e *WorkflowTransformExecutor) extractTransformConfig(step workflow.Step) (*TransformConfig, error) {
	if step.Config == nil {
		return nil, fmt.Errorf("step configuration is required for transform steps")
	}

	config := &TransformConfig{
		OnError: ErrorActionStop, // Default error action
	}

	// Extract transform name
	if transformName, exists := step.Config["transform"]; exists {
		if transformStr, ok := transformName.(string); ok {
			config.Transform = transformStr
		} else {
			return nil, fmt.Errorf("transform name must be a string")
		}
	}

	// Extract transform configuration
	if transformConfig, exists := step.Config["config"]; exists {
		if configMap, ok := transformConfig.(map[string]interface{}); ok {
			config.Config = configMap
		} else {
			return nil, fmt.Errorf("transform config must be an object")
		}
	}

	// Extract transform chain
	if chainConfig, exists := step.Config["chain"]; exists {
		if chainSlice, ok := chainConfig.([]interface{}); ok {
			for i, chainItem := range chainSlice {
				if chainMap, ok := chainItem.(map[string]interface{}); ok {
					chainStep, err := e.parseTransformStep(chainMap)
					if err != nil {
						return nil, fmt.Errorf("chain step %d: %w", i+1, err)
					}
					config.Chain = append(config.Chain, chainStep)
				} else {
					return nil, fmt.Errorf("chain step %d must be an object", i+1)
				}
			}
		} else {
			return nil, fmt.Errorf("chain must be an array")
		}
	}

	// Extract input mapping
	if inputMapping, exists := step.Config["input_mapping"]; exists {
		if mappingMap, ok := inputMapping.(map[string]interface{}); ok {
			config.InputMapping = make(map[string]string)
			for key, value := range mappingMap {
				if valueStr, ok := value.(string); ok {
					config.InputMapping[key] = valueStr
				} else {
					return nil, fmt.Errorf("input mapping values must be strings")
				}
			}
		} else {
			return nil, fmt.Errorf("input_mapping must be an object")
		}
	}

	// Extract output mapping
	if outputMapping, exists := step.Config["output_mapping"]; exists {
		if mappingMap, ok := outputMapping.(map[string]interface{}); ok {
			config.OutputMapping = make(map[string]string)
			for key, value := range mappingMap {
				if valueStr, ok := value.(string); ok {
					config.OutputMapping[key] = valueStr
				} else {
					return nil, fmt.Errorf("output mapping values must be strings")
				}
			}
		} else {
			return nil, fmt.Errorf("output_mapping must be an object")
		}
	}

	// Extract other configuration options
	if cacheEnabled, exists := step.Config["cache_enabled"]; exists {
		if cacheBool, ok := cacheEnabled.(bool); ok {
			config.CacheEnabled = cacheBool
		}
	}

	if cacheTTL, exists := step.Config["cache_ttl"]; exists {
		if cacheDuration, ok := cacheTTL.(time.Duration); ok {
			config.CacheTTL = cacheDuration
		} else if cacheStr, ok := cacheTTL.(string); ok {
			if duration, err := time.ParseDuration(cacheStr); err == nil {
				config.CacheTTL = duration
			}
		}
	}

	if onError, exists := step.Config["on_error"]; exists {
		if onErrorStr, ok := onError.(string); ok {
			config.OnError = TransformErrorAction(onErrorStr)
		}
	}

	if timeout, exists := step.Config["timeout"]; exists {
		if timeoutDuration, ok := timeout.(time.Duration); ok {
			config.Timeout = timeoutDuration
		} else if timeoutStr, ok := timeout.(string); ok {
			if duration, err := time.ParseDuration(timeoutStr); err == nil {
				config.Timeout = duration
			}
		}
	}

	return config, nil
}

// parseTransformStep parses a transform step from configuration
func (e *WorkflowTransformExecutor) parseTransformStep(stepMap map[string]interface{}) (TransformStep, error) {
	step := TransformStep{}

	// Parse transform name
	if name, exists := stepMap["name"]; exists {
		if nameStr, ok := name.(string); ok {
			step.Name = nameStr
		} else {
			return step, fmt.Errorf("transform name must be a string")
		}
	} else {
		return step, fmt.Errorf("transform name is required")
	}

	// Parse configuration
	if config, exists := stepMap["config"]; exists {
		if configMap, ok := config.(map[string]interface{}); ok {
			step.Config = configMap
		} else {
			return step, fmt.Errorf("config must be an object")
		}
	}

	// Parse input mapping
	if inputMapping, exists := stepMap["input_mapping"]; exists {
		if mappingMap, ok := inputMapping.(map[string]interface{}); ok {
			step.InputMapping = make(map[string]string)
			for key, value := range mappingMap {
				if valueStr, ok := value.(string); ok {
					step.InputMapping[key] = valueStr
				}
			}
		}
	}

	// Parse output mapping
	if outputMapping, exists := stepMap["output_mapping"]; exists {
		if mappingMap, ok := outputMapping.(map[string]interface{}); ok {
			step.OutputMapping = make(map[string]string)
			for key, value := range mappingMap {
				if valueStr, ok := value.(string); ok {
					step.OutputMapping[key] = valueStr
				}
			}
		}
	}

	// Parse condition
	if condition, exists := stepMap["condition"]; exists {
		if conditionStr, ok := condition.(string); ok {
			step.Condition = conditionStr
		}
	}

	// Parse error action
	if onError, exists := stepMap["on_error"]; exists {
		if onErrorStr, ok := onError.(string); ok {
			step.OnError = TransformErrorAction(onErrorStr)
		}
	}

	return step, nil
}

// applyInputMapping applies input mapping to create transform input data
func (e *WorkflowTransformExecutor) applyInputMapping(mapping map[string]string, variables map[string]interface{}, stepConfig map[string]interface{}) map[string]interface{} {
	if len(mapping) == 0 {
		// No mapping specified, use step config as input data
		return stepConfig
	}

	result := make(map[string]interface{})
	for targetKey, sourceKey := range mapping {
		// First try workflow variables
		if value, exists := variables[sourceKey]; exists {
			result[targetKey] = value
		} else if value, exists := stepConfig[sourceKey]; exists {
			// Then try step configuration
			result[targetKey] = value
		}
	}

	return result
}

// applyOutputMapping applies output mapping to update workflow variables
func (e *WorkflowTransformExecutor) applyOutputMapping(mapping map[string]string, outputData map[string]interface{}, execution *workflow.WorkflowExecution) {
	if len(mapping) == 0 {
		// No mapping specified, set all output data as variables
		for key, value := range outputData {
			execution.SetVariable(key, value)
		}
		return
	}

	// Apply specific mapping
	for sourceKey, targetKey := range mapping {
		if value, exists := outputData[sourceKey]; exists {
			execution.SetVariable(targetKey, value)
		}
	}
}

// createWorkflowError creates a workflow error for transform failures
func (e *WorkflowTransformExecutor) createWorkflowError(code workflow.ErrorCode, message, stepName string) *workflow.WorkflowError {
	return &workflow.WorkflowError{
		Code:        code,
		Message:     message,
		Timestamp:   time.Now(),
		StepName:    stepName,
		StepType:    workflow.StepType("transform"),
		Recoverable: code != workflow.ErrorCodeValidation,
	}
}