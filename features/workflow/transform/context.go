// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package transform

import (
	"fmt"
	"reflect"
	"strconv"
	"time"
)

// DefaultTransformContext provides a concrete implementation of TransformContext
//
// This context provides transforms with safe, type-checked access to:
//   - Input data from the current workflow step
//   - Variables from the entire workflow execution
//   - Transform-specific configuration
//   - Execution metadata and logging capabilities
//   - Temporary variables for transform chaining
type DefaultTransformContext struct {
	// data contains the input data for this transform
	data map[string]interface{}

	// variables contains workflow variables
	variables map[string]interface{}

	// config contains transform configuration
	config map[string]interface{}

	// transformName is the name of the transform being executed
	transformName string

	// executionID is the workflow execution ID
	executionID string

	// stepName is the current step name
	stepName string

	// workflowName is the workflow name
	workflowName string

	// tenant is the tenant context
	tenant string

	// temporaryVariables stores temporary variables for transform chaining
	temporaryVariables map[string]interface{}

	// metadata contains additional execution metadata
	metadata map[string]interface{}

	// logger provides logging capabilities
	logger TransformLogger
}

// NewDefaultTransformContext creates a new transform context
func NewDefaultTransformContext(data, variables, config map[string]interface{}) *DefaultTransformContext {
	return &DefaultTransformContext{
		data:               data,
		variables:          variables,
		config:             config,
		temporaryVariables: make(map[string]interface{}),
		metadata:           make(map[string]interface{}),
	}
}

// GetData returns the input data for this transform
func (ctx *DefaultTransformContext) GetData() map[string]interface{} {
	if ctx.data == nil {
		return make(map[string]interface{})
	}
	return ctx.data
}

// GetVariables returns all workflow variables
func (ctx *DefaultTransformContext) GetVariables() map[string]interface{} {
	if ctx.variables == nil {
		return make(map[string]interface{})
	}
	return ctx.variables
}

// GetConfig returns the transform configuration
func (ctx *DefaultTransformContext) GetConfig() map[string]interface{} {
	if ctx.config == nil {
		return make(map[string]interface{})
	}
	return ctx.config
}

// GetExecutionID returns the workflow execution ID
func (ctx *DefaultTransformContext) GetExecutionID() string {
	return ctx.executionID
}

// GetStepName returns the current step name
func (ctx *DefaultTransformContext) GetStepName() string {
	return ctx.stepName
}

// GetWorkflowName returns the workflow name
func (ctx *DefaultTransformContext) GetWorkflowName() string {
	return ctx.workflowName
}

// GetTenant returns the tenant context
func (ctx *DefaultTransformContext) GetTenant() string {
	return ctx.tenant
}

// GetMetadata returns additional execution metadata
func (ctx *DefaultTransformContext) GetMetadata() map[string]interface{} {
	if ctx.metadata == nil {
		return make(map[string]interface{})
	}
	return ctx.metadata
}

// Helper methods for type-safe data access

// GetString safely gets a string value from input data
func (ctx *DefaultTransformContext) GetString(key string) string {
	return ctx.getStringFromMap(ctx.data, key)
}

// GetInt safely gets an int value from input data
func (ctx *DefaultTransformContext) GetInt(key string) int {
	return ctx.getIntFromMap(ctx.data, key)
}

// GetFloat safely gets a float64 value from input data
func (ctx *DefaultTransformContext) GetFloat(key string) float64 {
	return ctx.getFloatFromMap(ctx.data, key)
}

// GetBool safely gets a bool value from input data
func (ctx *DefaultTransformContext) GetBool(key string) bool {
	return ctx.getBoolFromMap(ctx.data, key)
}

// GetArray safely gets an array value from input data
func (ctx *DefaultTransformContext) GetArray(key string) []interface{} {
	return ctx.getArrayFromMap(ctx.data, key)
}

// GetMap safely gets a map value from input data
func (ctx *DefaultTransformContext) GetMap(key string) map[string]interface{} {
	return ctx.getMapFromMap(ctx.data, key)
}

// Helper methods for type-safe variable access

// GetVariable gets a variable value
func (ctx *DefaultTransformContext) GetVariable(key string) (interface{}, bool) {
	if ctx.variables == nil {
		return nil, false
	}
	value, exists := ctx.variables[key]
	return value, exists
}

// GetVariableString safely gets a string variable
func (ctx *DefaultTransformContext) GetVariableString(key string) string {
	return ctx.getStringFromMap(ctx.variables, key)
}

// GetVariableInt safely gets an int variable
func (ctx *DefaultTransformContext) GetVariableInt(key string) int {
	return ctx.getIntFromMap(ctx.variables, key)
}

// GetVariableFloat safely gets a float64 variable
func (ctx *DefaultTransformContext) GetVariableFloat(key string) float64 {
	return ctx.getFloatFromMap(ctx.variables, key)
}

// GetVariableBool safely gets a bool variable
func (ctx *DefaultTransformContext) GetVariableBool(key string) bool {
	return ctx.getBoolFromMap(ctx.variables, key)
}

// Helper methods for type-safe config access

// GetConfigString safely gets a string config value
func (ctx *DefaultTransformContext) GetConfigString(key string) string {
	return ctx.getStringFromMap(ctx.config, key)
}

// GetConfigInt safely gets an int config value
func (ctx *DefaultTransformContext) GetConfigInt(key string) int {
	return ctx.getIntFromMap(ctx.config, key)
}

// GetConfigFloat safely gets a float64 config value
func (ctx *DefaultTransformContext) GetConfigFloat(key string) float64 {
	return ctx.getFloatFromMap(ctx.config, key)
}

// GetConfigBool safely gets a bool config value
func (ctx *DefaultTransformContext) GetConfigBool(key string) bool {
	return ctx.getBoolFromMap(ctx.config, key)
}

// GetConfigArray safely gets an array config value
func (ctx *DefaultTransformContext) GetConfigArray(key string) []interface{} {
	return ctx.getArrayFromMap(ctx.config, key)
}

// GetConfigMap safely gets a map config value
func (ctx *DefaultTransformContext) GetConfigMap(key string) map[string]interface{} {
	return ctx.getMapFromMap(ctx.config, key)
}

// Temporary variable methods for transform chaining

// SetTemporaryVariable sets a variable for use in subsequent transforms
func (ctx *DefaultTransformContext) SetTemporaryVariable(key string, value interface{}) {
	if ctx.temporaryVariables == nil {
		ctx.temporaryVariables = make(map[string]interface{})
	}
	ctx.temporaryVariables[key] = value
}

// GetTemporaryVariable gets a temporary variable set by a previous transform
func (ctx *DefaultTransformContext) GetTemporaryVariable(key string) (interface{}, bool) {
	if ctx.temporaryVariables == nil {
		return nil, false
	}
	value, exists := ctx.temporaryVariables[key]
	return value, exists
}

// GetLogger returns the transform logger
func (ctx *DefaultTransformContext) GetLogger() TransformLogger {
	if ctx.logger == nil {
		// Return a no-op logger if none is set
		return &NoOpTransformLogger{}
	}
	return ctx.logger
}

// SetExecutionMetadata sets execution metadata
func (ctx *DefaultTransformContext) SetExecutionMetadata(executionID, stepName, workflowName, tenant string) {
	ctx.executionID = executionID
	ctx.stepName = stepName
	ctx.workflowName = workflowName
	ctx.tenant = tenant
}

// SetLogger sets the transform logger
func (ctx *DefaultTransformContext) SetLogger(logger TransformLogger) {
	ctx.logger = logger
}

// SetAdditionalMetadata sets additional metadata
func (ctx *DefaultTransformContext) SetAdditionalMetadata(metadata map[string]interface{}) {
	if ctx.metadata == nil {
		ctx.metadata = make(map[string]interface{})
	}
	for k, v := range metadata {
		ctx.metadata[k] = v
	}
}

// Private helper methods for type conversion

// getStringFromMap safely gets a string value from a map
func (ctx *DefaultTransformContext) getStringFromMap(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}

	value, exists := m[key]
	if !exists {
		return ""
	}

	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case []interface{}, []string, []int, map[string]interface{}, map[string]string:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

// getIntFromMap safely gets an int value from a map
func (ctx *DefaultTransformContext) getIntFromMap(m map[string]interface{}, key string) int {
	if m == nil {
		return 0
	}

	value, exists := m[key]
	if !exists {
		return 0
	}

	if value == nil {
		return 0
	}

	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case bool:
		if v {
			return 1
		}
		return 0
	case string:
		// Try integer first
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		// Try float, then convert to int
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return int(f)
		}
		return 0
	default:
		return 0
	}
}

// getFloatFromMap safely gets a float64 value from a map
func (ctx *DefaultTransformContext) getFloatFromMap(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0.0
	}

	value, exists := m[key]
	if !exists {
		return 0.0
	}

	if value == nil {
		return 0.0
	}

	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case bool:
		if v {
			return 1.0
		}
		return 0.0
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
		return 0.0
	default:
		return 0.0
	}
}

// getBoolFromMap safely gets a bool value from a map
func (ctx *DefaultTransformContext) getBoolFromMap(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}

	value, exists := m[key]
	if !exists {
		return false
	}

	switch v := value.(type) {
	case bool:
		return v
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
		// Also support common string representations
		switch v {
		case "yes", "y", "1", "true", "TRUE", "True":
			return true
		case "no", "n", "0", "false", "FALSE", "False":
			return false
		}
		return false
	case int:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0.0
	default:
		return false
	}
}

// getArrayFromMap safely gets an array value from a map
func (ctx *DefaultTransformContext) getArrayFromMap(m map[string]interface{}, key string) []interface{} {
	if m == nil {
		return []interface{}{}
	}

	value, exists := m[key]
	if !exists {
		return []interface{}{}
	}

	// Try direct type assertion first
	if arr, ok := value.([]interface{}); ok {
		return arr
	}

	// Try to convert slice types using reflection
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Slice {
		result := make([]interface{}, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			result[i] = rv.Index(i).Interface()
		}
		return result
	}

	// If it's not an array, return empty array
	return []interface{}{}
}

// getMapFromMap safely gets a map value from a map
func (ctx *DefaultTransformContext) getMapFromMap(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return make(map[string]interface{})
	}

	value, exists := m[key]
	if !exists {
		return make(map[string]interface{})
	}

	if mapValue, ok := value.(map[string]interface{}); ok {
		return mapValue
	}

	// Try to convert other map types using reflection
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Map {
		result := make(map[string]interface{})
		for _, key := range rv.MapKeys() {
			if keyStr := ctx.convertToString(key.Interface()); keyStr != "" {
				result[keyStr] = rv.MapIndex(key).Interface()
			}
		}
		return result
	}

	return make(map[string]interface{})
}

// convertToString converts various types to string
func (ctx *DefaultTransformContext) convertToString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// NoOpTransformLogger provides a no-operation logger implementation
type NoOpTransformLogger struct{}

// Debug logs debug-level messages (no-op)
func (l *NoOpTransformLogger) Debug(msg string, fields ...interface{}) {}

// Info logs info-level messages (no-op)
func (l *NoOpTransformLogger) Info(msg string, fields ...interface{}) {}

// Warn logs warning-level messages (no-op)
func (l *NoOpTransformLogger) Warn(msg string, fields ...interface{}) {}

// Error logs error-level messages (no-op)
func (l *NoOpTransformLogger) Error(msg string, fields ...interface{}) {}

// WithField returns a logger with additional context field (no-op)
func (l *NoOpTransformLogger) WithField(key string, value interface{}) TransformLogger {
	return l
}

// WithFields returns a logger with additional context fields (no-op)
func (l *NoOpTransformLogger) WithFields(fields map[string]interface{}) TransformLogger {
	return l
}

// LogExecution logs the completion of a transform execution (no-op)
func (l *NoOpTransformLogger) LogExecution(transformName string, duration time.Duration, success bool, err error) {
}

// LogChainExecution logs the completion of a transform chain execution (no-op)
func (l *NoOpTransformLogger) LogChainExecution(chainLength int, totalDuration time.Duration, success bool, err error) {
}
