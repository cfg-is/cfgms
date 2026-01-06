// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package transform provides extensible data transformation capabilities for workflows
//
// This package implements a plugin-based data transformation framework that allows
// workflows to process, validate, and transform data between different systems and formats.
//
// The framework is designed for extensibility - new transforms can be easily added
// without modifying core code by implementing the Transform interface and registering
// with the TransformRegistry.
//
// Key Components:
//   - Transform: Core interface that all transforms must implement
//   - TransformRegistry: Auto-discovery and registration system for transforms
//   - TransformContext: Execution context with data, variables, and metadata
//   - TransformExecutor: Execution engine that orchestrates transform operations
//
// Example transform implementation:
//
//	type UppercaseTransform struct {
//		BaseTransform
//	}
//
//	func (t *UppercaseTransform) Execute(ctx TransformContext) (TransformResult, error) {
//		input := ctx.GetString("input")
//		return TransformResult{
//			Data: map[string]interface{}{
//				"output": strings.ToUpper(input),
//			},
//			Success: true,
//		}, nil
//	}
//
// Built-in transform categories:
//   - String transforms: uppercase, lowercase, trim, format, etc.
//   - Data parsing: JSON, XML, YAML, CSV parsing and generation
//   - Path operations: JSONPath and XPath queries
//   - Schema validation: JSON Schema validation
//   - Format conversion: Between JSON, XML, YAML, CSV
//   - Math operations: arithmetic, aggregation, filtering
//   - Template processing: Go template engine for dynamic content
package transform

import (
	"context"
	"time"
)

// Transform defines the core interface that all data transforms must implement
//
// This interface provides a consistent way to execute data transformations
// while allowing for complete flexibility in implementation. Each transform
// receives a TransformContext with input data and workflow variables, and
// returns a TransformResult with the transformed data.
type Transform interface {
	// Execute performs the data transformation
	Execute(ctx context.Context, transformCtx TransformContext) (TransformResult, error)

	// GetMetadata returns information about this transform
	GetMetadata() TransformMetadata

	// Validate validates the transform configuration and input data
	Validate(config map[string]interface{}) error

	// GetSchema returns the expected input/output schema for this transform
	GetSchema() TransformSchema
}

// TransformMetadata provides information about a transform for discovery and documentation
type TransformMetadata struct {
	// Name is the unique identifier for this transform
	Name string `json:"name"`

	// Version is the transform version for compatibility tracking
	Version string `json:"version"`

	// Description provides human-readable documentation
	Description string `json:"description"`

	// Category groups related transforms together
	Category TransformCategory `json:"category"`

	// Tags provide additional searchable metadata
	Tags []string `json:"tags,omitempty"`

	// Author information for custom transforms
	Author string `json:"author,omitempty"`

	// Documentation URL for detailed usage information
	DocumentationURL string `json:"documentation_url,omitempty"`

	// Examples provide usage examples
	Examples []TransformExample `json:"examples,omitempty"`

	// SupportsChaining indicates if this transform can be chained with others
	SupportsChaining bool `json:"supports_chaining"`

	// RequiredCapabilities lists any special capabilities needed
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
}

// TransformCategory defines categories for organizing transforms
type TransformCategory string

const (
	// CategoryString for string manipulation transforms
	CategoryString TransformCategory = "string"

	// CategoryData for data parsing and generation transforms
	CategoryData TransformCategory = "data"

	// CategoryPath for path-based data extraction transforms
	CategoryPath TransformCategory = "path"

	// CategoryValidation for data validation and schema transforms
	CategoryValidation TransformCategory = "validation"

	// CategoryConversion for format conversion transforms
	CategoryConversion TransformCategory = "conversion"

	// CategoryMath for mathematical and aggregation transforms
	CategoryMath TransformCategory = "math"

	// CategoryTemplate for template processing transforms
	CategoryTemplate TransformCategory = "template"

	// CategoryCustom for user-defined custom transforms
	CategoryCustom TransformCategory = "custom"

	// CategoryTest for test transforms
	CategoryTest TransformCategory = "test"

	// CategoryUtility for utility and helper transforms
	CategoryUtility TransformCategory = "utility"
)

// TransformExample provides usage examples for transforms
type TransformExample struct {
	// Name is a descriptive name for this example
	Name string `json:"name"`

	// Description explains what this example demonstrates
	Description string `json:"description"`

	// Input shows example input data
	Input map[string]interface{} `json:"input"`

	// Config shows example configuration
	Config map[string]interface{} `json:"config"`

	// Output shows expected output data
	Output map[string]interface{} `json:"output"`
}

// TransformSchema defines the expected input and output schema for a transform
type TransformSchema struct {
	// InputSchema defines the expected input data structure
	InputSchema SchemaDefinition `json:"input_schema"`

	// OutputSchema defines the expected output data structure
	OutputSchema SchemaDefinition `json:"output_schema"`

	// ConfigSchema defines the expected configuration structure
	ConfigSchema SchemaDefinition `json:"config_schema"`
}

// SchemaDefinition defines a data schema using JSON Schema-like structure
type SchemaDefinition struct {
	// Type defines the data type (string, number, object, array, boolean)
	Type string `json:"type"`

	// Properties defines object properties (for type: object)
	Properties map[string]SchemaDefinition `json:"properties,omitempty"`

	// Items defines array item schema (for type: array)
	Items *SchemaDefinition `json:"items,omitempty"`

	// Required lists required properties (for type: object)
	Required []string `json:"required,omitempty"`

	// Description provides human-readable documentation
	Description string `json:"description,omitempty"`

	// Examples provide example values
	Examples []interface{} `json:"examples,omitempty"`

	// Format provides additional format constraints (e.g., "email", "uri")
	Format string `json:"format,omitempty"`

	// Pattern provides regex pattern for string validation
	Pattern string `json:"pattern,omitempty"`

	// Minimum/Maximum for numeric validation
	Minimum *float64 `json:"minimum,omitempty"`
	Maximum *float64 `json:"maximum,omitempty"`

	// MinLength/MaxLength for string/array validation
	MinLength *int `json:"min_length,omitempty"`
	MaxLength *int `json:"max_length,omitempty"`

	// Enum provides allowed values
	Enum []interface{} `json:"enum,omitempty"`
}

// TransformContext provides execution context and data access for transforms
//
// This context provides transforms with access to:
//   - Input data from the current step
//   - Workflow variables from all previous steps
//   - Execution metadata and configuration
//   - Helper methods for data access and type conversion
type TransformContext interface {
	// GetData returns the input data for this transform
	GetData() map[string]interface{}

	// GetVariables returns all workflow variables
	GetVariables() map[string]interface{}

	// GetConfig returns the transform configuration
	GetConfig() map[string]interface{}

	// GetExecutionID returns the workflow execution ID
	GetExecutionID() string

	// GetStepName returns the current step name
	GetStepName() string

	// GetWorkflowName returns the workflow name
	GetWorkflowName() string

	// Helper methods for type-safe data access
	GetString(key string) string
	GetInt(key string) int
	GetFloat(key string) float64
	GetBool(key string) bool
	GetArray(key string) []interface{}
	GetMap(key string) map[string]interface{}

	// Helper methods for type-safe variable access
	GetVariable(key string) (interface{}, bool)
	GetVariableString(key string) string
	GetVariableInt(key string) int
	GetVariableFloat(key string) float64
	GetVariableBool(key string) bool

	// Helper methods for type-safe config access
	GetConfigString(key string) string
	GetConfigInt(key string) int
	GetConfigFloat(key string) float64
	GetConfigBool(key string) bool
	GetConfigArray(key string) []interface{}
	GetConfigMap(key string) map[string]interface{}

	// SetTemporaryVariable sets a variable for use in subsequent transforms
	SetTemporaryVariable(key string, value interface{})

	// GetTemporaryVariable gets a temporary variable set by a previous transform
	GetTemporaryVariable(key string) (interface{}, bool)

	// Logger provides access to the workflow logger
	GetLogger() TransformLogger

	// GetTenant returns the tenant context
	GetTenant() string

	// GetMetadata returns additional execution metadata
	GetMetadata() map[string]interface{}
}

// TransformResult contains the output of a transform execution
type TransformResult struct {
	// Data contains the transformed output data
	Data map[string]interface{} `json:"data"`

	// Success indicates whether the transform executed successfully
	Success bool `json:"success"`

	// Error contains error information if execution failed
	Error string `json:"error,omitempty"`

	// Warnings contains non-fatal warnings from the transformation
	Warnings []string `json:"warnings,omitempty"`

	// Metadata provides additional information about the transformation
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Duration tracks how long the transform took to execute
	Duration time.Duration `json:"duration"`

	// TransformName records which transform produced this result
	TransformName string `json:"transform_name"`

	// CacheKey provides a key for caching this result (optional)
	CacheKey string `json:"cache_key,omitempty"`

	// CacheTTL defines how long this result should be cached
	CacheTTL time.Duration `json:"cache_ttl,omitempty"`
}

// TransformLogger provides logging capabilities for transforms
type TransformLogger interface {
	// Debug logs debug-level messages
	Debug(msg string, fields ...interface{})

	// Info logs info-level messages
	Info(msg string, fields ...interface{})

	// Warn logs warning-level messages
	Warn(msg string, fields ...interface{})

	// Error logs error-level messages
	Error(msg string, fields ...interface{})

	// WithField returns a logger with additional context field
	WithField(key string, value interface{}) TransformLogger

	// WithFields returns a logger with additional context fields
	WithFields(fields map[string]interface{}) TransformLogger

	// LogExecution logs the completion of a transform execution
	LogExecution(transformName string, duration time.Duration, success bool, err error)

	// LogChainExecution logs the completion of a transform chain execution
	LogChainExecution(chainLength int, totalDuration time.Duration, success bool, err error)
}

// BaseTransform provides common functionality for transform implementations
//
// Transform developers can embed this struct to get default implementations
// of common methods and focus on the core Execute logic.
type BaseTransform struct {
	metadata TransformMetadata
	schema   TransformSchema
}

// GetMetadata returns the transform metadata
func (bt *BaseTransform) GetMetadata() TransformMetadata {
	return bt.metadata
}

// GetSchema returns the transform schema
func (bt *BaseTransform) GetSchema() TransformSchema {
	return bt.schema
}

// Validate provides basic validation (can be overridden)
func (bt *BaseTransform) Validate(config map[string]interface{}) error {
	// Default implementation performs basic schema validation
	// Individual transforms can override this for custom validation
	return nil
}

// SetMetadata allows setting metadata during transform initialization
func (bt *BaseTransform) SetMetadata(metadata TransformMetadata) {
	bt.metadata = metadata
}

// SetSchema allows setting schema during transform initialization
func (bt *BaseTransform) SetSchema(schema TransformSchema) {
	bt.schema = schema
}

// TransformRegistry defines the interface for transform discovery and registration
type TransformRegistry interface {
	// Register adds a transform to the registry
	Register(transform Transform) error

	// Get retrieves a transform by name
	Get(name string) (Transform, error)

	// List returns all registered transforms
	List() []Transform

	// ListByCategory returns transforms in a specific category
	ListByCategory(category TransformCategory) []Transform

	// Search finds transforms matching criteria
	Search(criteria SearchCriteria) []Transform

	// Unregister removes a transform from the registry (primarily for testing)
	Unregister(name string) error

	// GetMetadata returns metadata for all registered transforms
	GetMetadata() []TransformMetadata

	// Validate validates that all registered transforms are properly configured
	Validate() error
}

// SearchCriteria defines criteria for searching transforms
type SearchCriteria struct {
	// Category filters by transform category
	Category TransformCategory `json:"category,omitempty"`

	// Tags filters by tags (any of these tags)
	Tags []string `json:"tags,omitempty"`

	// Name filters by name (substring match)
	Name string `json:"name,omitempty"`

	// Description filters by description (substring match)
	Description string `json:"description,omitempty"`

	// Author filters by author
	Author string `json:"author,omitempty"`

	// RequiredCapabilities filters by required capabilities
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`

	// SupportsChaining filters by chaining support
	SupportsChaining *bool `json:"supports_chaining,omitempty"`
}

// TransformExecutor defines the interface for executing transform operations
type TransformExecutor interface {
	// Execute runs a single transform
	Execute(ctx context.Context, transformName string, config map[string]interface{}, data map[string]interface{}, variables map[string]interface{}) (TransformResult, error)

	// ExecuteChain runs a sequence of transforms
	ExecuteChain(ctx context.Context, chain []TransformStep, data map[string]interface{}, variables map[string]interface{}) (TransformResult, error)

	// Validate validates a transform configuration
	Validate(transformName string, config map[string]interface{}) error

	// GetTransformMetadata returns metadata for a specific transform
	GetTransformMetadata(transformName string) (TransformMetadata, error)

	// ListAvailableTransforms returns all available transforms
	ListAvailableTransforms() []TransformMetadata
}

// TransformStep defines a single step in a transform chain
type TransformStep struct {
	// Name is the transform name to execute
	Name string `json:"name"`

	// Config provides configuration for this transform
	Config map[string]interface{} `json:"config,omitempty"`

	// InputMapping defines how to map data for this transform
	InputMapping map[string]string `json:"input_mapping,omitempty"`

	// OutputMapping defines how to map output from this transform
	OutputMapping map[string]string `json:"output_mapping,omitempty"`

	// Condition defines when this transform should execute
	Condition string `json:"condition,omitempty"`

	// OnError defines error handling behavior
	OnError TransformErrorAction `json:"on_error,omitempty"`

	// CacheKey provides a key for caching this step's result
	CacheKey string `json:"cache_key,omitempty"`

	// CacheTTL defines how long to cache this step's result
	CacheTTL time.Duration `json:"cache_ttl,omitempty"`
}

// TransformErrorAction defines how to handle errors in transform chains
type TransformErrorAction string

const (
	// ErrorActionStop stops the entire chain on error
	ErrorActionStop TransformErrorAction = "stop"

	// ErrorActionContinue continues with the next transform on error
	ErrorActionContinue TransformErrorAction = "continue"

	// ErrorActionSkip skips the rest of the chain on error
	ErrorActionSkip TransformErrorAction = "skip"

	// ErrorActionRetry retries the failed transform
	ErrorActionRetry TransformErrorAction = "retry"
)

// TransformCache defines the interface for caching transform results
type TransformCache interface {
	// Get retrieves a cached result
	Get(key string) (TransformResult, bool)

	// Set stores a result in cache
	Set(key string, result TransformResult, ttl time.Duration)

	// Delete removes a cached result
	Delete(key string)

	// Clear removes all cached results
	Clear()

	// Stats returns cache statistics
	Stats() TransformCacheStats
}

// TransformCacheStats provides cache performance statistics
type TransformCacheStats struct {
	// HitCount is the number of cache hits
	HitCount int64 `json:"hit_count"`

	// MissCount is the number of cache misses
	MissCount int64 `json:"miss_count"`

	// HitRatio is the cache hit ratio (0.0 to 1.0)
	HitRatio float64 `json:"hit_ratio"`

	// Size is the current number of cached items
	Size int64 `json:"size"`

	// MemoryUsage is the estimated memory usage in bytes
	MemoryUsage int64 `json:"memory_usage"`
}
