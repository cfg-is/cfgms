package transform

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DefaultTransformExecutor provides a robust implementation of TransformExecutor
//
// This executor handles:
//   - Single transform execution with full context
//   - Transform chaining with data flow between steps
//   - Error handling and recovery strategies
//   - Caching for performance optimization
//   - Detailed logging and monitoring
//   - Tenant isolation and security
type DefaultTransformExecutor struct {
	// registry provides access to registered transforms
	registry TransformRegistry

	// cache provides optional result caching
	cache TransformCache

	// logger provides logging capabilities
	logger TransformLogger

	// config contains executor configuration
	config ExecutorConfig

	// stats tracks execution statistics
	stats *ExecutorStats

	// mutex protects concurrent access to stats
	mutex sync.RWMutex
}

// ExecutorConfig defines configuration for the transform executor
type ExecutorConfig struct {
	// EnableCaching controls whether to use result caching
	EnableCaching bool `json:"enable_caching"`

	// DefaultCacheTTL is the default cache TTL for results
	DefaultCacheTTL time.Duration `json:"default_cache_ttl"`

	// MaxChainLength limits the maximum number of transforms in a chain
	MaxChainLength int `json:"max_chain_length"`

	// ExecutionTimeout is the maximum time allowed for any single transform
	ExecutionTimeout time.Duration `json:"execution_timeout"`

	// ChainTimeout is the maximum time allowed for an entire chain
	ChainTimeout time.Duration `json:"chain_timeout"`

	// EnableStrictValidation controls whether to perform strict input validation
	EnableStrictValidation bool `json:"enable_strict_validation"`

	// RetryAttempts is the number of retry attempts for failed transforms
	RetryAttempts int `json:"retry_attempts"`

	// RetryDelay is the delay between retry attempts
	RetryDelay time.Duration `json:"retry_delay"`

	// EnableMetrics controls whether to collect detailed metrics
	EnableMetrics bool `json:"enable_metrics"`
}

// DefaultExecutorConfig returns sensible default configuration
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		EnableCaching:          true,
		DefaultCacheTTL:        5 * time.Minute,
		MaxChainLength:         10,
		ExecutionTimeout:       30 * time.Second,
		ChainTimeout:           5 * time.Minute,
		EnableStrictValidation: true,
		RetryAttempts:          3,
		RetryDelay:             1 * time.Second,
		EnableMetrics:          true,
	}
}

// NewDefaultTransformExecutor creates a new transform executor
func NewDefaultTransformExecutor(registry TransformRegistry, cache TransformCache, logger TransformLogger) *DefaultTransformExecutor {
	return &DefaultTransformExecutor{
		registry: registry,
		cache:    cache,
		logger:   logger,
		config:   DefaultExecutorConfig(),
		stats:    &ExecutorStats{},
	}
}

// SetConfig updates the executor configuration
func (e *DefaultTransformExecutor) SetConfig(config ExecutorConfig) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.config = config
}

// GetConfig returns the current executor configuration
func (e *DefaultTransformExecutor) GetConfig() ExecutorConfig {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.config
}

// Execute runs a single transform
func (e *DefaultTransformExecutor) Execute(ctx context.Context, transformName string, config map[string]interface{}, data map[string]interface{}, variables map[string]interface{}) (TransformResult, error) {
	startTime := time.Now()

	// Update stats
	if e.config.EnableMetrics {
		e.updateStats(func(stats *ExecutorStats) {
			stats.TotalExecutions++
		})
	}

	// Get the transform
	transform, err := e.registry.Get(transformName)
	if err != nil {
		result := TransformResult{
			Success:       false,
			Error:         fmt.Sprintf("Transform not found: %v", err),
			Duration:      time.Since(startTime),
			TransformName: transformName,
		}
		e.updateFailureStats()
		return result, err
	}

	// Validate configuration if strict validation is enabled
	if e.config.EnableStrictValidation {
		if err := transform.Validate(config); err != nil {
			result := TransformResult{
				Success:       false,
				Error:         fmt.Sprintf("Configuration validation failed: %v", err),
				Duration:      time.Since(startTime),
				TransformName: transformName,
			}
			e.updateFailureStats()
			return result, err
		}
	}

	// Check cache if enabled
	cacheKey := e.generateCacheKey(transformName, config, data)
	if e.config.EnableCaching && e.cache != nil && cacheKey != "" {
		if cached, found := e.cache.Get(cacheKey); found {
			e.logger.Debug("Transform result found in cache", "transform", transformName, "cache_key", cacheKey)
			if e.config.EnableMetrics {
				e.updateStats(func(stats *ExecutorStats) {
					stats.CacheHits++
				})
			}
			return cached, nil
		}
		if e.config.EnableMetrics {
			e.updateStats(func(stats *ExecutorStats) {
				stats.CacheMisses++
			})
		}
	}

	// Log execution start
	e.logger.Debug("Started execution of "+transformName, "transform", transformName)

	// Create execution context
	transformCtx := e.createTransformContext(transformName, config, data, variables)

	// Execute the transform with timeout
	result, err := e.executeWithTimeout(ctx, transform, transformCtx)

	// Record execution time
	result.Duration = time.Since(startTime)
	result.TransformName = transformName

	// Handle errors and retries
	if err != nil || !result.Success {
		if e.config.RetryAttempts > 0 {
			result, err = e.executeWithRetry(ctx, transform, transformCtx, e.config.RetryAttempts)
			result.Duration = time.Since(startTime)
			result.TransformName = transformName
		}

		if err != nil || !result.Success {
			e.updateFailureStats()
			e.logger.Error("Transform execution failed", "transform", transformName, "error", err, "result", result)
		}
	}

	// Cache successful results if caching is enabled
	if e.config.EnableCaching && e.cache != nil && result.Success && cacheKey != "" {
		cacheTTL := e.config.DefaultCacheTTL
		if result.CacheTTL > 0 {
			cacheTTL = result.CacheTTL
		}
		e.cache.Set(cacheKey, result, cacheTTL)
		e.logger.Debug("Transform result cached", "transform", transformName, "cache_key", cacheKey, "ttl", cacheTTL)
	}

	// Update success stats
	if result.Success && e.config.EnableMetrics {
		e.updateStats(func(stats *ExecutorStats) {
			stats.SuccessfulExecutions++
			stats.TotalExecutionTime += result.Duration
		})
	}

	// Log execution completion
	e.logger.LogExecution(transformName, result.Duration, result.Success, err)

	return result, err
}

// ExecuteChain runs a sequence of transforms
func (e *DefaultTransformExecutor) ExecuteChain(ctx context.Context, chain []TransformStep, data map[string]interface{}, variables map[string]interface{}) (TransformResult, error) {
	startTime := time.Now()

	// Validate chain length
	if len(chain) > e.config.MaxChainLength {
		return TransformResult{
			Success:  false,
			Error:    fmt.Sprintf("Transform chain exceeds maximum length of %d", e.config.MaxChainLength),
			Duration: time.Since(startTime),
		}, fmt.Errorf("transform chain too long")
	}

	// Set up chain timeout context
	chainCtx := ctx
	if e.config.ChainTimeout > 0 {
		var cancel context.CancelFunc
		chainCtx, cancel = context.WithTimeout(ctx, e.config.ChainTimeout)
		defer cancel()
	}

	// Initialize chain execution context
	currentData := make(map[string]interface{})
	for k, v := range data {
		currentData[k] = v
	}

	chainVariables := make(map[string]interface{})
	for k, v := range variables {
		chainVariables[k] = v
	}

	var allWarnings []string
	var allMetadata = make(map[string]interface{})
	var lastResult TransformResult

	// Execute each transform in the chain
	for i, step := range chain {
		e.logger.Debug("Executing transform step", "step", i+1, "total", len(chain), "transform", step.Name)

		// Check if we should execute this step based on condition
		if step.Condition != "" {
			shouldExecute, err := e.evaluateCondition(step.Condition, currentData, chainVariables)
			if err != nil {
				return TransformResult{
					Success:  false,
					Error:    fmt.Sprintf("Failed to evaluate condition for step %d: %v", i+1, err),
					Duration: time.Since(startTime),
				}, err
			}
			if !shouldExecute {
				e.logger.Debug("Skipping transform step due to condition", "step", i+1, "condition", step.Condition)
				continue
			}
		}

		// Apply input mapping
		stepData := e.applyInputMapping(step.InputMapping, currentData, chainVariables)

		// Execute the transform
		stepResult, err := e.Execute(chainCtx, step.Name, step.Config, stepData, chainVariables)

		// Handle errors based on the step's error action
		if err != nil || !stepResult.Success {
			switch step.OnError {
			case ErrorActionStop:
				return TransformResult{
					Success:  false,
					Error:    fmt.Sprintf("Transform chain stopped at step %d (%s): %s", i+1, step.Name, stepResult.Error),
					Duration: time.Since(startTime),
					Warnings: allWarnings,
					Metadata: allMetadata,
				}, err

			case ErrorActionContinue:
				warning := fmt.Sprintf("Step %d (%s) failed but continuing: %s", i+1, step.Name, stepResult.Error)
				allWarnings = append(allWarnings, warning)
				e.logger.Warn("Transform step failed but continuing", "step", i+1, "transform", step.Name, "error", stepResult.Error)
				continue

			case ErrorActionSkip:
				warning := fmt.Sprintf("Step %d (%s) failed, skipping remaining steps: %s", i+1, step.Name, stepResult.Error)
				allWarnings = append(allWarnings, warning)
				e.logger.Warn("Transform step failed, skipping chain", "step", i+1, "transform", step.Name, "error", stepResult.Error)
				goto skipRemaining

			case ErrorActionRetry:
				// Retry logic is handled within Execute method
				if !stepResult.Success {
					return TransformResult{
						Success:  false,
						Error:    fmt.Sprintf("Transform chain failed at step %d (%s) after retries: %s", i+1, step.Name, stepResult.Error),
						Duration: time.Since(startTime),
						Warnings: allWarnings,
						Metadata: allMetadata,
					}, err
				}

			default:
				// Default behavior is to stop on error
				return TransformResult{
					Success:  false,
					Error:    fmt.Sprintf("Transform chain failed at step %d (%s): %s", i+1, step.Name, stepResult.Error),
					Duration: time.Since(startTime),
					Warnings: allWarnings,
					Metadata: allMetadata,
				}, err
			}
		}

		// Apply output mapping and update current data
		if stepResult.Success {
			currentData = e.applyOutputMapping(step.OutputMapping, stepResult.Data, currentData, chainVariables)

			// Collect warnings and metadata
			allWarnings = append(allWarnings, stepResult.Warnings...)
			for k, v := range stepResult.Metadata {
				allMetadata[fmt.Sprintf("step_%d_%s", i+1, k)] = v
			}
		}

		lastResult = stepResult
	}

skipRemaining:
	// Build final result
	finalResult := TransformResult{
		Data:          currentData,
		Success:       true,
		Duration:      time.Since(startTime),
		Warnings:      allWarnings,
		Metadata:      allMetadata,
		TransformName: "chain",
	}

	// If we have a last result, inherit some properties
	if lastResult.TransformName != "" {
		finalResult.CacheKey = lastResult.CacheKey
		finalResult.CacheTTL = lastResult.CacheTTL
	}

	return finalResult, nil
}

// Validate validates a transform configuration
func (e *DefaultTransformExecutor) Validate(transformName string, config map[string]interface{}) error {
	transform, err := e.registry.Get(transformName)
	if err != nil {
		return fmt.Errorf("transform not found: %w", err)
	}

	return transform.Validate(config)
}

// GetTransformMetadata returns metadata for a specific transform
func (e *DefaultTransformExecutor) GetTransformMetadata(transformName string) (TransformMetadata, error) {
	transform, err := e.registry.Get(transformName)
	if err != nil {
		return TransformMetadata{}, fmt.Errorf("transform not found: %w", err)
	}

	return transform.GetMetadata(), nil
}

// ListAvailableTransforms returns all available transforms
func (e *DefaultTransformExecutor) ListAvailableTransforms() []TransformMetadata {
	return e.registry.GetMetadata()
}

// GetStats returns execution statistics
func (e *DefaultTransformExecutor) GetStats() ExecutorStats {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	// Create a copy to avoid race conditions
	stats := *e.stats
	if stats.TotalExecutions > 0 {
		stats.SuccessRate = float64(stats.SuccessfulExecutions) / float64(stats.TotalExecutions)
		stats.AverageExecutionTime = stats.TotalExecutionTime / time.Duration(stats.SuccessfulExecutions)
	}

	return stats
}

// ResetStats resets execution statistics
func (e *DefaultTransformExecutor) ResetStats() {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.stats = &ExecutorStats{}
}

// createTransformContext creates a transform context for execution
func (e *DefaultTransformExecutor) createTransformContext(transformName string, config map[string]interface{}, data map[string]interface{}, variables map[string]interface{}) TransformContext {
	return &DefaultTransformContext{
		data:               data,
		variables:          variables,
		config:             config,
		transformName:      transformName,
		temporaryVariables: make(map[string]interface{}),
		logger:             e.logger.WithField("transform", transformName),
	}
}

// executeWithTimeout executes a transform with timeout
func (e *DefaultTransformExecutor) executeWithTimeout(ctx context.Context, transform Transform, transformCtx TransformContext) (TransformResult, error) {
	if e.config.ExecutionTimeout <= 0 {
		return transform.Execute(ctx, transformCtx)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, e.config.ExecutionTimeout)
	defer cancel()

	resultChan := make(chan TransformResult, 1)
	errorChan := make(chan error, 1)

	go func() {
		result, err := transform.Execute(timeoutCtx, transformCtx)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return TransformResult{}, err
	case <-timeoutCtx.Done():
		return TransformResult{
			Success: false,
			Error:   fmt.Sprintf("Transform execution timed out after %v", e.config.ExecutionTimeout),
		}, fmt.Errorf("execution timeout")
	}
}

// executeWithRetry executes a transform with retry logic
func (e *DefaultTransformExecutor) executeWithRetry(ctx context.Context, transform Transform, transformCtx TransformContext, attempts int) (TransformResult, error) {
	var lastResult TransformResult
	var lastError error

	for i := 0; i < attempts; i++ {
		if i > 0 {
			// Wait before retry
			select {
			case <-time.After(e.config.RetryDelay):
			case <-ctx.Done():
				return lastResult, ctx.Err()
			}
			e.logger.Debug("Retrying transform execution", "attempt", i+1, "total_attempts", attempts)
		}

		result, err := e.executeWithTimeout(ctx, transform, transformCtx)

		if err == nil && result.Success {
			return result, nil
		}

		lastResult = result
		lastError = err
	}

	// All retries failed
	return lastResult, lastError
}

// generateCacheKey generates a cache key for the given parameters
func (e *DefaultTransformExecutor) generateCacheKey(transformName string, config map[string]interface{}, data map[string]interface{}) string {
	// Simple implementation - in production you might want something more sophisticated
	return fmt.Sprintf("%s:%v:%v", transformName, config, data)
}

// evaluateCondition evaluates a condition string (basic implementation)
func (e *DefaultTransformExecutor) evaluateCondition(condition string, data map[string]interface{}, variables map[string]interface{}) (bool, error) {
	// This is a simplified implementation
	// In production, you might want to use a proper expression evaluator
	if condition == "" {
		return true, nil
	}

	// For now, just support simple variable existence checks
	if strings.HasPrefix(condition, "exists(") && strings.HasSuffix(condition, ")") {
		varName := condition[7 : len(condition)-1]
		_, existsInData := data[varName]
		_, existsInVars := variables[varName]
		return existsInData || existsInVars, nil
	}

	// Default to true for unrecognized conditions
	return true, nil
}

// applyInputMapping applies input mapping to transform input data
func (e *DefaultTransformExecutor) applyInputMapping(mapping map[string]string, data map[string]interface{}, variables map[string]interface{}) map[string]interface{} {
	if len(mapping) == 0 {
		return data
	}

	result := make(map[string]interface{})
	for targetKey, sourceKey := range mapping {
		if value, exists := data[sourceKey]; exists {
			result[targetKey] = value
		} else if value, exists := variables[sourceKey]; exists {
			result[targetKey] = value
		}
	}

	return result
}

// applyOutputMapping applies output mapping to transform output data
func (e *DefaultTransformExecutor) applyOutputMapping(mapping map[string]string, outputData map[string]interface{}, currentData map[string]interface{}, variables map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Start with current data
	for k, v := range currentData {
		result[k] = v
	}

	// Apply output mapping
	if len(mapping) > 0 {
		for sourceKey, targetKey := range mapping {
			if value, exists := outputData[sourceKey]; exists {
				result[targetKey] = value
			}
		}
	} else {
		// No mapping specified, merge all output data
		for k, v := range outputData {
			result[k] = v
		}
	}

	return result
}

// updateStats safely updates execution statistics
func (e *DefaultTransformExecutor) updateStats(fn func(*ExecutorStats)) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	fn(e.stats)
}

// updateFailureStats updates failure statistics
func (e *DefaultTransformExecutor) updateFailureStats() {
	if e.config.EnableMetrics {
		e.updateStats(func(stats *ExecutorStats) {
			stats.FailedExecutions++
		})
	}
}

// ExecutorStats tracks execution statistics
type ExecutorStats struct {
	// TotalExecutions is the total number of transform executions
	TotalExecutions int64 `json:"total_executions"`

	// SuccessfulExecutions is the number of successful executions
	SuccessfulExecutions int64 `json:"successful_executions"`

	// FailedExecutions is the number of failed executions
	FailedExecutions int64 `json:"failed_executions"`

	// SuccessRate is the success rate (0.0 to 1.0)
	SuccessRate float64 `json:"success_rate"`

	// TotalExecutionTime is the total time spent executing transforms
	TotalExecutionTime time.Duration `json:"total_execution_time"`

	// AverageExecutionTime is the average execution time
	AverageExecutionTime time.Duration `json:"average_execution_time"`

	// CacheHits is the number of cache hits
	CacheHits int64 `json:"cache_hits"`

	// CacheMisses is the number of cache misses
	CacheMisses int64 `json:"cache_misses"`
}
