package transform

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultTransformExecutor(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	cache := DefaultMemoryTransformCache()
	logger := &NoOpTransformLogger{}

	executor := NewDefaultTransformExecutor(registry, cache, logger)

	assert.NotNil(t, executor)
}

func TestTransformExecutor_Execute(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	cache := DefaultMemoryTransformCache()
	logger := &TestTransformLogger{}
	executor := NewDefaultTransformExecutor(registry, cache, logger)

	// Register a test transform
	transform := NewMockTransform("test_transform")
	err := registry.Register(transform)
	require.NoError(t, err)

	ctx := context.Background()
	config := map[string]interface{}{}
	data := map[string]interface{}{"test": "hello"}
	variables := map[string]interface{}{}

	// Test successful execution
	result, err := executor.Execute(ctx, "test_transform", config, data, variables)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "processed_hello", result.Data["result"])
	assert.Greater(t, result.Duration, time.Duration(0))

	// Verify logging
	testLogger := logger
	assert.Len(t, testLogger.Logs, 3)
	assert.Contains(t, testLogger.Logs[0], "Started execution")
	assert.Contains(t, testLogger.Logs[1], "Transform result cached")
	assert.Contains(t, testLogger.Logs[2], "Completed execution")
}

func TestTransformExecutor_ExecuteNotFound(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	cache := DefaultMemoryTransformCache()
	logger := &NoOpTransformLogger{}
	executor := NewDefaultTransformExecutor(registry, cache, logger)

	ctx := context.Background()
	config := map[string]interface{}{}
	data := map[string]interface{}{}
	variables := map[string]interface{}{}

	// Test non-existent transform
	_, err := executor.Execute(ctx, "non_existent", config, data, variables)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transform 'non_existent' not found")
}

func TestTransformExecutor_ExecuteWithTimeout(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	cache := DefaultMemoryTransformCache()
	logger := &NoOpTransformLogger{}
	executor := NewDefaultTransformExecutor(registry, cache, logger)

	// Create a slow transform
	slowTransform := NewMockTransform("slow_transform")
	slowTransform.executeFunc = func(ctx context.Context, transformCtx TransformContext) (TransformResult, error) {
		select {
		case <-time.After(time.Second):
			return TransformResult{Success: true}, nil
		case <-ctx.Done():
			return TransformResult{
				Success: false,
				Error:   "execution cancelled",
			}, ctx.Err()
		}
	}

	err := registry.Register(slowTransform)
	require.NoError(t, err)

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()

	config := map[string]interface{}{}
	data := map[string]interface{}{}
	variables := map[string]interface{}{}

	// Test timeout
	_, err = executor.Execute(ctx, "slow_transform", config, data, variables)

	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestTransformExecutor_ExecuteChain(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	cache := DefaultMemoryTransformCache()
	logger := &TestTransformLogger{}
	executor := NewDefaultTransformExecutor(registry, cache, logger)

	// Register test transforms
	uppercaseTransform := NewMockTransform("uppercase")
	uppercaseTransform.executeFunc = func(ctx context.Context, transformCtx TransformContext) (TransformResult, error) {
		text := transformCtx.GetString("text")
		return TransformResult{
			Data:     map[string]interface{}{"text": text + "_UPPER"},
			Success:  true,
			Duration: time.Millisecond * 10,
		}, nil
	}

	prefixTransform := NewMockTransform("prefix")
	prefixTransform.executeFunc = func(ctx context.Context, transformCtx TransformContext) (TransformResult, error) {
		text := transformCtx.GetString("text")
		return TransformResult{
			Data:     map[string]interface{}{"text": "PREFIX_" + text},
			Success:  true,
			Duration: time.Millisecond * 10,
		}, nil
	}

	err := registry.Register(uppercaseTransform)
	require.NoError(t, err)

	err = registry.Register(prefixTransform)
	require.NoError(t, err)

	// Define transform chain
	chain := []TransformStep{
		{
			Name: "uppercase",
			InputMapping: map[string]string{
				"text": "input_text",
			},
			OutputMapping: map[string]string{
				"text": "intermediate_text",
			},
		},
		{
			Name: "prefix",
			InputMapping: map[string]string{
				"text": "intermediate_text",
			},
			OutputMapping: map[string]string{
				"text": "final_text",
			},
		},
	}

	ctx := context.Background()
	data := map[string]interface{}{"input_text": "hello"}
	variables := map[string]interface{}{}

	// Test chain execution
	result, err := executor.ExecuteChain(ctx, chain, data, variables)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "PREFIX_hello_UPPER", result.Data["final_text"])

	// Verify both transforms were executed
	testLogger := logger
	assert.Greater(t, len(testLogger.Logs), 2)
}

func TestTransformExecutor_ExecuteChainWithError(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	cache := DefaultMemoryTransformCache()
	logger := &NoOpTransformLogger{}
	executor := NewDefaultTransformExecutor(registry, cache, logger)

	// Register transforms - one that fails
	successTransform := NewMockTransform("success")
	failTransform := NewMockTransform("fail")
	failTransform.executeFunc = func(ctx context.Context, transformCtx TransformContext) (TransformResult, error) {
		return TransformResult{
			Success: false,
			Error:   "intentional failure",
		}, nil
	}

	err := registry.Register(successTransform)
	require.NoError(t, err)

	err = registry.Register(failTransform)
	require.NoError(t, err)

	// Define chain with failing transform
	chain := []TransformStep{
		{Name: "success"},
		{Name: "fail"},
	}

	ctx := context.Background()
	data := map[string]interface{}{}
	variables := map[string]interface{}{}

	// Test chain execution failure
	result, err := executor.ExecuteChain(ctx, chain, data, variables)

	require.NoError(t, err) // No execution error, but transform failed
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "intentional failure")
}

func TestTransformExecutor_Validate(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	cache := DefaultMemoryTransformCache()
	logger := &NoOpTransformLogger{}
	executor := NewDefaultTransformExecutor(registry, cache, logger)

	// Register transform with validation
	transform := NewMockTransform("validating_transform")
	transform.validateFunc = func(config map[string]interface{}) error {
		if config == nil {
			return errors.New("config is required")
		}
		if _, exists := config["required_field"]; !exists {
			return errors.New("required_field is missing")
		}
		return nil
	}

	err := registry.Register(transform)
	require.NoError(t, err)

	// Test validation success
	config := map[string]interface{}{"required_field": "value"}
	err = executor.Validate("validating_transform", config)
	assert.NoError(t, err)

	// Test validation failure
	config = map[string]interface{}{}
	err = executor.Validate("validating_transform", config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required_field is missing")

	// Test non-existent transform
	err = executor.Validate("non_existent", config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTransformExecutor_ListAvailableTransforms(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	cache := DefaultMemoryTransformCache()
	logger := &NoOpTransformLogger{}
	executor := NewDefaultTransformExecutor(registry, cache, logger)

	// Test empty registry
	metadata := executor.ListAvailableTransforms()
	assert.Empty(t, metadata)

	// Add transforms
	transform1 := NewMockTransform("transform1")
	transform2 := NewMockTransform("transform2")

	err := registry.Register(transform1)
	require.NoError(t, err)

	err = registry.Register(transform2)
	require.NoError(t, err)

	// Test listing
	metadata = executor.ListAvailableTransforms()
	assert.Len(t, metadata, 2)

	names := make([]string, len(metadata))
	for i, m := range metadata {
		names[i] = m.Name
	}
	assert.Contains(t, names, "transform1")
	assert.Contains(t, names, "transform2")
}

func TestTransformExecutor_WithCaching(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	cache := DefaultMemoryTransformCache()
	logger := &TestTransformLogger{}
	executor := NewDefaultTransformExecutor(registry, cache, logger)

	// Register transform that tracks execution count
	var executionCount int
	countingTransform := NewMockTransform("counting")
	countingTransform.executeFunc = func(ctx context.Context, transformCtx TransformContext) (TransformResult, error) {
		executionCount++
		input := transformCtx.GetString("test")
		return TransformResult{
			Data:     map[string]interface{}{"result": "counted_" + input},
			Success:  true,
			Duration: time.Millisecond * 10,
		}, nil
	}

	err := registry.Register(countingTransform)
	require.NoError(t, err)

	ctx := context.Background()
	config := map[string]interface{}{}
	data := map[string]interface{}{"test": "hello"}
	variables := map[string]interface{}{}

	// First execution - should run transform
	result1, err := executor.Execute(ctx, "counting", config, data, variables)
	require.NoError(t, err)
	assert.True(t, result1.Success)
	assert.Equal(t, 1, executionCount)

	// Second execution with same inputs - should use cache
	result2, err := executor.Execute(ctx, "counting", config, data, variables)
	require.NoError(t, err)
	assert.True(t, result2.Success)
	assert.Equal(t, 1, executionCount) // Should not increment
	assert.Equal(t, result1.Data, result2.Data)

	// Third execution with different inputs - should run transform
	data["test"] = "world"
	result3, err := executor.Execute(ctx, "counting", config, data, variables)
	require.NoError(t, err)
	assert.True(t, result3.Success)
	assert.Equal(t, 2, executionCount) // Should increment
	assert.NotEqual(t, result1.Data, result3.Data)
}

func TestTransformExecutor_ConcurrentExecution(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	cache := DefaultMemoryTransformCache()
	logger := &NoOpTransformLogger{}
	executor := NewDefaultTransformExecutor(registry, cache, logger)

	// Register a simple transform
	transform := NewMockTransform("concurrent_test")
	err := registry.Register(transform)
	require.NoError(t, err)

	ctx := context.Background()
	config := map[string]interface{}{}
	variables := map[string]interface{}{}

	// Execute transform concurrently
	const numGoroutines = 50
	results := make([]TransformResult, numGoroutines)
	errors := make([]error, numGoroutines)
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			data := map[string]interface{}{"test": string(rune('A' + index))}
			results[index], errors[index] = executor.Execute(ctx, "concurrent_test", config, data, variables)
		}(i)
	}

	wg.Wait()

	// Verify all executions succeeded
	for i := 0; i < numGoroutines; i++ {
		assert.NoError(t, errors[i], "Execution %d failed", i)
		assert.True(t, results[i].Success, "Result %d was not successful", i)
	}
}

// TestTransformLogger for testing
type TestTransformLogger struct {
	Logs []string
	mu   sync.Mutex
}

func (l *TestTransformLogger) Debug(msg string, fields ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Logs = append(l.Logs, "DEBUG: "+msg)
}

func (l *TestTransformLogger) Info(msg string, fields ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Logs = append(l.Logs, "INFO: "+msg)
}

func (l *TestTransformLogger) Warn(msg string, fields ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Logs = append(l.Logs, "WARN: "+msg)
}

func (l *TestTransformLogger) Error(msg string, fields ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Logs = append(l.Logs, "ERROR: "+msg)
}

func (l *TestTransformLogger) LogExecution(transformName string, duration time.Duration, success bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if success {
		l.Logs = append(l.Logs, "Completed execution of "+transformName)
	} else {
		l.Logs = append(l.Logs, "Failed execution of "+transformName)
	}
}

func (l *TestTransformLogger) LogChainExecution(chainLength int, totalDuration time.Duration, success bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if success {
		l.Logs = append(l.Logs, "Completed chain execution")
	} else {
		l.Logs = append(l.Logs, "Failed chain execution")
	}
}

func (l *TestTransformLogger) WithField(key string, value interface{}) TransformLogger {
	return l // Return same logger for simplicity in tests
}

func (l *TestTransformLogger) WithFields(fields map[string]interface{}) TransformLogger {
	return l // Return same logger for simplicity in tests
}

