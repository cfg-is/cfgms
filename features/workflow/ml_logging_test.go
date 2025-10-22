package workflow

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// MockLoggingProvider implements the LoggingProvider interface for testing
type MockLoggingProvider struct {
	mock.Mock
	entries []interfaces.LogEntry
	mutex   sync.RWMutex
}

func (m *MockLoggingProvider) Name() string {
	return "mock"
}

func (m *MockLoggingProvider) Description() string {
	return "Mock logging provider for testing"
}

func (m *MockLoggingProvider) Available() (bool, error) {
	args := m.Called()
	return args.Bool(0), args.Error(1)
}

func (m *MockLoggingProvider) GetVersion() string {
	return "1.0.0"
}

func (m *MockLoggingProvider) GetCapabilities() interfaces.LoggingCapabilities {
	return interfaces.LoggingCapabilities{
		SupportsCompression:       true,
		SupportsRetentionPolicies: true,
		SupportsRealTimeQueries:   true,
		SupportsBatchWrites:       true,
		SupportsTimeRangeQueries:  true,
		MaxEntriesPerSecond:       10000,
		MaxBatchSize:              1000,
		DefaultRetentionDays:      30,
	}
}

func (m *MockLoggingProvider) Initialize(config map[string]interface{}) error {
	args := m.Called(config)
	return args.Error(0)
}

func (m *MockLoggingProvider) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockLoggingProvider) WriteEntry(ctx context.Context, entry interfaces.LogEntry) error {
	args := m.Called(ctx, entry)
	m.mutex.Lock()
	m.entries = append(m.entries, entry)
	m.mutex.Unlock()
	return args.Error(0)
}

func (m *MockLoggingProvider) WriteBatch(ctx context.Context, entries []interfaces.LogEntry) error {
	args := m.Called(ctx, entries)
	m.mutex.Lock()
	m.entries = append(m.entries, entries...)
	m.mutex.Unlock()
	return args.Error(0)
}

func (m *MockLoggingProvider) QueryTimeRange(ctx context.Context, query interfaces.TimeRangeQuery) ([]interfaces.LogEntry, error) {
	args := m.Called(ctx, query)
	return args.Get(0).([]interfaces.LogEntry), args.Error(1)
}

func (m *MockLoggingProvider) QueryCount(ctx context.Context, query interfaces.CountQuery) (int64, error) {
	args := m.Called(ctx, query)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockLoggingProvider) QueryLevels(ctx context.Context, query interfaces.LevelQuery) ([]interfaces.LogEntry, error) {
	args := m.Called(ctx, query)
	return args.Get(0).([]interfaces.LogEntry), args.Error(1)
}

func (m *MockLoggingProvider) ApplyRetentionPolicy(ctx context.Context, policy interfaces.RetentionPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockLoggingProvider) GetStats(ctx context.Context) (interfaces.ProviderStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(interfaces.ProviderStats), args.Error(1)
}

func (m *MockLoggingProvider) Flush(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockLoggingProvider) GetLoggedEntries() []interfaces.LogEntry {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	entries := make([]interfaces.LogEntry, len(m.entries))
	copy(entries, m.entries)
	return entries
}

func TestMLLogger_LogExecutionStart(t *testing.T) {
	// Setup
	mockProvider := &MockLoggingProvider{}
	mockProvider.On("WriteBatch", mock.Anything, mock.Anything).Return(nil)

	_ = pkgtesting.NewMockLogger(true)
	moduleLogger := logging.ForModule("test")
	mlLogger := NewMLLogger(moduleLogger, mockProvider)
	defer func() { _ = mlLogger.Close() }()

	// Create test execution
	execution := &WorkflowExecution{
		ID:           "test-execution-1",
		WorkflowName: "test-workflow",
		StartTime:    time.Now(),
		Variables:    map[string]interface{}{"test_var": "test_value"},
	}

	workflow := Workflow{
		Name:    "test-workflow",
		Version: "1.0.0",
		Steps:   []Step{{Name: "step1", Type: StepTypeTask}},
		Timeout: 30 * time.Second,
	}

	// Test execution start logging
	mlLogger.LogExecutionStart(execution, workflow)

	// Force flush to ensure entry is written
	mlLogger.flushBuffer()

	// Verify the entry was logged
	entries := mockProvider.GetLoggedEntries()
	assert.NotEmpty(t, entries)

	// Verify entry structure
	entry := entries[0]
	assert.Equal(t, "INFO", entry.Level)
	assert.Equal(t, "workflow_engine", entry.ServiceName)
	assert.Equal(t, "ml_logger", entry.Component)

	// Verify ML data
	mlDataStr, exists := entry.Fields["ml_data"].(string)
	assert.True(t, exists)

	var mlData MLLogEntry
	err := json.Unmarshal([]byte(mlDataStr), &mlData)
	assert.NoError(t, err)

	assert.Equal(t, "execution_start", mlData.EventType)
	assert.Equal(t, "test-execution-1", mlData.ExecutionID)
	assert.Equal(t, "test-workflow", mlData.WorkflowName)
	assert.Contains(t, mlData.VariableStates, "test_var")
	assert.NotNil(t, mlData.PerformanceMetrics)
}

func TestMLLogger_LogVariableChange(t *testing.T) {
	// Setup
	mockProvider := &MockLoggingProvider{}
	mockProvider.On("WriteBatch", mock.Anything, mock.Anything).Return(nil)

	moduleLogger := logging.ForModule("test")
	mlLogger := NewMLLogger(moduleLogger, mockProvider)
	defer func() { _ = mlLogger.Close() }()

	execution := &WorkflowExecution{
		ID:           "test-execution-1",
		WorkflowName: "test-workflow",
		Variables:    map[string]interface{}{"var1": "old_value", "var2": "unchanged"},
	}

	// Test variable change logging
	mlLogger.LogVariableChange(execution, "var1", "old_value", "new_value", "test_step")

	// Force flush
	mlLogger.flushBuffer()

	// Verify the entry was logged
	entries := mockProvider.GetLoggedEntries()
	assert.NotEmpty(t, entries)

	entry := entries[0]
	mlDataStr := entry.Fields["ml_data"].(string)

	var mlData MLLogEntry
	err := json.Unmarshal([]byte(mlDataStr), &mlData)
	assert.NoError(t, err)

	assert.Equal(t, "variable_change", mlData.EventType)
	assert.Equal(t, "test_step", mlData.StepName)
	assert.Len(t, mlData.VariableChanges, 1)

	change := mlData.VariableChanges[0]
	assert.Equal(t, "var1", change.VariableName)
	assert.Equal(t, "old_value", change.OldValue)
	assert.Equal(t, "new_value", change.NewValue)
	assert.Equal(t, "update", change.ChangeType)
	assert.Equal(t, "test_step", change.StepContext)
}

func TestMLLogger_LogAPIRequest(t *testing.T) {
	// Setup
	mockProvider := &MockLoggingProvider{}
	mockProvider.On("WriteBatch", mock.Anything, mock.Anything).Return(nil)

	moduleLogger := logging.ForModule("test")
	mlLogger := NewMLLogger(moduleLogger, mockProvider)
	defer func() { _ = mlLogger.Close() }()

	execution := &WorkflowExecution{
		ID:           "test-execution-1",
		WorkflowName: "test-workflow",
	}

	headers := map[string]string{"Content-Type": "application/json"}
	body := map[string]interface{}{"key": "value"}

	// Test API request logging
	mlLogger.LogAPIRequest(execution, "api_step", "https://api.example.com/test", "POST", headers, body, "req-123")

	// Force flush
	mlLogger.flushBuffer()

	// Verify the entry was logged
	entries := mockProvider.GetLoggedEntries()
	assert.NotEmpty(t, entries)

	entry := entries[0]
	mlDataStr := entry.Fields["ml_data"].(string)

	var mlData MLLogEntry
	err := json.Unmarshal([]byte(mlDataStr), &mlData)
	assert.NoError(t, err)

	assert.Equal(t, "api_request", mlData.EventType)
	assert.Equal(t, "api_step", mlData.StepName)
	assert.NotNil(t, mlData.APIRequestData)

	apiData := mlData.APIRequestData
	assert.Equal(t, "https://api.example.com/test", apiData.URL)
	assert.Equal(t, "POST", apiData.Method)
	assert.Equal(t, headers, apiData.Headers)
	assert.Equal(t, body, apiData.Body)
	assert.Equal(t, "req-123", apiData.RequestID)
}

func TestMLLogger_LogAPIResponse(t *testing.T) {
	// Setup
	mockProvider := &MockLoggingProvider{}
	mockProvider.On("WriteBatch", mock.Anything, mock.Anything).Return(nil)

	moduleLogger := logging.ForModule("test")
	mlLogger := NewMLLogger(moduleLogger, mockProvider)
	defer func() { _ = mlLogger.Close() }()

	execution := &WorkflowExecution{
		ID:           "test-execution-1",
		WorkflowName: "test-workflow",
	}

	headers := map[string]string{"Content-Type": "application/json"}
	body := map[string]interface{}{"result": "success"}
	responseTime := 150 * time.Millisecond

	// Test API response logging
	mlLogger.LogAPIResponse(execution, "api_step", 200, headers, body, responseTime, "req-123")

	// Force flush
	mlLogger.flushBuffer()

	// Verify the entry was logged
	entries := mockProvider.GetLoggedEntries()
	assert.NotEmpty(t, entries)

	entry := entries[0]
	mlDataStr := entry.Fields["ml_data"].(string)

	var mlData MLLogEntry
	err := json.Unmarshal([]byte(mlDataStr), &mlData)
	assert.NoError(t, err)

	assert.Equal(t, "api_response", mlData.EventType)
	assert.Equal(t, "api_step", mlData.StepName)
	assert.NotNil(t, mlData.APIResponseData)

	apiData := mlData.APIResponseData
	assert.Equal(t, 200, apiData.StatusCode)
	assert.Equal(t, headers, apiData.Headers)
	assert.Equal(t, body, apiData.Body)
	assert.Equal(t, responseTime, apiData.ResponseTime)
	assert.Equal(t, "req-123", apiData.RequestID)
	assert.Greater(t, apiData.ResponseSize, int64(0))
}

func TestMLLogger_LogErrorPattern(t *testing.T) {
	// Setup
	mockProvider := &MockLoggingProvider{}
	mockProvider.On("WriteBatch", mock.Anything, mock.Anything).Return(nil)

	moduleLogger := logging.ForModule("test")
	mlLogger := NewMLLogger(moduleLogger, mockProvider)
	defer func() { _ = mlLogger.Close() }()

	execution := &WorkflowExecution{
		ID:           "test-execution-1",
		WorkflowName: "test-workflow",
	}

	// Create a workflow error
	workflowErr := &WorkflowError{
		Code:         ErrorCodeHTTPRequest,
		Message:      "API call failed",
		StepName:     "api_step",
		StepType:     StepTypeHTTP,
		Details:      map[string]interface{}{"status_code": 500},
		Timestamp:    time.Now(),
		Recoverable:  true,
		RetryAttempt: 1,
	}

	// Test error pattern logging
	mlLogger.LogErrorPattern(execution, "api_step", workflowErr)

	// Force flush
	mlLogger.flushBuffer()

	// Verify the entry was logged
	entries := mockProvider.GetLoggedEntries()
	assert.NotEmpty(t, entries)

	entry := entries[0]
	mlDataStr := entry.Fields["ml_data"].(string)

	var mlData MLLogEntry
	err := json.Unmarshal([]byte(mlDataStr), &mlData)
	assert.NoError(t, err)

	assert.Equal(t, "error_pattern", mlData.EventType)
	assert.Equal(t, "api_step", mlData.StepName)
	assert.NotNil(t, mlData.ErrorPattern)

	errorPattern := mlData.ErrorPattern
	assert.Equal(t, "HTTP_REQUEST_FAILED", errorPattern.ErrorCode)
	assert.Equal(t, "API call failed", errorPattern.ErrorMessage)
	assert.Equal(t, "workflow_error", errorPattern.ErrorType)
	assert.Equal(t, 1, errorPattern.RetryAttempt)
	assert.True(t, errorPattern.IsRecoverable)
	assert.False(t, errorPattern.IsFatal)
	assert.Equal(t, "network", errorPattern.FailureCategory)
}

func TestMLLogger_LogPerformanceSnapshot(t *testing.T) {
	// Setup
	mockProvider := &MockLoggingProvider{}
	mockProvider.On("WriteBatch", mock.Anything, mock.Anything).Return(nil)

	moduleLogger := logging.ForModule("test")
	mlLogger := NewMLLogger(moduleLogger, mockProvider)
	defer func() { _ = mlLogger.Close() }()

	execution := &WorkflowExecution{
		ID:           "test-execution-1",
		WorkflowName: "test-workflow",
	}

	// Test performance snapshot logging
	mlLogger.LogPerformanceSnapshot(execution, "test_step")

	// Force flush
	mlLogger.flushBuffer()

	// Verify the entry was logged
	entries := mockProvider.GetLoggedEntries()
	assert.NotEmpty(t, entries)

	entry := entries[0]
	mlDataStr := entry.Fields["ml_data"].(string)

	var mlData MLLogEntry
	err := json.Unmarshal([]byte(mlDataStr), &mlData)
	assert.NoError(t, err)

	assert.Equal(t, "performance_snapshot", mlData.EventType)
	assert.Equal(t, "test_step", mlData.StepName)
	assert.NotNil(t, mlData.PerformanceMetrics)

	perfMetrics := mlData.PerformanceMetrics
	assert.GreaterOrEqual(t, perfMetrics.CPUUsagePercent, 0.0)
	assert.Greater(t, perfMetrics.GoRoutineCount, 0)
	assert.Greater(t, perfMetrics.MemoryUsageBytes, uint64(0))
	assert.GreaterOrEqual(t, perfMetrics.ThreadCount, 1)
}

func TestPerformanceCollector_CollectMetrics(t *testing.T) {
	collector := NewPerformanceCollector()

	metrics := collector.CollectMetrics()

	assert.NotNil(t, metrics)
	assert.GreaterOrEqual(t, metrics.CPUUsagePercent, 0.0)
	assert.LessOrEqual(t, metrics.CPUUsagePercent, 100.0)
	assert.Greater(t, metrics.GoRoutineCount, 0)
	assert.Greater(t, metrics.MemoryUsageBytes, uint64(0))
	assert.GreaterOrEqual(t, metrics.ThreadCount, 1)
	assert.NotZero(t, metrics.Timestamp)
}

func TestWorkflowPerformanceCollector_StepTracking(t *testing.T) {
	collector := NewWorkflowPerformanceCollector()

	// Test step tracking
	collector.StartStep("step1")
	collector.StartStep("step2")

	activeSteps := collector.GetActiveSteps()
	assert.Len(t, activeSteps, 2)
	assert.Contains(t, activeSteps, "step1")
	assert.Contains(t, activeSteps, "step2")

	// End a step
	collector.EndStep("step1")

	activeSteps = collector.GetActiveSteps()
	assert.Len(t, activeSteps, 1)
	assert.Contains(t, activeSteps, "step2")
	assert.NotContains(t, activeSteps, "step1")

	// Check step execution count
	assert.Equal(t, 2, collector.GetStepExecutionCount())

	// Collect metrics with workflow context
	metrics := collector.CollectWorkflowMetrics()
	assert.Equal(t, 2, metrics.StepExecutionCount)
	assert.Equal(t, 1, metrics.ActiveStepCount)
}

func TestDetermineChangeType(t *testing.T) {
	tests := []struct {
		oldValue interface{}
		newValue interface{}
		expected string
	}{
		{nil, "new", "create"},
		{"old", nil, "delete"},
		{"old", "new", "update"},
		{123, 456, "update"},
	}

	for _, test := range tests {
		result := determineChangeType(test.oldValue, test.newValue)
		assert.Equal(t, test.expected, result)
	}
}

func TestCategorizeError(t *testing.T) {
	tests := []struct {
		errorCode ErrorCode
		expected  string
	}{
		{ErrorCodeHTTPRequest, "network"},
		{ErrorCodeAPIRequest, "network"},
		{ErrorCodeAuthenticationFailure, "auth"},
		{ErrorCodeValidation, "data"},
		{ErrorCodeConditionEvaluation, "logic"},
		{ErrorCodeTimeout, "resource"},
		{ErrorCodeUnknown, "unknown"},
	}

	for _, test := range tests {
		result := categorizeError(test.errorCode)
		assert.Equal(t, test.expected, result)
	}
}

func TestMLLogger_BufferManagement(t *testing.T) {
	// Setup with small buffer for testing
	mockProvider := &MockLoggingProvider{}
	mockProvider.On("WriteBatch", mock.Anything, mock.Anything).Return(nil)

	moduleLogger := logging.ForModule("test")
	mlLogger := NewMLLogger(moduleLogger, mockProvider)
	mlLogger.bufferSize = 2 // Small buffer for testing
	defer func() { _ = mlLogger.Close() }()

	execution := &WorkflowExecution{
		ID:           "test-execution-1",
		WorkflowName: "test-workflow",
	}

	// Log multiple entries to trigger buffer flush
	mlLogger.LogPerformanceSnapshot(execution, "step1")
	mlLogger.LogPerformanceSnapshot(execution, "step2")
	mlLogger.LogPerformanceSnapshot(execution, "step3") // Should trigger flush

	// Wait a bit for async flush
	time.Sleep(100 * time.Millisecond)

	// Verify entries were flushed to provider
	entries := mockProvider.GetLoggedEntries()
	assert.GreaterOrEqual(t, len(entries), 2) // At least the first 2 should be flushed
}

func TestMLLogger_Disabled(t *testing.T) {
	// Setup
	mockProvider := &MockLoggingProvider{}
	moduleLogger := logging.ForModule("test")
	mlLogger := NewMLLogger(moduleLogger, mockProvider)
	mlLogger.enabled = false // Disable logging
	defer func() { _ = mlLogger.Close() }()

	execution := &WorkflowExecution{
		ID:           "test-execution-1",
		WorkflowName: "test-workflow",
	}

	// Try to log - should be ignored
	mlLogger.LogPerformanceSnapshot(execution, "step1")
	mlLogger.flushBuffer()

	// Verify no entries were logged
	entries := mockProvider.GetLoggedEntries()
	assert.Empty(t, entries)
}
