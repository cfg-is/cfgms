package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// MLLogEntry represents enhanced log entries for machine learning analysis
type MLLogEntry struct {
	// Core workflow context
	Timestamp    time.Time `json:"timestamp"`
	ExecutionID  string    `json:"execution_id"`
	WorkflowName string    `json:"workflow_name"`
	StepName     string    `json:"step_name,omitempty"`
	EventType    string    `json:"event_type"`

	// ML-specific event types: "execution_start", "execution_end", "step_start", "step_end",
	// "variable_change", "api_request", "api_response", "performance_snapshot", "error_pattern"

	// Variable state tracking
	VariableStates map[string]interface{} `json:"variable_states,omitempty"`
	VariableChanges []MLVariableChange    `json:"variable_changes,omitempty"`

	// API interaction logging
	APIRequestData  *APIRequestData  `json:"api_request_data,omitempty"`
	APIResponseData *APIResponseData `json:"api_response_data,omitempty"`

	// Performance metrics
	PerformanceMetrics *PerformanceMetrics `json:"performance_metrics,omitempty"`

	// Error pattern analysis
	ErrorPattern *ErrorPattern `json:"error_pattern,omitempty"`

	// Execution flow tracking
	ExecutionPath    []string               `json:"execution_path,omitempty"`
	LoopIteration    int                   `json:"loop_iteration,omitempty"`
	ParentStepName   string                `json:"parent_step_name,omitempty"`

	// Timing and duration data
	StartTime        time.Time             `json:"start_time,omitempty"`
	EndTime          time.Time             `json:"end_time,omitempty"`
	Duration         time.Duration         `json:"duration,omitempty"`

	// Additional structured fields for ML analysis
	MLMetadata       map[string]interface{} `json:"ml_metadata,omitempty"`
}

// MLVariableChange tracks individual variable state changes for ML analysis
type MLVariableChange struct {
	VariableName string      `json:"variable_name"`
	OldValue     interface{} `json:"old_value"`
	NewValue     interface{} `json:"new_value"`
	ChangeType   string      `json:"change_type"` // "create", "update", "delete"
	Timestamp    time.Time   `json:"timestamp"`
	StepContext  string      `json:"step_context"`
}

// APIRequestData captures complete API request information
type APIRequestData struct {
	URL            string                 `json:"url"`
	Method         string                 `json:"method"`
	Headers        map[string]string      `json:"headers"`
	Body           interface{}            `json:"body,omitempty"`
	Authentication string                 `json:"authentication_type,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	Timeout        time.Duration          `json:"timeout,omitempty"`
	RetryAttempt   int                   `json:"retry_attempt,omitempty"`
	RequestID      string                `json:"request_id,omitempty"`
}

// APIResponseData captures complete API response information
type APIResponseData struct {
	StatusCode       int                    `json:"status_code"`
	Headers          map[string]string      `json:"headers"`
	Body             interface{}            `json:"body,omitempty"`
	ResponseSize     int64                  `json:"response_size_bytes"`
	ResponseTime     time.Duration          `json:"response_time"`
	Timestamp        time.Time              `json:"timestamp"`
	ErrorMessage     string                 `json:"error_message,omitempty"`
	RequestID        string                 `json:"request_id,omitempty"`
	NetworkLatency   time.Duration          `json:"network_latency,omitempty"`
	ProcessingTime   time.Duration          `json:"processing_time,omitempty"`
}

// PerformanceMetrics captures system performance during workflow execution
type PerformanceMetrics struct {
	// CPU metrics
	CPUUsagePercent    float64 `json:"cpu_usage_percent"`
	GoRoutineCount     int     `json:"goroutine_count"`
	ThreadCount        int     `json:"thread_count"`

	// Memory metrics
	MemoryUsageBytes   uint64  `json:"memory_usage_bytes"`
	MemoryAllocBytes   uint64  `json:"memory_alloc_bytes"`
	MemorySystemBytes  uint64  `json:"memory_system_bytes"`
	GCCount            uint32  `json:"gc_count"`
	GCPauseTime        time.Duration `json:"gc_pause_time"`

	// Network metrics (when available)
	NetworkBytesIn     uint64  `json:"network_bytes_in,omitempty"`
	NetworkBytesOut    uint64  `json:"network_bytes_out,omitempty"`
	NetworkConnections int     `json:"network_connections,omitempty"`

	// Disk I/O metrics (when available)
	DiskReadBytes      uint64  `json:"disk_read_bytes,omitempty"`
	DiskWriteBytes     uint64  `json:"disk_write_bytes,omitempty"`

	// Workflow-specific metrics
	StepExecutionCount int     `json:"step_execution_count"`
	ActiveStepCount    int     `json:"active_step_count"`
	QueueDepth         int     `json:"queue_depth,omitempty"`

	Timestamp          time.Time `json:"timestamp"`
}

// ErrorPattern captures structured error information for pattern analysis
type ErrorPattern struct {
	ErrorCode        string                 `json:"error_code"`
	ErrorMessage     string                 `json:"error_message"`
	ErrorType        string                 `json:"error_type"`
	StackTrace       []string               `json:"stack_trace,omitempty"`
	ContextData      map[string]interface{} `json:"context_data,omitempty"`
	PreviousErrors   []string               `json:"previous_errors,omitempty"`
	RecoveryActions  []string               `json:"recovery_actions,omitempty"`
	RetryAttempt     int                   `json:"retry_attempt"`
	IsFatal          bool                  `json:"is_fatal"`
	IsRecoverable    bool                  `json:"is_recoverable"`
	FailureCategory  string                `json:"failure_category"` // "network", "auth", "data", "logic", "resource"
	Timestamp        time.Time             `json:"timestamp"`
}

// MLLogger provides enhanced logging capabilities for machine learning analysis
type MLLogger struct {
	globalLogger     *logging.ModuleLogger
	loggingProvider  interfaces.LoggingProvider
	perfCollector    *PerformanceCollector
	enabled          bool
	bufferSize       int
	flushInterval    time.Duration
	entryBuffer      []MLLogEntry
	bufferMutex      sync.RWMutex
	stopCh           chan struct{}
	wg               sync.WaitGroup
}

// NewMLLogger creates a new ML-enhanced logger for workflow execution
func NewMLLogger(globalLogger *logging.ModuleLogger, provider interfaces.LoggingProvider) *MLLogger {
	ml := &MLLogger{
		globalLogger:    globalLogger,
		loggingProvider: provider,
		perfCollector:   NewPerformanceCollector(),
		enabled:         true,
		bufferSize:      1000,
		flushInterval:   5 * time.Second,
		entryBuffer:     make([]MLLogEntry, 0, 1000),
		stopCh:          make(chan struct{}),
	}

	// Start background flushing
	ml.wg.Add(1)
	go ml.flushLoop()

	return ml
}

// LogExecutionStart logs the beginning of workflow execution with initial state
func (ml *MLLogger) LogExecutionStart(execution *WorkflowExecution, workflow Workflow) {
	if !ml.enabled {
		return
	}

	entry := MLLogEntry{
		Timestamp:        time.Now(),
		ExecutionID:      execution.ID,
		WorkflowName:     execution.WorkflowName,
		EventType:        "execution_start",
		VariableStates:   execution.GetVariables(),
		PerformanceMetrics: ml.perfCollector.CollectMetrics(),
		StartTime:        execution.StartTime,
		MLMetadata: map[string]interface{}{
			"workflow_version": workflow.Version,
			"total_steps":      len(workflow.Steps),
			"timeout":          workflow.Timeout.String(),
		},
	}

	ml.logEntry(entry)
}

// LogExecutionEnd logs the completion of workflow execution with final metrics
func (ml *MLLogger) LogExecutionEnd(execution *WorkflowExecution) {
	if !ml.enabled {
		return
	}

	endTime := time.Now()
	if execution.GetEndTime() != nil {
		endTime = *execution.GetEndTime()
	}

	entry := MLLogEntry{
		Timestamp:        time.Now(),
		ExecutionID:      execution.ID,
		WorkflowName:     execution.WorkflowName,
		EventType:        "execution_end",
		VariableStates:   execution.GetVariables(),
		PerformanceMetrics: ml.perfCollector.CollectMetrics(),
		StartTime:        execution.StartTime,
		EndTime:          endTime,
		Duration:         endTime.Sub(execution.StartTime),
		MLMetadata: map[string]interface{}{
			"final_status":     execution.GetStatus(),
			"total_steps":      len(execution.GetStepResults()),
			"error_message":    execution.GetError(),
		},
	}

	ml.logEntry(entry)
}

// LogStepStart logs the beginning of step execution with variable state
func (ml *MLLogger) LogStepStart(execution *WorkflowExecution, step Step, executionPath []string) {
	if !ml.enabled {
		return
	}

	entry := MLLogEntry{
		Timestamp:        time.Now(),
		ExecutionID:      execution.ID,
		WorkflowName:     execution.WorkflowName,
		StepName:         step.Name,
		EventType:        "step_start",
		VariableStates:   execution.GetVariables(),
		ExecutionPath:    executionPath,
		PerformanceMetrics: ml.perfCollector.CollectMetrics(),
		StartTime:        time.Now(),
		MLMetadata: map[string]interface{}{
			"step_type":   step.Type,
			"step_config": step.Config,
			"timeout":     step.Timeout.String(),
		},
	}

	ml.logEntry(entry)
}

// LogStepEnd logs the completion of step execution with results
func (ml *MLLogger) LogStepEnd(execution *WorkflowExecution, step Step, result StepResult, executionPath []string) {
	if !ml.enabled {
		return
	}

	entry := MLLogEntry{
		Timestamp:        time.Now(),
		ExecutionID:      execution.ID,
		WorkflowName:     execution.WorkflowName,
		StepName:         step.Name,
		EventType:        "step_end",
		VariableStates:   execution.GetVariables(),
		ExecutionPath:    executionPath,
		PerformanceMetrics: ml.perfCollector.CollectMetrics(),
		StartTime:        result.StartTime,
		EndTime:          func() time.Time {
			if result.EndTime != nil {
				return *result.EndTime
			}
			return time.Time{}
		}(),
		Duration:         result.Duration,
		MLMetadata: map[string]interface{}{
			"step_status":   result.Status,
			"retry_count":   result.RetryCount,
			"step_output":   result.Output,
		},
	}

	// Add error pattern if step failed
	if result.Status == StatusFailed && result.ErrorDetails != nil {
		entry.ErrorPattern = &ErrorPattern{
			ErrorCode:       string(result.ErrorDetails.Code),
			ErrorMessage:    result.ErrorDetails.Message,
			ErrorType:       "step_execution",
			StackTrace:      extractStackTrace(result.ErrorDetails.StackTrace),
			ContextData:     result.ErrorDetails.Details,
			RetryAttempt:    result.RetryCount,
			IsFatal:         !result.ErrorDetails.Recoverable,
			IsRecoverable:   result.ErrorDetails.Recoverable,
			FailureCategory: categorizeError(result.ErrorDetails.Code),
			Timestamp:       time.Now(),
		}
	}

	ml.logEntry(entry)
}

// LogVariableChange logs individual variable state changes
func (ml *MLLogger) LogVariableChange(execution *WorkflowExecution, variableName string, oldValue, newValue interface{}, stepContext string) {
	if !ml.enabled {
		return
	}

	change := MLVariableChange{
		VariableName: variableName,
		OldValue:     oldValue,
		NewValue:     newValue,
		ChangeType:   determineChangeType(oldValue, newValue),
		Timestamp:    time.Now(),
		StepContext:  stepContext,
	}

	entry := MLLogEntry{
		Timestamp:       time.Now(),
		ExecutionID:     execution.ID,
		WorkflowName:    execution.WorkflowName,
		StepName:        stepContext,
		EventType:       "variable_change",
		VariableChanges: []MLVariableChange{change},
		VariableStates:  execution.GetVariables(),
	}

	ml.logEntry(entry)
}

// LogAPIRequest logs outgoing API request details
func (ml *MLLogger) LogAPIRequest(execution *WorkflowExecution, stepName, url, method string, headers map[string]string, body interface{}, requestID string) {
	if !ml.enabled {
		return
	}

	entry := MLLogEntry{
		Timestamp:   time.Now(),
		ExecutionID: execution.ID,
		WorkflowName: execution.WorkflowName,
		StepName:    stepName,
		EventType:   "api_request",
		APIRequestData: &APIRequestData{
			URL:       url,
			Method:    method,
			Headers:   headers,
			Body:      body,
			Timestamp: time.Now(),
			RequestID: requestID,
		},
	}

	ml.logEntry(entry)
}

// LogAPIResponse logs incoming API response details
func (ml *MLLogger) LogAPIResponse(execution *WorkflowExecution, stepName string, statusCode int, headers map[string]string, body interface{}, responseTime time.Duration, requestID string) {
	if !ml.enabled {
		return
	}

	responseSize := int64(0)
	if body != nil {
		if bodyBytes, err := json.Marshal(body); err == nil {
			responseSize = int64(len(bodyBytes))
		}
	}

	entry := MLLogEntry{
		Timestamp:   time.Now(),
		ExecutionID: execution.ID,
		WorkflowName: execution.WorkflowName,
		StepName:    stepName,
		EventType:   "api_response",
		APIResponseData: &APIResponseData{
			StatusCode:   statusCode,
			Headers:      headers,
			Body:         body,
			ResponseSize: responseSize,
			ResponseTime: responseTime,
			Timestamp:    time.Now(),
			RequestID:    requestID,
		},
	}

	ml.logEntry(entry)
}

// LogPerformanceSnapshot logs a performance metrics snapshot
func (ml *MLLogger) LogPerformanceSnapshot(execution *WorkflowExecution, stepName string) {
	if !ml.enabled {
		return
	}

	entry := MLLogEntry{
		Timestamp:          time.Now(),
		ExecutionID:        execution.ID,
		WorkflowName:       execution.WorkflowName,
		StepName:           stepName,
		EventType:          "performance_snapshot",
		PerformanceMetrics: ml.perfCollector.CollectMetrics(),
	}

	ml.logEntry(entry)
}

// LogErrorPattern logs structured error information for pattern analysis
func (ml *MLLogger) LogErrorPattern(execution *WorkflowExecution, stepName string, err *WorkflowError) {
	if !ml.enabled {
		return
	}

	entry := MLLogEntry{
		Timestamp:   time.Now(),
		ExecutionID: execution.ID,
		WorkflowName: execution.WorkflowName,
		StepName:    stepName,
		EventType:   "error_pattern",
		ErrorPattern: &ErrorPattern{
			ErrorCode:       string(err.Code),
			ErrorMessage:    err.Message,
			ErrorType:       "workflow_error",
			StackTrace:      extractStackTrace(err.StackTrace),
			ContextData:     err.Details,
			RetryAttempt:    err.RetryAttempt,
			IsFatal:         !err.Recoverable,
			IsRecoverable:   err.Recoverable,
			FailureCategory: categorizeError(err.Code),
			Timestamp:       time.Now(),
		},
	}

	ml.logEntry(entry)
}

// logEntry adds an entry to the buffer for batched writing
func (ml *MLLogger) logEntry(entry MLLogEntry) {
	ml.bufferMutex.Lock()
	defer ml.bufferMutex.Unlock()

	ml.entryBuffer = append(ml.entryBuffer, entry)

	// Flush if buffer is full
	if len(ml.entryBuffer) >= ml.bufferSize {
		go ml.flushBuffer()
	}
}

// flushLoop runs the background flush process
func (ml *MLLogger) flushLoop() {
	defer ml.wg.Done()

	ticker := time.NewTicker(ml.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ml.flushBuffer()
		case <-ml.stopCh:
			ml.flushBuffer() // Final flush
			return
		}
	}
}

// flushBuffer writes buffered entries to the logging provider
func (ml *MLLogger) flushBuffer() {
	ml.bufferMutex.Lock()
	if len(ml.entryBuffer) == 0 {
		ml.bufferMutex.Unlock()
		return
	}

	// Copy buffer and reset
	entries := make([]MLLogEntry, len(ml.entryBuffer))
	copy(entries, ml.entryBuffer)
	ml.entryBuffer = ml.entryBuffer[:0]
	ml.bufferMutex.Unlock()

	// Convert to standard log entries and write
	logEntries := make([]interfaces.LogEntry, len(entries))
	for i, mlEntry := range entries {
		logEntries[i] = ml.convertToLogEntry(mlEntry)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := ml.loggingProvider.WriteBatch(ctx, logEntries); err != nil {
		ml.globalLogger.Error("Failed to write ML log batch", "error", err, "entry_count", len(logEntries))
	}
}

// convertToLogEntry converts MLLogEntry to standard LogEntry format
func (ml *MLLogger) convertToLogEntry(mlEntry MLLogEntry) interfaces.LogEntry {
	// Serialize the entire ML entry as structured data
	mlData, _ := json.Marshal(mlEntry)

	return interfaces.LogEntry{
		Timestamp:   mlEntry.Timestamp,
		Level:       "INFO",
		Message:     fmt.Sprintf("ML workflow event: %s", mlEntry.EventType),
		ServiceName: "workflow_engine",
		Component:   "ml_logger",
		Fields: map[string]interface{}{
			"ml_event_type":    mlEntry.EventType,
			"execution_id":     mlEntry.ExecutionID,
			"workflow_name":    mlEntry.WorkflowName,
			"step_name":        mlEntry.StepName,
			"ml_data":          string(mlData),
		},
	}
}

// Close cleanly shuts down the ML logger
func (ml *MLLogger) Close() error {
	ml.enabled = false
	close(ml.stopCh)
	ml.wg.Wait()
	return nil
}

// Helper functions

func extractStackTrace(stackFrames []StackFrame) []string {
	traces := make([]string, len(stackFrames))
	for i, frame := range stackFrames {
		traces[i] = fmt.Sprintf("%s (%s:%d)", frame.Function, frame.File, frame.Line)
	}
	return traces
}

func categorizeError(code ErrorCode) string {
	switch code {
	case ErrorCodeHTTPRequest, ErrorCodeAPIRequest, ErrorCodeWebhookDelivery:
		return "network"
	case ErrorCodeAuthenticationFailure:
		return "auth"
	case ErrorCodeValidation, ErrorCodeVariableResolution:
		return "data"
	case ErrorCodeConditionEvaluation, ErrorCodeLoopExecution:
		return "logic"
	case ErrorCodeTimeout, ErrorCodeRateLimitExceeded:
		return "resource"
	default:
		return "unknown"
	}
}

func determineChangeType(oldValue, newValue interface{}) string {
	if oldValue == nil && newValue != nil {
		return "create"
	} else if oldValue != nil && newValue == nil {
		return "delete"
	} else {
		return "update"
	}
}