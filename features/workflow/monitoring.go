package workflow

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// Monitor provides monitoring and metrics for workflow executions
type Monitor struct {
	logger   logging.Logger
	metrics  *WorkflowMetrics
	mutex    sync.RWMutex
	watchers map[string][]ExecutionWatcher
}

// WorkflowMetrics contains aggregated metrics for workflow executions
type WorkflowMetrics struct {
	TotalExecutions     int64             `json:"total_executions"`
	CompletedExecutions int64             `json:"completed_executions"`
	FailedExecutions    int64             `json:"failed_executions"`
	CancelledExecutions int64             `json:"cancelled_executions"`
	AverageExecutionTime time.Duration    `json:"average_execution_time"`
	WorkflowStats       map[string]*WorkflowStats `json:"workflow_stats"`
	LastUpdated         time.Time         `json:"last_updated"`
}

// WorkflowStats contains statistics for a specific workflow
type WorkflowStats struct {
	ExecutionCount   int64         `json:"execution_count"`
	SuccessCount     int64         `json:"success_count"`
	FailureCount     int64         `json:"failure_count"`
	AverageTime      time.Duration `json:"average_time"`
	LastExecution    time.Time     `json:"last_execution"`
	TotalSteps       int64         `json:"total_steps"`
	SuccessfulSteps  int64         `json:"successful_steps"`
	FailedSteps      int64         `json:"failed_steps"`
}

// ExecutionEvent represents an event in workflow execution
type ExecutionEvent struct {
	ExecutionID string            `json:"execution_id"`
	WorkflowName string           `json:"workflow_name"`
	EventType   ExecutionEventType `json:"event_type"`
	StepName    string            `json:"step_name,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// ExecutionEventType defines the type of execution event
type ExecutionEventType string

const (
	EventExecutionStarted   ExecutionEventType = "execution_started"
	EventExecutionCompleted ExecutionEventType = "execution_completed"
	EventExecutionFailed    ExecutionEventType = "execution_failed"
	EventExecutionCancelled ExecutionEventType = "execution_cancelled"
	EventStepStarted        ExecutionEventType = "step_started"
	EventStepCompleted      ExecutionEventType = "step_completed"
	EventStepFailed         ExecutionEventType = "step_failed"
	EventStepSkipped        ExecutionEventType = "step_skipped"
)

// ExecutionWatcher defines the interface for watching workflow executions
type ExecutionWatcher interface {
	OnEvent(event ExecutionEvent)
}

// NewMonitor creates a new workflow monitor
func NewMonitor(logger logging.Logger) *Monitor {
	return &Monitor{
		logger: logger,
		metrics: &WorkflowMetrics{
			WorkflowStats: make(map[string]*WorkflowStats),
			LastUpdated:   time.Now(),
		},
		watchers: make(map[string][]ExecutionWatcher),
	}
}

// TrackExecution records metrics for a workflow execution
func (m *Monitor) TrackExecution(execution *WorkflowExecution) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.metrics.TotalExecutions++

	// Update workflow-specific stats
	workflowStats := m.getOrCreateWorkflowStats(execution.WorkflowName)
	workflowStats.ExecutionCount++
	workflowStats.LastExecution = execution.StartTime

	// Calculate step statistics using thread-safe access
	stepResults := make(map[string]StepResult)
	execution.mutex.RLock()
	for k, v := range execution.StepResults {
		stepResults[k] = v
	}
	execution.mutex.RUnlock()

	totalSteps := int64(len(stepResults))
	successfulSteps := int64(0)
	failedSteps := int64(0)

	for _, result := range stepResults {
		if result.Status == StatusCompleted {
			successfulSteps++
		} else if result.Status == StatusFailed {
			failedSteps++
		}
	}

	workflowStats.TotalSteps += totalSteps
	workflowStats.SuccessfulSteps += successfulSteps
	workflowStats.FailedSteps += failedSteps

	// Update execution status metrics
	switch execution.Status {
	case StatusCompleted:
		m.metrics.CompletedExecutions++
		workflowStats.SuccessCount++
		
		// Update execution time
		if execution.EndTime != nil {
			duration := execution.EndTime.Sub(execution.StartTime)
			if workflowStats.AverageTime == 0 {
				workflowStats.AverageTime = duration
			} else {
				workflowStats.AverageTime = time.Duration(
					(int64(workflowStats.AverageTime) + int64(duration)) / 2,
				)
			}
		}

	case StatusFailed:
		m.metrics.FailedExecutions++
		workflowStats.FailureCount++

	case StatusCancelled:
		m.metrics.CancelledExecutions++
	}

	// Update average execution time
	if m.metrics.CompletedExecutions > 0 {
		totalTime := time.Duration(0)
		count := int64(0)
		
		for _, stats := range m.metrics.WorkflowStats {
			if stats.AverageTime > 0 && stats.SuccessCount > 0 {
				totalTime += time.Duration(int64(stats.AverageTime) * stats.SuccessCount)
				count += stats.SuccessCount
			}
		}
		
		if count > 0 {
			m.metrics.AverageExecutionTime = totalTime / time.Duration(count)
		}
	}

	m.metrics.LastUpdated = time.Now()

	// Emit tracking event
	m.emitEvent(ExecutionEvent{
		ExecutionID:  execution.ID,
		WorkflowName: execution.WorkflowName,
		EventType:    m.getEventTypeFromStatus(execution.Status),
		Timestamp:    time.Now(),
		Data: map[string]interface{}{
			"total_steps":      totalSteps,
			"successful_steps": successfulSteps,
			"failed_steps":     failedSteps,
			"duration":         execution.EndTime.Sub(execution.StartTime).String(),
		},
	})
}

// TrackStepExecution records metrics for a step execution
func (m *Monitor) TrackStepExecution(executionID, workflowName, stepName string, result StepResult) {
	event := ExecutionEvent{
		ExecutionID:  executionID,
		WorkflowName: workflowName,
		StepName:     stepName,
		EventType:    m.getEventTypeFromStepStatus(result.Status),
		Timestamp:    time.Now(),
		Data: map[string]interface{}{
			"duration":    result.Duration.String(),
			"retry_count": result.RetryCount,
		},
	}

	if result.Error != "" {
		event.Data["error"] = result.Error
	}

	m.emitEvent(event)
}

// GetMetrics returns the current workflow metrics
func (m *Monitor) GetMetrics() WorkflowMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Deep copy to avoid race conditions
	metricsCopy := *m.metrics
	metricsCopy.WorkflowStats = make(map[string]*WorkflowStats)
	
	for name, stats := range m.metrics.WorkflowStats {
		statsCopy := *stats
		metricsCopy.WorkflowStats[name] = &statsCopy
	}

	return metricsCopy
}

// GetWorkflowStats returns statistics for a specific workflow
func (m *Monitor) GetWorkflowStats(workflowName string) (*WorkflowStats, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats, exists := m.metrics.WorkflowStats[workflowName]
	if !exists {
		return nil, false
	}

	// Return a copy
	statsCopy := *stats
	return &statsCopy, true
}

// AddWatcher adds a watcher for workflow execution events
func (m *Monitor) AddWatcher(executionID string, watcher ExecutionWatcher) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.watchers[executionID] = append(m.watchers[executionID], watcher)
}

// RemoveWatcher removes a watcher for workflow execution events
func (m *Monitor) RemoveWatcher(executionID string, watcher ExecutionWatcher) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	watchers := m.watchers[executionID]
	for i, w := range watchers {
		if w == watcher {
			m.watchers[executionID] = append(watchers[:i], watchers[i+1:]...)
			break
		}
	}

	if len(m.watchers[executionID]) == 0 {
		delete(m.watchers, executionID)
	}
}

// getOrCreateWorkflowStats gets or creates workflow statistics
func (m *Monitor) getOrCreateWorkflowStats(workflowName string) *WorkflowStats {
	stats, exists := m.metrics.WorkflowStats[workflowName]
	if !exists {
		stats = &WorkflowStats{}
		m.metrics.WorkflowStats[workflowName] = stats
	}
	return stats
}

// emitEvent emits an execution event to all watchers
func (m *Monitor) emitEvent(event ExecutionEvent) {
	// Log the event
	m.logger.Info("Workflow execution event",
		"execution_id", event.ExecutionID,
		"workflow", event.WorkflowName,
		"event_type", event.EventType,
		"step", event.StepName)

	// Notify watchers
	m.mutex.RLock()
	watchers := make([]ExecutionWatcher, len(m.watchers[event.ExecutionID]))
	copy(watchers, m.watchers[event.ExecutionID])
	m.mutex.RUnlock()

	for _, watcher := range watchers {
		go func(w ExecutionWatcher) {
			defer func() {
				if r := recover(); r != nil {
					m.logger.Error("Watcher panicked",
						"execution_id", event.ExecutionID,
						"error", r)
				}
			}()
			w.OnEvent(event)
		}(watcher)
	}
}

// getEventTypeFromStatus converts execution status to event type
func (m *Monitor) getEventTypeFromStatus(status ExecutionStatus) ExecutionEventType {
	switch status {
	case StatusRunning:
		return EventExecutionStarted
	case StatusCompleted:
		return EventExecutionCompleted
	case StatusFailed:
		return EventExecutionFailed
	case StatusCancelled:
		return EventExecutionCancelled
	default:
		return EventExecutionStarted
	}
}

// getEventTypeFromStepStatus converts step status to event type
func (m *Monitor) getEventTypeFromStepStatus(status ExecutionStatus) ExecutionEventType {
	switch status {
	case StatusRunning:
		return EventStepStarted
	case StatusCompleted:
		return EventStepCompleted
	case StatusFailed:
		return EventStepFailed
	default:
		return EventStepStarted
	}
}

// LoggingWatcher is a simple watcher that logs execution events
type LoggingWatcher struct {
	logger logging.Logger
}

// NewLoggingWatcher creates a new logging watcher
func NewLoggingWatcher(logger logging.Logger) *LoggingWatcher {
	return &LoggingWatcher{logger: logger}
}

// OnEvent logs the execution event
func (w *LoggingWatcher) OnEvent(event ExecutionEvent) {
	data, err := json.Marshal(event.Data)
	if err != nil {
		data = []byte("{\"error\": \"failed to marshal event data\"}")
	}
	
	w.logger.Info("Workflow event",
		"execution_id", event.ExecutionID,
		"workflow", event.WorkflowName,
		"event_type", event.EventType,
		"step", event.StepName,
		"timestamp", event.Timestamp.Format(time.RFC3339),
		"data", string(data))
}

// ReportGenerator provides workflow execution reports
type ReportGenerator struct {
	monitor *Monitor
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(monitor *Monitor) *ReportGenerator {
	return &ReportGenerator{monitor: monitor}
}

// GenerateReport generates a comprehensive workflow execution report
func (r *ReportGenerator) GenerateReport() string {
	metrics := r.monitor.GetMetrics()
	
	report := fmt.Sprintf("Workflow Execution Report\n")
	report += fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339))
	
	report += fmt.Sprintf("Overall Statistics:\n")
	report += fmt.Sprintf("  Total Executions: %d\n", metrics.TotalExecutions)
	report += fmt.Sprintf("  Completed: %d\n", metrics.CompletedExecutions)
	report += fmt.Sprintf("  Failed: %d\n", metrics.FailedExecutions)
	report += fmt.Sprintf("  Cancelled: %d\n", metrics.CancelledExecutions)
	
	if metrics.AverageExecutionTime > 0 {
		report += fmt.Sprintf("  Average Execution Time: %s\n", metrics.AverageExecutionTime)
	}
	
	report += fmt.Sprintf("\nWorkflow Statistics:\n")
	for workflowName, stats := range metrics.WorkflowStats {
		successRate := float64(0)
		if stats.ExecutionCount > 0 {
			successRate = float64(stats.SuccessCount) / float64(stats.ExecutionCount) * 100
		}
		
		report += fmt.Sprintf("  %s:\n", workflowName)
		report += fmt.Sprintf("    Executions: %d\n", stats.ExecutionCount)
		report += fmt.Sprintf("    Success Rate: %.1f%%\n", successRate)
		report += fmt.Sprintf("    Average Time: %s\n", stats.AverageTime)
		report += fmt.Sprintf("    Last Execution: %s\n", stats.LastExecution.Format(time.RFC3339))
		report += fmt.Sprintf("    Total Steps: %d\n", stats.TotalSteps)
		report += fmt.Sprintf("    Successful Steps: %d\n", stats.SuccessfulSteps)
		report += fmt.Sprintf("    Failed Steps: %d\n", stats.FailedSteps)
		report += "\n"
	}
	
	return report
}