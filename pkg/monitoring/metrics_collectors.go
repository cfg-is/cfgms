// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package monitoring

import (
	"context"
	"math"
	"runtime"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// BasicMetricsCollector provides basic metrics collection functionality.
type BasicMetricsCollector struct {
	componentName string
	logger        logging.Logger
	startTime     time.Time
}

// NewBasicMetricsCollector creates a new basic metrics collector.
func NewBasicMetricsCollector(componentName string, logger logging.Logger) *BasicMetricsCollector {
	return &BasicMetricsCollector{
		componentName: componentName,
		logger:        logger,
		startTime:     time.Now(),
	}
}

// CollectMetrics collects basic metrics for the component.
func (bmc *BasicMetricsCollector) CollectMetrics(ctx context.Context) (*ComponentMetrics, error) {
	metrics := &ComponentMetrics{
		ComponentName: bmc.componentName,
		Timestamp:     time.Now(),
		Performance:   &PerformanceMetrics{},
		Resource:      &ResourceMetrics{},
		Business:      make(map[string]interface{}),
		Custom:        make(map[string]interface{}),
	}

	// Collect runtime metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Safe conversion to prevent integer overflow
	if memStats.Alloc > math.MaxInt64 {
		metrics.Resource.MemoryBytes = math.MaxInt64
	} else {
		metrics.Resource.MemoryBytes = int64(memStats.Alloc)
	}
	metrics.Resource.Goroutines = runtime.NumGoroutine()

	// Basic performance metrics
	metrics.Performance.ResponseTime = 0 // Will be overridden by specific collectors
	metrics.Performance.Throughput = 0
	metrics.Performance.ErrorRate = 0
	metrics.Performance.SuccessRate = 100.0
	metrics.Performance.RequestCount = 0
	metrics.Performance.ActiveConnections = 0

	// System resource metrics (basic approximations)
	metrics.Resource.CPUPercent = float64(runtime.NumGoroutine()) / 100.0 // Rough approximation
	metrics.Resource.MemoryPercent = float64(memStats.Alloc) / float64(memStats.Sys) * 100.0
	metrics.Resource.DiskBytes = 0 // TODO: Implement disk usage collection
	metrics.Resource.DiskPercent = 0
	metrics.Resource.NetworkBytesIn = 0
	metrics.Resource.NetworkBytesOut = 0
	metrics.Resource.FileDescriptors = 0 // TODO: Implement FD counting

	// Custom metrics
	metrics.Custom["uptime_seconds"] = time.Since(bmc.startTime).Seconds()
	metrics.Custom["gc_count"] = memStats.NumGC
	metrics.Custom["gc_pause_ns"] = memStats.PauseTotalNs
	metrics.Custom["heap_objects"] = memStats.HeapObjects

	return metrics, nil
}

// GetMetricsSchema returns the schema for basic metrics.
func (bmc *BasicMetricsCollector) GetMetricsSchema() MetricsSchema {
	return MetricsSchema{
		ComponentName: bmc.componentName,
		Version:       "1.0",
		Fields: map[string]MetricsFieldSpec{
			"memory_bytes": {
				Type:        "integer",
				Description: "Memory allocated in bytes",
				Unit:        "bytes",
				Min:         0,
			},
			"goroutines": {
				Type:        "integer",
				Description: "Number of active goroutines",
				Unit:        "count",
				Min:         0,
			},
			"cpu_percent": {
				Type:        "float",
				Description: "CPU utilization percentage",
				Unit:        "percent",
				Min:         0.0,
				Max:         100.0,
			},
			"response_time": {
				Type:        "duration",
				Description: "Average response time",
				Unit:        "nanoseconds",
				Min:         0,
			},
			"throughput": {
				Type:        "float",
				Description: "Requests per second",
				Unit:        "rps",
				Min:         0.0,
			},
			"error_rate": {
				Type:        "float",
				Description: "Error rate percentage",
				Unit:        "percent",
				Min:         0.0,
				Max:         100.0,
			},
		},
	}
}

// ControllerMetricsCollector provides metrics collection for controller components.
type ControllerMetricsCollector struct {
	*BasicMetricsCollector
	requestCount      int64
	errorCount        int64
	totalResponseTime time.Duration
	activeConnections int64
}

// NewControllerMetricsCollector creates a metrics collector for controller components.
func NewControllerMetricsCollector(logger logging.Logger) *ControllerMetricsCollector {
	return &ControllerMetricsCollector{
		BasicMetricsCollector: NewBasicMetricsCollector("controller", logger),
	}
}

// RecordRequest records a completed request with its duration and success status.
func (cmc *ControllerMetricsCollector) RecordRequest(duration time.Duration, success bool) {
	cmc.requestCount++
	cmc.totalResponseTime += duration
	if !success {
		cmc.errorCount++
	}
}

// RecordActiveConnection records a change in active connections.
func (cmc *ControllerMetricsCollector) RecordActiveConnection(delta int64) {
	cmc.activeConnections += delta
	if cmc.activeConnections < 0 {
		cmc.activeConnections = 0
	}
}

// CollectMetrics collects controller-specific metrics.
func (cmc *ControllerMetricsCollector) CollectMetrics(ctx context.Context) (*ComponentMetrics, error) {
	metrics, err := cmc.BasicMetricsCollector.CollectMetrics(ctx)
	if err != nil {
		return nil, err
	}

	// Update performance metrics
	metrics.Performance.RequestCount = cmc.requestCount
	metrics.Performance.ActiveConnections = cmc.activeConnections

	if cmc.requestCount > 0 {
		metrics.Performance.ResponseTime = cmc.totalResponseTime / time.Duration(cmc.requestCount)
		metrics.Performance.ErrorRate = float64(cmc.errorCount) / float64(cmc.requestCount) * 100.0
		metrics.Performance.SuccessRate = 100.0 - metrics.Performance.ErrorRate

		// Calculate throughput (requests per second over uptime)
		uptime := time.Since(cmc.startTime)
		if uptime > 0 {
			metrics.Performance.Throughput = float64(cmc.requestCount) / uptime.Seconds()
		}
	}

	// Business metrics
	metrics.Business["total_requests"] = cmc.requestCount
	metrics.Business["total_errors"] = cmc.errorCount
	metrics.Business["active_sessions"] = cmc.activeConnections

	return metrics, nil
}

// StewardMetricsCollector provides metrics collection for steward components.
type StewardMetricsCollector struct {
	*BasicMetricsCollector
	configExecutions int64
	configErrors     int64
	moduleExecutions map[string]int64
	lastHeartbeat    time.Time
	connectionUptime time.Duration
}

// NewStewardMetricsCollector creates a metrics collector for steward components.
func NewStewardMetricsCollector(logger logging.Logger) *StewardMetricsCollector {
	return &StewardMetricsCollector{
		BasicMetricsCollector: NewBasicMetricsCollector("steward", logger),
		moduleExecutions:      make(map[string]int64),
		lastHeartbeat:         time.Now(),
	}
}

// RecordConfigExecution records a configuration execution.
func (smc *StewardMetricsCollector) RecordConfigExecution(success bool) {
	smc.configExecutions++
	if !success {
		smc.configErrors++
	}
}

// RecordModuleExecution records a module execution.
func (smc *StewardMetricsCollector) RecordModuleExecution(moduleName string) {
	smc.moduleExecutions[moduleName]++
}

// UpdateHeartbeat updates the last heartbeat time.
func (smc *StewardMetricsCollector) UpdateHeartbeat() {
	smc.lastHeartbeat = time.Now()
}

// UpdateConnectionUptime updates the connection uptime.
func (smc *StewardMetricsCollector) UpdateConnectionUptime(uptime time.Duration) {
	smc.connectionUptime = uptime
}

// CollectMetrics collects steward-specific metrics.
func (smc *StewardMetricsCollector) CollectMetrics(ctx context.Context) (*ComponentMetrics, error) {
	metrics, err := smc.BasicMetricsCollector.CollectMetrics(ctx)
	if err != nil {
		return nil, err
	}

	// Update performance metrics
	if smc.configExecutions > 0 {
		metrics.Performance.ErrorRate = float64(smc.configErrors) / float64(smc.configExecutions) * 100.0
		metrics.Performance.SuccessRate = 100.0 - metrics.Performance.ErrorRate
	}

	// Business metrics
	metrics.Business["config_executions"] = smc.configExecutions
	metrics.Business["config_errors"] = smc.configErrors
	metrics.Business["module_executions"] = smc.moduleExecutions
	metrics.Business["connection_uptime_seconds"] = smc.connectionUptime.Seconds()
	metrics.Business["heartbeat_age_seconds"] = time.Since(smc.lastHeartbeat).Seconds()

	return metrics, nil
}

// WorkflowMetricsCollector provides metrics collection for workflow components.
type WorkflowMetricsCollector struct {
	*BasicMetricsCollector
	workflowExecutions map[string]int64
	workflowErrors     map[string]int64
	totalExecutionTime time.Duration
	activeWorkflows    int64
}

// NewWorkflowMetricsCollector creates a metrics collector for workflow components.
func NewWorkflowMetricsCollector(logger logging.Logger) *WorkflowMetricsCollector {
	return &WorkflowMetricsCollector{
		BasicMetricsCollector: NewBasicMetricsCollector("workflow", logger),
		workflowExecutions:    make(map[string]int64),
		workflowErrors:        make(map[string]int64),
	}
}

// RecordWorkflowExecution records a workflow execution.
func (wmc *WorkflowMetricsCollector) RecordWorkflowExecution(workflowName string, duration time.Duration, success bool) {
	wmc.workflowExecutions[workflowName]++
	wmc.totalExecutionTime += duration
	if !success {
		wmc.workflowErrors[workflowName]++
	}
}

// UpdateActiveWorkflows updates the count of active workflows.
func (wmc *WorkflowMetricsCollector) UpdateActiveWorkflows(count int64) {
	wmc.activeWorkflows = count
}

// CollectMetrics collects workflow-specific metrics.
func (wmc *WorkflowMetricsCollector) CollectMetrics(ctx context.Context) (*ComponentMetrics, error) {
	metrics, err := wmc.BasicMetricsCollector.CollectMetrics(ctx)
	if err != nil {
		return nil, err
	}

	// Calculate totals
	totalExecutions := int64(0)
	totalErrors := int64(0)

	for _, count := range wmc.workflowExecutions {
		totalExecutions += count
	}
	for _, count := range wmc.workflowErrors {
		totalErrors += count
	}

	// Update performance metrics
	if totalExecutions > 0 {
		metrics.Performance.ResponseTime = wmc.totalExecutionTime / time.Duration(totalExecutions)
		metrics.Performance.ErrorRate = float64(totalErrors) / float64(totalExecutions) * 100.0
		metrics.Performance.SuccessRate = 100.0 - metrics.Performance.ErrorRate

		// Calculate throughput
		uptime := time.Since(wmc.startTime)
		if uptime > 0 {
			metrics.Performance.Throughput = float64(totalExecutions) / uptime.Seconds()
		}
	}

	metrics.Performance.ActiveConnections = wmc.activeWorkflows

	// Business metrics
	metrics.Business["workflow_executions"] = wmc.workflowExecutions
	metrics.Business["workflow_errors"] = wmc.workflowErrors
	metrics.Business["total_executions"] = totalExecutions
	metrics.Business["total_errors"] = totalErrors
	metrics.Business["active_workflows"] = wmc.activeWorkflows

	return metrics, nil
}

// StorageMetricsCollector provides metrics collection for storage systems.
type StorageMetricsCollector struct {
	*BasicMetricsCollector
	readOperations   int64
	writeOperations  int64
	deleteOperations int64
	readErrors       int64
	writeErrors      int64
	deleteErrors     int64
	totalReadTime    time.Duration
	totalWriteTime   time.Duration
	totalDeleteTime  time.Duration
}

// NewStorageMetricsCollector creates a metrics collector for storage systems.
func NewStorageMetricsCollector(logger logging.Logger) *StorageMetricsCollector {
	return &StorageMetricsCollector{
		BasicMetricsCollector: NewBasicMetricsCollector("storage", logger),
	}
}

// RecordRead records a read operation.
func (smc *StorageMetricsCollector) RecordRead(duration time.Duration, success bool) {
	smc.readOperations++
	smc.totalReadTime += duration
	if !success {
		smc.readErrors++
	}
}

// RecordWrite records a write operation.
func (smc *StorageMetricsCollector) RecordWrite(duration time.Duration, success bool) {
	smc.writeOperations++
	smc.totalWriteTime += duration
	if !success {
		smc.writeErrors++
	}
}

// RecordDelete records a delete operation.
func (smc *StorageMetricsCollector) RecordDelete(duration time.Duration, success bool) {
	smc.deleteOperations++
	smc.totalDeleteTime += duration
	if !success {
		smc.deleteErrors++
	}
}

// CollectMetrics collects storage-specific metrics.
func (smc *StorageMetricsCollector) CollectMetrics(ctx context.Context) (*ComponentMetrics, error) {
	metrics, err := smc.BasicMetricsCollector.CollectMetrics(ctx)
	if err != nil {
		return nil, err
	}

	totalOperations := smc.readOperations + smc.writeOperations + smc.deleteOperations
	totalErrors := smc.readErrors + smc.writeErrors + smc.deleteErrors
	totalTime := smc.totalReadTime + smc.totalWriteTime + smc.totalDeleteTime

	// Update performance metrics
	if totalOperations > 0 {
		metrics.Performance.ResponseTime = totalTime / time.Duration(totalOperations)
		metrics.Performance.ErrorRate = float64(totalErrors) / float64(totalOperations) * 100.0
		metrics.Performance.SuccessRate = 100.0 - metrics.Performance.ErrorRate

		// Calculate throughput
		uptime := time.Since(smc.startTime)
		if uptime > 0 {
			metrics.Performance.Throughput = float64(totalOperations) / uptime.Seconds()
		}
	}

	// Business metrics
	metrics.Business["read_operations"] = smc.readOperations
	metrics.Business["write_operations"] = smc.writeOperations
	metrics.Business["delete_operations"] = smc.deleteOperations
	metrics.Business["read_errors"] = smc.readErrors
	metrics.Business["write_errors"] = smc.writeErrors
	metrics.Business["delete_errors"] = smc.deleteErrors
	metrics.Business["avg_read_time_ns"] = int64(0)
	metrics.Business["avg_write_time_ns"] = int64(0)
	metrics.Business["avg_delete_time_ns"] = int64(0)

	if smc.readOperations > 0 {
		metrics.Business["avg_read_time_ns"] = smc.totalReadTime.Nanoseconds() / smc.readOperations
	}
	if smc.writeOperations > 0 {
		metrics.Business["avg_write_time_ns"] = smc.totalWriteTime.Nanoseconds() / smc.writeOperations
	}
	if smc.deleteOperations > 0 {
		metrics.Business["avg_delete_time_ns"] = smc.totalDeleteTime.Nanoseconds() / smc.deleteOperations
	}

	return metrics, nil
}
