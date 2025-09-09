package monitoring

import (
	"context"
	"runtime"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// metricsCollectionLoop runs the periodic metrics collection.
func (sm *SystemMonitor) metricsCollectionLoop(ctx context.Context) {
	ticker := time.NewTicker(sm.config.MetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.collectMetrics(ctx)
		case <-sm.shutdownCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// collectMetrics collects metrics from all registered collectors.
func (sm *SystemMonitor) collectMetrics(ctx context.Context) {
	ctx, span := sm.tracer.Start(ctx, "system_monitor.collect_metrics")
	defer span.End()
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	startTime := time.Now()
	
	// Collect from all registered collectors
	for name, collector := range sm.collectors {
		collectorCtx, collectorSpan := sm.tracer.Start(ctx, "system_monitor.collect_from_collector")
		collectorSpan.SetAttributes(
			attribute.String("collector_name", name),
			attribute.String("component_name", collector.GetComponentName()),
		)
		
		metrics, err := collector.CollectMetrics(collectorCtx)
		if err != nil {
			sm.logger.ErrorCtx(collectorCtx, "Failed to collect metrics",
				"collector_name", name,
				"error", err)
			
			// Emit error event
			sm.emitEvent(SystemEvent{
				ID:            telemetry.GenerateCorrelationID(),
				Type:          EventResourceAlert,
				Source:        "system_monitor",
				Component:     "metrics_collection",
				Timestamp:     time.Now(),
				CorrelationID: telemetry.GetCorrelationID(collectorCtx),
				Severity:      SeverityError,
				Data: map[string]interface{}{
					"collector_name": name,
					"error":          err.Error(),
				},
			})
		} else {
			sm.systemMetrics.ComponentMetrics[name] = metrics
		}
		
		collectorSpan.End()
	}
	
	// Update workflow metrics from workflow monitor
	workflowMetrics := sm.workflowMonitor.GetMetrics()
	sm.systemMetrics.WorkflowExecutions = workflowMetrics.TotalExecutions
	sm.systemMetrics.WorkflowSuccesses = workflowMetrics.CompletedExecutions
	sm.systemMetrics.WorkflowFailures = workflowMetrics.FailedExecutions
	
	// Update timestamp
	sm.systemMetrics.LastUpdated = time.Now()
	
	// Log collection time
	collectionTime := time.Since(startTime)
	sm.logger.DebugCtx(ctx, "Metrics collection completed",
		"collection_time_ms", collectionTime.Milliseconds(),
		"collectors_count", len(sm.collectors))
	
	// Export metrics if export manager is configured
	if sm.exportManager != nil {
		sm.exportMetrics(ctx)
	}
}

// resourceMonitoringLoop runs the periodic resource monitoring.
func (sm *SystemMonitor) resourceMonitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(sm.config.ResourceInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.collectResourceMetrics(ctx)
		case <-sm.shutdownCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// collectResourceMetrics collects system resource metrics.
func (sm *SystemMonitor) collectResourceMetrics(ctx context.Context) {
	ctx, span := sm.tracer.Start(ctx, "system_monitor.collect_resource_metrics")
	defer span.End()
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// Collect memory statistics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	// Update resource metrics
	sm.resourceMetrics.MemoryUsedBytes = memStats.Alloc
	sm.resourceMetrics.MemoryTotalBytes = memStats.Sys
	if sm.resourceMetrics.MemoryTotalBytes > 0 {
		sm.resourceMetrics.MemoryUsagePercent = float64(sm.resourceMetrics.MemoryUsedBytes) / float64(sm.resourceMetrics.MemoryTotalBytes) * 100
	}
	
	// Collect GC metrics if enabled
	if sm.config.EnableDetailedGCMetrics {
		sm.resourceMetrics.GCCycles = memStats.NumGC
		// Note: CPU usage would require platform-specific implementations
		// For now, we'll use a placeholder that could be enhanced with cgo or platform-specific packages
	}
	
	// Collect goroutine count
	sm.resourceMetrics.Goroutines = runtime.NumGoroutine()
	sm.resourceMetrics.CPUCores = runtime.NumCPU()
	sm.resourceMetrics.CollectedAt = time.Now()
	
	// Release the lock before checking alerts to avoid deadlock with emitEvent
	sm.mu.Unlock()
	
	// Check for resource alerts (this may call emitEvent which needs RLock)
	sm.checkResourceAlerts(ctx)
	
	// Re-acquire lock for the defer statement
	sm.mu.Lock()
	
	sm.logger.DebugCtx(ctx, "Resource metrics collected",
		"memory_used_mb", sm.resourceMetrics.MemoryUsedBytes/1024/1024,
		"memory_usage_percent", sm.resourceMetrics.MemoryUsagePercent,
		"goroutines", sm.resourceMetrics.Goroutines)
}

// checkResourceAlerts checks if any resource thresholds are exceeded.
func (sm *SystemMonitor) checkResourceAlerts(ctx context.Context) {
	// Memory usage alert
	if sm.resourceMetrics.MemoryUsagePercent > sm.config.MemoryAlertThreshold {
		sm.emitEvent(SystemEvent{
			ID:            telemetry.GenerateCorrelationID(),
			Type:          EventResourceAlert,
			Source:        "system_monitor",
			Component:     "resource_monitoring",
			Timestamp:     time.Now(),
			CorrelationID: telemetry.GetCorrelationID(ctx),
			Severity:      SeverityWarning,
			Data: map[string]interface{}{
				"metric":      "memory_usage",
				"value":       sm.resourceMetrics.MemoryUsagePercent,
				"threshold":   sm.config.MemoryAlertThreshold,
				"used_bytes":  sm.resourceMetrics.MemoryUsedBytes,
				"total_bytes": sm.resourceMetrics.MemoryTotalBytes,
			},
		})
	}
	
	// Goroutine count alert
	if sm.resourceMetrics.Goroutines > sm.config.GoroutineAlertThreshold {
		sm.emitEvent(SystemEvent{
			ID:            telemetry.GenerateCorrelationID(),
			Type:          EventResourceAlert,
			Source:        "system_monitor",
			Component:     "resource_monitoring",
			Timestamp:     time.Now(),
			CorrelationID: telemetry.GetCorrelationID(ctx),
			Severity:      SeverityWarning,
			Data: map[string]interface{}{
				"metric":    "goroutines",
				"value":     sm.resourceMetrics.Goroutines,
				"threshold": sm.config.GoroutineAlertThreshold,
			},
		})
	}
}

// healthCheckLoop runs periodic health checks.
func (sm *SystemMonitor) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(sm.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.performHealthChecks(ctx)
		case <-sm.shutdownCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// performHealthChecks runs health checks on all registered collectors.
func (sm *SystemMonitor) performHealthChecks(ctx context.Context) {
	ctx, span := sm.tracer.Start(ctx, "system_monitor.health_checks")
	defer span.End()
	
	sm.mu.RLock()
	collectors := make(map[string]MetricsCollector)
	for name, collector := range sm.collectors {
		collectors[name] = collector
	}
	sm.mu.RUnlock()
	
	healthyCount := 0
	totalCount := len(collectors)
	
	for name, collector := range collectors {
		healthCtx, healthSpan := sm.tracer.Start(ctx, "system_monitor.health_check_collector")
		healthSpan.SetAttributes(
			attribute.String("collector_name", name),
			attribute.String("component_name", collector.GetComponentName()),
		)
		
		status, err := collector.GetHealthStatus(healthCtx)
		if err != nil {
			sm.logger.WarnCtx(healthCtx, "Health check failed",
				"collector_name", name,
				"error", err)
		} else if status.Status == "healthy" {
			healthyCount++
		}
		
		healthSpan.End()
	}
	
	sm.logger.DebugCtx(ctx, "Health checks completed",
		"healthy_collectors", healthyCount,
		"total_collectors", totalCount,
		"health_percentage", float64(healthyCount)/float64(totalCount)*100)
}

// emitEvent emits a system event to all registered watchers.
func (sm *SystemMonitor) emitEvent(event SystemEvent) {
	// Inject correlation context if tracer is available
	if sm.config.EnableEventCorrelation && sm.tracer != nil && event.CorrelationID == "" {
		event.CorrelationID = telemetry.GenerateCorrelationID()
	}
	
	// Export event if export manager is configured
	if sm.exportManager != nil {
		go sm.exportEvent(context.Background(), event)
	}
	
	// Find watchers for this event type and "all" events
	var watchersToNotify []SystemEventWatcher
	
	sm.mu.RLock()
	if watchers, exists := sm.watchers[string(event.Type)]; exists {
		watchersToNotify = append(watchersToNotify, watchers...)
	}
	if watchers, exists := sm.watchers["all"]; exists {
		watchersToNotify = append(watchersToNotify, watchers...)
	}
	sm.mu.RUnlock()
	
	// Notify all watchers
	for _, watcher := range watchersToNotify {
		go func(w SystemEventWatcher) {
			defer func() {
				if r := recover(); r != nil {
					sm.logger.Error("Event watcher panic",
						"watcher_name", w.GetWatcherName(),
						"event_type", event.Type,
						"panic", r)
				}
			}()
			
			w.OnSystemEvent(event)
		}(watcher)
	}
	
	// Log the event
	sm.logger.InfoCtx(context.Background(), "System event emitted",
		"event_id", event.ID,
		"event_type", event.Type,
		"source", event.Source,
		"component", event.Component,
		"severity", event.Severity,
		"correlation_id", event.CorrelationID)
}