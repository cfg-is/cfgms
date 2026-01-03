// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/monitoring/export"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// exportMetrics exports the current metrics data to all configured exporters.
func (sm *SystemMonitor) exportMetrics(ctx context.Context) {
	if sm.exportManager == nil {
		return
	}

	// Prepare export data
	exportData := export.ExportData{
		SystemMetrics:   sm.convertSystemMetrics(),
		ResourceMetrics: sm.convertResourceMetrics(),
		HealthStatus:    sm.convertHealthStatus(),
		Timestamp:       time.Now(),
		CorrelationID:   telemetry.GetCorrelationID(ctx),
		Source:          "controller",
		ExportType:      export.ExportTypeScheduled,
	}

	// Add component-specific metrics
	if len(sm.systemMetrics.ComponentMetrics) > 0 {
		componentMetrics := make(map[string]interface{})
		for name, metrics := range sm.systemMetrics.ComponentMetrics {
			componentMetrics[name] = metrics
		}
		exportData.ControllerMetrics = componentMetrics
	}

	// Add workflow metrics
	workflowMetrics := sm.workflowMonitor.GetMetrics()
	exportData.WorkflowMetrics = map[string]interface{}{
		"total_executions":     workflowMetrics.TotalExecutions,
		"completed_executions": workflowMetrics.CompletedExecutions,
		"failed_executions":    workflowMetrics.FailedExecutions,
	}

	// Queue for export
	if err := sm.exportManager.Export(exportData); err != nil {
		sm.logger.WarnCtx(ctx, "Failed to queue metrics for export", "error", err)
	}
}

// exportEvent exports a system event to all configured exporters.
func (sm *SystemMonitor) exportEvent(ctx context.Context, event SystemEvent) {
	if sm.exportManager == nil {
		return
	}

	// Convert to export format
	exportEvent := export.SystemEvent{
		ID:            event.ID,
		Type:          string(event.Type),
		Source:        event.Source,
		Component:     event.Component,
		Timestamp:     event.Timestamp,
		Severity:      string(event.Severity),
		Message:       sm.formatEventMessage(event),
		CorrelationID: event.CorrelationID,
		TraceID:       event.TraceID,
		Data:          event.Data,
	}

	// Prepare export data
	exportData := export.ExportData{
		Events:        []export.SystemEvent{exportEvent},
		Timestamp:     time.Now(),
		CorrelationID: event.CorrelationID,
		Source:        "controller",
		ExportType:    export.ExportTypeTriggered,
	}

	// Queue for export
	if err := sm.exportManager.Export(exportData); err != nil {
		sm.logger.WarnCtx(ctx, "Failed to queue event for export", "error", err)
	}
}

// GetExporterHealth returns the health status of all configured exporters.
func (sm *SystemMonitor) GetExporterHealth() map[string]export.ExporterHealth {
	if sm.exportManager == nil {
		return make(map[string]export.ExporterHealth)
	}

	return sm.exportManager.GetExporterHealth()
}

// EnableExporter enables a specific exporter by name.
func (sm *SystemMonitor) EnableExporter(name string, config export.ExporterConfig) error {
	if sm.exportRegistry == nil {
		return fmt.Errorf("export registry not initialized")
	}

	// Create exporter from registry
	exporter, err := sm.exportRegistry.CreateExporter(name)
	if err != nil {
		return fmt.Errorf("failed to create exporter %s: %w", name, err)
	}

	// Configure the exporter
	if err := exporter.Configure(config); err != nil {
		return fmt.Errorf("failed to configure exporter %s: %w", name, err)
	}

	// Register with export manager
	if sm.exportManager == nil {
		// Create export manager if not exists
		sm.exportManager = export.NewExportManager(sm.logger, sm.tracer, sm.config.ExportConfig)
		if err := sm.exportManager.Start(context.Background()); err != nil {
			return fmt.Errorf("failed to start export manager: %w", err)
		}
	}

	if err := sm.exportManager.RegisterExporter(name, exporter); err != nil {
		return fmt.Errorf("failed to register exporter %s: %w", name, err)
	}

	// Start the exporter
	if err := exporter.Start(context.Background()); err != nil {
		return fmt.Errorf("failed to start exporter %s: %w", name, err)
	}

	return nil
}

// convertSystemMetrics converts internal system metrics to export format.
func (sm *SystemMonitor) convertSystemMetrics() map[string]interface{} {
	return map[string]interface{}{
		"total_stewards":           sm.systemMetrics.TotalStewards,
		"connected_stewards":       sm.systemMetrics.ConnectedStewards,
		"healthy_stewards":         sm.systemMetrics.HealthyStewards,
		"configurations_applied":   sm.systemMetrics.ConfigurationsApplied,
		"configuration_errors":     sm.systemMetrics.ConfigurationErrors,
		"workflow_executions":      sm.systemMetrics.WorkflowExecutions,
		"workflow_successes":       sm.systemMetrics.WorkflowSuccesses,
		"workflow_failures":        sm.systemMetrics.WorkflowFailures,
		"average_response_time_ms": sm.systemMetrics.AverageResponseTime.Milliseconds(),
		"average_config_time_ms":   sm.systemMetrics.AverageConfigTime.Milliseconds(),
		"uptime_seconds":           time.Since(sm.systemMetrics.StartTime).Seconds(),
	}
}

// convertResourceMetrics converts internal resource metrics to export format.
func (sm *SystemMonitor) convertResourceMetrics() map[string]interface{} {
	metrics := map[string]interface{}{
		"cpu_usage_percent":    sm.resourceMetrics.CPUUsagePercent,
		"cpu_cores":            sm.resourceMetrics.CPUCores,
		"memory_used_bytes":    sm.resourceMetrics.MemoryUsedBytes,
		"memory_total_bytes":   sm.resourceMetrics.MemoryTotalBytes,
		"memory_usage_percent": sm.resourceMetrics.MemoryUsagePercent,
		"goroutines":           sm.resourceMetrics.Goroutines,
		"gc_cycles":            sm.resourceMetrics.GCCycles,
	}

	// Add GC pause metrics if available
	if len(sm.resourceMetrics.GCPauses) > 0 {
		var totalPauseMs int64
		for _, pause := range sm.resourceMetrics.GCPauses {
			totalPauseMs += pause.Milliseconds()
		}
		metrics["gc_total_pause_ms"] = totalPauseMs
		metrics["gc_pause_count"] = len(sm.resourceMetrics.GCPauses)
		if len(sm.resourceMetrics.GCPauses) > 0 {
			metrics["gc_avg_pause_ms"] = totalPauseMs / int64(len(sm.resourceMetrics.GCPauses))
		}
	}

	return metrics
}

// formatEventMessage creates a human-readable message for an event.
func (sm *SystemMonitor) formatEventMessage(event SystemEvent) string {
	switch event.Type {
	case EventStewardConnected:
		return fmt.Sprintf("Steward connected from %s", event.Source)
	case EventStewardDisconnected:
		return fmt.Sprintf("Steward disconnected from %s", event.Source)
	case EventStewardHealthChange:
		if status, ok := event.Data["status"].(string); ok {
			return fmt.Sprintf("Steward health changed to %s", status)
		}
		return "Steward health status changed"
	case EventConfigurationApplied:
		return "Configuration successfully applied"
	case EventConfigurationFailed:
		if err, ok := event.Data["error"].(string); ok {
			return fmt.Sprintf("Configuration failed: %s", err)
		}
		return "Configuration application failed"
	case EventResourceAlert:
		if resource, ok := event.Data["resource"].(string); ok {
			return fmt.Sprintf("Resource alert for %s", resource)
		}
		return "Resource usage alert"
	default:
		return string(event.Type)
	}
}

// convertHealthStatus converts internal health status to export format.
func (sm *SystemMonitor) convertHealthStatus() map[string]export.HealthStatus {
	// Get internal health status
	internalHealth := sm.GetSystemHealth()

	// Convert to export format
	exportHealth := make(map[string]export.HealthStatus)
	for component, health := range internalHealth {
		exportHealth[component] = export.HealthStatus{
			Status:      health.Status,
			Message:     health.Message,
			LastChecked: health.LastChecked,
			Details:     health.Details,
		}
	}

	return exportHealth
}
