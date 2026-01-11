// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package export

import (
	"context"
	"fmt"
	"time"
)

// exportLoop processes export data and sends it to all enabled exporters.
func (em *ExportManager) exportLoop(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			em.logger.ErrorCtx(ctx, "Export loop panic recovered",
				"panic", r)
		}
	}()

	ticker := time.NewTicker(em.config.ExportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-em.shutdownCh:
			return
		case data, ok := <-em.dataChannel:
			if !ok {
				// Channel closed, exit loop
				return
			}
			em.processExportData(ctx, data)
		case <-ticker.C:
			// Periodic health check trigger
			em.triggerHealthChecks(ctx)
		}
	}
}

// processExportData sends data to all enabled exporters.
func (em *ExportManager) processExportData(ctx context.Context, data ExportData) {
	ctx, span := em.tracer.Start(ctx, "export_manager.process_data")
	defer span.End()

	em.mu.RLock()
	exporters := make(map[string]MonitoringExporter)
	for name, exporter := range em.exporters {
		if em.isExporterEnabled(name, data.ExportType) {
			exporters[name] = exporter
		}
	}
	em.mu.RUnlock()

	// Debug logging for test environments
	if data.ExportType == ExportTypeManual {
		em.logger.InfoCtx(ctx, "Processing manual export data",
			"exporters_found", len(exporters),
			"total_exporters", len(em.exporters),
			"export_type", data.ExportType)
		// Log each exporter check result
		for name := range em.exporters {
			enabled := em.isExporterEnabled(name, data.ExportType)
			em.logger.InfoCtx(ctx, "Exporter check",
				"name", name,
				"enabled", enabled,
				"export_type", data.ExportType)
		}
	}

	// Export to all enabled exporters in parallel (or synchronously for manual exports)
	for name, exporter := range exporters {
		if data.ExportType == ExportTypeManual {
			// Process synchronously for test environments
			em.exportToExporter(ctx, name, exporter, data)
		} else {
			go em.exportToExporter(ctx, name, exporter, data)
		}
	}
}

// exportToExporter exports data to a specific exporter with retry logic.
func (em *ExportManager) exportToExporter(ctx context.Context, name string, exporter MonitoringExporter, data ExportData) {
	startTime := time.Now()

	// Create exporter-specific context with timeout
	exporterConfig := em.config.Exporters[name]
	timeout := exporterConfig.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	exportCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Filter data based on exporter configuration
	filteredData := em.filterDataForExporter(data, exporterConfig)

	var lastErr error
	for attempt := 0; attempt <= em.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt) * em.config.RetryBackoff
			select {
			case <-time.After(backoff):
			case <-exportCtx.Done():
				return
			}
		}

		err := exporter.Export(exportCtx, filteredData)
		if err == nil {
			// Success
			responseTime := time.Since(startTime)
			em.updateExporterSuccess(name, responseTime)

			em.logger.DebugCtx(exportCtx, "Successfully exported data",
				"exporter_name", name,
				"response_time_ms", responseTime.Milliseconds(),
				"data_size_bytes", em.estimateDataSize(filteredData))
			return
		}

		lastErr = err
		em.logger.WarnCtx(exportCtx, "Export attempt failed",
			"exporter_name", name,
			"attempt", attempt+1,
			"max_retries", em.config.MaxRetries,
			"error", err)
	}

	// All retries failed
	em.updateExporterFailure(name, lastErr)

	// Send to error channel for centralized error handling
	select {
	case em.errorCh <- ExportError{
		ExporterName: name,
		Error:        lastErr,
		Data:         data,
		Timestamp:    time.Now(),
		Attempt:      em.config.MaxRetries + 1,
	}:
	default:
		// Error channel full, log the error
		em.logger.ErrorCtx(ctx, "Failed to send export error to error channel",
			"exporter_name", name,
			"error", lastErr)
	}
}

// healthCheckLoop periodically checks the health of all exporters.
func (em *ExportManager) healthCheckLoop(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			em.logger.ErrorCtx(ctx, "Health check loop panic recovered",
				"panic", r)
		}
	}()

	ticker := time.NewTicker(em.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-em.shutdownCh:
			return
		case <-ticker.C:
			em.performHealthChecks(ctx)
		}
	}
}

// performHealthChecks runs health checks on all exporters.
func (em *ExportManager) performHealthChecks(ctx context.Context) {
	ctx, span := em.tracer.Start(ctx, "export_manager.health_checks")
	defer span.End()

	em.mu.RLock()
	exporters := make(map[string]MonitoringExporter)
	for name, exporter := range em.exporters {
		exporters[name] = exporter
	}
	em.mu.RUnlock()

	// Run health checks in parallel
	for name, exporter := range exporters {
		go em.checkExporterHealth(ctx, name, exporter)
	}
}

// checkExporterHealth performs a health check on a specific exporter.
func (em *ExportManager) checkExporterHealth(ctx context.Context, name string, exporter MonitoringExporter) {
	startTime := time.Now()

	// Create health check context with timeout
	healthCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	health := exporter.HealthCheck(healthCtx)
	responseTime := time.Since(startTime)

	// Update health status
	em.healthMu.Lock()
	existingHealth := em.exporterHealth[name]
	existingHealth.Status = health.Status
	existingHealth.Message = health.Message
	existingHealth.ResponseTime = responseTime
	existingHealth.LastHealthCheck = time.Now()

	if health.Status != "healthy" {
		existingHealth.ErrorCount++
	}

	em.exporterHealth[name] = existingHealth
	em.healthMu.Unlock()

	em.logger.DebugCtx(ctx, "Exporter health check completed",
		"exporter_name", name,
		"status", health.Status,
		"response_time_ms", responseTime.Milliseconds())
}

// errorHandlingLoop processes export errors for centralized error handling.
func (em *ExportManager) errorHandlingLoop(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			em.logger.ErrorCtx(ctx, "Error handling loop panic recovered",
				"panic", r)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-em.shutdownCh:
			return
		case exportError := <-em.errorCh:
			em.handleExportError(ctx, exportError)
		}
	}
}

// handleExportError processes a specific export error.
func (em *ExportManager) handleExportError(ctx context.Context, exportError ExportError) {
	em.logger.ErrorCtx(ctx, "Export operation failed",
		"exporter_name", exportError.ExporterName,
		"error", exportError.Error,
		"attempts", exportError.Attempt,
		"timestamp", exportError.Timestamp)

	// Update exporter health to reflect the error
	em.updateExporterHealth(exportError.ExporterName, "unhealthy",
		fmt.Sprintf("Export failed: %v", exportError.Error), exportError.Error)

	// Here you could implement additional error handling logic:
	// - Dead letter queue for failed exports
	// - Circuit breaker pattern
	// - Alerting for critical export failures
	// - Automatic exporter restart attempts
}

// triggerHealthChecks triggers health checks outside the normal schedule.
func (em *ExportManager) triggerHealthChecks(ctx context.Context) {
	// This is called periodically to ensure health checks happen even if
	// no export operations are occurring
	go em.performHealthChecks(ctx)
}

// Helper functions

// isExporterEnabled checks if an exporter should handle a specific export type.
func (em *ExportManager) isExporterEnabled(name string, exportType ExportType) bool {
	config, exists := em.config.Exporters[name]
	if !exists || !config.Enabled {
		return false
	}

	// If no specific export types are configured, handle all types
	if len(config.ExportTypes) == 0 {
		return true
	}

	// Check if this export type is allowed
	for _, allowedType := range config.ExportTypes {
		if allowedType == exportType {
			return true
		}
	}

	return false
}

// filterDataForExporter filters export data based on exporter configuration.
func (em *ExportManager) filterDataForExporter(data ExportData, config ExporterConfig) ExportData {
	filtered := data // Start with all data

	// If no data types are specified, return all data
	if len(config.DataTypes) == 0 {
		return filtered
	}

	// Create a new filtered data structure
	filtered = ExportData{
		Timestamp:     data.Timestamp,
		CorrelationID: data.CorrelationID,
		Source:        data.Source,
		ExportType:    data.ExportType,
	}

	// Filter based on configured data types
	for _, dataType := range config.DataTypes {
		switch dataType {
		case "metrics":
			filtered.SystemMetrics = data.SystemMetrics
			filtered.ResourceMetrics = data.ResourceMetrics
			filtered.StewardMetrics = data.StewardMetrics
			filtered.ControllerMetrics = data.ControllerMetrics
			filtered.WorkflowMetrics = data.WorkflowMetrics
		case "events":
			filtered.Events = data.Events
		case "logs":
			filtered.Logs = data.Logs
		case "traces":
			filtered.Traces = data.Traces
		case "health":
			filtered.HealthStatus = data.HealthStatus
		}
	}

	return filtered
}

// updateExporterSuccess updates exporter health after successful export.
func (em *ExportManager) updateExporterSuccess(name string, responseTime time.Duration) {
	em.healthMu.Lock()
	defer em.healthMu.Unlock()

	health := em.exporterHealth[name]
	health.Status = "healthy"
	health.Message = "Export successful"
	health.LastExport = time.Now()
	health.ResponseTime = responseTime
	health.ExportCount++
	health.LastError = nil

	em.exporterHealth[name] = health
}

// updateExporterFailure updates exporter health after failed export.
func (em *ExportManager) updateExporterFailure(name string, err error) {
	em.healthMu.Lock()
	defer em.healthMu.Unlock()

	health := em.exporterHealth[name]
	health.Status = "unhealthy"
	health.Message = fmt.Sprintf("Export failed: %v", err)
	health.LastError = err
	health.ErrorCount++

	em.exporterHealth[name] = health
}

// estimateDataSize provides a rough estimate of export data size for logging.
func (em *ExportManager) estimateDataSize(data ExportData) int {
	// This is a very rough estimate - in production you might want more accurate sizing
	size := 0

	// Estimate metrics size
	size += len(data.SystemMetrics) * 50
	size += len(data.ResourceMetrics) * 50
	size += len(data.StewardMetrics) * 50
	size += len(data.ControllerMetrics) * 50
	size += len(data.WorkflowMetrics) * 50

	// Estimate events and logs
	size += len(data.Events) * 200
	size += len(data.Logs) * 150
	size += len(data.Traces) * 300
	size += len(data.HealthStatus) * 100

	return size
}
