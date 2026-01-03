// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package workflow

import (
	"context"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// MLEnhancedEngine wraps the standard workflow engine with ML logging capabilities
type MLEnhancedEngine struct {
	*Engine
	mlLogger      *MLLogger
	perfCollector *WorkflowPerformanceCollector
	mlEnabled     bool
}

// NewMLEnhancedEngine creates a new workflow engine with ML logging capabilities
func NewMLEnhancedEngine(engine *Engine, loggingProvider interfaces.LoggingProvider) *MLEnhancedEngine {
	mlLogger := NewMLLogger(engine.logger, loggingProvider)
	perfCollector := NewWorkflowPerformanceCollector()

	return &MLEnhancedEngine{
		Engine:        engine,
		mlLogger:      mlLogger,
		perfCollector: perfCollector,
		mlEnabled:     true,
	}
}

// ExecuteWorkflow executes a workflow with enhanced ML logging
func (e *MLEnhancedEngine) ExecuteWorkflow(ctx context.Context, workflow Workflow, variables map[string]interface{}) (*WorkflowExecution, error) {
	// Call parent execution
	execution, err := e.Engine.ExecuteWorkflow(ctx, workflow, variables)
	if err != nil {
		return execution, err
	}

	// Add ML logging for execution start
	if e.mlEnabled {
		e.mlLogger.LogExecutionStart(execution, workflow)
		e.perfCollector.Reset()
	}

	return execution, nil
}

// EnableMLLogging enables or disables ML logging
func (e *MLEnhancedEngine) EnableMLLogging(enabled bool) {
	e.mlEnabled = enabled
}

// GetMLExporter returns an ML data exporter for this engine
func (e *MLEnhancedEngine) GetMLExporter() *MLDataExporter {
	// Get the logging provider from the ML logger
	return NewMLDataExporter(e.mlLogger.loggingProvider)
}

// Close cleanly shuts down the ML enhanced engine
func (e *MLEnhancedEngine) Close() error {
	if e.mlLogger != nil {
		return e.mlLogger.Close()
	}
	return nil
}

// Note: Future enhancement - complete ML integration would require
// modifying the core engine methods to capture API request/response data
// This current implementation provides the framework for ML logging integration

// MLLoggingConfig provides configuration for ML logging features
type MLLoggingConfig struct {
	Enabled                bool   `json:"enabled"`
	BufferSize             int    `json:"buffer_size"`
	FlushIntervalSeconds   int    `json:"flush_interval_seconds"`
	IncludeVariableStates  bool   `json:"include_variable_states"`
	IncludeAPIData         bool   `json:"include_api_data"`
	IncludePerformanceData bool   `json:"include_performance_data"`
	LoggingProviderName    string `json:"logging_provider_name"`
}

// DefaultMLLoggingConfig returns default ML logging configuration
func DefaultMLLoggingConfig() MLLoggingConfig {
	return MLLoggingConfig{
		Enabled:                true,
		BufferSize:             1000,
		FlushIntervalSeconds:   5,
		IncludeVariableStates:  true,
		IncludeAPIData:         true,
		IncludePerformanceData: true,
		LoggingProviderName:    "file", // Default to file provider
	}
}

// NewMLEnhancedEngineFromConfig creates an ML-enhanced engine from configuration
func NewMLEnhancedEngineFromConfig(engine *Engine, config MLLoggingConfig) (*MLEnhancedEngine, error) {
	if !config.Enabled {
		return &MLEnhancedEngine{
			Engine:    engine,
			mlEnabled: false,
		}, nil
	}

	// Get logging provider
	loggingProvider, err := interfaces.GetLoggingProvider(config.LoggingProviderName)
	if err != nil {
		return nil, err
	}

	mlEngine := NewMLEnhancedEngine(engine, loggingProvider)

	// Configure the ML logger based on config
	if mlEngine.mlLogger != nil {
		mlEngine.mlLogger.bufferSize = config.BufferSize
		// Additional configuration would be applied here
	}

	return mlEngine, nil
}

// GetMLLoggingStatus returns the current status of ML logging
func (e *MLEnhancedEngine) GetMLLoggingStatus() map[string]interface{} {
	status := map[string]interface{}{
		"enabled":        e.mlEnabled,
		"buffer_size":    0,
		"entries_logged": 0,
	}

	if e.mlLogger != nil {
		e.mlLogger.bufferMutex.RLock()
		status["buffer_size"] = e.mlLogger.bufferSize
		status["buffered_entries"] = len(e.mlLogger.entryBuffer)
		e.mlLogger.bufferMutex.RUnlock()
	}

	if e.perfCollector != nil {
		status["active_steps"] = len(e.perfCollector.GetActiveSteps())
		status["total_step_executions"] = e.perfCollector.GetStepExecutionCount()
	}

	return status
}

// FlushMLLogs manually flushes any buffered ML log entries
func (e *MLEnhancedEngine) FlushMLLogs() error {
	if e.mlLogger != nil {
		e.mlLogger.flushBuffer()
	}
	return nil
}
