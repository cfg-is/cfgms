// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// This file provides the controller-mode configuration executor.
//
// Executor wraps ExecutionEngine so the controller-connected steward uses the same
// Get→Compare→Set→Verify workflow and the full set of 7 built-in modules as
// standalone mode. This is the single execution path for all steward operation modes.
package execution

import (
	"context"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ExecutorConfig holds configuration for creating a controller-mode Executor.
type ExecutorConfig struct {
	// TenantID for this steward
	TenantID string

	// Logger for execution logging
	Logger logging.Logger
}

// Executor applies configurations received from the controller using the unified
// execution engine. It wraps ExecutionEngine to provide the controller-mode
// interface: raw config bytes in, ConfigStatusReport out.
//
// Both standalone and controller-connected stewards use the same underlying
// ExecutionEngine with all 7 built-in modules and Get→Compare→Set→Verify workflow.
type Executor struct {
	engine   *ExecutionEngine
	tenantID string
	logger   logging.Logger
}

// NewExecutor creates a controller-mode Executor backed by the unified execution engine.
//
// All 7 built-in modules (file, directory, script, firewall, package, patch, acme)
// are registered and the Get→Compare→Set→Verify workflow is used, matching
// the behavior of standalone mode.
func NewExecutor(cfg *ExecutorConfig) (*Executor, error) {
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure:  config.ActionContinue,
		ResourceFailure:    config.ActionWarn,
		ConfigurationError: config.ActionFail,
	}

	// Empty registry — all 7 built-in modules are loaded on demand by the factory
	registry := discovery.ModuleRegistry{}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	engine := New(moduleFactory, comparator, errorConfig, cfg.Logger)

	return &Executor{
		engine:   engine,
		tenantID: cfg.TenantID,
		logger:   cfg.Logger,
	}, nil
}

// ApplyConfiguration parses YAML or JSON configuration bytes and applies them
// using the unified execution engine. Returns a ConfigStatusReport suitable for
// publishing to the control plane.
//
// The method accepts both YAML and JSON formats (JSON is valid YAML).
func (e *Executor) ApplyConfiguration(ctx context.Context, configData []byte, version string) (*cpTypes.ConfigStatusReport, error) {
	startTime := time.Now()

	report := &cpTypes.ConfigStatusReport{
		ConfigVersion: version,
		Status:        "OK",
		Message:       "Configuration applied successfully",
		Modules:       make(map[string]cpTypes.ModuleStatus),
		Timestamp:     time.Now(),
	}

	e.logger.Info("Applying configuration", "version", version, "size", len(configData))

	// Parse configuration — YAML v3 accepts both YAML and JSON formats
	var cfg config.StewardConfig
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		e.logger.Error("Failed to parse configuration", "error", err)
		report.Status = "ERROR"
		report.Message = fmt.Sprintf("Configuration parsing failed: %v", err)
		return report, fmt.Errorf("failed to parse configuration: %w", err)
	}

	e.logger.Info("Parsed configuration",
		"steward_id", cfg.Steward.ID,
		"resource_count", len(cfg.Resources))

	// Add tenant context
	if e.tenantID != "" {
		ctx = logging.WithTenant(ctx, e.tenantID)
	}

	// Execute using the unified Get→Compare→Set→Verify engine
	execReport := e.engine.ExecuteConfiguration(ctx, cfg)

	// Convert ExecutionReport to ConfigStatusReport
	report.ExecutionTimeMs = execReport.EndTime.Sub(execReport.StartTime).Milliseconds()

	hasErrors := false

	// Group per-resource results into per-module module statuses
	for _, result := range execReport.ResourceResults {
		moduleName := result.ModuleName

		moduleStatus, exists := report.Modules[moduleName]
		if !exists {
			moduleStatus = cpTypes.ModuleStatus{
				Name:      moduleName,
				Status:    "OK",
				Timestamp: time.Now(),
				Details:   make(map[string]interface{}),
			}
		}

		// Accumulate success/error counts
		successCount, _ := moduleStatus.Details["success_count"].(int)
		errorCount, _ := moduleStatus.Details["error_count"].(int)
		totalCount, _ := moduleStatus.Details["total_count"].(int)
		totalCount++

		switch result.Status {
		case StatusSuccess, StatusNoChange:
			successCount++
		case StatusFailed:
			errorCount++
			hasErrors = true
			moduleStatus.Status = "ERROR"
			if result.Error != "" {
				errList, _ := moduleStatus.Details["errors"].([]string)
				moduleStatus.Details["errors"] = append(errList, fmt.Sprintf("%s: %s", result.ResourceName, result.Error))
			}
		case StatusSkipped:
			// Skipped resources are counted but don't set ERROR status
		}

		moduleStatus.Details["success_count"] = successCount
		moduleStatus.Details["error_count"] = errorCount
		moduleStatus.Details["total_count"] = totalCount

		if errorCount > 0 {
			moduleStatus.Message = fmt.Sprintf("Applied %d/%d resources (%d errors)", successCount, totalCount, errorCount)
		} else {
			moduleStatus.Message = fmt.Sprintf("Applied %d resources", totalCount)
		}

		report.Modules[moduleName] = moduleStatus
	}

	// Propagate execution-level errors
	if len(execReport.Errors) > 0 {
		hasErrors = true
	}

	if hasErrors {
		report.Status = "ERROR"
		report.Message = "Configuration applied with errors"
	}

	report.ExecutionTimeMs = time.Since(startTime).Milliseconds()

	e.logger.Info("Configuration application completed",
		"version", version,
		"status", report.Status,
		"execution_time_ms", report.ExecutionTimeMs)

	return report, nil
}
