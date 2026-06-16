// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// This file provides the unified configuration executor.
//
// Executor owns the complete Get→Compare→Set→Verify workflow and is the single
// execution path for all steward operation modes (standalone and controller-connected).
package execution

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// ExecutorConfig holds configuration for creating an Executor.
type ExecutorConfig struct {
	// TenantID for this steward (controller mode; may be empty in standalone mode)
	TenantID string

	// Logger for execution logging
	Logger logging.Logger

	// Factory is an optional pre-built module factory. When nil, NewExecutor creates
	// one with an empty registry and default error handling (all 7 built-in modules).
	Factory *factory.ModuleFactory

	// Comparator is an optional pre-built state comparator. When nil, NewExecutor
	// creates a default one.
	Comparator *stewardtesting.StateComparator

	// ErrorHandling controls resource failure behaviour. Zero value applies when
	// Factory is provided by the caller; defaults are used otherwise.
	ErrorHandling config.ErrorHandlingConfig

	// DriftMode controls how the executor responds to detected drift.
	// Defaults to DriftModeApply (current behavior) when not set.
	// Thread from controller-delivered cfg via SetDriftMode; never from local files.
	DriftMode config.DriftMode

	// SecretStore is the steward's secret store. When non-nil, NewExecutor injects
	// it into the default factory it creates so that modules implementing
	// SecretStoreInjectable (e.g. hyperv) receive the store before Configure runs.
	// Ignored when Factory is supplied — callers wiring their own factory are
	// responsible for injecting the secret store themselves.
	SecretStore secretsif.SecretStore
}

// Executor applies configurations using the unified Get→Compare→Set→Verify workflow.
// It serves both standalone mode (direct ExecuteConfiguration calls) and controller
// mode (ApplyConfiguration with raw config bytes in, ConfigStatusReport out).
type Executor struct {
	factory      *factory.ModuleFactory
	comparator   *stewardtesting.StateComparator
	config       config.ErrorHandlingConfig
	tenantID     string
	logger       logging.Logger
	driftHandler DriftEventHandler
	driftMode    config.DriftMode
}

// NewExecutor creates an Executor. When cfg.Factory is nil, an empty registry and
// default error config are used (all 7 built-in modules available on demand).
func NewExecutor(cfg *ExecutorConfig) (*Executor, error) {
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	f := cfg.Factory
	comp := cfg.Comparator
	errCfg := cfg.ErrorHandling

	if f == nil {
		defaultErrCfg := config.ErrorHandlingConfig{
			ModuleLoadFailure:  config.ActionContinue,
			ResourceFailure:    config.ActionWarn,
			ConfigurationError: config.ActionFail,
		}
		// Empty registry — all 7 built-in modules are loaded on demand by the factory
		f = factory.New(discovery.ModuleRegistry{}, defaultErrCfg, cfg.Logger)
		errCfg = defaultErrCfg
		// Wire the secret store into the auto-created factory so modules that
		// implement SecretStoreInjectable (e.g. hyperv) receive it before
		// Configure runs. Without this, controller-connected stewards see
		// `secret store must be injected before Configure` on every secret-
		// using resource.
		if cfg.SecretStore != nil {
			f.SetSecretStore(cfg.SecretStore)
		}
	}
	if comp == nil {
		comp = stewardtesting.NewStateComparator()
	}

	return &Executor{
		factory:    f,
		comparator: comp,
		config:     errCfg,
		tenantID:   cfg.TenantID,
		logger:     cfg.Logger,
		driftMode:  cfg.DriftMode,
	}, nil
}

// SetDriftEventHandler registers a callback invoked when the Compare step detects
// drift on a managed resource, before Set corrects it. Pass nil to remove a handler.
func (e *Executor) SetDriftEventHandler(handler DriftEventHandler) {
	e.driftHandler = handler
}

// SetDriftMode updates the executor's drift mode. Call this when the
// controller delivers a new cfg with an updated drift_mode field.
// An empty string is treated as DriftModeApply (default behavior).
func (e *Executor) SetDriftMode(mode config.DriftMode) {
	e.driftMode = mode
}

// ExecuteConfiguration executes the complete configuration for all resources.
func (e *Executor) ExecuteConfiguration(ctx context.Context, cfg config.StewardConfig) ExecutionReport {
	report := ExecutionReport{
		StartTime:       time.Now(),
		TotalResources:  len(cfg.Resources),
		ResourceResults: make([]ResourceResult, 0, len(cfg.Resources)),
		Errors:          make([]string, 0),
	}

	e.logger.Info("Starting configuration execution",
		"total_resources", report.TotalResources)

	for _, resource := range cfg.Resources {
		select {
		case <-ctx.Done():
			e.logger.Warn("Configuration execution cancelled")
			report.Errors = append(report.Errors, "execution cancelled: "+ctx.Err().Error())
			return report
		default:
			result := e.ExecuteResource(ctx, resource)
			report.ResourceResults = append(report.ResourceResults, result)

			switch result.Status {
			case StatusSuccess, StatusNoChange:
				report.SuccessfulCount++
			case StatusFailed:
				report.FailedCount++
			case StatusSkipped:
				report.SkippedCount++
			case StatusNonCompliant:
				report.NonCompliantCount++
			}
		}
	}

	report.EndTime = time.Now()

	e.logger.Info("Configuration execution completed",
		"total", report.TotalResources,
		"successful", report.SuccessfulCount,
		"failed", report.FailedCount,
		"skipped", report.SkippedCount,
		"non_compliant", report.NonCompliantCount,
		"duration", report.EndTime.Sub(report.StartTime))

	return report
}

// ExecuteResource executes configuration for a single resource.
func (e *Executor) ExecuteResource(ctx context.Context, resource config.ResourceConfig) ResourceResult {
	startTime := time.Now()

	result := ResourceResult{
		ResourceName: resource.Name,
		ModuleName:   resource.Module,
		Status:       StatusFailed,
	}

	// For modules that manage filesystem resources (file, directory), use the path
	// from config as the identifier. Otherwise fall back to the resource name.
	// For typed module refs (e.g. "hyperv.vm"), this builds the module-internal
	// typed resourceID (e.g. "vm:m2-test-vm").
	resourceID := e.getResourceIdentifier(resource)

	// A module ref may carry a resource-type suffix (e.g. "hyperv.vm"). The
	// bundle component ("hyperv") selects the signed module bundle to load;
	// the type suffix is resolved into the resourceID by getResourceIdentifier.
	// Loading MUST use the bundle name only — there is one signed bundle per
	// module (ADR-006), and the ".vm"/".vswitch" suffix is a
	// resource-type selector, not a separate module.
	bundle, _ := parseModuleRef(resource.Module)

	e.logger.Info("Executing resource configuration",
		"resource", resource.Name,
		"resource_id", resourceID,
		"module", resource.Module)

	module, err := e.factory.CreateModuleInstance(bundle)
	if err != nil {
		result.Error = fmt.Sprintf("failed to load module: %v", err)
		result.ExecutionTime = time.Since(startTime)
		if rerr := e.handleResourceError(resource, err); rerr != nil {
			result.Error = rerr.Error()
			return result
		}
		return result
	}

	if module == nil {
		// Module loading failed but error handling allowed continuation
		result.Status = StatusSkipped
		result.Error = "module loading failed but continuing per configuration"
		result.ExecutionTime = time.Since(startTime)
		return result
	}

	desiredState, err := e.createConfigState(resource.Config)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create config state: %v", err)
		result.ExecutionTime = time.Since(startTime)
		if rerr := e.handleResourceError(resource, err); rerr != nil {
			result.Error = rerr.Error()
			return result
		}
		return result
	}

	// If the module requires initialization before Get() (e.g., file module needs
	// AllowedBasePath to validate paths before reading), configure it now.
	if configurable, ok := module.(modules.Configurable); ok {
		if err := configurable.Configure(desiredState); err != nil {
			result.Error = fmt.Sprintf("failed to configure module: %v", err)
			result.ExecutionTime = time.Since(startTime)
			if rerr := e.handleResourceError(resource, err); rerr != nil {
				result.Error = rerr.Error()
				return result
			}
			return result
		}
	}

	currentState, err := module.Get(ctx, resourceID)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get current state: %v", err)
		result.ExecutionTime = time.Since(startTime)
		if rerr := e.handleResourceError(resource, err); rerr != nil {
			result.Error = rerr.Error()
			return result
		}
		return result
	}

	driftDetected, stateDiff := e.comparator.CompareStates(currentState, desiredState)
	result.DriftDetected = driftDetected
	result.StateDiff = &stateDiff

	if !driftDetected {
		result.Status = StatusNoChange
		result.ExecutionTime = time.Since(startTime)
		e.logger.Info("Resource is already in desired state",
			"resource", resource.Name)
		return result
	}

	e.logger.Info("Configuration drift detected",
		"resource", resource.Name,
		"changes_required", len(stateDiff.ChangedFields),
		"changed_fields", stateDiff.GetChangedFieldNames(),
		"added_fields", stateDiff.GetAddedFieldNames(),
		"removed_fields", stateDiff.GetRemovedFieldNames())

	// Tag the event type for upstream telemetry before invoking the handler.
	// "drift.detected.monitor" lets the controller distinguish monitor-mode stewards
	// from apply-mode stewards that simply have not drifted.
	if e.driftMode == config.DriftModeMonitor {
		stateDiff.EventType = "drift.detected.monitor"
	} else {
		stateDiff.EventType = "drift.detected"
	}

	// Emit drift event. Handler fires in both modes — ordering is always preserved.
	if e.driftHandler != nil {
		e.driftHandler(resource.Name, resource.Module, &stateDiff)
	}

	// In monitor mode, report non-compliance without correcting the drift.
	if e.driftMode == config.DriftModeMonitor {
		result.Status = StatusNonCompliant
		result.ExecutionTime = time.Since(startTime)
		e.logger.Info("Monitor mode: drift detected, skipping Set",
			"resource", resource.Name,
			"event_type", stateDiff.EventType)
		return result
	}

	if err := module.Set(ctx, resourceID, desiredState); err != nil {
		result.Error = fmt.Sprintf("failed to apply configuration: %v", err)
		result.ExecutionTime = time.Since(startTime)
		if rerr := e.handleResourceError(resource, err); rerr != nil {
			result.Error = rerr.Error()
			return result
		}
		return result
	}

	result.ChangesApplied = true

	if err := e.verifyChanges(ctx, module, resourceID, desiredState); err != nil {
		result.Error = fmt.Sprintf("verification failed: %v", err)
		result.ExecutionTime = time.Since(startTime)
		if rerr := e.handleResourceError(resource, err); rerr != nil {
			result.Error = rerr.Error()
			return result
		}
		return result
	}

	result.Status = StatusSuccess
	result.ExecutionTime = time.Since(startTime)

	e.logger.Info("Resource configuration applied successfully",
		"resource", resource.Name,
		"duration", result.ExecutionTime)

	return result
}

// createConfigState converts a map[string]interface{} to a ConfigState.
func (e *Executor) createConfigState(configData map[string]interface{}) (modules.ConfigState, error) {
	return &genericConfigState{data: configData}, nil
}

// parseModuleRef splits a module reference into its bundle and resource-type
// components on the FIRST ".". A ref without a dot has no resource type:
//
//	"hyperv.vm"   -> ("hyperv", "vm")
//	"hyperv.vswitch" -> ("hyperv", "vswitch")
//	"directory"   -> ("directory", "")
//
// The bundle component names the one signed module bundle to load (ADR-006);
// the resource-type component is resolved by the steward executor into the
// module's internal typed resourceID — the bundle is never split.
func parseModuleRef(module string) (bundle, resourceType string) {
	idx := strings.IndexByte(module, '.')
	if idx < 0 {
		return module, ""
	}
	return module[:idx], module[idx+1:]
}

// getResourceIdentifier returns the module-internal identifier passed to the
// module's Get/Set for a resource.
//
// Rules:
//   - Untyped module ref (no "." — e.g. "file", "directory", "script"): keep
//     the legacy behaviour — the "path" config field when set & non-empty,
//     else the plain resource name. This preserves back-compat for the
//     filesystem modules that key on a path.
//   - Typed module ref (e.g. "hyperv.vm", "hyperv.vswitch"): build the module's
//     typed resourceID as "<resourceType>:<name>" (e.g. "vm:m2-test-vm"). The
//     plain resource name stays strictly validated; the type lives in the
//     module field. This is uniform across all typed modules — there is no
//     compound id and no config folding.
func (e *Executor) getResourceIdentifier(resource config.ResourceConfig) string {
	_, resourceType := parseModuleRef(resource.Module)

	if resourceType == "" {
		// Untyped module: legacy path/name behaviour (file, directory, script, …).
		if path, ok := resource.Config["path"].(string); ok && path != "" {
			return path
		}
		return resource.Name
	}

	// Typed resource: "<type>:<name>" (e.g. "vm:m2-test-vm", "vswitch:m2-test-vsw").
	return resourceType + ":" + resource.Name
}

// verifyChanges confirms that the applied configuration matches the desired state.
func (e *Executor) verifyChanges(ctx context.Context, module modules.Module,
	resourceID string, desiredState modules.ConfigState) error {

	currentState, err := module.Get(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("failed to get state for verification: %w", err)
	}

	driftDetected, stateDiff := e.comparator.CompareStates(currentState, desiredState)
	if driftDetected {
		// Promoted from Debug → Info: when a Set passes but verification
		// still finds drift, operators need to know WHAT failed to apply
		// without rebuilding the steward in debug mode. The fields are
		// already structured so they don't clutter normal output.
		e.logger.Info("Verification found remaining drift",
			"changed_fields", stateDiff.GetChangedFieldNames(),
			"added_fields", stateDiff.GetAddedFieldNames(),
			"removed_fields", stateDiff.GetRemovedFieldNames(),
			"detailed_diff", stateDiff.GetDetailedDiff())
		return fmt.Errorf("verification failed: changes not fully applied, remaining differences: %d changed, %d added, %d removed",
			len(stateDiff.ChangedFields), len(stateDiff.AddedFields), len(stateDiff.RemovedFields))
	}

	return nil
}

// handleResourceError handles errors according to the configured error handling policy.
// Returns a non-nil error only for ActionFail — the caller must abort the convergence pass.
// For ActionContinue and ActionWarn, returns nil so execution continues.
func (e *Executor) handleResourceError(resource config.ResourceConfig, err error) error {
	switch e.config.ResourceFailure {
	case config.ActionContinue:
		e.logger.Error("Resource execution failed, continuing",
			"resource", resource.Name,
			"error", err)
	case config.ActionWarn:
		e.logger.Warn("Resource execution failed",
			"resource", resource.Name,
			"error", err)
	case config.ActionFail:
		e.logger.Error("Resource execution failed",
			"resource", resource.Name,
			"error", err)
		return fmt.Errorf("convergence aborted by ActionFail policy: %w", err)
	}
	return nil
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

	// cfg.Steward.ID is the locally-declared steward identifier from the
	// SYNCED config payload — which the controller does not populate (the
	// runtime steward_id comes from registration, not configuration). Logging
	// the empty value pollutes any `tail -1 | grep steward_id` consumer
	// (notably the fleet-e2e framework_test.go:178 wait). Omit when empty.
	logArgs := []interface{}{"resource_count", len(cfg.Resources)}
	if cfg.Steward.ID != "" {
		logArgs = append(logArgs, "steward_id", cfg.Steward.ID)
	}
	e.logger.Info("Parsed configuration", logArgs...)

	// Add tenant context
	if e.tenantID != "" {
		ctx = logging.WithTenant(ctx, e.tenantID)
	}

	execReport := e.ExecuteConfiguration(ctx, cfg)

	report.ExecutionTimeMs = execReport.EndTime.Sub(execReport.StartTime).Milliseconds()

	hasErrors := false
	hasNonCompliant := false

	// Group per-resource results into per-module statuses
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

		successCount, _ := moduleStatus.Details["success_count"].(int)
		errorCount, _ := moduleStatus.Details["error_count"].(int)
		nonCompliantCount, _ := moduleStatus.Details["non_compliant_count"].(int)
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
		case StatusNonCompliant:
			// Drift detected in monitor mode — not corrected, not an execution error.
			nonCompliantCount++
			hasNonCompliant = true
			if moduleStatus.Status == "OK" {
				moduleStatus.Status = "NON_COMPLIANT"
			}
		}

		moduleStatus.Details["success_count"] = successCount
		moduleStatus.Details["error_count"] = errorCount
		moduleStatus.Details["non_compliant_count"] = nonCompliantCount
		moduleStatus.Details["total_count"] = totalCount

		if errorCount > 0 {
			moduleStatus.Message = fmt.Sprintf("Applied %d/%d resources (%d errors)", successCount, totalCount, errorCount)
		} else if nonCompliantCount > 0 {
			moduleStatus.Message = fmt.Sprintf("Monitored %d resources (%d non-compliant)", totalCount, nonCompliantCount)
		} else {
			moduleStatus.Message = fmt.Sprintf("Applied %d resources", totalCount)
		}

		report.Modules[moduleName] = moduleStatus
	}

	if len(execReport.Errors) > 0 {
		hasErrors = true
	}

	if hasErrors {
		report.Status = "ERROR"
		report.Message = "Configuration applied with errors"
	} else if hasNonCompliant {
		report.Status = "NON_COMPLIANT"
		report.Message = "Configuration monitored: drift detected but not corrected"
	}

	report.ExecutionTimeMs = time.Since(startTime).Milliseconds()

	e.logger.Info("Configuration application completed",
		"version", version,
		"status", report.Status,
		"execution_time_ms", report.ExecutionTimeMs)

	return report, nil
}
