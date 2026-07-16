// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// This file provides the unified configuration executor.
//
// Executor owns the complete Get→Compare→Set→Verify workflow and is the single
// execution path for all steward operation modes (standalone and controller-connected).
package execution

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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

	// StewardID is the registered steward identity stamped into emitted LogEntry
	// events. Leave empty in standalone mode or when event emission is not configured.
	StewardID string

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

	// EventEmitter, when non-nil, receives convergence detection and outcome events.
	// Enqueue must never block the caller; the concrete implementation drops when full.
	EventEmitter EventEmitter

	// ModuleCallTimeoutSec is the per-call timeout (in seconds) applied individually
	// to each module.Get, module.Set, and verifyChanges invocation. Zero or negative
	// values default to 120 s. There is no "infinite" option — all module calls have
	// a finite deadline to prevent a hung module from wedging the convergence loop
	// (ADR-012 §7).
	ModuleCallTimeoutSec int

	// ModuleDNASnapshot is an optional shared module-DNA store (#2520). When set,
	// this executor records observed module state into it and reads from it in
	// CollectModuleDNAAttributes. The steward client passes ONE store into every
	// executor it builds so module DNA survives executor re-init on reconnect. Nil
	// gives the executor a private store (standalone / tests).
	ModuleDNASnapshot *ModuleDNASnapshot
}

// Executor applies configurations using the unified Get→Compare→Set→Verify workflow.
// It serves both standalone mode (direct ExecuteConfiguration calls) and controller
// mode (ApplyConfiguration with raw config bytes in, ConfigStatusReport out).
type Executor struct {
	factory    *factory.ModuleFactory
	comparator *stewardtesting.StateComparator
	config     config.ErrorHandlingConfig
	tenantID   string
	stewardID  string
	logger     logging.Logger

	// mu protects driftHandler and driftMode. Both can be written after construction
	// (controller delivers new cfg, tests replace the handler) while ExecuteResource
	// reads them concurrently from the monitor event loop.
	mu           sync.RWMutex
	driftHandler DriftEventHandler
	driftMode    config.DriftMode

	// eventEmitter, when non-nil, receives convergence detection and outcome events
	// (ADR-012 §2). Enqueue is the only emitter call on the convergence goroutine;
	// the actual LogStream send runs on the emitter's own goroutine.
	eventEmitter EventEmitter

	// moduleCallTimeout is the per-call deadline applied to module.Get, module.Set,
	// and verifyChanges. Derived from ModuleCallTimeoutSec at construction; defaults
	// to 120 s when the config field is zero or negative (ADR-012 §7).
	moduleCallTimeout time.Duration

	// moduleDNA is the shared, process-stable module-DNA snapshot (#2520). Injected
	// via ExecutorConfig.ModuleDNASnapshot so it survives executor re-init on
	// reconnect; NewExecutor allocates a private one when none is supplied.
	moduleDNA *ModuleDNASnapshot

	// Monitor engine fields (Issue #2435). Protected by monitorMu except where noted.
	monitorFields
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

	callTimeout := time.Duration(cfg.ModuleCallTimeoutSec) * time.Second
	if callTimeout <= 0 {
		callTimeout = 120 * time.Second
	}

	moduleDNA := cfg.ModuleDNASnapshot
	if moduleDNA == nil {
		moduleDNA = NewModuleDNASnapshot()
	}

	return &Executor{
		factory:           f,
		comparator:        comp,
		config:            errCfg,
		tenantID:          cfg.TenantID,
		stewardID:         cfg.StewardID,
		logger:            cfg.Logger,
		driftMode:         cfg.DriftMode,
		eventEmitter:      cfg.EventEmitter,
		moduleCallTimeout: callTimeout,
		moduleDNA:         moduleDNA,
	}, nil
}

// SetDriftEventHandler registers a callback invoked when the Compare step detects
// drift on a managed resource, before Set corrects it. Pass nil to remove a handler.
func (e *Executor) SetDriftEventHandler(handler DriftEventHandler) {
	e.mu.Lock()
	e.driftHandler = handler
	e.mu.Unlock()
}

// SetDriftMode updates the executor's drift mode. Call this when the
// controller delivers a new cfg with an updated drift_mode field.
// An empty string is treated as DriftModeApply (default behavior).
func (e *Executor) SetDriftMode(mode config.DriftMode) {
	e.mu.Lock()
	e.driftMode = mode
	e.mu.Unlock()
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
			case StatusFailed, StatusTimeout:
				report.FailedCount++
			case StatusSkipped:
				report.SkippedCount++
			case StatusNonCompliant:
				report.NonCompliantCount++
			}
		}
	}

	// Drop DNA snapshot entries for resources no longer in the config so a removed
	// resource disappears from module DNA (#2520). Only the full pass knows the
	// complete managed set, so prune here rather than in ExecuteResource.
	keep := make(map[string]struct{}, len(cfg.Resources))
	for _, r := range cfg.Resources {
		keep[e.GetResourceID(r)] = struct{}{}
	}
	e.pruneModuleDNAState(keep)

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

	// Snapshot drift mode and handler once for this resource's execution.
	// Both may be updated concurrently while the monitor event loop dispatches calls.
	e.mu.RLock()
	driftMode := e.driftMode
	driftHandler := e.driftHandler
	e.mu.RUnlock()

	// Generate correlation ID for the detection+outcome event pair (ADR-012 §2).
	correlationID := uuid.New().String()
	driftModeStr := "apply"
	if driftMode == config.DriftModeMonitor {
		driftModeStr = "report"
	}

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

	// Detection event: enqueued before module.Get so a module hang still leaves
	// the detection observable on the out-of-band channel (ADR-012 §2 crash-isolation).
	e.enqueueDetection(correlationID, resourceID, driftModeStr)

	// module.Get with per-call deadline so a hung module cannot wedge the
	// convergence loop (ADR-012 §7). The deadline is derived from the ambient ctx
	// so outer cancellation still propagates.
	getCallStart := time.Now()
	getCtx, getCancel := context.WithTimeout(ctx, e.moduleCallTimeout)
	defer getCancel()
	// effectiveBudget is the actual enforced duration — min(ctx.Deadline(), e.moduleCallTimeout).
	// Logging this instead of the hardcoded e.moduleCallTimeout ensures the WARN is
	// truthful when a caller supplies a tighter ambient deadline.
	getEffectiveDl, _ := getCtx.Deadline()
	getEffectiveBudget := getEffectiveDl.Sub(getCallStart)
	currentState, err := module.Get(getCtx, resourceID)
	if err != nil {
		result.ExecutionTime = time.Since(startTime)
		if errors.Is(err, context.DeadlineExceeded) {
			result.Status = StatusTimeout
			result.Error = fmt.Sprintf("module.Get did not finish within %s", getEffectiveBudget)
			e.enqueueTimeoutOutcome(correlationID, getEffectiveBudget, result.ExecutionTime)
			e.logger.Warn("module.Get timeout",
				"resource", resource.Name,
				"module", resource.Module,
				"timeout_ms", getEffectiveBudget.Milliseconds(),
				"elapsed_ms", result.ExecutionTime.Milliseconds())
			return result
		}
		result.Error = fmt.Sprintf("failed to get current state: %v", err)
		if rerr := e.handleResourceError(resource, err); rerr != nil {
			result.Error = rerr.Error()
			return result
		}
		return result
	}

	// Capture the observed state for module DNA publication (#2520 mechanism 1).
	// The periodic convergence loop AND monitor-triggered targeted reconciles both
	// land here, so caching the Get result keeps module DNA live at steady state —
	// not only when a change-event fires — with no extra module call.
	e.cacheModuleDNAState(resourceID, currentState)

	// Managed-elsewhere short-circuit (Story #2577): a module may report from Get
	// that the resource is real and in its desired terminal state but managed by a
	// DIFFERENT authority — e.g. a clustered HA VM owned by another cluster node.
	// This node is not the manager, so field-level drift against its local view is
	// not meaningful; treat it as compliant with no Compare/Set/Verify. The
	// accountable authority (the CNO for HA VMs) owns "does it exist / have an
	// owner"; a non-owner only abstains.
	if me, ok := currentState.(modules.ManagedElsewhere); ok {
		if managed, authority := me.ManagedElsewhere(); managed {
			result.Status = StatusNoChange
			result.ExecutionTime = time.Since(startTime)
			e.logger.Info("Resource managed on another node — compliant by delegation",
				"resource", resource.Name,
				"managed_by", authority)
			return result
		}
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
	if driftMode == config.DriftModeMonitor {
		stateDiff.EventType = "drift.detected.monitor"
	} else {
		stateDiff.EventType = "drift.detected"
	}

	// Emit drift event. Handler fires in both modes — ordering is always preserved.
	if driftHandler != nil {
		driftHandler(resource.Name, resource.Module, &stateDiff)
	}

	// In monitor mode, report non-compliance without correcting the drift.
	if driftMode == config.DriftModeMonitor {
		result.Status = StatusNonCompliant
		result.ExecutionTime = time.Since(startTime)
		// Outcome: drift detected and reported; no correction applied.
		e.enqueueOutcome(correlationID, "drift_reported", result.ExecutionTime)
		e.logger.Info("Monitor mode: drift detected, skipping Set",
			"resource", resource.Name,
			"event_type", stateDiff.EventType)
		return result
	}

	// module.Set with per-call deadline (ADR-012 §7).
	setCallStart := time.Now()
	setCtx, setCancel := context.WithTimeout(ctx, e.moduleCallTimeout)
	defer setCancel()
	setEffectiveDl, _ := setCtx.Deadline()
	setEffectiveBudget := setEffectiveDl.Sub(setCallStart)
	if err := module.Set(setCtx, resourceID, desiredState); err != nil {
		result.ExecutionTime = time.Since(startTime)
		if errors.Is(err, context.DeadlineExceeded) {
			result.Status = StatusTimeout
			result.Error = fmt.Sprintf("module.Set did not finish within %s", setEffectiveBudget)
			e.enqueueTimeoutOutcome(correlationID, setEffectiveBudget, result.ExecutionTime)
			e.logger.Warn("module.Set timeout",
				"resource", resource.Name,
				"module", resource.Module,
				"timeout_ms", setEffectiveBudget.Milliseconds(),
				"elapsed_ms", result.ExecutionTime.Milliseconds())
			return result
		}
		result.Error = fmt.Sprintf("failed to apply configuration: %v", err)
		// Outcome: Set failed; record before error-handling may continue.
		e.enqueueOutcome(correlationID, "error", result.ExecutionTime)
		if rerr := e.handleResourceError(resource, err); rerr != nil {
			result.Error = rerr.Error()
			return result
		}
		return result
	}

	result.ChangesApplied = true

	// verifyChanges with per-call deadline (ADR-012 §7). The deadline applies to
	// the module.Get call inside verifyChanges.
	verifyCallStart := time.Now()
	verifyCtx, verifyCancel := context.WithTimeout(ctx, e.moduleCallTimeout)
	defer verifyCancel()
	verifyEffectiveDl, _ := verifyCtx.Deadline()
	verifyEffectiveBudget := verifyEffectiveDl.Sub(verifyCallStart)
	if err := e.verifyChanges(verifyCtx, module, resourceID, desiredState); err != nil {
		result.ExecutionTime = time.Since(startTime)
		if errors.Is(err, context.DeadlineExceeded) {
			result.Status = StatusTimeout
			result.Error = fmt.Sprintf("verifyChanges did not finish within %s", verifyEffectiveBudget)
			e.enqueueTimeoutOutcome(correlationID, verifyEffectiveBudget, result.ExecutionTime)
			e.logger.Warn("verifyChanges timeout",
				"resource", resource.Name,
				"module", resource.Module,
				"timeout_ms", verifyEffectiveBudget.Milliseconds(),
				"elapsed_ms", result.ExecutionTime.Milliseconds())
			return result
		}
		result.Error = fmt.Sprintf("verification failed: %v", err)
		// Outcome: post-Set verification failed.
		e.enqueueOutcome(correlationID, "error", result.ExecutionTime)
		if rerr := e.handleResourceError(resource, err); rerr != nil {
			result.Error = rerr.Error()
			return result
		}
		return result
	}

	result.Status = StatusSuccess
	result.ExecutionTime = time.Since(startTime)
	// Outcome: convergence applied and verified successfully.
	e.enqueueOutcome(correlationID, "applied", result.ExecutionTime)

	e.logger.Info("Resource configuration applied successfully",
		"resource", resource.Name,
		"duration", result.ExecutionTime)

	return result
}

// createConfigState converts a map[string]interface{} to a ConfigState.
func (e *Executor) createConfigState(configData map[string]interface{}) (modules.ConfigState, error) {
	return &genericConfigState{data: configData}, nil
}

// GetResourceID returns the module-internal resource identifier for the given
// ResourceConfig. This is the identifier passed to module.Get, module.Set, and
// Monitor() — callers that need to match ChangeEvent.ResourceID against cfg
// resources must use this method to ensure the IDs are consistent.
func (e *Executor) GetResourceID(resource config.ResourceConfig) string {
	return e.getResourceIdentifier(resource)
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
		case StatusFailed, StatusTimeout:
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
